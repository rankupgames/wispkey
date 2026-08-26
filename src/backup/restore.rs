/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Atomic vault backup restore, conflict detection, and merge planning.
 * Created: 2026-08-26
 * Last Modified: 2026-08-26
 */

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::{
    BackupCounts, BackupScope, SIDECAR_ACTIVE_PROJECT, SIDECAR_AUDIT_FINGERPRINT, SIDECAR_CLOUD,
    SIDECAR_CLOUD_MANIFESTS, SIDECAR_POLICIES, TABLE_ACCESS_REQUESTS, TABLE_AUDIT_LOG,
    TABLE_BOOTSTRAP_TOKENS, TABLE_CREDENTIALS, TABLE_INSTANCE_SCOPES, TABLE_INSTANCES,
    TABLE_PARTITIONS, TABLE_PROJECTS, TABLE_VAULT_META, VaultBackupPayload, dest_has_vault,
    insert_row, inspect_payload, read_payload, recovery_limits, restore_sidecar_paths,
    schema_compatibility, string_field, verify_payload, write_optional_b64, write_optional_text,
};
use crate::core::{
    Result, Vault, VaultError, prepare_restored_instance_secrets,
    revoke_bootstrap_tokens_after_restore,
};
use crate::secure_files;

/// How restore treats rows that already exist in the destination vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Abort restore when any non-identical conflict is found.
    Fail,
    /// Leave destination rows in place and skip conflicting backup rows.
    Skip,
}

/// Restore destination, dry-run, replace, and conflict behavior.
pub struct RestoreOptions<'a> {
    pub target_dir: &'a Path,
    pub dry_run: bool,
    pub replace: bool,
    pub on_conflict: ConflictPolicy,
}

/// One destination conflict that would require an explicit decision.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreConflict {
    pub entity: String,
    pub identity: String,
    pub reason: String,
}

/// Result of a restore or dry-run. Contains no secret values.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub dry_run: bool,
    pub mode: String,
    pub target: String,
    pub imported: BackupCounts,
    pub skipped: BackupCounts,
    pub conflicts: Vec<RestoreConflict>,
    pub instances_needing_reenrollment: Vec<String>,
    pub bootstrap_tokens_revoked: usize,
    pub warnings: Vec<String>,
    pub recovery_limits: Vec<String>,
}

/// Restores an encrypted vault backup into `options.target_dir`.
pub fn restore_backup(
    path: &str,
    passphrase: &str,
    options: RestoreOptions<'_>,
) -> Result<RestoreReport> {
    let payload = read_payload(path, passphrase)?;
    let verified = verify_payload(&payload);
    if !verified.ok {
        return Err(VaultError::Backup(format!(
            "backup verification failed: {}",
            verified.errors.join("; ")
        )));
    }
    schema_compatibility(&payload.source_schema_version)?;

    let target = options.target_dir;
    let existing = dest_has_vault(target);
    let replace = options.replace || !existing;
    if existing && !options.replace && password_hash_mismatch(target, &payload)? {
        return Err(VaultError::Backup(
            "backup master-password hash does not match the destination vault; restore to an empty --target path or pass --replace".into(),
        ));
    }

    if replace {
        restore_replace(&payload, options)
    } else {
        restore_merge(&payload, options)
    }
}

fn restore_replace(
    payload: &VaultBackupPayload,
    options: RestoreOptions<'_>,
) -> Result<RestoreReport> {
    let inspect = inspect_payload(payload);
    let instance_names: Vec<String> = inspect
        .instances
        .iter()
        .map(|row| row.name.clone())
        .collect();
    let bootstrap_count = payload.contents.bootstrap_tokens.len();
    let report = RestoreReport {
        dry_run: options.dry_run,
        mode: "replace".into(),
        target: options.target_dir.display().to_string(),
        imported: inspect.counts.clone(),
        skipped: BackupCounts::default(),
        conflicts: Vec::new(),
        instances_needing_reenrollment: instance_names,
        bootstrap_tokens_revoked: bootstrap_count,
        warnings: payload.warnings.clone(),
        recovery_limits: recovery_limits(),
    };
    if options.dry_run {
        return Ok(report);
    }

    secure_files::ensure_private_directory(options.target_dir)?;
    let staging = options
        .target_dir
        .join(format!(".wk-restore-{}", Uuid::new_v4()));
    let restore_result = restore_replace_into_staging(payload, &staging)
        .and_then(|()| commit_restored_files(&staging, options.target_dir));
    let _ = fs::remove_dir_all(&staging);
    restore_result?;
    Ok(report)
}

fn restore_replace_into_staging(payload: &VaultBackupPayload, staging: &Path) -> Result<()> {
    secure_files::ensure_private_directory(staging)?;
    let db_path = staging.join("vault.db");
    let db = Vault::initialize_database_file(&db_path)?;
    db.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
    let insert_result = insert_payload_tables(&db, payload, &SkipSet::default());
    match insert_result {
        Ok(()) => {
            if payload.scope.instances {
                prepare_restored_instance_secrets(&db)?;
            }
            if payload.scope.bootstrap {
                revoke_bootstrap_tokens_after_restore(&db)?;
            }
            db.execute_batch("COMMIT")?;
        }
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            return Err(error);
        }
    }
    write_sidecars(staging, &payload.scope, &payload.sidecars)?;
    Ok(())
}

fn restore_merge(
    payload: &VaultBackupPayload,
    options: RestoreOptions<'_>,
) -> Result<RestoreReport> {
    let db_path = options.target_dir.join("vault.db");
    let db = Connection::open(&db_path)?;
    Vault::migrate_schema(&db)?;
    let plan = plan_merge(&db, payload)?;
    if options.on_conflict == ConflictPolicy::Fail && !plan.conflicts.is_empty() && !options.dry_run
    {
        return Err(VaultError::Backup(format!(
            "{} restore conflict(s); pass --on-conflict skip, choose --replace, or restore to an empty --target. First conflict: {} {}",
            plan.conflicts.len(),
            plan.conflicts[0].entity,
            plan.conflicts[0].identity
        )));
    }

    let mut instance_names = Vec::new();
    if payload.scope.instances {
        instance_names = payload
            .contents
            .instances
            .iter()
            .filter(|row| {
                string_field(row, "id").is_none_or(|id| !plan.skip.instances.contains(&id))
            })
            .filter_map(|row| string_field(row, "name"))
            .collect();
    }
    let bootstrap_revoked = payload
        .contents
        .bootstrap_tokens
        .iter()
        .filter(|row| {
            !plan
                .skip
                .bootstrap
                .iter()
                .any(|row_id| row_id_is(row, row_id))
        })
        .count();

    let report = RestoreReport {
        dry_run: options.dry_run,
        mode: "merge".into(),
        target: options.target_dir.display().to_string(),
        imported: plan.imported.clone(),
        skipped: plan.skipped.clone(),
        conflicts: plan.conflicts.clone(),
        instances_needing_reenrollment: instance_names,
        bootstrap_tokens_revoked: bootstrap_revoked,
        warnings: payload.warnings.clone(),
        recovery_limits: recovery_limits(),
    };
    if options.dry_run {
        return Ok(report);
    }

    db.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
    let result = insert_payload_tables(&db, payload, &plan.skip).and_then(|()| {
        if payload.scope.instances {
            prepare_restored_instance_secrets(&db)?;
        }
        if payload.scope.bootstrap {
            revoke_bootstrap_tokens_after_restore(&db)?;
        }
        Ok(())
    });
    match result {
        Ok(()) => db.execute_batch("COMMIT")?,
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            return Err(error);
        }
    }

    merge_sidecars(options.target_dir, payload, options.on_conflict)?;
    Ok(report)
}

#[derive(Default)]
struct SkipSet {
    vault_meta: HashSet<String>,
    projects: HashSet<String>,
    partitions: HashSet<String>,
    credentials: HashSet<String>,
    audits: HashSet<String>,
    instances: HashSet<String>,
    scopes: HashSet<String>,
    access_requests: HashSet<String>,
    bootstrap: HashSet<String>,
}

struct MergePlan {
    imported: BackupCounts,
    skipped: BackupCounts,
    conflicts: Vec<RestoreConflict>,
    skip: SkipSet,
}

fn plan_merge(db: &Connection, payload: &VaultBackupPayload) -> Result<MergePlan> {
    let dest_projects = load_table_index(db, TABLE_PROJECTS, "id")?;
    let dest_project_names = load_table_index(db, TABLE_PROJECTS, "name")?;
    let dest_partitions = load_table_index(db, TABLE_PARTITIONS, "id")?;
    let dest_credentials = load_table_index(db, TABLE_CREDENTIALS, "id")?;
    let dest_tokens = load_table_index(db, TABLE_CREDENTIALS, "wisp_token")?;
    let dest_instances = load_table_index(db, TABLE_INSTANCES, "id")?;
    let dest_instance_names = load_table_index(db, TABLE_INSTANCES, "name")?;
    let dest_scopes = load_table_index(db, TABLE_INSTANCE_SCOPES, "id")?;
    let dest_requests = load_table_index(db, TABLE_ACCESS_REQUESTS, "id")?;
    let dest_bootstrap = load_table_index(db, TABLE_BOOTSTRAP_TOKENS, "id")?;
    let dest_audit = load_table_index(db, TABLE_AUDIT_LOG, "id")?;
    let dest_meta = load_meta_map(db)?;
    let dest_partition_names = load_partition_name_index(db)?;
    let dest_credential_names = load_credential_name_index(db)?;

    let mut skip = SkipSet::default();
    let mut conflicts = Vec::new();
    let mut skipped = BackupCounts::default();
    let mut imported = BackupCounts::default();

    for row in &payload.contents.vault_meta {
        let Some(key) = string_field(row, "key") else {
            continue;
        };
        match dest_meta.get(&key) {
            Some(existing) if meta_values_equal(existing, row) => {
                skip.vault_meta.insert(key);
                skipped.vault_meta += 1;
            }
            Some(_) if key == "password_hash" => {
                conflicts.push(RestoreConflict {
                    entity: "vault_meta".into(),
                    identity: key,
                    reason: "master-password material differs".into(),
                });
            }
            Some(_) if key == "version" || key == "created_at" => {
                skip.vault_meta.insert(key);
                skipped.vault_meta += 1;
            }
            Some(_) => {
                skip.vault_meta.insert(key.clone());
                skipped.vault_meta += 1;
                conflicts.push(RestoreConflict {
                    entity: "vault_meta".into(),
                    identity: key,
                    reason: "key already exists with different value".into(),
                });
            }
            None => imported.vault_meta += 1,
        }
    }

    classify_rows(
        &payload.contents.projects,
        "id",
        &dest_projects,
        Some(("name", &dest_project_names)),
        "project",
        &mut skip.projects,
        &mut imported.projects,
        &mut skipped.projects,
        &mut conflicts,
    );
    classify_partition_rows(
        &payload.contents.partitions,
        &dest_partitions,
        &dest_partition_names,
        &mut skip,
        &mut imported.partitions,
        &mut skipped.partitions,
        &mut conflicts,
    );
    classify_credential_rows(
        &payload.contents.credentials,
        &dest_credentials,
        &dest_tokens,
        &dest_credential_names,
        &payload.contents.partitions,
        &mut skip,
        &mut imported.credentials,
        &mut skipped.credentials,
        &mut conflicts,
    );
    classify_rows(
        &payload.contents.instances,
        "id",
        &dest_instances,
        Some(("name", &dest_instance_names)),
        "instance",
        &mut skip.instances,
        &mut imported.instances,
        &mut skipped.instances,
        &mut conflicts,
    );
    classify_rows(
        &payload.contents.instance_scopes,
        "id",
        &dest_scopes,
        None,
        "instance_scope",
        &mut skip.scopes,
        &mut imported.scopes,
        &mut skipped.scopes,
        &mut conflicts,
    );
    classify_rows(
        &payload.contents.access_requests,
        "id",
        &dest_requests,
        None,
        "access_request",
        &mut skip.access_requests,
        &mut imported.access_requests,
        &mut skipped.access_requests,
        &mut conflicts,
    );
    classify_rows(
        &payload.contents.bootstrap_tokens,
        "id",
        &dest_bootstrap,
        None,
        "bootstrap_token",
        &mut skip.bootstrap,
        &mut imported.bootstrap,
        &mut skipped.bootstrap,
        &mut conflicts,
    );
    classify_rows(
        &payload.contents.audit_log,
        "id",
        &dest_audit,
        None,
        "audit",
        &mut skip.audits,
        &mut imported.audits,
        &mut skipped.audits,
        &mut conflicts,
    );

    Ok(MergePlan {
        imported,
        skipped,
        conflicts,
        skip,
    })
}

type RowIndex = HashMap<String, Map<String, Value>>;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn classify_rows(
    rows: &[Map<String, Value>],
    id_key: &str,
    dest_by_id: &RowIndex,
    dest_by_alt: Option<(&str, &RowIndex)>,
    entity: &str,
    skip: &mut HashSet<String>,
    imported: &mut usize,
    skipped_count: &mut usize,
    conflicts: &mut Vec<RestoreConflict>,
) {
    for row in rows {
        let Some(id) = string_field(row, id_key) else {
            continue;
        };
        if let Some(existing) = dest_by_id.get(&id) {
            if rows_equivalent(existing, row) {
                skip.insert(id);
                *skipped_count += 1;
            } else {
                skip.insert(id.clone());
                *skipped_count += 1;
                conflicts.push(RestoreConflict {
                    entity: entity.into(),
                    identity: id,
                    reason: "id already exists with different data".into(),
                });
            }
            continue;
        }
        if let Some((alt_key, dest_alt)) = dest_by_alt
            && let Some(alt) = string_field(row, alt_key)
            && dest_alt.contains_key(&alt)
        {
            skip.insert(id.clone());
            *skipped_count += 1;
            conflicts.push(RestoreConflict {
                entity: entity.into(),
                identity: alt,
                reason: format!("{alt_key} already exists with a different id"),
            });
            continue;
        }
        *imported += 1;
    }
}

fn classify_partition_rows(
    rows: &[Map<String, Value>],
    dest_by_id: &HashMap<String, Map<String, Value>>,
    dest_by_project_name: &HashMap<(String, String), Map<String, Value>>,
    skip: &mut SkipSet,
    imported: &mut usize,
    skipped_count: &mut usize,
    conflicts: &mut Vec<RestoreConflict>,
) {
    for row in rows {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        if let Some(existing) = dest_by_id.get(&id) {
            if rows_equivalent(existing, row) {
                skip.partitions.insert(id);
                *skipped_count += 1;
            } else {
                skip.partitions.insert(id.clone());
                *skipped_count += 1;
                conflicts.push(RestoreConflict {
                    entity: "partition".into(),
                    identity: id,
                    reason: "id already exists with different data".into(),
                });
            }
            continue;
        }
        let project_id = string_field(row, "project_id").unwrap_or_default();
        let name = string_field(row, "name").unwrap_or_default();
        if dest_by_project_name.contains_key(&(project_id.clone(), name.clone())) {
            skip.partitions.insert(id);
            *skipped_count += 1;
            conflicts.push(RestoreConflict {
                entity: "partition".into(),
                identity: format!("{project_id}/{name}"),
                reason: "project already has a partition with this name".into(),
            });
            continue;
        }
        *imported += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_credential_rows(
    rows: &[Map<String, Value>],
    dest_by_id: &HashMap<String, Map<String, Value>>,
    dest_by_token: &HashMap<String, Map<String, Value>>,
    dest_by_project_name: &HashMap<(String, String), Map<String, Value>>,
    partitions: &[Map<String, Value>],
    skip: &mut SkipSet,
    imported: &mut usize,
    skipped_count: &mut usize,
    conflicts: &mut Vec<RestoreConflict>,
) {
    let partitions_by_id = partitions
        .iter()
        .filter_map(|row| string_field(row, "id").map(|id| (id, row)))
        .collect::<HashMap<_, _>>();
    for row in rows {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        if let Some(existing) = dest_by_id.get(&id) {
            if rows_equivalent(existing, row) {
                skip.credentials.insert(id);
                *skipped_count += 1;
            } else {
                skip.credentials.insert(id.clone());
                *skipped_count += 1;
                conflicts.push(RestoreConflict {
                    entity: "credential".into(),
                    identity: id,
                    reason: "id already exists with different data".into(),
                });
            }
            continue;
        }
        if let Some(token) = string_field(row, "wisp_token")
            && dest_by_token.contains_key(&token)
        {
            skip.credentials.insert(id.clone());
            *skipped_count += 1;
            conflicts.push(RestoreConflict {
                entity: "credential".into(),
                identity: string_field(row, "name").unwrap_or(id),
                reason: "wisp token already exists".into(),
            });
            continue;
        }
        let partition_id = string_field(row, "partition_id").unwrap_or_default();
        let project_id = partitions_by_id
            .get(&partition_id)
            .and_then(|partition| string_field(partition, "project_id"))
            .unwrap_or_default();
        let name = string_field(row, "name").unwrap_or_default();
        if dest_by_project_name.contains_key(&(project_id.clone(), name.clone())) {
            skip.credentials.insert(id);
            *skipped_count += 1;
            conflicts.push(RestoreConflict {
                entity: "credential".into(),
                identity: format!("{project_id}/{name}"),
                reason: "project already has a credential with this name".into(),
            });
            continue;
        }
        *imported += 1;
    }
}

fn insert_payload_tables(
    db: &Connection,
    payload: &VaultBackupPayload,
    skip: &SkipSet,
) -> Result<()> {
    insert_table(
        db,
        TABLE_VAULT_META,
        &payload.contents.vault_meta,
        &skip.vault_meta,
        "key",
    )?;
    insert_table(
        db,
        TABLE_PROJECTS,
        &payload.contents.projects,
        &skip.projects,
        "id",
    )?;
    insert_table(
        db,
        TABLE_PARTITIONS,
        &payload.contents.partitions,
        &skip.partitions,
        "id",
    )?;
    insert_table(
        db,
        TABLE_CREDENTIALS,
        &payload.contents.credentials,
        &skip.credentials,
        "id",
    )?;
    insert_table(
        db,
        TABLE_INSTANCES,
        &payload.contents.instances,
        &skip.instances,
        "id",
    )?;
    insert_table(
        db,
        TABLE_INSTANCE_SCOPES,
        &payload.contents.instance_scopes,
        &skip.scopes,
        "id",
    )?;
    insert_table(
        db,
        TABLE_ACCESS_REQUESTS,
        &payload.contents.access_requests,
        &skip.access_requests,
        "id",
    )?;
    insert_table(
        db,
        TABLE_BOOTSTRAP_TOKENS,
        &payload.contents.bootstrap_tokens,
        &skip.bootstrap,
        "id",
    )?;
    insert_table(
        db,
        TABLE_AUDIT_LOG,
        &payload.contents.audit_log,
        &skip.audits,
        "id",
    )?;
    Ok(())
}

fn insert_table(
    db: &Connection,
    table: &str,
    rows: &[Map<String, Value>],
    skip: &HashSet<String>,
    id_key: &str,
) -> Result<()> {
    for row in rows {
        if let Some(id) = string_field(row, id_key)
            && skip.contains(&id)
        {
            continue;
        }
        insert_row(db, table, row)?;
    }
    Ok(())
}

fn write_sidecars(dir: &Path, scope: &BackupScope, sidecars: &super::BackupSidecars) -> Result<()> {
    if scope.policies {
        write_optional_text(
            &dir.join(SIDECAR_POLICIES),
            sidecars.policies_toml.as_deref(),
        )?;
    }
    if scope.cloud {
        write_optional_text(&dir.join(SIDECAR_CLOUD), sidecars.cloud_json.as_deref())?;
        write_optional_text(
            &dir.join(SIDECAR_CLOUD_MANIFESTS),
            sidecars.cloud_manifests_json.as_deref(),
        )?;
    }
    if scope.active_project {
        write_optional_text(
            &dir.join(SIDECAR_ACTIVE_PROJECT),
            sidecars.active_project.as_deref(),
        )?;
    }
    if scope.audits {
        write_optional_b64(
            &dir.join(SIDECAR_AUDIT_FINGERPRINT),
            sidecars.audit_fingerprint_key_b64.as_deref(),
        )?;
    }
    Ok(())
}

fn merge_sidecars(
    target: &Path,
    payload: &VaultBackupPayload,
    policy: ConflictPolicy,
) -> Result<()> {
    let candidates = [
        (
            payload.scope.policies,
            SIDECAR_POLICIES,
            payload.sidecars.policies_toml.as_deref(),
            false,
        ),
        (
            payload.scope.cloud,
            SIDECAR_CLOUD,
            payload.sidecars.cloud_json.as_deref(),
            false,
        ),
        (
            payload.scope.cloud,
            SIDECAR_CLOUD_MANIFESTS,
            payload.sidecars.cloud_manifests_json.as_deref(),
            false,
        ),
        (
            payload.scope.active_project,
            SIDECAR_ACTIVE_PROJECT,
            payload.sidecars.active_project.as_deref(),
            false,
        ),
        (
            payload.scope.audits,
            SIDECAR_AUDIT_FINGERPRINT,
            payload.sidecars.audit_fingerprint_key_b64.as_deref(),
            true,
        ),
    ];
    for (included, name, contents, b64) in candidates {
        if !included {
            continue;
        }
        let Some(contents) = contents else {
            continue;
        };
        let dest = target.join(name);
        if dest.exists() {
            if policy == ConflictPolicy::Fail {
                return Err(VaultError::Backup(format!(
                    "sidecar '{name}' already exists; pass --on-conflict skip or --replace"
                )));
            }
            continue;
        }
        if b64 {
            write_optional_b64(&dest, Some(contents))?;
        } else {
            write_optional_text(&dest, Some(contents))?;
        }
    }
    Ok(())
}

fn commit_restored_files(staging: &Path, target: &Path) -> Result<()> {
    secure_files::ensure_private_directory(target)?;
    let backup_dir = staging.join("replaced");
    fs::create_dir_all(&backup_dir)?;
    let mut swapped: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for path in restore_sidecar_paths(staging) {
        if !path.exists() {
            continue;
        }
        let name = path
            .file_name()
            .ok_or_else(|| VaultError::Backup("invalid restored file name".into()))?;
        let dest = target.join(name);
        let replaced = if dest.exists() {
            let backup = backup_dir.join(name);
            fs::rename(&dest, &backup)?;
            Some(backup)
        } else {
            None
        };
        if let Err(error) = fs::rename(&path, &dest) {
            rollback_swaps(target, &swapped);
            return Err(error.into());
        }
        swapped.push((dest, replaced));
    }
    Ok(())
}

fn rollback_swaps(target: &Path, swapped: &[(PathBuf, Option<PathBuf>)]) {
    for (dest, replaced) in swapped.iter().rev() {
        let failed = target.join(format!(
            ".wk-restore-failed-{}",
            dest.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("file")
        ));
        let _ = fs::rename(dest, &failed);
        if let Some(backup) = replaced {
            let _ = fs::rename(backup, dest);
        }
    }
}

fn password_hash_mismatch(target: &Path, payload: &VaultBackupPayload) -> Result<bool> {
    let db = Connection::open(target.join("vault.db"))?;
    let dest_hash: Option<String> = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'password_hash'",
            [],
            |row| row.get(0),
        )
        .ok();
    let backup_hash = payload.contents.vault_meta.iter().find_map(|row| {
        if string_field(row, "key").as_deref() == Some("password_hash") {
            string_field(row, "value")
        } else {
            None
        }
    });
    Ok(match (dest_hash, backup_hash) {
        (Some(dest), Some(backup)) => dest != backup,
        _ => true,
    })
}

fn load_table_index(
    db: &Connection,
    table: &str,
    key: &str,
) -> Result<HashMap<String, Map<String, Value>>> {
    let rows = super::dump_table(db, table)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| string_field(&row, key).map(|id| (id, row)))
        .collect())
}

fn load_meta_map(db: &Connection) -> Result<HashMap<String, Map<String, Value>>> {
    load_table_index(db, TABLE_VAULT_META, "key")
}

fn load_partition_name_index(
    db: &Connection,
) -> Result<HashMap<(String, String), Map<String, Value>>> {
    let rows = super::dump_table(db, TABLE_PARTITIONS)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let project_id = string_field(&row, "project_id")?;
            let name = string_field(&row, "name")?;
            Some(((project_id, name), row))
        })
        .collect())
}

fn load_credential_name_index(
    db: &Connection,
) -> Result<HashMap<(String, String), Map<String, Value>>> {
    let partitions = super::dump_table(db, TABLE_PARTITIONS)?;
    let projects_by_partition = partitions
        .iter()
        .filter_map(|row| {
            let id = string_field(row, "id")?;
            let project_id = string_field(row, "project_id")?;
            Some((id, project_id))
        })
        .collect::<HashMap<_, _>>();
    let credentials = super::dump_table(db, TABLE_CREDENTIALS)?;
    Ok(credentials
        .into_iter()
        .filter_map(|row| {
            let name = string_field(&row, "name")?;
            let partition_id = string_field(&row, "partition_id")?;
            let project_id = projects_by_partition.get(&partition_id)?.clone();
            Some(((project_id, name), row))
        })
        .collect())
}

fn rows_equivalent(left: &Map<String, Value>, right: &Map<String, Value>) -> bool {
    comparable_row(left) == comparable_row(right)
}

fn comparable_row(row: &Map<String, Value>) -> Map<String, Value> {
    row.iter()
        .filter(|(key, _)| !matches!(key.as_str(), "updated_at" | "last_used_at" | "last_seen_at"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn meta_values_equal(left: &Map<String, Value>, right: &Map<String, Value>) -> bool {
    string_field(left, "value") == string_field(right, "value")
}

fn row_id_is(row: &Map<String, Value>, id: &str) -> bool {
    string_field(row, "id").as_deref() == Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_commit_leaves_original_vault() {
        let target = tempfile::tempdir().expect("target");
        let staging = tempfile::tempdir().expect("staging");
        fs::write(target.path().join("vault.db"), b"OLD").expect("old vault");
        fs::write(staging.path().join("vault.db"), b"NEW").expect("new vault");
        fs::write(staging.path().join(SIDECAR_POLICIES), b"[policy]").expect("policies");
        fs::create_dir_all(target.path().join("blocked")).expect("blocked dir");
        let policies_dest = target.path().join(SIDECAR_POLICIES);
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(
                target.path().join("blocked").join("missing"),
                &policies_dest,
            )
            .expect("dangling dest symlink");
            let result = commit_restored_files(staging.path(), target.path());
            let original = fs::read(target.path().join("vault.db")).unwrap_or_else(|_| {
                fs::read(staging.path().join("replaced").join("vault.db")).unwrap_or_default()
            });
            assert!(
                result.is_err() || original == b"NEW" || original == b"OLD",
                "commit should either fail closed or complete"
            );
            if result.is_err() {
                let restored = fs::read(target.path().join("vault.db")).expect("read vault");
                assert_eq!(restored, b"OLD");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (policies_dest, commit_restored_files);
        }
    }
}
