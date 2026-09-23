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
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
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
    validate_replace_target(options.target_dir, payload)?;
    let inspect = inspect_payload(payload);
    let instance_names: Vec<String> = inspect
        .instances
        .iter()
        .filter(|row| row.status == "active")
        .map(|row| row.name.clone())
        .collect();
    let bootstrap_count = payload
        .contents
        .bootstrap_tokens
        .iter()
        .filter(|row| string_field(row, "status").as_deref() == Some("active"))
        .count();
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
    match restore_result {
        Ok(()) => {
            let _ = fs::remove_dir_all(&staging);
            Ok(report)
        }
        Err(error) => Err(error),
    }
}

fn restore_replace_into_staging(payload: &VaultBackupPayload, staging: &Path) -> Result<()> {
    secure_files::ensure_private_directory(staging)?;
    let db_path = staging.join("vault.db");
    let db = Vault::initialize_database_file(&db_path)?;
    db.execute_batch("PRAGMA foreign_keys = ON; BEGIN IMMEDIATE TRANSACTION")?;
    let instance_ids = row_ids(&payload.contents.instances);
    let bootstrap_ids = row_ids(&payload.contents.bootstrap_tokens);
    let insert_result = insert_payload_tables(&db, payload, &SkipSet::default());
    match insert_result {
        Ok(()) => {
            if payload.scope.instances {
                prepare_restored_instance_secrets(&db, &instance_ids)?;
            }
            if payload.scope.bootstrap {
                revoke_bootstrap_tokens_after_restore(&db, &bootstrap_ids)?;
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
    if options.dry_run {
        let planning_db = open_merge_planning_db(&db_path)?;
        let plan = plan_merge(&planning_db, options.target_dir, payload)?;
        return Ok(merge_report(payload, &options, &plan));
    }

    let staging = options
        .target_dir
        .join(format!(".wk-restore-{}", Uuid::new_v4()));
    stage_merge_sidecars(&staging, payload)?;

    let db = Connection::open(&db_path)?;
    db.execute_batch("PRAGMA foreign_keys = ON; BEGIN IMMEDIATE TRANSACTION")?;
    let mut created_sidecars = Vec::new();
    let result = (|| {
        Vault::migrate_schema(&db)?;
        let plan = plan_merge(&db, options.target_dir, payload)?;
        if options.on_conflict == ConflictPolicy::Fail && !plan.conflicts.is_empty() {
            return Err(VaultError::Backup(format!(
                "{} restore conflict(s); pass --on-conflict skip, choose --replace, or restore to an empty --target. First conflict: {} {}",
                plan.conflicts.len(),
                plan.conflicts[0].entity,
                plan.conflicts[0].identity
            )));
        }

        let report = merge_report(payload, &options, &plan);
        let instance_ids = inserted_row_ids(&payload.contents.instances, &plan.skip.instances);
        let bootstrap_ids =
            inserted_row_ids(&payload.contents.bootstrap_tokens, &plan.skip.bootstrap);
        insert_payload_tables(&db, payload, &plan.skip)?;
        apply_staged_sidecars(
            options.target_dir,
            &staging,
            options.on_conflict,
            &mut created_sidecars,
        )?;
        if payload.scope.instances {
            prepare_restored_instance_secrets(&db, &instance_ids)?;
        }
        if payload.scope.bootstrap {
            revoke_bootstrap_tokens_after_restore(&db, &bootstrap_ids)?;
        }
        db.execute_batch("COMMIT")?;
        Ok(report)
    })();

    match result {
        Ok(report) => {
            let _ = fs::remove_dir_all(&staging);
            Ok(report)
        }
        Err(error) => {
            let db_rollback = db.execute_batch("ROLLBACK");
            let sidecar_rollback = remove_created_sidecars(&created_sidecars);
            if db_rollback.is_err() || sidecar_rollback.is_err() {
                return Err(VaultError::Backup(format!(
                    "merge failed and rollback was incomplete; recovery files retained at {}",
                    staging.display()
                )));
            }
            Err(error)
        }
    }
}

fn merge_report(
    payload: &VaultBackupPayload,
    options: &RestoreOptions<'_>,
    plan: &MergePlan,
) -> RestoreReport {
    let instance_names = if payload.scope.instances {
        payload
            .contents
            .instances
            .iter()
            .filter(|row| {
                string_field(row, "status").as_deref() == Some("active")
                    && string_field(row, "id").is_some_and(|id| !plan.skip.instances.contains(&id))
            })
            .filter_map(|row| string_field(row, "name"))
            .collect()
    } else {
        Vec::new()
    };
    let bootstrap_revoked = payload
        .contents
        .bootstrap_tokens
        .iter()
        .filter(|row| string_field(row, "status").as_deref() == Some("active"))
        .filter(|row| string_field(row, "id").is_some_and(|id| !plan.skip.bootstrap.contains(&id)))
        .count();

    RestoreReport {
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
    }
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

fn plan_merge(db: &Connection, target: &Path, payload: &VaultBackupPayload) -> Result<MergePlan> {
    validate_payload_graph(payload)?;
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
                skip.vault_meta.insert(key.clone());
                skipped.vault_meta += 1;
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
    let available_projects =
        available_reference_ids(&payload.contents.projects, &dest_projects, &skip.projects);
    classify_partition_rows(
        &payload.contents.partitions,
        &dest_partitions,
        &dest_partition_names,
        &available_projects,
        &mut skip,
        &mut imported.partitions,
        &mut skipped.partitions,
        &mut conflicts,
    );
    let mut available_partitions = available_reference_ids(
        &payload.contents.partitions,
        &dest_partitions,
        &skip.partitions,
    );
    for row in &payload.contents.partitions {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        let project_id = string_field(row, "project_id").unwrap_or_default();
        if !available_projects.contains(&project_id) {
            available_partitions.remove(&id);
        }
    }
    classify_credential_rows(
        &payload.contents.credentials,
        &dest_credentials,
        &dest_tokens,
        &dest_credential_names,
        &payload.contents.partitions,
        &dest_partitions,
        &available_partitions,
        &mut skip,
        &mut imported.credentials,
        &mut skipped.credentials,
        &mut conflicts,
    );
    let mut available_credentials = available_reference_ids(
        &payload.contents.credentials,
        &dest_credentials,
        &skip.credentials,
    );
    for row in &payload.contents.credentials {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        let partition_id = string_field(row, "partition_id").unwrap_or_default();
        if !available_partitions.contains(&partition_id) {
            available_credentials.remove(&id);
        }
    }
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
    let available_instances = available_reference_ids(
        &payload.contents.instances,
        &dest_instances,
        &skip.instances,
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
    propagate_instance_dependencies(
        &payload.contents.instance_scopes,
        &payload.contents.access_requests,
        &available_instances,
        &available_credentials,
        &mut skip,
        &mut imported,
        &mut skipped,
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

    append_sidecar_conflicts(target, payload, &mut conflicts)?;

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

#[allow(clippy::too_many_arguments)]
fn classify_partition_rows(
    rows: &[Map<String, Value>],
    dest_by_id: &HashMap<String, Map<String, Value>>,
    dest_by_project_name: &HashMap<(String, String), Map<String, Value>>,
    available_projects: &HashSet<String>,
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
        if !available_projects.contains(&project_id) {
            skip_with_dependency_conflict(
                id,
                "partition",
                format!("referenced project '{project_id}' was not available"),
                &mut skip.partitions,
                skipped_count,
                conflicts,
            );
            continue;
        }
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
    dest_partitions: &HashMap<String, Map<String, Value>>,
    available_partitions: &HashSet<String>,
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
        if !available_partitions.contains(&partition_id) {
            skip_with_dependency_conflict(
                id,
                "credential",
                format!("referenced partition '{partition_id}' was not available"),
                &mut skip.credentials,
                skipped_count,
                conflicts,
            );
            continue;
        }
        let project_id = partitions_by_id
            .get(&partition_id)
            .and_then(|partition| string_field(partition, "project_id"))
            .or_else(|| {
                dest_partitions
                    .get(&partition_id)
                    .and_then(|partition| string_field(partition, "project_id"))
            })
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

fn available_reference_ids(
    rows: &[Map<String, Value>],
    dest_by_id: &RowIndex,
    skipped: &HashSet<String>,
) -> HashSet<String> {
    let mut available = dest_by_id.keys().cloned().collect::<HashSet<_>>();
    for row in rows {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        if skipped.contains(&id) {
            if dest_by_id
                .get(&id)
                .is_some_and(|existing| rows_equivalent(existing, row))
            {
                available.insert(id);
            } else {
                available.remove(&id);
            }
        } else {
            available.insert(id);
        }
    }
    available
}

fn skip_with_dependency_conflict(
    id: String,
    entity: &str,
    reason: String,
    skip: &mut HashSet<String>,
    skipped_count: &mut usize,
    conflicts: &mut Vec<RestoreConflict>,
) -> bool {
    if skip.insert(id.clone()) {
        *skipped_count += 1;
        conflicts.push(RestoreConflict {
            entity: entity.into(),
            identity: id,
            reason,
        });
        true
    } else {
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn propagate_instance_dependencies(
    scopes: &[Map<String, Value>],
    requests: &[Map<String, Value>],
    available_instances: &HashSet<String>,
    available_credentials: &HashSet<String>,
    skip: &mut SkipSet,
    imported: &mut BackupCounts,
    skipped: &mut BackupCounts,
    conflicts: &mut Vec<RestoreConflict>,
) {
    for row in scopes {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        if skip.scopes.contains(&id) {
            continue;
        }
        let instance_id = string_field(row, "instance_id").unwrap_or_default();
        if !available_instances.contains(&instance_id) {
            if skip_with_dependency_conflict(
                id,
                "instance_scope",
                format!("referenced instance '{instance_id}' was not available"),
                &mut skip.scopes,
                &mut skipped.scopes,
                conflicts,
            ) {
                imported.scopes -= 1;
            }
            continue;
        }
        if string_field(row, "scope_type").as_deref() == Some("credential") {
            let Some(credential_id) = string_field(row, "credential_id") else {
                if skip_with_dependency_conflict(
                    id,
                    "instance_scope",
                    "credential scope has no stable credential id".into(),
                    &mut skip.scopes,
                    &mut skipped.scopes,
                    conflicts,
                ) {
                    imported.scopes -= 1;
                }
                continue;
            };
            if !available_credentials.contains(&credential_id)
                && skip_with_dependency_conflict(
                    id,
                    "instance_scope",
                    format!("referenced credential '{credential_id}' was not available"),
                    &mut skip.scopes,
                    &mut skipped.scopes,
                    conflicts,
                )
            {
                imported.scopes -= 1;
            }
        }
    }

    for row in requests {
        let Some(id) = string_field(row, "id") else {
            continue;
        };
        if skip.access_requests.contains(&id) {
            continue;
        }
        let instance_id = string_field(row, "instance_id").unwrap_or_default();
        if !available_instances.contains(&instance_id) {
            if skip_with_dependency_conflict(
                id,
                "access_request",
                format!("referenced instance '{instance_id}' was not available"),
                &mut skip.access_requests,
                &mut skipped.access_requests,
                conflicts,
            ) {
                imported.access_requests -= 1;
            }
            continue;
        }
        let Some(credential_id) = string_field(row, "credential_id") else {
            if skip_with_dependency_conflict(
                id,
                "access_request",
                "access request has no stable credential id".into(),
                &mut skip.access_requests,
                &mut skipped.access_requests,
                conflicts,
            ) {
                imported.access_requests -= 1;
            }
            continue;
        };
        if !available_credentials.contains(&credential_id)
            && skip_with_dependency_conflict(
                id,
                "access_request",
                format!("referenced credential '{credential_id}' was not available"),
                &mut skip.access_requests,
                &mut skipped.access_requests,
                conflicts,
            )
        {
            imported.access_requests -= 1;
        }
    }
}

fn validate_payload_graph(payload: &VaultBackupPayload) -> Result<()> {
    validate_unique_ids(&payload.contents.projects, TABLE_PROJECTS)?;
    validate_unique_ids(&payload.contents.partitions, TABLE_PARTITIONS)?;
    validate_unique_ids(&payload.contents.credentials, TABLE_CREDENTIALS)?;
    validate_unique_ids(&payload.contents.instances, TABLE_INSTANCES)?;
    validate_unique_ids(&payload.contents.instance_scopes, TABLE_INSTANCE_SCOPES)?;
    validate_unique_ids(&payload.contents.access_requests, TABLE_ACCESS_REQUESTS)?;
    validate_unique_ids(&payload.contents.bootstrap_tokens, TABLE_BOOTSTRAP_TOKENS)?;
    validate_unique_ids(&payload.contents.audit_log, TABLE_AUDIT_LOG)?;

    for (table, rows, required) in [
        (
            TABLE_PROJECTS,
            &payload.contents.projects,
            ["id"].as_slice(),
        ),
        (
            TABLE_PARTITIONS,
            &payload.contents.partitions,
            ["id", "project_id"].as_slice(),
        ),
        (
            TABLE_CREDENTIALS,
            &payload.contents.credentials,
            ["id", "partition_id"].as_slice(),
        ),
        (
            TABLE_INSTANCES,
            &payload.contents.instances,
            ["id"].as_slice(),
        ),
        (
            TABLE_INSTANCE_SCOPES,
            &payload.contents.instance_scopes,
            ["id", "instance_id"].as_slice(),
        ),
        (
            TABLE_ACCESS_REQUESTS,
            &payload.contents.access_requests,
            ["id", "instance_id"].as_slice(),
        ),
        (
            TABLE_BOOTSTRAP_TOKENS,
            &payload.contents.bootstrap_tokens,
            ["id"].as_slice(),
        ),
        (
            TABLE_AUDIT_LOG,
            &payload.contents.audit_log,
            ["id"].as_slice(),
        ),
    ] {
        for row in rows {
            if required.iter().any(|key| string_field(row, key).is_none()) {
                return Err(VaultError::Backup(format!(
                    "backup reference graph is invalid: {table} row is missing a required identity"
                )));
            }
        }
    }
    Ok(())
}

fn validate_unique_ids(rows: &[Map<String, Value>], table: &str) -> Result<()> {
    let mut ids = HashSet::new();
    for row in rows {
        if let Some(id) = string_field(row, "id")
            && !ids.insert(id.clone())
        {
            return Err(VaultError::Backup(format!(
                "backup reference graph is invalid: duplicate {table} id '{id}'"
            )));
        }
    }
    Ok(())
}

fn append_sidecar_conflicts(
    target: &Path,
    payload: &VaultBackupPayload,
    conflicts: &mut Vec<RestoreConflict>,
) -> Result<()> {
    for (included, name, contents) in merge_sidecar_candidates(payload) {
        if included && contents.is_some() && path_entry_exists(&target.join(name))? {
            conflicts.push(RestoreConflict {
                entity: "sidecar".into(),
                identity: name.into(),
                reason: "sidecar already exists".into(),
            });
        }
    }
    Ok(())
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

fn merge_sidecar_candidates(
    payload: &VaultBackupPayload,
) -> [(bool, &'static str, Option<&str>); 5] {
    [
        (
            payload.scope.policies,
            SIDECAR_POLICIES,
            payload.sidecars.policies_toml.as_deref(),
        ),
        (
            payload.scope.cloud,
            SIDECAR_CLOUD,
            payload.sidecars.cloud_json.as_deref(),
        ),
        (
            payload.scope.cloud,
            SIDECAR_CLOUD_MANIFESTS,
            payload.sidecars.cloud_manifests_json.as_deref(),
        ),
        (
            payload.scope.active_project,
            SIDECAR_ACTIVE_PROJECT,
            payload.sidecars.active_project.as_deref(),
        ),
        (
            payload.scope.audits,
            SIDECAR_AUDIT_FINGERPRINT,
            payload.sidecars.audit_fingerprint_key_b64.as_deref(),
        ),
    ]
}

fn stage_merge_sidecars(staging: &Path, payload: &VaultBackupPayload) -> Result<()> {
    secure_files::ensure_private_directory(staging)?;
    write_sidecars(staging, &payload.scope, &payload.sidecars)
}

fn apply_staged_sidecars(
    target: &Path,
    staging: &Path,
    policy: ConflictPolicy,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    for path in restore_sidecar_paths(staging) {
        if !path_entry_exists(&path)? {
            continue;
        }
        let name = path
            .file_name()
            .ok_or_else(|| VaultError::Backup("invalid staged sidecar name".into()))?;
        let dest = target.join(name);
        if path_entry_exists(&dest)? {
            if policy == ConflictPolicy::Fail {
                return Err(VaultError::Backup(format!(
                    "sidecar '{}' appeared during merge; no files were replaced",
                    name.to_string_lossy()
                )));
            }
            continue;
        }
        let contents = fs::read(&path)?;
        match secure_files::create_private(&dest, &contents) {
            Ok(true) => created.push(dest.clone()),
            Ok(false) if policy == ConflictPolicy::Skip => {}
            Ok(false) => {
                return Err(VaultError::Backup(format!(
                    "sidecar '{}' appeared during merge; no files were replaced",
                    name.to_string_lossy()
                )));
            }
            Err(error) => {
                if path_entry_exists(&dest)? {
                    created.push(dest);
                }
                return Err(error);
            }
        }
    }
    Ok(())
}

fn remove_created_sidecars(created: &[PathBuf]) -> Result<()> {
    let mut failures = Vec::new();
    for path in created.iter().rev() {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != ErrorKind::NotFound
        {
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(VaultError::Backup(format!(
            "sidecar rollback failed: {}",
            failures.join(", ")
        )))
    }
}

fn open_merge_planning_db(path: &Path) -> Result<Connection> {
    let source = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut planning = Connection::open_in_memory()?;
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut planning)?;
        backup.run_to_completion(100, Duration::from_millis(0), None)?;
    }
    Vault::migrate_schema(&planning)?;
    Ok(planning)
}

fn validate_replace_target(target: &Path, payload: &VaultBackupPayload) -> Result<()> {
    for name in [
        "session",
        "session-protector",
        "vault.db-wal",
        "vault.db-shm",
        "vault.db-journal",
        "proxy.pid",
        "proxy.json",
        "owner.sock",
        "owner.json",
    ] {
        if path_entry_exists(&target.join(name))? {
            return Err(VaultError::Backup(format!(
                "replace refused while target contains live or journal file '{name}'; stop WispKey and remove stale excluded state first"
            )));
        }
    }
    if target == Vault::vault_dir() && Vault::protector_status().available {
        return Err(VaultError::Backup(
            "replace refused while a remembered unlock protector is available for the target; run `wispkey lock --forget` first".into(),
        ));
    }
    for (included, name, contents) in merge_sidecar_candidates(payload) {
        if (!included || contents.is_none()) && path_entry_exists(&target.join(name))? {
            return Err(VaultError::Backup(format!(
                "replace refused because backup does not contain target sidecar '{name}'; use a full backup or remove the stale sidecar first"
            )));
        }
    }
    Ok(())
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn row_ids(rows: &[Map<String, Value>]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| string_field(row, "id"))
        .collect()
}

fn inserted_row_ids(rows: &[Map<String, Value>], skipped: &HashSet<String>) -> Vec<String> {
    rows.iter()
        .filter_map(|row| string_field(row, "id"))
        .filter(|id| !skipped.contains(id))
        .collect()
}

fn commit_restored_files(staging: &Path, target: &Path) -> Result<()> {
    secure_files::ensure_private_directory(target)?;
    let backup_dir = staging.join("replaced");
    fs::create_dir_all(&backup_dir)?;
    let mut swapped: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for path in restore_sidecar_paths(staging) {
        let result = (|| {
            if !path_entry_exists(&path)? {
                return Ok(());
            }
            let name = path
                .file_name()
                .ok_or_else(|| VaultError::Backup("invalid restored file name".into()))?;
            let dest = target.join(name);
            let replaced = if path_entry_exists(&dest)? {
                let backup = backup_dir.join(name);
                fs::rename(&dest, &backup)?;
                Some(backup)
            } else {
                None
            };
            swapped.push((dest.clone(), replaced));
            fs::rename(&path, &dest)?;
            Ok(())
        })();
        if let Err(error) = result {
            return rollback_commit_error(error, staging, &swapped);
        }
    }
    Ok(())
}

fn rollback_commit_error(
    error: VaultError,
    staging: &Path,
    swapped: &[(PathBuf, Option<PathBuf>)],
) -> Result<()> {
    if let Err(rollback_error) = rollback_swaps(swapped) {
        return Err(VaultError::Backup(format!(
            "restore commit failed: {error}; rollback failed: {rollback_error}; recovery files retained at {}",
            staging.display()
        )));
    }
    Err(error)
}

fn rollback_swaps(swapped: &[(PathBuf, Option<PathBuf>)]) -> Result<()> {
    let mut failures = Vec::new();
    for (dest, replaced) in swapped.iter().rev() {
        if let Err(error) = fs::remove_file(dest)
            && error.kind() != ErrorKind::NotFound
        {
            failures.push(format!("{}: {error}", dest.display()));
            continue;
        }
        if let Some(backup) = replaced
            && let Err(error) = fs::rename(backup, dest)
        {
            failures.push(format!("{}: {error}", dest.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(VaultError::Backup(format!(
            "restore rollback failed; replacement backups were retained: {}",
            failures.join(", ")
        )))
    }
}

fn password_hash_mismatch(target: &Path, payload: &VaultBackupPayload) -> Result<bool> {
    let db =
        Connection::open_with_flags(target.join("vault.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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

    #[test]
    fn rollback_restores_current_swap_and_retains_backup_on_failure() {
        let target = tempfile::tempdir().expect("target");
        let staging = tempfile::tempdir().expect("staging");
        let destination = target.path().join("vault.db");
        let backup = staging.path().join("replaced").join("vault.db");
        fs::create_dir_all(backup.parent().expect("backup parent")).expect("backup directory");
        fs::write(&destination, b"NEW").expect("new destination");
        fs::write(&backup, b"OLD").expect("old backup");

        rollback_swaps(&[(destination.clone(), Some(backup.clone()))]).expect("rollback");
        assert_eq!(
            fs::read(&destination).expect("restored destination"),
            b"OLD"
        );
        assert!(!backup.exists());

        let failed_target = target.path().join("blocked");
        let failed_backup = staging.path().join("replaced").join("blocked");
        fs::create_dir_all(&failed_target).expect("blocked destination");
        fs::write(&failed_backup, b"RECOVERY").expect("recovery backup");
        let rollback = rollback_swaps(&[(failed_target, Some(failed_backup.clone()))]);
        assert!(rollback.is_err());
        assert!(
            failed_backup.exists(),
            "failed rollback must retain its backup"
        );
    }

    #[test]
    fn failed_second_destination_backup_move_rolls_back_previous_swap() {
        let target = tempfile::tempdir().expect("target");
        let staging = tempfile::tempdir().expect("staging");
        fs::write(target.path().join("vault.db"), b"OLD VAULT").expect("old vault");
        fs::write(target.path().join(SIDECAR_POLICIES), b"OLD POLICIES").expect("old policies");
        fs::write(staging.path().join("vault.db"), b"NEW VAULT").expect("new vault");
        fs::write(staging.path().join(SIDECAR_POLICIES), b"NEW POLICIES").expect("new policies");
        let blocked_backup = staging.path().join("replaced").join(SIDECAR_POLICIES);
        fs::create_dir_all(&blocked_backup).expect("blocked backup directory");

        let result = commit_restored_files(staging.path(), target.path());

        assert!(result.is_err(), "second destination backup move must fail");
        assert_eq!(
            fs::read(target.path().join("vault.db")).expect("restored vault"),
            b"OLD VAULT"
        );
        assert_eq!(
            fs::read(target.path().join(SIDECAR_POLICIES)).expect("original policies"),
            b"OLD POLICIES"
        );
        assert!(
            blocked_backup.is_dir(),
            "failed backup move must retain recovery state"
        );
    }
}
