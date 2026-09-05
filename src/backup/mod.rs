/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Encrypted full-vault backup, inspection, verification, and restore.
 * Created: 2026-08-26
 * Last Modified: 2026-08-26
 */

mod restore;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ring::digest::{SHA256, digest};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use crate::bundle;
use crate::core::{CURRENT_SCHEMA_VERSION, Result, Vault, VaultError};
use crate::secure_files;

pub use restore::{ConflictPolicy, RestoreOptions, RestoreReport, restore_backup};

const VAULT_BACKUP_MAGIC: &[u8; 4] = b"WKVB";
const BACKUP_FORMAT_VERSION: u32 = 1;
const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 6;
const MAX_VAULT_BACKUP_BYTES: u64 = 512 * 1024 * 1024;

const TABLE_VAULT_META: &str = "vault_meta";
const TABLE_PROJECTS: &str = "projects";
const TABLE_PARTITIONS: &str = "partitions";
const TABLE_CREDENTIALS: &str = "credentials";
const TABLE_AUDIT_LOG: &str = "audit_log";
const TABLE_INSTANCES: &str = "instances";
const TABLE_INSTANCE_SCOPES: &str = "instance_scopes";
const TABLE_ACCESS_REQUESTS: &str = "access_requests";
const TABLE_BOOTSTRAP_TOKENS: &str = "bootstrap_tokens";

const SIDECAR_POLICIES: &str = "policies.toml";
const SIDECAR_CLOUD: &str = "cloud.json";
const SIDECAR_CLOUD_MANIFESTS: &str = "cloud-manifests.json";
const SIDECAR_ACTIVE_PROJECT: &str = "active_project";
const SIDECAR_AUDIT_FINGERPRINT: &str = "audit-fingerprint.key";
const PROTECTED_VAULT_OUTPUT_NAMES: &[&str] = &[
    "vault.db",
    "vault.db-wal",
    "vault.db-shm",
    "vault.db-journal",
    "session",
    "session-device-seed",
    "session-protector",
    "proxy.pid",
    "proxy.json",
    "owner.sock",
    "owner.json",
    SIDECAR_POLICIES,
    SIDECAR_CLOUD,
    SIDECAR_CLOUD_MANIFESTS,
    SIDECAR_ACTIVE_PROJECT,
    SIDECAR_AUDIT_FINGERPRINT,
];

/// Explicit include/exclude flags recorded in every vault backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupScope {
    pub credentials: bool,
    pub projects: bool,
    pub partitions: bool,
    pub policies: bool,
    pub audits: bool,
    pub instances: bool,
    pub scopes: bool,
    pub access_requests: bool,
    pub bootstrap: bool,
    pub cloud: bool,
    pub active_project: bool,
}

impl BackupScope {
    /// Includes every supported vault table and sidecar.
    #[must_use]
    pub fn all_included() -> Self {
        Self {
            credentials: true,
            projects: true,
            partitions: true,
            policies: true,
            audits: true,
            instances: true,
            scopes: true,
            access_requests: true,
            bootstrap: true,
            cloud: true,
            active_project: true,
        }
    }

    /// Applies comma-separated exclude names. Parent excludes cascade to dependents.
    pub fn exclude_names(&mut self, excludes: &[String]) -> Result<()> {
        for raw in excludes {
            match raw.trim() {
                "" => continue,
                "credentials" => self.credentials = false,
                "projects" => {
                    self.projects = false;
                    self.partitions = false;
                    self.credentials = false;
                }
                "partitions" => {
                    self.partitions = false;
                    self.credentials = false;
                }
                "policies" => self.policies = false,
                "audits" => self.audits = false,
                "instances" => {
                    self.instances = false;
                    self.scopes = false;
                    self.access_requests = false;
                }
                "scopes" => self.scopes = false,
                "access-requests" | "access_requests" => self.access_requests = false,
                "bootstrap" => self.bootstrap = false,
                "cloud" => self.cloud = false,
                "active-project" | "active_project" => self.active_project = false,
                other => {
                    return Err(VaultError::Backup(format!(
                        "unknown backup exclude '{other}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCounts {
    pub vault_meta: usize,
    pub projects: usize,
    pub partitions: usize,
    pub credentials: usize,
    pub audits: usize,
    pub instances: usize,
    pub scopes: usize,
    pub access_requests: usize,
    pub bootstrap: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BackupIntegrity {
    #[serde(default)]
    content_sha256: String,
    #[serde(default)]
    row_counts: BackupCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BackupContents {
    #[serde(default)]
    vault_meta: Vec<Map<String, Value>>,
    #[serde(default)]
    projects: Vec<Map<String, Value>>,
    #[serde(default)]
    partitions: Vec<Map<String, Value>>,
    #[serde(default)]
    credentials: Vec<Map<String, Value>>,
    #[serde(default)]
    audit_log: Vec<Map<String, Value>>,
    #[serde(default)]
    instances: Vec<Map<String, Value>>,
    #[serde(default)]
    instance_scopes: Vec<Map<String, Value>>,
    #[serde(default)]
    access_requests: Vec<Map<String, Value>>,
    #[serde(default)]
    bootstrap_tokens: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BackupSidecars {
    #[serde(default)]
    policies_toml: Option<String>,
    #[serde(default)]
    cloud_json: Option<String>,
    #[serde(default)]
    cloud_manifests_json: Option<String>,
    #[serde(default)]
    active_project: Option<String>,
    #[serde(default)]
    audit_fingerprint_key_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultBackupPayload {
    format_version: u32,
    exported_at: String,
    source_schema_version: String,
    #[serde(default)]
    source_vault_created_at: Option<String>,
    scope: BackupScope,
    contents: BackupContents,
    #[serde(default)]
    sidecars: BackupSidecars,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    integrity: BackupIntegrity,
}

/// Owner-visible summary of a created backup. Contains no secret values.
#[derive(Debug, Clone, Serialize)]
pub struct BackupCreateSummary {
    pub output: String,
    pub format_version: u32,
    pub source_schema_version: String,
    pub scope: BackupScope,
    pub counts: BackupCounts,
    pub warnings: Vec<String>,
}

/// Decrypted backup metadata with secret material omitted.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInspect {
    pub format_version: u32,
    pub source_schema_version: String,
    pub exported_at: String,
    pub source_vault_created_at: Option<String>,
    pub compatible: bool,
    pub scope: BackupScope,
    pub counts: BackupCounts,
    pub projects: Vec<String>,
    pub partitions: Vec<InspectPartition>,
    pub credentials: Vec<InspectCredential>,
    pub instances: Vec<InspectInstance>,
    pub sidecars: InspectSidecars,
    pub warnings: Vec<String>,
    pub recovery_limits: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectPartition {
    pub name: String,
    pub project: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectCredential {
    pub name: String,
    pub project: String,
    pub partition: String,
    pub credential_type: String,
    pub hosts: String,
    pub tags: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectInstance {
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectSidecars {
    pub policies: bool,
    pub cloud: bool,
    pub cloud_session_token_present: bool,
    pub cloud_manifests: bool,
    pub active_project: Option<String>,
    pub audit_fingerprint_key: bool,
}

/// Integrity and compatibility check for an encrypted vault backup.
#[derive(Debug, Clone, Serialize)]
pub struct BackupVerify {
    pub ok: bool,
    pub format_version: u32,
    pub source_schema_version: String,
    pub integrity_ok: bool,
    pub compatible: bool,
    pub counts: BackupCounts,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Writes an encrypted, authenticated vault backup of the opened vault.
pub fn create_backup(
    vault: &Vault,
    vault_dir: &Path,
    passphrase: &str,
    output_path: &str,
    scope: &BackupScope,
) -> Result<BackupCreateSummary> {
    reject_protected_backup_output(vault_dir, output_path)?;
    let db = vault.db();
    let (source_schema_version, source_vault_created_at, contents) = snapshot_database(db, scope)?;
    let sidecars = dump_sidecars(vault_dir, scope)?;
    let warnings = backup_warnings(scope);
    let mut payload = VaultBackupPayload {
        format_version: BACKUP_FORMAT_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        source_schema_version,
        source_vault_created_at,
        scope: scope.clone(),
        contents,
        sidecars,
        warnings: warnings.clone(),
        integrity: BackupIntegrity::default(),
    };
    payload.integrity = compute_integrity(&payload)?;

    bundle::write_encrypted_payload_with_limit_no_clobber(
        VAULT_BACKUP_MAGIC,
        &payload,
        passphrase,
        output_path,
        MAX_VAULT_BACKUP_BYTES,
    )?;

    Ok(BackupCreateSummary {
        output: output_path.to_string(),
        format_version: payload.format_version,
        source_schema_version: payload.source_schema_version,
        scope: payload.scope,
        counts: payload.integrity.row_counts,
        warnings,
    })
}

/// Decrypts a vault backup and returns metadata with secret fields omitted.
pub fn inspect_backup(path: &str, passphrase: &str) -> Result<BackupInspect> {
    let payload = read_payload(path, passphrase)?;
    Ok(inspect_payload(&payload))
}

/// Decrypts a vault backup and checks format, integrity, and schema compatibility.
pub fn verify_backup(path: &str, passphrase: &str) -> Result<BackupVerify> {
    let payload = read_payload(path, passphrase)?;
    Ok(verify_payload(&payload))
}

pub(crate) fn recovery_limits() -> Vec<String> {
    vec![
        "A lost vault master password cannot be recovered from a backup. The backup passphrase only unwraps the archive; credential blobs stay encrypted with the original master key.".into(),
        "A lost backup passphrase makes the archive unreadable.".into(),
        "Session files and remembered protectors are machine-bound and are never restored. Unlock the restored vault with the original master password.".into(),
        "A corrupt vault.db can be replaced by restoring onto an empty --target path or with --replace.".into(),
        "A partial backup cannot recreate omitted tables or sidecars. Inspect the recorded scope before restore.".into(),
        "Database rows are snapshotted in one SQLite read transaction, but sidecars are read separately; stop WispKey and quiesce the vault for a cross-file-consistent backup.".into(),
        "Restore can roll back ordinary process I/O failures, but SQLite and multiple sidecar renames are not power-loss atomic; verify after a crash or interrupted restore.".into(),
        "Replace refuses stale sessions, remembered protectors, SQLite WAL/journal files, live IPC state, and omitted target sidecars instead of claiming those files were restored.".into(),
        "Instance bearer secrets and bootstrap tokens are never stored at rest. Restored instances are marked needs_reenrollment; run `wispkey instance rotate-secret` to mint a new secret.".into(),
        "Env-sideload secrets live in process environment only and are not part of a vault backup.".into(),
    ]
}

fn read_payload(path: &str, passphrase: &str) -> Result<VaultBackupPayload> {
    bundle::read_encrypted_payload_with_limit(
        VAULT_BACKUP_MAGIC,
        path,
        passphrase,
        MAX_VAULT_BACKUP_BYTES,
    )
}

fn inspect_payload(payload: &VaultBackupPayload) -> BackupInspect {
    let compatibility = schema_compatibility(&payload.source_schema_version);
    let projects_by_id = index_by(&payload.contents.projects, "id");
    let partitions_by_id = index_by(&payload.contents.partitions, "id");
    let projects = payload
        .contents
        .projects
        .iter()
        .filter_map(|row| string_field(row, "name"))
        .collect();
    let partitions = payload
        .contents
        .partitions
        .iter()
        .filter_map(|row| {
            let name = string_field(row, "name")?;
            let project_id = string_field(row, "project_id").unwrap_or_default();
            let project = projects_by_id
                .get(&project_id)
                .and_then(|project| string_field(project, "name"))
                .unwrap_or_else(|| project_id.clone());
            Some(InspectPartition { name, project })
        })
        .collect();
    let credentials = payload
        .contents
        .credentials
        .iter()
        .filter_map(|row| {
            let name = string_field(row, "name")?;
            let partition_id = string_field(row, "partition_id").unwrap_or_default();
            let partition_row = partitions_by_id.get(&partition_id);
            let partition = partition_row
                .and_then(|row| string_field(row, "name"))
                .unwrap_or_else(|| partition_id.clone());
            let project_id = partition_row
                .and_then(|row| string_field(row, "project_id"))
                .unwrap_or_default();
            let project = projects_by_id
                .get(&project_id)
                .and_then(|row| string_field(row, "name"))
                .unwrap_or(project_id);
            Some(InspectCredential {
                name,
                project,
                partition,
                credential_type: credential_type_label(row),
                hosts: string_field(row, "hosts").unwrap_or_default(),
                tags: string_field(row, "tags").unwrap_or_default(),
            })
        })
        .collect();
    let instances = payload
        .contents
        .instances
        .iter()
        .filter_map(|row| {
            Some(InspectInstance {
                name: string_field(row, "name")?,
                status: string_field(row, "status").unwrap_or_else(|| "active".into()),
            })
        })
        .collect();

    BackupInspect {
        format_version: payload.format_version,
        source_schema_version: payload.source_schema_version.clone(),
        exported_at: payload.exported_at.clone(),
        source_vault_created_at: payload.source_vault_created_at.clone(),
        compatible: compatibility.is_ok(),
        scope: payload.scope.clone(),
        counts: counts_from_contents(&payload.contents),
        projects,
        partitions,
        credentials,
        instances,
        sidecars: inspect_sidecars(&payload.sidecars),
        warnings: payload.warnings.clone(),
        recovery_limits: recovery_limits(),
    }
}

fn verify_payload(payload: &VaultBackupPayload) -> BackupVerify {
    let mut errors = Vec::new();
    if payload.format_version != BACKUP_FORMAT_VERSION {
        errors.push(format!(
            "unsupported backup format version {}",
            payload.format_version
        ));
    }
    let expected = match compute_integrity(payload) {
        Ok(integrity) => integrity,
        Err(error) => {
            errors.push(error.to_string());
            BackupIntegrity::default()
        }
    };
    let integrity_ok = expected.content_sha256 == payload.integrity.content_sha256
        && expected.row_counts == payload.integrity.row_counts
        && expected.row_counts == counts_from_contents(&payload.contents);
    if !integrity_ok {
        errors.push("backup integrity check failed".into());
    }
    match schema_compatibility(&payload.source_schema_version) {
        Ok(()) => {}
        Err(error) => errors.push(error.to_string()),
    }
    BackupVerify {
        ok: errors.is_empty(),
        format_version: payload.format_version,
        source_schema_version: payload.source_schema_version.clone(),
        integrity_ok,
        compatible: errors
            .iter()
            .all(|error| !error.contains("schema") && !error.contains("format")),
        counts: counts_from_contents(&payload.contents),
        warnings: payload.warnings.clone(),
        errors,
    }
}

fn dump_contents(db: &Connection, scope: &BackupScope) -> Result<BackupContents> {
    Ok(BackupContents {
        vault_meta: dump_table(db, TABLE_VAULT_META)?,
        projects: if scope.projects {
            dump_table(db, TABLE_PROJECTS)?
        } else {
            Vec::new()
        },
        partitions: if scope.partitions {
            dump_table(db, TABLE_PARTITIONS)?
        } else {
            Vec::new()
        },
        credentials: if scope.credentials {
            dump_table(db, TABLE_CREDENTIALS)?
        } else {
            Vec::new()
        },
        audit_log: if scope.audits {
            dump_table(db, TABLE_AUDIT_LOG)?
        } else {
            Vec::new()
        },
        instances: if scope.instances {
            dump_table(db, TABLE_INSTANCES)?
        } else {
            Vec::new()
        },
        instance_scopes: if scope.scopes {
            dump_table(db, TABLE_INSTANCE_SCOPES)?
        } else {
            Vec::new()
        },
        access_requests: if scope.access_requests {
            dump_table(db, TABLE_ACCESS_REQUESTS)?
        } else {
            Vec::new()
        },
        bootstrap_tokens: if scope.bootstrap {
            dump_table(db, TABLE_BOOTSTRAP_TOKENS)?
        } else {
            Vec::new()
        },
    })
}

fn snapshot_database(
    db: &Connection,
    scope: &BackupScope,
) -> Result<(String, Option<String>, BackupContents)> {
    db.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let snapshot = (|| {
        let source_schema_version = schema_version_from_db(db)?;
        let source_vault_created_at = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'created_at'",
                [],
                |row| row.get(0),
            )
            .ok();
        let contents = dump_contents(db, scope)?;
        Ok((source_schema_version, source_vault_created_at, contents))
    })();
    match snapshot {
        Ok(snapshot) => {
            if let Err(error) = db.execute_batch("COMMIT") {
                let _ = db.execute_batch("ROLLBACK");
                Err(error.into())
            } else {
                Ok(snapshot)
            }
        }
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn dump_sidecars(vault_dir: &Path, scope: &BackupScope) -> Result<BackupSidecars> {
    Ok(BackupSidecars {
        policies_toml: if scope.policies {
            read_optional_text(&vault_dir.join(SIDECAR_POLICIES))?
        } else {
            None
        },
        cloud_json: if scope.cloud {
            read_optional_text(&vault_dir.join(SIDECAR_CLOUD))?
        } else {
            None
        },
        cloud_manifests_json: if scope.cloud {
            read_optional_text(&vault_dir.join(SIDECAR_CLOUD_MANIFESTS))?
        } else {
            None
        },
        active_project: if scope.active_project {
            read_optional_text(&vault_dir.join(SIDECAR_ACTIVE_PROJECT))?
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        } else {
            None
        },
        audit_fingerprint_key_b64: if scope.audits {
            read_optional_bytes_b64(&vault_dir.join(SIDECAR_AUDIT_FINGERPRINT))?
        } else {
            None
        },
    })
}

fn dump_table(db: &Connection, table: &str) -> Result<Vec<Map<String, Value>>> {
    if !is_safe_ident(table) {
        return Err(VaultError::Backup(format!("invalid table name {table}")));
    }
    let mut statement = db.prepare(&format!("SELECT * FROM {table}"))?;
    let columns: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        let mut map = Map::new();
        for (index, column) in columns.iter().enumerate() {
            map.insert(column.clone(), sqlite_to_json(row, index)?);
        }
        rows.push(map);
    }
    Ok(rows)
}

fn sqlite_to_json(row: &rusqlite::Row<'_>, index: usize) -> Result<Value> {
    Ok(match row.get_ref(index)? {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::Number(value.into()),
        ValueRef::Real(value) => Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueRef::Text(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        ValueRef::Blob(value) => Value::String(BASE64.encode(value)),
    })
}

fn compute_integrity(payload: &VaultBackupPayload) -> Result<BackupIntegrity> {
    let mut for_hash = payload.clone();
    for_hash.integrity = BackupIntegrity::default();
    let canonical = serde_json::to_vec(&for_hash).map_err(|error| {
        VaultError::Backup(format!("serializing backup for integrity hash: {error}"))
    })?;
    Ok(BackupIntegrity {
        content_sha256: sha256_hex(&canonical),
        row_counts: counts_from_contents(&payload.contents),
    })
}

fn counts_from_contents(contents: &BackupContents) -> BackupCounts {
    BackupCounts {
        vault_meta: contents.vault_meta.len(),
        projects: contents.projects.len(),
        partitions: contents.partitions.len(),
        credentials: contents.credentials.len(),
        audits: contents.audit_log.len(),
        instances: contents.instances.len(),
        scopes: contents.instance_scopes.len(),
        access_requests: contents.access_requests.len(),
        bootstrap: contents.bootstrap_tokens.len(),
    }
}

fn schema_version_from_db(db: &Connection) -> Result<String> {
    db.query_row(
        "SELECT value FROM vault_meta WHERE key = 'version'",
        [],
        |row| row.get(0),
    )
    .map_err(VaultError::from)
}

fn schema_compatibility(source_schema_version: &str) -> Result<()> {
    let source = parse_schema_version(source_schema_version)?;
    let current = parse_schema_version(CURRENT_SCHEMA_VERSION)?;
    if source > current {
        return Err(VaultError::Backup(format!(
            "backup schema {source_schema_version} is newer than this WispKey ({CURRENT_SCHEMA_VERSION})"
        )));
    }
    if source < MIN_SUPPORTED_SCHEMA_VERSION {
        return Err(VaultError::Backup(format!(
            "backup schema {source_schema_version} is older than the minimum supported version {MIN_SUPPORTED_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn parse_schema_version(version: &str) -> Result<u32> {
    version
        .parse::<u32>()
        .map_err(|_| VaultError::Backup(format!("invalid schema version '{version}'")))
}

fn backup_warnings(scope: &BackupScope) -> Vec<String> {
    let mut warnings = vec![
        "session, protector, proxy, and owner IPC files are excluded".to_string(),
        "env-sideload secrets are not stored in the vault and are not backed up".to_string(),
        "database rows are captured in one SQLite read transaction; sidecars are read separately, so stop WispKey and quiesce the vault for cross-file consistency".to_string(),
    ];
    if scope.instances {
        warnings.push(
            "instance bearer secrets are not stored and cannot be restored; restored instances require re-enrollment".into(),
        );
    }
    if scope.bootstrap {
        warnings.push(
            "bootstrap token secrets are not stored; restored tokens are revoked and must be reminted".into(),
        );
    }
    warnings
}

fn inspect_sidecars(sidecars: &BackupSidecars) -> InspectSidecars {
    let cloud_session_token_present = sidecars
        .cloud_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|value| value.get("clerk_session_token").cloned())
        .is_some_and(|value| match value {
            Value::String(token) => !token.is_empty(),
            _ => false,
        });
    InspectSidecars {
        policies: sidecars.policies_toml.is_some(),
        cloud: sidecars.cloud_json.is_some(),
        cloud_session_token_present,
        cloud_manifests: sidecars.cloud_manifests_json.is_some(),
        active_project: sidecars.active_project.clone(),
        audit_fingerprint_key: sidecars.audit_fingerprint_key_b64.is_some(),
    }
}

fn index_by<'a>(
    rows: &'a [Map<String, Value>],
    key: &str,
) -> BTreeMap<String, &'a Map<String, Value>> {
    let mut index = BTreeMap::new();
    for row in rows {
        if let Some(id) = string_field(row, key) {
            index.insert(id, row);
        }
    }
    index
}

fn string_field(row: &Map<String, Value>, key: &str) -> Option<String> {
    match row.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn credential_type_label(row: &Map<String, Value>) -> String {
    match row.get("credential_type") {
        Some(Value::String(raw)) => serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|parsed| match parsed {
                Value::String(name) => Some(name),
                Value::Object(object) => object.keys().next().cloned().or_else(|| {
                    object
                        .get("type")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }),
                _ => None,
            })
            .unwrap_or_else(|| raw.clone()),
        _ => String::new(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = digest(&SHA256, bytes);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn is_safe_ident(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn read_optional_text(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_optional_bytes_b64(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(BASE64.encode(bytes))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn reject_protected_backup_output(vault_dir: &Path, output_path: &str) -> Result<()> {
    let output = Path::new(output_path);
    let output = normalize_path(if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    });
    let vault_dir = normalize_path(fs::canonicalize(vault_dir)?);
    let Some(parent) = output.parent() else {
        return Ok(());
    };
    let Some(name) = output.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let lexical_match = normalize_path(parent) == vault_dir;
    let symlink_match = match fs::canonicalize(parent) {
        Ok(parent) => normalize_path(&parent) == vault_dir,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if (lexical_match || symlink_match) && PROTECTED_VAULT_OUTPUT_NAMES.contains(&name) {
        return Err(VaultError::Backup(format!(
            "backup output '{}' is a protected active-vault file",
            output.display()
        )));
    }
    Ok(())
}

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.as_ref().components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn write_optional_text(path: &Path, contents: Option<&str>) -> Result<()> {
    let Some(contents) = contents else {
        return Ok(());
    };
    secure_files::write_private(path, contents.as_bytes())
}

fn write_optional_b64(path: &Path, contents: Option<&str>) -> Result<()> {
    let Some(contents) = contents else {
        return Ok(());
    };
    let bytes = BASE64
        .decode(contents.trim())
        .map_err(|error| VaultError::Backup(format!("invalid sidecar encoding: {error}")))?;
    secure_files::write_private(path, &bytes)
}

fn json_to_sqlite(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(flag) => rusqlite::types::Value::Integer(i64::from(*flag)),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                rusqlite::types::Value::Integer(integer)
            } else if let Some(real) = number.as_f64() {
                rusqlite::types::Value::Real(real)
            } else {
                rusqlite::types::Value::Text(number.to_string())
            }
        }
        Value::String(text) => rusqlite::types::Value::Text(text.clone()),
        other => rusqlite::types::Value::Text(other.to_string()),
    }
}

fn table_columns(db: &Connection, table: &str) -> Result<Vec<String>> {
    if !is_safe_ident(table) {
        return Err(VaultError::Backup(format!("invalid table name {table}")));
    }
    let mut statement = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns)
}

fn insert_row(db: &Connection, table: &str, row: &Map<String, Value>) -> Result<()> {
    let allowed = table_columns(db, table)?;
    let columns: Vec<&str> = allowed
        .iter()
        .map(String::as_str)
        .filter(|column| row.contains_key(*column))
        .collect();
    if columns.is_empty() {
        return Ok(());
    }
    let placeholders = (1..=columns.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({placeholders})",
        columns.join(", ")
    );
    let values: Vec<rusqlite::types::Value> = columns
        .iter()
        .map(|column| json_to_sqlite(row.get(*column).unwrap_or(&Value::Null)))
        .collect();
    db.execute(&sql, rusqlite::params_from_iter(values))?;
    Ok(())
}

fn dest_has_vault(target: &Path) -> bool {
    target.join("vault.db").exists()
}

fn restore_sidecar_paths(dir: &Path) -> Vec<PathBuf> {
    vec![
        dir.join("vault.db"),
        dir.join(SIDECAR_POLICIES),
        dir.join(SIDECAR_CLOUD),
        dir.join(SIDECAR_CLOUD_MANIFESTS),
        dir.join(SIDECAR_ACTIVE_PROJECT),
        dir.join(SIDECAR_AUDIT_FINGERPRINT),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_payload_omits_secret_fields() {
        let mut credential = Map::new();
        credential.insert("id".into(), Value::String("cred-1".into()));
        credential.insert("name".into(), Value::String("api-key".into()));
        credential.insert("credential_type".into(), Value::String("\"ApiKey\"".into()));
        credential.insert(
            "encrypted_value".into(),
            Value::String("ciphertext-should-not-leak".into()),
        );
        credential.insert("wisp_token".into(), Value::String("wk_api_secret".into()));
        credential.insert("hosts".into(), Value::String("api.example.com".into()));
        credential.insert("tags".into(), Value::String("prod".into()));
        credential.insert("partition_id".into(), Value::String("personal".into()));

        let mut partition = Map::new();
        partition.insert("id".into(), Value::String("personal".into()));
        partition.insert("name".into(), Value::String("personal".into()));
        partition.insert("project_id".into(), Value::String("default".into()));

        let mut project = Map::new();
        project.insert("id".into(), Value::String("default".into()));
        project.insert("name".into(), Value::String("default".into()));

        let payload = VaultBackupPayload {
            format_version: BACKUP_FORMAT_VERSION,
            exported_at: "2026-08-26T00:00:00Z".into(),
            source_schema_version: CURRENT_SCHEMA_VERSION.into(),
            source_vault_created_at: None,
            scope: BackupScope::all_included(),
            contents: BackupContents {
                projects: vec![project],
                partitions: vec![partition],
                credentials: vec![credential],
                ..BackupContents::default()
            },
            sidecars: BackupSidecars {
                cloud_json: Some(
                    r#"{"api_url":"https://api.wispkey.com","clerk_session_token":"clerk-secret-token","tier":"Personal"}"#
                        .into(),
                ),
                ..BackupSidecars::default()
            },
            warnings: Vec::new(),
            integrity: BackupIntegrity::default(),
        };

        let inspect = inspect_payload(&payload);
        let json = serde_json::to_string(&inspect).expect("inspect json");
        assert!(!json.contains("ciphertext-should-not-leak"));
        assert!(!json.contains("clerk-secret-token"));
        assert!(!json.contains("encrypted_value"));
        assert!(!json.contains("wk_api_secret"));
        assert!(!json.contains("password_hash"));
        assert_eq!(inspect.credentials[0].name, "api-key");
        assert!(inspect.sidecars.cloud_session_token_present);
    }

    #[test]
    fn older_schema_payload_is_compatible() {
        let payload = VaultBackupPayload {
            format_version: BACKUP_FORMAT_VERSION,
            exported_at: "2026-08-26T00:00:00Z".into(),
            source_schema_version: "10".into(),
            source_vault_created_at: None,
            scope: BackupScope::all_included(),
            contents: BackupContents::default(),
            sidecars: BackupSidecars::default(),
            warnings: Vec::new(),
            integrity: BackupIntegrity::default(),
        };
        let mut with_hash = payload.clone();
        with_hash.integrity = compute_integrity(&payload).expect("integrity");
        let verified = verify_payload(&with_hash);
        assert!(verified.ok, "{:?}", verified.errors);
        assert!(verified.compatible);
    }

    #[test]
    fn future_schema_payload_is_rejected() {
        let error = schema_compatibility("99").expect_err("future schema");
        assert!(error.to_string().contains("newer than this WispKey"));
    }

    #[test]
    fn restore_fills_missing_schema_v10_credential_columns() {
        let target = tempfile::tempdir().expect("target");
        let backup_dir = tempfile::tempdir().expect("backup dir");
        let backup_path = backup_dir.path().join("legacy.wkbackup");
        let now = "2026-08-26T00:00:00+00:00";

        let vault_meta = vec![
            meta_row("version", "10"),
            meta_row("password_hash", "not-a-real-hash"),
            meta_row("created_at", now),
        ];
        let mut project = Map::new();
        project.insert("id".into(), Value::String("default".into()));
        project.insert("name".into(), Value::String("default".into()));
        project.insert("description".into(), Value::String(String::new()));
        project.insert("created_at".into(), Value::String(now.into()));
        project.insert("updated_at".into(), Value::String(now.into()));

        let mut partition = Map::new();
        partition.insert("id".into(), Value::String("personal".into()));
        partition.insert("name".into(), Value::String("personal".into()));
        partition.insert("description".into(), Value::String(String::new()));
        partition.insert("project_id".into(), Value::String("default".into()));
        partition.insert("created_at".into(), Value::String(now.into()));
        partition.insert("updated_at".into(), Value::String(now.into()));

        let mut credential = Map::new();
        credential.insert("id".into(), Value::String("cred-legacy".into()));
        credential.insert("name".into(), Value::String("legacy-key".into()));
        credential.insert("description".into(), Value::String(String::new()));
        credential.insert("credential_type".into(), Value::String("\"ApiKey\"".into()));
        credential.insert("encrypted_value".into(), Value::String("AAAA".into()));
        credential.insert(
            "wisp_token".into(),
            Value::String("wk_legacy_aaaaaaa".into()),
        );
        credential.insert("hosts".into(), Value::String(String::new()));
        credential.insert("tags".into(), Value::String(String::new()));
        credential.insert("created_at".into(), Value::String(now.into()));
        credential.insert("updated_at".into(), Value::String(now.into()));
        credential.insert("partition_id".into(), Value::String("personal".into()));

        let mut payload = VaultBackupPayload {
            format_version: BACKUP_FORMAT_VERSION,
            exported_at: now.into(),
            source_schema_version: "10".into(),
            source_vault_created_at: Some(now.into()),
            scope: BackupScope::all_included(),
            contents: BackupContents {
                vault_meta,
                projects: vec![project],
                partitions: vec![partition],
                credentials: vec![credential],
                ..BackupContents::default()
            },
            sidecars: BackupSidecars::default(),
            warnings: Vec::new(),
            integrity: BackupIntegrity::default(),
        };
        payload.integrity = compute_integrity(&payload).expect("integrity");
        crate::bundle::write_encrypted_payload_with_limit(
            VAULT_BACKUP_MAGIC,
            &payload,
            "test-bundle-passphrase",
            backup_path.to_str().expect("utf8"),
            MAX_VAULT_BACKUP_BYTES,
        )
        .expect("write backup");

        restore_backup(
            backup_path.to_str().expect("utf8"),
            "test-bundle-passphrase",
            RestoreOptions {
                target_dir: target.path(),
                dry_run: false,
                replace: true,
                on_conflict: ConflictPolicy::Fail,
            },
        )
        .expect("restore");

        let db = rusqlite::Connection::open(target.path().join("vault.db")).expect("open restored");
        let origin: String = db
            .query_row(
                "SELECT origin FROM credentials WHERE name = 'legacy-key'",
                [],
                |row| row.get(0),
            )
            .expect("origin");
        let lifecycle: String = db
            .query_row(
                "SELECT lifecycle_state FROM credentials WHERE name = 'legacy-key'",
                [],
                |row| row.get(0),
            )
            .expect("lifecycle");
        assert_eq!(origin, "");
        assert_eq!(lifecycle, "active");
    }

    fn meta_row(key: &str, value: &str) -> Map<String, Value> {
        let mut row = Map::new();
        row.insert("key".into(), Value::String(key.into()));
        row.insert("value".into(), Value::String(value.into()));
        row
    }
}
