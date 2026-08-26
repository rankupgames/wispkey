/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Vault engine -- encrypted credential storage and domain operations.
 * Created: 2026-04-07
 * Last Modified: 2026-08-25
 */

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::secure_files;

mod crypto;
mod instances;
mod protector;
mod rows;
mod schema;
mod session;
mod session_store;
mod templates;
#[cfg(test)]
mod tests;

pub use instances::{
    AccessRequest, BootstrapJoinResult, BootstrapToken, CreateBootstrapTokenResult,
    EnrollInstanceResult, Instance, InstanceScopeInput, RotateInstanceSecretResult,
};
use rows::{credential_from_row, parse_csv, partition_from_row, project_from_row};
#[cfg(test)]
use rows::{parse_credential_type_column, parse_datetime_column};
pub use templates::{
    OVH_API_TEMPLATE, OvhApiTemplate, OwnedAddCredentialRequest, expand_credential_template,
};

/// Default partition name used when none is specified (`personal`).
pub const DEFAULT_PARTITION_NAME: &str = "personal";
/// Default project name for new vaults and implicit project context (`default`).
pub const DEFAULT_PROJECT_NAME: &str = "default";
const CURRENT_SCHEMA_VERSION: &str = "11";

/// Errors returned by vault operations (I/O, crypto, schema, and business rules).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found -- run `wispkey init` first")]
    NotFound,
    #[error("vault is locked -- run `wispkey unlock` first")]
    Locked,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("credential '{0}' already exists")]
    DuplicateCredential(String),
    #[error("credential '{0}' not found")]
    CredentialNotFound(String),
    #[error("invalid credential type: {0}")]
    InvalidCredentialType(String),
    #[error("invalid .env file: {0}")]
    InvalidEnvFile(String),
    #[error(".env credential conflict: {0}")]
    EnvCredentialConflict(String),
    #[error("credential name must not be empty")]
    EmptyCredentialName,
    #[error("credential value must not be empty")]
    EmptyCredentialValue,
    #[error("invalid credential template: {0}")]
    InvalidCredentialTemplate(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("session expired -- run `wispkey unlock` to mint a new session")]
    SessionExpired,
    #[error("session expired or invalid")]
    SessionInvalid,
    #[error("remembered unlock expired -- run `wispkey unlock` with the master password")]
    ProtectorExpired,
    #[error(
        "no remembered unlock is available -- run `wispkey unlock` with --password-file, WISPKEY_PASSWORD, or an interactive prompt; use --remember to store an OS-backed or local protector"
    )]
    ProtectorUnavailable,
    #[error("{0}")]
    ProtectorUnavailableOs(String),
    #[error("session timeout must be zero or a positive number of minutes")]
    InvalidSessionTimeout,
    #[error("partition '{0}' already exists")]
    DuplicatePartition(String),
    #[error("partition '{0}' not found")]
    PartitionNotFound(String),
    #[error("cannot delete the default 'personal' partition")]
    CannotDeleteDefaultPartition,
    #[error("project '{0}' already exists")]
    DuplicateProject(String),
    #[error("project '{0}' not found")]
    ProjectNotFound(String),
    #[error("cannot delete the default project")]
    CannotDeleteDefaultProject,
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("instance '{0}' already exists")]
    DuplicateInstance(String),
    #[error("instance '{0}' not found")]
    InstanceNotFound(String),
    #[error("instance '{0}' is not active")]
    InstanceNotActive(String),
    #[error("instance secret rotation for '{0}' raced another state change; retry")]
    InstanceSecretRotationConflict(String),
    #[error("instance secret rotation intervals must be positive and grace must not be negative")]
    InvalidInstanceSecretRotation,
    #[error("invalid instance scope type: {0}")]
    InvalidInstanceScope(String),
    #[error("instance scope '{0}' not found")]
    InstanceScopeNotFound(String),
    #[error("access request '{0}' not found")]
    AccessRequestNotFound(String),
    #[error("access request '{0}' is already decided")]
    AccessRequestAlreadyDecided(String),
    #[error("invalid website origin: {0}")]
    InvalidOrigin(String),
    #[error("invalid credential lifecycle state: {0}")]
    InvalidLifecycle(String),
    #[error("invalid, expired, exhausted, or revoked bootstrap token")]
    InvalidBootstrapToken,
    #[error("bootstrap token '{0}' not found")]
    BootstrapTokenNotFound(String),
}

/// Convenient `Result` alias using [`VaultError`] as the error type.
pub type Result<T> = std::result::Result<T, VaultError>;

/// Stored credential kind (bearer, API key, auth schemes, and parameterized variants).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum CredentialType {
    BearerToken,
    ApiKey,
    BasicAuth,
    CustomHeader { header_name: String },
    QueryParam { param_name: String },
    WebsiteLogin,
}

/// Encrypted website-login payload. Username and password stay inside
/// encrypted credential material and are never stored in tags or descriptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebsiteLoginPayload {
    pub username: String,
    pub password: String,
}

/// Lifecycle for generated website logins. Review dates notify; they never auto-delete.
pub const LIFECYCLE_PENDING: &str = "pending";
pub const LIFECYCLE_ACTIVE: &str = "active";
pub const LIFECYCLE_ARCHIVED: &str = "archived";

impl CredentialType {
    /// Parses a wire/type string into a [`CredentialType`], using optional header or query param names when required.
    pub fn from_str_with_params(
        type_str: &str,
        header_name: Option<&str>,
        param_name: Option<&str>,
    ) -> Result<Self> {
        match type_str {
            "bearer_token" => Ok(Self::BearerToken),
            "api_key" => Ok(Self::ApiKey),
            "basic_auth" => Ok(Self::BasicAuth),
            "custom_header" => {
                let name = header_name.ok_or_else(|| {
                    VaultError::InvalidCredentialType("custom_header requires --header-name".into())
                })?;
                Ok(Self::CustomHeader {
                    header_name: name.to_string(),
                })
            }
            "query_param" => {
                let name = param_name.ok_or_else(|| {
                    VaultError::InvalidCredentialType("query_param requires --param-name".into())
                })?;
                Ok(Self::QueryParam {
                    param_name: name.to_string(),
                })
            }
            "website_login" => Ok(Self::WebsiteLogin),
            other => Err(VaultError::InvalidCredentialType(other.to_string())),
        }
    }

    /// Stable snake_case label for this variant (for CLI and persistence).
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::BearerToken => "bearer_token",
            Self::ApiKey => "api_key",
            Self::BasicAuth => "basic_auth",
            Self::CustomHeader { .. } => "custom_header",
            Self::QueryParam { .. } => "query_param",
            Self::WebsiteLogin => "website_login",
        }
    }
}

/// Metadata for one stored credential (no secret value; use decrypt helpers when unlocked).
#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub description: String,
    pub credential_type: CredentialType,
    pub wisp_token: String,
    pub hosts: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub partition_id: Option<String>,
    pub origin: String,
    pub lifecycle_state: String,
    pub review_at: Option<DateTime<Utc>>,
}

/// Parameters for creating a credential.
///
/// This keeps project/partition routing explicit at the call site and prevents
/// the CLI, imports, desktop bridge, and tests from drifting onto different
/// credential creation paths.
#[derive(Debug, Clone)]
pub struct AddCredentialRequest<'a> {
    pub name: &'a str,
    pub credential_type: CredentialType,
    pub value: &'a str,
    pub description: Option<&'a str>,
    pub hosts: Option<&'a str>,
    pub tags: Option<&'a str>,
    pub partition: Option<&'a str>,
    pub project: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub lifecycle_state: Option<&'a str>,
    pub review_at: Option<&'a str>,
}

/// Parameters for generating and storing a website login atomically.
#[derive(Debug, Clone)]
pub struct GenerateWebsiteLoginRequest<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub url: &'a str,
    pub project: Option<&'a str>,
    pub partition: Option<&'a str>,
    pub review_at: Option<DateTime<Utc>>,
    pub length: Option<usize>,
    pub symbols: bool,
}

#[cfg(test)]
impl<'a> AddCredentialRequest<'a> {
    #[must_use]
    pub fn new(name: &'a str, credential_type: CredentialType, value: &'a str) -> Self {
        Self {
            name,
            credential_type,
            value,
            description: None,
            hosts: None,
            tags: None,
            partition: None,
            project: None,
            origin: None,
            lifecycle_state: None,
            review_at: None,
        }
    }

    #[must_use]
    pub fn description(mut self, description: Option<&'a str>) -> Self {
        self.description = description;
        self
    }

    #[must_use]
    pub fn hosts(mut self, hosts: Option<&'a str>) -> Self {
        self.hosts = hosts;
        self
    }

    #[must_use]
    pub fn tags(mut self, tags: Option<&'a str>) -> Self {
        self.tags = tags;
        self
    }

    #[must_use]
    pub fn partition(mut self, partition: Option<&'a str>) -> Self {
        self.partition = partition;
        self
    }

    #[must_use]
    pub fn project(mut self, project: Option<&'a str>) -> Self {
        self.project = project;
        self
    }
}

/// Parameters for updating an existing credential in place (preserves wisp token and id).
#[derive(Debug, Clone)]
pub struct UpdateCredentialRequest<'a> {
    pub name: &'a str,
    pub credential_type: CredentialType,
    pub value: &'a str,
    pub description: Option<&'a str>,
    pub hosts: Option<&'a str>,
    pub tags: Option<&'a str>,
    pub project: Option<&'a str>,
}

/// A named bucket of credentials within a project.
#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub project_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Top-level grouping for partitions and credentials.
#[derive(Debug, Clone, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Open encrypted vault backed by SQLite; holds DB handle and optional in-memory master key when unlocked.
pub struct Vault {
    db: Connection,
    master_key: Option<[u8; 32]>,
    session_timeout_override: Option<i64>,
}

impl Vault {
    fn resolve_partition_id_for_insert(
        &self,
        partition: Option<&str>,
        project: Option<&str>,
    ) -> Result<String> {
        let name = partition.unwrap_or(DEFAULT_PARTITION_NAME);
        let active = resolve_active_project();
        let project_name = project.unwrap_or(&active);
        let project_id = self.resolve_project_id(project_name)?;
        let id: String = self
            .db
            .query_row(
                "SELECT id FROM partitions WHERE project_id = ?1 AND name = ?2",
                params![project_id, name],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::PartitionNotFound(name.to_string()))?;
        Ok(id)
    }

    /// Inserts a new credential (encrypted secret, wisp token, optional description/hosts/tags/partition).
    pub fn add_credential(&self, request: AddCredentialRequest<'_>) -> Result<Credential> {
        self.add_credentials_atomic(&[request])?
            .pop()
            .ok_or_else(|| VaultError::Encryption("credential insert produced no row".into()))
    }

    /// Inserts every credential in one transaction. Any failure rolls back the whole batch.
    pub fn add_credentials_atomic(
        &self,
        requests: &[AddCredentialRequest<'_>],
    ) -> Result<Vec<Credential>> {
        if requests.is_empty() {
            return Err(VaultError::InvalidCredentialTemplate(
                "at least one credential is required".into(),
            ));
        }

        let mut seen_names = HashSet::new();
        for request in requests {
            validate_add_request(request)?;
            if !seen_names.insert(request.name) {
                return Err(VaultError::DuplicateCredential(request.name.to_string()));
            }
        }

        let key = self.ensure_unlocked()?;
        self.db.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
        let inserted = (|| {
            let mut created = Vec::with_capacity(requests.len());
            for request in requests {
                created.push(self.insert_credential_row(key, request)?);
            }
            Ok(created)
        })();
        match inserted {
            Ok(created) => {
                if let Err(error) = self.db.execute_batch("COMMIT") {
                    let _ = self.db.execute_batch("ROLLBACK");
                    return Err(error.into());
                }
                Ok(created)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn insert_credential_row(
        &self,
        key: &[u8; 32],
        request: &AddCredentialRequest<'_>,
    ) -> Result<Credential> {
        let active = resolve_active_project();
        let project_name = request.project.unwrap_or(&active);
        let project_id = self.resolve_project_id(project_name)?;

        let existing: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 AND c.name = ?2",
            params![project_id, request.name],
            |row| row.get(0),
        )?;
        if existing {
            return Err(VaultError::DuplicateCredential(request.name.to_string()));
        }

        let partition_id =
            self.resolve_partition_id_for_insert(request.partition, request.project)?;

        let id = Uuid::new_v4().to_string();
        let encrypted_value = self.encrypt_bytes(key, request.value.as_bytes())?;
        let wisp_token = self.generate_wisp_token(request.name)?;
        let type_json = serde_json::to_string(&request.credential_type)
            .expect("CredentialType serializes to json");
        let desc = request.description.unwrap_or("");
        let hosts_csv = request.hosts.unwrap_or("");
        let tags_csv = request.tags.unwrap_or("");
        let origin = request.origin.unwrap_or("");
        let lifecycle_state = request.lifecycle_state.unwrap_or(LIFECYCLE_ACTIVE);
        validate_lifecycle_state(lifecycle_state)?;
        let review_at = request.review_at;
        let now = Utc::now().to_rfc3339();

        self.db.execute(
			"INSERT INTO credentials (id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, partition_id, origin, lifecycle_state, review_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
			params![id, request.name, desc, type_json, BASE64.encode(&encrypted_value), wisp_token, hosts_csv, tags_csv, now, now, partition_id, origin, lifecycle_state, review_at],
		)?;

        Ok(Credential {
            id,
            name: request.name.to_string(),
            description: desc.to_string(),
            credential_type: request.credential_type.clone(),
            wisp_token,
            hosts: parse_csv(hosts_csv),
            tags: parse_csv(tags_csv),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            partition_id: Some(partition_id),
            origin: origin.to_string(),
            lifecycle_state: lifecycle_state.to_string(),
            review_at: review_at.and_then(parse_optional_review_at),
        })
    }

    /// Generates a unique password, encrypts username+password together, and
    /// stores the login before any fill attempt. Never returns the password.
    pub fn generate_website_login(
        &self,
        request: GenerateWebsiteLoginRequest<'_>,
    ) -> Result<Credential> {
        let origin = parse_https_origin(request.url)?;
        if request.username.trim().is_empty() {
            return Err(VaultError::InvalidCredentialType(
                "website login username must not be empty".into(),
            ));
        }
        let mut policy = crate::random::PasswordPolicy::default_strong();
        if let Some(length) = request.length {
            policy.length = length;
        }
        policy.symbols = request.symbols;
        let password = crate::random::generate_password(&policy)?;
        let payload = WebsiteLoginPayload {
            username: request.username.to_string(),
            password,
        };
        let value = serde_json::to_string(&payload)
            .map_err(|error| VaultError::Encryption(error.to_string()))?;
        let host = origin_host(&origin);
        let review_at = request.review_at.map(|value| value.to_rfc3339());
        self.add_credential(AddCredentialRequest {
            name: request.name,
            credential_type: CredentialType::WebsiteLogin,
            value: &value,
            description: None,
            hosts: Some(&host),
            tags: None,
            partition: request.partition,
            project: request.project,
            origin: Some(&origin),
            lifecycle_state: Some(LIFECYCLE_PENDING),
            review_at: review_at.as_deref(),
        })
    }

    /// Archives, restores, or activates a credential lifecycle. Never deletes.
    pub fn set_credential_lifecycle(
        &self,
        name: &str,
        lifecycle_state: &str,
        project: Option<&str>,
    ) -> Result<Credential> {
        let _ = self.ensure_unlocked()?;
        validate_lifecycle_state(lifecycle_state)?;
        let active = resolve_active_project();
        let project_name = project.unwrap_or(&active);
        let credential = self.get_credential_in_project(project_name, name)?;
        if credential.credential_type != CredentialType::WebsiteLogin {
            return Err(VaultError::InvalidCredentialType(
                "lifecycle changes are only supported for website_login credentials".into(),
            ));
        }
        match (credential.lifecycle_state.as_str(), lifecycle_state) {
            (_, LIFECYCLE_ARCHIVED) => {}
            (LIFECYCLE_ARCHIVED, LIFECYCLE_PENDING | LIFECYCLE_ACTIVE) => {}
            (LIFECYCLE_PENDING, LIFECYCLE_ACTIVE) => {}
            (current, next) if current == next => {}
            (current, next) => {
                return Err(VaultError::InvalidLifecycle(format!(
                    "cannot change lifecycle from {current} to {next}"
                )));
            }
        }
        let now = Utc::now().to_rfc3339();
        self.db.execute(
            "UPDATE credentials SET lifecycle_state = ?1, updated_at = ?2 WHERE id = ?3",
            params![lifecycle_state, now, credential.id],
        )?;
        self.get_credential_in_project(project_name, name)
    }

    /// Lists website logins whose review date is due. Never deletes them.
    pub fn list_due_website_logins(&self, project: Option<&str>) -> Result<Vec<Credential>> {
        let credentials = if let Some(project_name) = project {
            self.list_credentials_in_project(project_name)?
        } else {
            self.list_credentials()?
        };
        let now = Utc::now();
        Ok(credentials
            .into_iter()
            .filter(|credential| {
                credential.credential_type == CredentialType::WebsiteLogin
                    && credential.lifecycle_state != LIFECYCLE_ARCHIVED
                    && credential
                        .review_at
                        .is_some_and(|review_at| review_at <= now)
            })
            .collect())
    }

    /// Updates an existing credential in place: re-encrypts with a new value and
    /// patches metadata fields while preserving the wisp token, id, and partition.
    pub fn update_credential(&self, request: UpdateCredentialRequest<'_>) -> Result<Credential> {
        let key = self.ensure_unlocked()?;
        let active = resolve_active_project();
        let project_name = request.project.unwrap_or(&active);
        let project_id = self.resolve_project_id(project_name)?;

        let (cred_id, partition_id, created_at_str, wisp_token, origin, lifecycle_state, review_at_str): (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ) = self
            .db
            .query_row(
                "SELECT c.id, c.partition_id, c.created_at, c.wisp_token, c.origin, c.lifecycle_state, c.review_at FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 AND c.name = ?2",
                params![project_id, request.name],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .map_err(|_| VaultError::CredentialNotFound(request.name.to_string()))?;

        let encrypted_value = self.encrypt_bytes(key, request.value.as_bytes())?;
        let type_json = serde_json::to_string(&request.credential_type)
            .expect("CredentialType serializes to json");
        let desc = request.description.unwrap_or("");
        let hosts_csv = request.hosts.unwrap_or("");
        let tags_csv = request.tags.unwrap_or("");
        let now = Utc::now().to_rfc3339();

        self.db.execute(
            "UPDATE credentials SET credential_type = ?1, encrypted_value = ?2, description = ?3, hosts = ?4, tags = ?5, updated_at = ?6 WHERE id = ?7",
            params![type_json, BASE64.encode(&encrypted_value), desc, hosts_csv, tags_csv, now, cred_id],
        )?;

        let created_at =
            rows::parse_datetime_column(0, &created_at_str).unwrap_or_else(|_| Utc::now());

        Ok(Credential {
            id: cred_id,
            name: request.name.to_string(),
            description: desc.to_string(),
            credential_type: request.credential_type,
            wisp_token,
            hosts: parse_csv(hosts_csv),
            tags: parse_csv(tags_csv),
            created_at,
            updated_at: Utc::now(),
            last_used_at: None,
            partition_id: Some(partition_id),
            origin,
            lifecycle_state,
            review_at: review_at_str.and_then(|value| parse_optional_review_at(&value)),
        })
    }

    /// Creates a partition; uses `project` or the active project when unset.
    pub fn create_partition(
        &self,
        name: &str,
        description: &str,
        project: Option<&str>,
    ) -> Result<Partition> {
        let _ = self.ensure_unlocked()?;

        let active = resolve_active_project();
        let project_name = project.unwrap_or(&active);
        let project_id = self.resolve_project_id(project_name)?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM partitions WHERE project_id = ?1 AND name = ?2",
            params![project_id, name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(VaultError::DuplicatePartition(name.to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
			"INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
			params![id, name, description, project_id, now, now],
		)?;

        self.get_partition_in_project(project_name, name)
    }

    /// Lists all partitions across every project, sorted by name.
    pub fn list_partitions(&self) -> Result<Vec<Partition>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, project_id, created_at, updated_at FROM partitions ORDER BY name",
        )?;
        let partitions = stmt
            .query_map([], partition_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(partitions)
    }

    /// Lists partitions belonging to the named project.
    pub fn list_partitions_in_project(&self, project_name: &str) -> Result<Vec<Partition>> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, project_id, created_at, updated_at FROM partitions WHERE project_id = ?1 ORDER BY name",
        )?;
        let partitions = stmt
            .query_map(params![project_id], partition_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(partitions)
    }

    /// Loads a partition by name in the active project.
    #[allow(dead_code)]
    pub fn get_partition(&self, name: &str) -> Result<Partition> {
        let active = resolve_active_project();
        self.get_partition_in_project(&active, name)
    }

    /// Loads a partition by name in a specific project.
    pub fn get_partition_in_project(&self, project_name: &str, name: &str) -> Result<Partition> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, project_id, created_at, updated_at FROM partitions WHERE project_id = ?1 AND name = ?2",
        )?;
        stmt.query_row(params![project_id, name], partition_from_row)
            .map_err(|_| VaultError::PartitionNotFound(name.to_string()))
    }

    /// Loads a partition directly by id.
    pub fn get_partition_by_id(&self, id: &str) -> Result<Partition> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, project_id, created_at, updated_at FROM partitions WHERE id = ?1",
        )?;
        stmt.query_row(params![id], partition_from_row)
            .map_err(|_| VaultError::PartitionNotFound(id.to_string()))
    }

    /// Deletes a partition (not `personal`); reassigns its credentials to the default partition.
    pub fn delete_partition(&self, name: &str) -> Result<()> {
        let active = resolve_active_project();
        self.delete_partition_in_project(&active, name)
    }

    /// Deletes a partition in a specific project and moves credentials to that project's personal partition.
    pub fn delete_partition_in_project(&self, project_name: &str, name: &str) -> Result<()> {
        let _ = self.ensure_unlocked()?;

        if name == DEFAULT_PARTITION_NAME {
            return Err(VaultError::CannotDeleteDefaultPartition);
        }

        let partition: Partition = self.get_partition_in_project(project_name, name)?;
        let personal_id =
            self.resolve_partition_id_for_insert(Some(DEFAULT_PARTITION_NAME), Some(project_name))?;

        self.db.execute(
            "UPDATE credentials SET partition_id = ?1, updated_at = ?2 WHERE partition_id = ?3",
            params![personal_id, Utc::now().to_rfc3339(), partition.id],
        )?;
        let affected = self.db.execute(
            "DELETE FROM partitions WHERE id = ?1",
            params![partition.id],
        )?;
        if affected == 0 {
            return Err(VaultError::PartitionNotFound(name.to_string()));
        }
        Ok(())
    }

    /// Moves a credential to another partition by name.
    pub fn assign_credential_to_partition(
        &self,
        credential_name: &str,
        partition_name: &str,
    ) -> Result<()> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials WHERE name = ?1",
            params![credential_name],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::CredentialNotFound(credential_name.to_string()));
        }

        let credential = self.get_credential(credential_name)?;
        let project_name = credential
            .partition_id
            .as_ref()
            .and_then(|id| self.get_partition_project_name(id).ok().flatten())
            .unwrap_or_else(resolve_active_project);
        let partition_id =
            self.resolve_partition_id_for_insert(Some(partition_name), Some(&project_name))?;
        self.db.execute(
            "UPDATE credentials SET partition_id = ?1, updated_at = ?2 WHERE id = ?3",
            params![partition_id, Utc::now().to_rfc3339(), credential.id],
        )?;
        Ok(())
    }

    /// Lists credentials in the given partition, sorted by name.
    #[allow(dead_code)]
    pub fn list_credentials_in_partition(&self, partition_name: &str) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let active = resolve_active_project();
        self.list_credentials_in_partition_for_project(&active, partition_name)
    }

    /// Lists credentials in the given project partition, sorted by name.
    pub fn list_credentials_in_partition_for_project(
        &self,
        project_name: &str,
        partition_name: &str,
    ) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let partition_id =
            self.resolve_partition_id_for_insert(Some(partition_name), Some(project_name))?;
        let mut stmt = self.db.prepare(
			"SELECT id, name, description, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id, origin, lifecycle_state, review_at FROM credentials WHERE partition_id = ?1 ORDER BY name",
		)?;
        let credentials = stmt
            .query_map(params![partition_id], credential_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(credentials)
    }

    /// Counts credentials assigned to a partition by partition id.
    pub fn partition_credential_count(&self, partition_id: &str) -> Result<usize> {
        let count: usize = self.db.query_row(
            "SELECT COUNT(*) FROM credentials WHERE partition_id = ?1",
            params![partition_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Lists every credential in the vault, sorted by name.
    pub fn list_credentials(&self) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare("SELECT id, name, description, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id, origin, lifecycle_state, review_at FROM credentials ORDER BY name")?;
        let credentials = stmt
            .query_map([], credential_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(credentials)
    }

    /// Fetches credential metadata by name in the active project.
    pub fn get_credential(&self, name: &str) -> Result<Credential> {
        let active = resolve_active_project();
        self.get_credential_in_project(&active, name)
    }

    pub fn get_credential_in_project(&self, project_name: &str, name: &str) -> Result<Credential> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let mut stmt = self.db.prepare(
			"SELECT c.id, c.name, c.description, c.credential_type, c.wisp_token, c.hosts, c.tags, c.created_at, c.updated_at, c.last_used_at, c.partition_id, c.origin, c.lifecycle_state, c.review_at FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 AND c.name = ?2",
		)?;
        stmt.query_row(params![project_id, name], credential_from_row)
            .map_err(|_| VaultError::CredentialNotFound(name.to_string()))
    }

    /// Decrypts and returns the stored secret for a credential by name.
    #[allow(dead_code)]
    pub fn decrypt_credential_value(&self, name: &str) -> Result<String> {
        let active = resolve_active_project();
        self.decrypt_credential_value_in_project(&active, name)
    }

    pub fn decrypt_credential_value_in_project(
        &self,
        project_name: &str,
        name: &str,
    ) -> Result<String> {
        let key = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let encoded: String = self
            .db
            .query_row(
                "SELECT c.encrypted_value FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 AND c.name = ?2",
                params![project_id, name],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::CredentialNotFound(name.to_string()))?;
        let encrypted = BASE64
            .decode(&encoded)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let decrypted = self.decrypt_bytes(key, &encrypted)?;
        String::from_utf8(decrypted).map_err(|e| VaultError::Encryption(e.to_string()))
    }

    /// Deletes a credential row by name.
    pub fn remove_credential(&self, name: &str) -> Result<()> {
        let active = resolve_active_project();
        self.remove_credential_in_project(&active, name)
    }

    pub fn remove_credential_in_project(&self, project_name: &str, name: &str) -> Result<()> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let affected = self.db.execute(
            "DELETE FROM credentials WHERE name = ?1 AND partition_id IN (SELECT id FROM partitions WHERE project_id = ?2)",
            params![name, project_id],
        )?;
        if affected == 0 {
            return Err(VaultError::CredentialNotFound(name.to_string()));
        }
        Ok(())
    }

    /// Issues a new unique wisp token for an existing credential.
    pub fn rotate_wisp_token(&self, name: &str) -> Result<String> {
        let active = resolve_active_project();
        self.rotate_wisp_token_in_project(&active, name)
    }

    pub fn rotate_wisp_token_in_project(&self, project_name: &str, name: &str) -> Result<String> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 AND c.name = ?2",
            params![project_id, name],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::CredentialNotFound(name.to_string()));
        }

        let new_token = self.generate_wisp_token(name)?;
        self.db.execute(
            "UPDATE credentials SET wisp_token = ?1, updated_at = ?2 WHERE name = ?3 AND partition_id IN (SELECT id FROM partitions WHERE project_id = ?4)",
            params![new_token, Utc::now().to_rfc3339(), name, project_id],
        )?;
        Ok(new_token)
    }

    /// Resolves a wisp token to credential metadata and decrypted secret; updates `last_used_at`.
    pub fn lookup_by_wisp_token(&self, token: &str) -> Result<(Credential, String)> {
        let key = self.ensure_unlocked()?;

        let mut stmt = self.db.prepare("SELECT id, name, description, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id, origin, lifecycle_state, review_at, encrypted_value FROM credentials WHERE wisp_token = ?1")?;
        let (cred, encoded) = stmt
            .query_row(params![token], |row| {
                let encrypted_value: String = row.get(14)?;
                let cred = credential_from_row(row)?;
                Ok((cred, encrypted_value))
            })
            .map_err(|_| VaultError::CredentialNotFound(token.to_string()))?;

        let encrypted = BASE64
            .decode(&encoded)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let decrypted = self.decrypt_bytes(key, &encrypted)?;
        let value =
            String::from_utf8(decrypted).map_err(|e| VaultError::Encryption(e.to_string()))?;

        self.db.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE wisp_token = ?2",
            params![Utc::now().to_rfc3339(), token],
        )?;

        Ok((cred, value))
    }

    /// Creates a new project with the given name and description.
    pub fn create_project(&self, name: &str, description: &str) -> Result<Project> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM projects WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(VaultError::DuplicateProject(name.to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
			"INSERT INTO projects (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
			params![id, name, description, now, now],
		)?;
        self.db.execute(
            "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES (?1, ?2, '', ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                DEFAULT_PARTITION_NAME,
                id,
                now,
                now
            ],
        )?;

        self.get_project(name)
    }

    /// Lists all projects, sorted by name.
    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, created_at, updated_at FROM projects ORDER BY name",
        )?;
        let projects = stmt
            .query_map([], project_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(projects)
    }

    /// Loads a project by unique name.
    pub fn get_project(&self, name: &str) -> Result<Project> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, created_at, updated_at FROM projects WHERE name = ?1",
        )?;
        stmt.query_row(params![name], project_from_row)
            .map_err(|_| VaultError::ProjectNotFound(name.to_string()))
    }

    /// Deletes a project (not `default`); reassigns non-conflicting partitions to default.
    /// Credentials in partitions that already exist in default move to that default partition.
    pub fn delete_project(&self, name: &str) -> Result<()> {
        let _ = self.ensure_unlocked()?;

        if name == DEFAULT_PROJECT_NAME {
            return Err(VaultError::CannotDeleteDefaultProject);
        }

        let project = self.get_project(name)?;
        let default_id: String = self.db.query_row(
            "SELECT id FROM projects WHERE name = ?1",
            params![DEFAULT_PROJECT_NAME],
            |row| row.get(0),
        )?;

        let mut stmt = self
            .db
            .prepare("SELECT id, name FROM partitions WHERE project_id = ?1 ORDER BY name")?;
        let partitions = stmt
            .query_map(params![project.id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        let now = Utc::now().to_rfc3339();
        for (partition_id, partition_name) in partitions {
            let default_partition_id: Option<String> = self
                .db
                .query_row(
                    "SELECT id FROM partitions WHERE project_id = ?1 AND name = ?2",
                    params![default_id, partition_name],
                    |row| row.get(0),
                )
                .ok();

            if let Some(target_partition_id) = default_partition_id {
                self.db.execute(
                    "UPDATE credentials SET partition_id = ?1, updated_at = ?2 WHERE partition_id = ?3",
                    params![target_partition_id, now, partition_id],
                )?;
                self.db.execute(
                    "DELETE FROM partitions WHERE id = ?1",
                    params![partition_id],
                )?;
            } else {
                self.db.execute(
                    "UPDATE partitions SET project_id = ?1, updated_at = ?2 WHERE id = ?3",
                    params![default_id, now, partition_id],
                )?;
            }
        }

        let affected = self
            .db
            .execute("DELETE FROM projects WHERE id = ?1", params![project.id])?;
        if affected == 0 {
            return Err(VaultError::ProjectNotFound(name.to_string()));
        }
        Ok(())
    }

    /// Counts partitions in a project by project id.
    pub fn project_partition_count(&self, project_id: &str) -> Result<usize> {
        let count: usize = self.db.query_row(
            "SELECT COUNT(*) FROM partitions WHERE project_id = ?1",
            params![project_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn resolve_project_id(&self, project_name: &str) -> Result<String> {
        let id: String = self
            .db
            .query_row(
                "SELECT id FROM projects WHERE name = ?1",
                params![project_name],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::ProjectNotFound(project_name.to_string()))?;
        Ok(id)
    }

    /// Lists credentials whose partition belongs to the named project.
    pub fn list_credentials_in_project(&self, project_name: &str) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let project_id = self.resolve_project_id(project_name)?;
        let mut stmt = self.db.prepare(
			"SELECT c.id, c.name, c.description, c.credential_type, c.wisp_token, c.hosts, c.tags, c.created_at, c.updated_at, c.last_used_at, c.partition_id, c.origin, c.lifecycle_state, c.review_at FROM credentials c JOIN partitions p ON c.partition_id = p.id WHERE p.project_id = ?1 ORDER BY c.name",
		)?;
        let credentials = stmt
            .query_map(params![project_id], credential_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(credentials)
    }

    /// Project name for a partition id, if the join resolves.
    pub fn get_partition_project_name(&self, partition_id: &str) -> Result<Option<String>> {
        let result: Option<String> = self.db.query_row(
            "SELECT p.name FROM projects p JOIN partitions pt ON pt.project_id = p.id WHERE pt.id = ?1",
            params![partition_id],
            |row| row.get(0),
        ).ok();
        Ok(result)
    }

    /// Total number of credential rows in the vault.
    pub fn credential_count(&self) -> Result<usize> {
        let count: usize = self
            .db
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;
        Ok(count)
    }

    /// RFC3339 timestamp from vault metadata when the vault was created.
    pub fn vault_created_at(&self) -> Result<String> {
        let created: String = self.db.query_row(
            "SELECT value FROM vault_meta WHERE key = 'created_at'",
            [],
            |row| row.get(0),
        )?;
        Ok(created)
    }

    fn generate_wisp_token(&self, name: &str) -> Result<String> {
        let slug: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        let slug = slug.trim_matches('_');

        loop {
            let random_part = crate::random::alphanumeric(8, true)?;
            let token = format!("wk_{}_{}", slug, random_part);

            let exists: bool = self.db.query_row(
                "SELECT COUNT(*) > 0 FROM credentials WHERE wisp_token = ?1",
                params![token],
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(token);
            }
        }
    }
}

fn validate_add_request(request: &AddCredentialRequest<'_>) -> Result<()> {
    if request.name.trim().is_empty() {
        return Err(VaultError::EmptyCredentialName);
    }
    if request.value.trim().is_empty() {
        return Err(VaultError::EmptyCredentialValue);
    }
    Ok(())
}

/// Active project name: `WISPKEY_PROJECT`, else `active_project` file, else [`DEFAULT_PROJECT_NAME`].
pub fn resolve_active_project() -> String {
    if let Ok(project) = std::env::var("WISPKEY_PROJECT")
        && !project.is_empty()
    {
        return project;
    }

    let active_path = Vault::vault_dir().join("active_project");
    if let Ok(content) = fs::read_to_string(&active_path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    DEFAULT_PROJECT_NAME.to_string()
}

/// Writes the active project name to `active_project` under [`Vault::vault_dir`].
pub fn set_active_project(name: &str) -> Result<()> {
    let vault_dir = Vault::vault_dir();
    secure_files::ensure_private_directory(&vault_dir)?;
    fs::write(vault_dir.join("active_project"), name)?;
    Ok(())
}

/// Returns the exact HTTPS origin (`https://host[:port]`) for website-login policy binding.
pub fn parse_https_origin(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw.trim()).map_err(|error| {
        VaultError::InvalidOrigin(format!("invalid website login URL: {error}"))
    })?;
    if parsed.scheme() != "https" {
        return Err(VaultError::InvalidOrigin(
            "website login URL must use https".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(VaultError::InvalidOrigin(
            "website login URL must not include userinfo".into(),
        ));
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            let valid = !domain.is_empty()
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                });
            if !valid {
                return Err(VaultError::InvalidOrigin(
                    "website login URL host is invalid".into(),
                ));
            }
            domain.to_string()
        }
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        None => {
            return Err(VaultError::InvalidOrigin(
                "website login URL is missing a host".into(),
            ));
        }
    };
    Ok(match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

fn origin_host(origin: &str) -> String {
    origin
        .strip_prefix("https://")
        .unwrap_or(origin)
        .to_string()
}

fn validate_lifecycle_state(state: &str) -> Result<()> {
    match state {
        LIFECYCLE_PENDING | LIFECYCLE_ACTIVE | LIFECYCLE_ARCHIVED => Ok(()),
        other => Err(VaultError::InvalidLifecycle(other.to_string())),
    }
}

fn parse_optional_review_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|datetime| datetime.with_timezone(&Utc))
}
