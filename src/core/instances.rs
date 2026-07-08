use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;
use uuid::Uuid;

use super::rows::parse_datetime_column;
use super::{Credential, Result, Vault, VaultError};

const INSTANCE_STATUS_ACTIVE: &str = "active";
const INSTANCE_STATUS_REVOKED: &str = "revoked";
const REQUEST_STATUS_PENDING: &str = "pending";
const REQUEST_STATUS_APPROVED: &str = "approved";
const REQUEST_STATUS_DENIED: &str = "denied";

/// Host-enrolled client identity for scoped multi-instance access.
#[derive(Debug, Clone, Serialize)]
pub struct Instance {
    pub id: String,
    pub name: String,
    pub status: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub scopes: Vec<InstanceScope>,
    pub pending_request_count: usize,
}

/// One scope selector attached to an instance.
#[derive(Debug, Clone, Serialize)]
pub struct InstanceScope {
    pub id: String,
    pub instance_id: String,
    pub scope_type: String,
    pub scope_value: String,
    pub created_at: DateTime<Utc>,
}

/// Scope selector input for enrollment and CLI handlers.
#[derive(Debug, Clone)]
pub struct InstanceScopeInput {
    pub scope_type: String,
    pub scope_value: String,
}

impl InstanceScopeInput {
    #[must_use]
    pub fn new(scope_type: &str, scope_value: &str) -> Self {
        Self {
            scope_type: scope_type.to_string(),
            scope_value: scope_value.to_string(),
        }
    }
}

/// Enrollment result containing the one-time plaintext secret.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollInstanceResult {
    pub instance: Instance,
    pub secret: String,
}

/// Host-visible request for an out-of-scope credential.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRequest {
    pub id: String,
    pub instance_id: String,
    pub instance_name: String,
    pub credential_name: String,
    pub status: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
}

impl Vault {
    /// Enrolls a new instance, returning its generated plaintext secret exactly once.
    pub fn enroll_instance(
        &self,
        name: &str,
        description: &str,
        scopes: &[InstanceScopeInput],
    ) -> Result<EnrollInstanceResult> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM instances WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(VaultError::DuplicateInstance(name.to_string()));
        }

        for scope in scopes {
            validate_scope_type(&scope.scope_type)?;
        }

        let id = Uuid::new_v4().to_string();
        let secret = crate::random::alphanumeric(48, false)?;
        let secret_hash = hash_instance_secret(&secret)?;
        let now = Utc::now().to_rfc3339();

        self.db.execute(
            "INSERT INTO instances (id, name, secret_hash, status, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, name, secret_hash, INSTANCE_STATUS_ACTIVE, description, now, now],
        )?;

        for scope in scopes {
            self.add_instance_scope(&id, &scope.scope_type, &scope.scope_value)?;
        }

        Ok(EnrollInstanceResult {
            instance: self.get_instance(&id)?,
            secret,
        })
    }

    /// Lists all instances with scopes and pending request counts.
    pub fn list_instances(&self) -> Result<Vec<Instance>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, status, description, created_at, updated_at, last_seen_at FROM instances ORDER BY name",
        )?;
        let basics = stmt
            .query_map([], instance_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        basics
            .into_iter()
            .map(|mut instance| {
                self.populate_instance_details(&mut instance)?;
                Ok(instance)
            })
            .collect()
    }

    /// Loads an instance by id or name.
    pub fn get_instance(&self, identifier: &str) -> Result<Instance> {
        let _ = self.ensure_unlocked()?;
        let mut instance = self
            .db
            .query_row(
                "SELECT id, name, status, description, created_at, updated_at, last_seen_at FROM instances WHERE id = ?1 OR name = ?1 LIMIT 1",
                params![identifier],
                instance_from_row,
            )
            .map_err(|_| VaultError::InstanceNotFound(identifier.to_string()))?;
        self.populate_instance_details(&mut instance)?;
        Ok(instance)
    }

    /// Adds one scope selector to an instance. Duplicate selectors are reused.
    pub fn add_instance_scope(
        &self,
        instance_id: &str,
        scope_type: &str,
        scope_value: &str,
    ) -> Result<InstanceScope> {
        let _ = self.ensure_unlocked()?;
        validate_scope_type(scope_type)?;
        self.ensure_instance_exists(instance_id)?;

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
            "INSERT OR IGNORE INTO instance_scopes (id, instance_id, scope_type, scope_value, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, instance_id, scope_type, scope_value, now],
        )?;
        self.load_instance_scope(instance_id, scope_type, scope_value)
    }

    /// Removes one scope selector from an instance.
    pub fn remove_instance_scope(
        &self,
        instance_id: &str,
        scope_type: &str,
        scope_value: &str,
    ) -> Result<()> {
        let _ = self.ensure_unlocked()?;
        validate_scope_type(scope_type)?;
        self.ensure_instance_exists(instance_id)?;

        let affected = self.db.execute(
            "DELETE FROM instance_scopes WHERE instance_id = ?1 AND scope_type = ?2 AND scope_value = ?3",
            params![instance_id, scope_type, scope_value],
        )?;
        if affected == 0 {
            return Err(VaultError::InstanceScopeNotFound(format!(
                "{scope_type}:{scope_value}"
            )));
        }
        Ok(())
    }

    /// Revokes an instance without deleting its rows.
    pub fn revoke_instance(&self, identifier: &str) -> Result<Instance> {
        let _ = self.ensure_unlocked()?;
        let instance = self.get_instance(identifier)?;
        self.db.execute(
            "UPDATE instances SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                INSTANCE_STATUS_REVOKED,
                Utc::now().to_rfc3339(),
                instance.id
            ],
        )?;
        self.get_instance(identifier)
    }

    /// Verifies an instance secret. Revoked instances and wrong secrets fail closed.
    #[allow(dead_code)]
    pub fn verify_instance_secret(&self, instance_id: &str, secret: &str) -> Result<bool> {
        let _ = self.ensure_unlocked()?;
        let (status, stored_hash): (String, String) = self
            .db
            .query_row(
                "SELECT status, secret_hash FROM instances WHERE id = ?1",
                params![instance_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| VaultError::InstanceNotFound(instance_id.to_string()))?;

        if status != INSTANCE_STATUS_ACTIVE {
            return Ok(false);
        }

        let parsed_hash = argon2::PasswordHash::new(&stored_hash)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let verified = argon2_hasher()
            .verify_password(secret.as_bytes(), &parsed_hash)
            .is_ok();
        if verified {
            self.db.execute(
                "UPDATE instances SET last_seen_at = ?1, updated_at = ?2 WHERE id = ?3",
                params![
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    instance_id
                ],
            )?;
        }
        Ok(verified)
    }

    /// Returns true when a credential name matches any explicit or approved instance scope.
    #[allow(dead_code)]
    pub fn credential_in_scope(&self, instance_id: &str, credential_name: &str) -> Result<bool> {
        let _ = self.ensure_unlocked()?;
        let instance = self.get_instance(instance_id)?;
        if instance.status != INSTANCE_STATUS_ACTIVE {
            return Ok(false);
        }

        let credentials = self.credentials_named_across_projects(credential_name)?;
        if credentials.is_empty() {
            return Ok(false);
        }

        let approved: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM access_requests WHERE instance_id = ?1 AND credential_name = ?2 AND status = ?3",
            params![instance.id, credential_name, REQUEST_STATUS_APPROVED],
            |row| row.get(0),
        )?;
        if approved {
            return Ok(true);
        }

        for credential in credentials {
            if self.credential_matches_instance_scopes(&instance, &credential)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Creates a pending request for a credential, or reuses an existing pending row.
    #[allow(dead_code)]
    pub fn create_or_reuse_access_request(
        &self,
        instance_id: &str,
        credential_name: &str,
        reason: &str,
    ) -> Result<AccessRequest> {
        let _ = self.ensure_unlocked()?;
        self.ensure_instance_exists(instance_id)?;
        if self
            .credentials_named_across_projects(credential_name)?
            .is_empty()
        {
            return Err(VaultError::CredentialNotFound(credential_name.to_string()));
        }

        if let Some(existing) = self.find_pending_access_request(instance_id, credential_name)? {
            return Ok(existing);
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
            "INSERT INTO access_requests (id, instance_id, credential_name, status, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, instance_id, credential_name, REQUEST_STATUS_PENDING, reason, now],
        )?;
        self.get_access_request(&id)
    }

    /// Lists host-visible access requests.
    pub fn list_access_requests(
        &self,
        instance: Option<&str>,
        pending_only: bool,
    ) -> Result<Vec<AccessRequest>> {
        let _ = self.ensure_unlocked()?;
        let instance_id = instance
            .map(|identifier| self.get_instance(identifier).map(|instance| instance.id))
            .transpose()?;

        match (instance_id, pending_only) {
            (Some(id), true) => self.query_access_requests(
                "WHERE ar.instance_id = ?1 AND ar.status = ?2",
                params![id, REQUEST_STATUS_PENDING],
            ),
            (Some(id), false) => {
                self.query_access_requests("WHERE ar.instance_id = ?1", params![id])
            }
            (None, true) => {
                self.query_access_requests("WHERE ar.status = ?1", params![REQUEST_STATUS_PENDING])
            }
            (None, false) => self.query_access_requests("", []),
        }
    }

    /// Approves or denies a pending access request.
    pub fn decide_access_request(&self, request_id: &str, approve: bool) -> Result<AccessRequest> {
        let _ = self.ensure_unlocked()?;
        let request = self.get_access_request(request_id)?;
        if request.status != REQUEST_STATUS_PENDING {
            return Err(VaultError::AccessRequestAlreadyDecided(
                request_id.to_string(),
            ));
        }

        let status = if approve {
            REQUEST_STATUS_APPROVED
        } else {
            REQUEST_STATUS_DENIED
        };
        self.db.execute(
            "UPDATE access_requests SET status = ?1, decided_at = ?2 WHERE id = ?3",
            params![status, Utc::now().to_rfc3339(), request_id],
        )?;
        self.get_access_request(request_id)
    }

    fn ensure_instance_exists(&self, instance_id: &str) -> Result<()> {
        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM instances WHERE id = ?1",
            params![instance_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::InstanceNotFound(instance_id.to_string()));
        }
        Ok(())
    }

    fn populate_instance_details(&self, instance: &mut Instance) -> Result<()> {
        instance.scopes = self.load_instance_scopes(&instance.id)?;
        instance.pending_request_count = self.pending_access_request_count(&instance.id)?;
        Ok(())
    }

    fn load_instance_scopes(&self, instance_id: &str) -> Result<Vec<InstanceScope>> {
        let mut stmt = self.db.prepare(
            "SELECT id, instance_id, scope_type, scope_value, created_at FROM instance_scopes WHERE instance_id = ?1 ORDER BY scope_type, scope_value",
        )?;
        let scopes = stmt
            .query_map(params![instance_id], instance_scope_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(scopes)
    }

    fn load_instance_scope(
        &self,
        instance_id: &str,
        scope_type: &str,
        scope_value: &str,
    ) -> Result<InstanceScope> {
        self.db
            .query_row(
                "SELECT id, instance_id, scope_type, scope_value, created_at FROM instance_scopes WHERE instance_id = ?1 AND scope_type = ?2 AND scope_value = ?3",
                params![instance_id, scope_type, scope_value],
                instance_scope_from_row,
            )
            .map_err(|_| VaultError::InstanceScopeNotFound(format!("{scope_type}:{scope_value}")))
    }

    fn pending_access_request_count(&self, instance_id: &str) -> Result<usize> {
        let count = self.db.query_row(
            "SELECT COUNT(*) FROM access_requests WHERE instance_id = ?1 AND status = ?2",
            params![instance_id, REQUEST_STATUS_PENDING],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn credentials_named_across_projects(&self, credential_name: &str) -> Result<Vec<Credential>> {
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id FROM credentials WHERE name = ?1 ORDER BY name",
        )?;
        let credentials = stmt
            .query_map(params![credential_name], super::rows::credential_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(credentials)
    }

    fn credential_matches_instance_scopes(
        &self,
        instance: &Instance,
        credential: &Credential,
    ) -> Result<bool> {
        for scope in &instance.scopes {
            match scope.scope_type.as_str() {
                "credential" if credential.name == scope.scope_value => return Ok(true),
                "tag" if credential.tags.iter().any(|tag| tag == &scope.scope_value) => {
                    return Ok(true);
                }
                "partition" => {
                    if let Some(partition_id) = &credential.partition_id
                        && self.partition_matches_scope(partition_id, &scope.scope_value)?
                    {
                        return Ok(true);
                    }
                }
                "project" => {
                    if let Some(partition_id) = &credential.partition_id
                        && self.project_matches_scope(partition_id, &scope.scope_value)?
                    {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    fn partition_matches_scope(&self, partition_id: &str, scope_value: &str) -> Result<bool> {
        let matches: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM partitions WHERE id = ?1 AND (id = ?2 OR name = ?2)",
            params![partition_id, scope_value],
            |row| row.get(0),
        )?;
        Ok(matches)
    }

    fn project_matches_scope(&self, partition_id: &str, scope_value: &str) -> Result<bool> {
        let matches: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM partitions pt JOIN projects p ON pt.project_id = p.id WHERE pt.id = ?1 AND p.name = ?2",
            params![partition_id, scope_value],
            |row| row.get(0),
        )?;
        Ok(matches)
    }

    fn find_pending_access_request(
        &self,
        instance_id: &str,
        credential_name: &str,
    ) -> Result<Option<AccessRequest>> {
        self.db
            .query_row(
                "SELECT ar.id, ar.instance_id, i.name, ar.credential_name, ar.status, ar.reason, ar.created_at, ar.decided_at FROM access_requests ar JOIN instances i ON ar.instance_id = i.id WHERE ar.instance_id = ?1 AND ar.credential_name = ?2 AND ar.status = ?3 ORDER BY ar.created_at LIMIT 1",
                params![instance_id, credential_name, REQUEST_STATUS_PENDING],
                access_request_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn get_access_request(&self, request_id: &str) -> Result<AccessRequest> {
        self.db
            .query_row(
                "SELECT ar.id, ar.instance_id, i.name, ar.credential_name, ar.status, ar.reason, ar.created_at, ar.decided_at FROM access_requests ar JOIN instances i ON ar.instance_id = i.id WHERE ar.id = ?1",
                params![request_id],
                access_request_from_row,
            )
            .map_err(|_| VaultError::AccessRequestNotFound(request_id.to_string()))
    }

    fn query_access_requests<P>(&self, where_clause: &str, params: P) -> Result<Vec<AccessRequest>>
    where
        P: rusqlite::Params,
    {
        let sql = format!(
            "SELECT ar.id, ar.instance_id, i.name, ar.credential_name, ar.status, ar.reason, ar.created_at, ar.decided_at FROM access_requests ar JOIN instances i ON ar.instance_id = i.id {where_clause} ORDER BY ar.created_at DESC"
        );
        let mut stmt = self.db.prepare(&sql)?;
        let requests = stmt
            .query_map(params, access_request_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(requests)
    }
}

fn hash_instance_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2_hasher()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| VaultError::Encryption(e.to_string()))
}

fn argon2_hasher() -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
    )
}

fn validate_scope_type(scope_type: &str) -> Result<()> {
    match scope_type {
        "partition" | "project" | "credential" | "tag" => Ok(()),
        other => Err(VaultError::InvalidInstanceScope(other.to_string())),
    }
}

fn instance_from_row(row: &Row<'_>) -> rusqlite::Result<Instance> {
    let created_str: String = row.get(4)?;
    let updated_str: String = row.get(5)?;
    let last_seen_str: Option<String> = row.get(6)?;
    Ok(Instance {
        id: row.get(0)?,
        name: row.get(1)?,
        status: row.get(2)?,
        description: row.get(3)?,
        created_at: parse_datetime_column(4, &created_str)?,
        updated_at: parse_datetime_column(5, &updated_str)?,
        last_seen_at: last_seen_str
            .as_deref()
            .map(|value| parse_datetime_column(6, value))
            .transpose()?,
        scopes: Vec::new(),
        pending_request_count: 0,
    })
}

fn instance_scope_from_row(row: &Row<'_>) -> rusqlite::Result<InstanceScope> {
    let created_str: String = row.get(4)?;
    Ok(InstanceScope {
        id: row.get(0)?,
        instance_id: row.get(1)?,
        scope_type: row.get(2)?,
        scope_value: row.get(3)?,
        created_at: parse_datetime_column(4, &created_str)?,
    })
}

fn access_request_from_row(row: &Row<'_>) -> rusqlite::Result<AccessRequest> {
    let created_str: String = row.get(6)?;
    let decided_str: Option<String> = row.get(7)?;
    Ok(AccessRequest {
        id: row.get(0)?,
        instance_id: row.get(1)?,
        instance_name: row.get(2)?,
        credential_name: row.get(3)?,
        status: row.get(4)?,
        reason: row.get(5)?,
        created_at: parse_datetime_column(6, &created_str)?,
        decided_at: decided_str
            .as_deref()
            .map(|value| parse_datetime_column(7, value))
            .transpose()?,
    })
}
