//! Durable, metadata-only grants for approved cross-node operations.
//! The caller that issues a grant must be the authenticated local owner; grant IDs
//! are references, not bearer credentials. No function here decrypts a secret.

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Duration, Utc};
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Vault;
use super::operation_session::OperationSessionBinding as SessionLease;

pub type GrantResult<T> = std::result::Result<T, &'static str>;
const MAX_GRANT_SECONDS: i64 = 300;
const MAX_RUNTIME_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct AuthenticatedRequester {
    instance_id: String,
    generation: String,
}

impl AuthenticatedRequester {
    /// Authenticate the enrolled instance, rejecting a previous rotation-grace
    /// secret even if the proxy still accepts it during its rollout window.
    pub fn authenticate(vault: &Vault, id: &str, secret: &str) -> GrantResult<Self> {
        if Uuid::parse_str(id).is_err() || secret.is_empty() {
            return Err("requester authentication failed");
        }
        let verified = vault
            .verify_instance_secret(id, secret)
            .map_err(|_| "requester authentication failed")?;
        if !verified {
            return Err("requester authentication failed");
        }
        Ok(Self {
            instance_id: id.to_owned(),
            generation: current_secret_generation(vault.db(), id, secret)?,
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

fn current_secret_generation(db: &Connection, id: &str, secret: &str) -> GrantResult<String> {
    let (status, stored_hash): (String, String) = db
        .query_row(
            "SELECT status, secret_hash FROM instances WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "requester authentication failed")?;
    let parsed =
        argon2::PasswordHash::new(&stored_hash).map_err(|_| "requester authentication failed")?;
    if status != "active"
        || Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_err()
    {
        return Err("requester authentication failed");
    }
    Ok(hash_text(&stored_hash))
}

/// All strings are approved catalog metadata, never caller-provided command text.
#[derive(Clone)]
pub struct OperationBinding {
    pub operation: String,
    pub target: String,
    pub environment: String,
    pub credential_id: String,
    pub project_id: String,
    pub provider_credential_id: Option<String>,
    pub provider_project_id: Option<String>,
    pub old_password_credential_id: Option<String>,
    pub catalog_revision: String,
    pub requester_instance_id: String,
    pub expires_at: DateTime<Utc>,
    pub max_grant_seconds: u32,
    pub max_runtime_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Pending,
    Started,
    Succeeded,
    DeliveryAcknowledged,
    FailedChild,
    TimedOut,
    Canceled,
    OutcomeUnknown,
    RevocationUnverified,
}

impl GrantState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::DeliveryAcknowledged => "delivery_acknowledged",
            Self::FailedChild => "failed_child",
            Self::TimedOut => "timed_out",
            Self::Canceled => "canceled",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::RevocationUnverified => "revocation_unverified",
        }
    }

    fn from_str(value: &str) -> GrantResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "started" => Ok(Self::Started),
            "succeeded" => Ok(Self::Succeeded),
            "delivery_acknowledged" => Ok(Self::DeliveryAcknowledged),
            "failed_child" => Ok(Self::FailedChild),
            "timed_out" => Ok(Self::TimedOut),
            "canceled" => Ok(Self::Canceled),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            "revocation_unverified" => Ok(Self::RevocationUnverified),
            _ => Err("operation state unavailable"),
        }
    }

    fn terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Started)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantStatus {
    pub grant_id: String,
    pub operation: String,
    pub target: String,
    pub environment: String,
    pub credential_ref: String,
    pub expires_at: DateTime<Utc>,
    pub state: GrantState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptStatus {
    pub attempt_id: String,
    pub grant_id: String,
    pub operation: String,
    pub target: String,
    pub environment: String,
    pub credential_ref: String,
    pub expires_at: DateTime<Utc>,
    pub hard_deadline: DateTime<Utc>,
    pub state: GrantState,
    pub cancel_requested: bool,
    pub exit_code: Option<i32>,
}

#[derive(Clone, Serialize)]
pub struct OperationAudit {
    pub timestamp: DateTime<Utc>,
    pub requester: String,
    pub operation: String,
    pub target: String,
    pub environment: String,
    pub credential_ref: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub result: String,
}

/// Called by the vault schema hook. No plaintext or token columns are stored.
pub(crate) fn create_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS operation_grants (
            id TEXT PRIMARY KEY,
            operation TEXT NOT NULL, target TEXT NOT NULL, environment TEXT NOT NULL,
            credential_ref TEXT NOT NULL, project_id TEXT NOT NULL,
            catalog_revision TEXT NOT NULL, credential_revision TEXT NOT NULL,
            provider_credential_ref TEXT, provider_project_id TEXT, provider_revision TEXT,
            old_password_credential_ref TEXT, old_password_revision TEXT,
            requester_instance_id TEXT NOT NULL, instance_generation TEXT NOT NULL,
            session_issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            max_grant_seconds INTEGER NOT NULL, max_runtime_seconds INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','started','succeeded','delivery_acknowledged','failed_child','timed_out','canceled','outcome_unknown','revocation_unverified'))
        );
        CREATE TABLE IF NOT EXISTS operation_attempts (
            id TEXT PRIMARY KEY, grant_id TEXT NOT NULL UNIQUE REFERENCES operation_grants(id),
            hard_deadline TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','succeeded','delivery_acknowledged','failed_child','timed_out','canceled','outcome_unknown','revocation_unverified')),
            cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
            secret_released INTEGER NOT NULL DEFAULT 0 CHECK(secret_released IN (0,1)),
            provider_released INTEGER NOT NULL DEFAULT 0 CHECK(provider_released IN (0,1)),
            old_password_released INTEGER NOT NULL DEFAULT 0 CHECK(old_password_released IN (0,1)),
            exit_code INTEGER, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operation_audit (
            timestamp TEXT NOT NULL, requester TEXT NOT NULL, operation TEXT NOT NULL,
            target TEXT NOT NULL, environment TEXT NOT NULL,
            credential_ref TEXT, expires_at TEXT NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('authorized','denied_identity','denied','started','succeeded','delivery_acknowledged','failed_child','timed_out','cancel_requested','canceled','outcome_unknown','revocation_unverified'))
        );
        CREATE INDEX IF NOT EXISTS operation_attempts_state ON operation_attempts(state);",
    )
}

/// The owner-only caller approves one exact binding. This API never accepts a
/// credential value, and does not grant any authority to the requester itself.
pub fn issue_grant(
    vault: &Vault,
    binding: &OperationBinding,
    requested_expires_at: DateTime<Utc>,
) -> GrantResult<GrantStatus> {
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    issue_with_session(vault.db(), binding, requested_expires_at, &session)
}

fn issue_with_session(
    db: &Connection,
    binding: &OperationBinding,
    requested_expires_at: DateTime<Utc>,
    session: &SessionLease,
) -> GrantResult<GrantStatus> {
    validate_binding(binding)?;
    let now = Utc::now();
    let expires_at = binding
        .expires_at
        .min(requested_expires_at)
        .min(session.expires_at)
        .min(now + Duration::seconds(i64::from(binding.max_grant_seconds)));
    if expires_at <= now {
        return Err("authorization expired");
    }
    let tx = db
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let generation = instance_generation(&tx, &binding.requester_instance_id)?;
    let revision = credential_revision(&tx, &binding.project_id, &binding.credential_id)?;
    let provider_revision = match (
        &binding.provider_project_id,
        &binding.provider_credential_id,
    ) {
        (Some(project), Some(credential)) => Some(credential_revision(&tx, project, credential)?),
        (None, None) => None,
        _ => return Err("invalid operation binding"),
    };
    let old_password_revision = binding
        .old_password_credential_id
        .as_deref()
        .map(|credential| credential_revision(&tx, &binding.project_id, credential))
        .transpose()?;
    let id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO operation_grants (id,operation,target,environment,credential_ref,project_id,catalog_revision,credential_revision,provider_credential_ref,provider_project_id,provider_revision,old_password_credential_ref,old_password_revision,requester_instance_id,instance_generation,session_issued_at,expires_at,max_grant_seconds,max_runtime_seconds,state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,'pending')",
        params![id,binding.operation,binding.target,binding.environment,binding.credential_id,binding.project_id,binding.catalog_revision,revision,binding.provider_credential_id,binding.provider_project_id,provider_revision,binding.old_password_credential_id,old_password_revision,binding.requester_instance_id,generation,session.revision,expires_at.to_rfc3339(),binding.max_grant_seconds,binding.max_runtime_seconds],
    )
    .map_err(|_| "operation store unavailable")?;
    audit(
        &tx,
        &binding.requester_instance_id,
        binding,
        expires_at,
        "authorized",
    )?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    Ok(GrantStatus {
        grant_id: id,
        operation: binding.operation.clone(),
        target: binding.target.clone(),
        environment: binding.environment.clone(),
        credential_ref: binding.credential_id.clone(),
        expires_at,
        state: GrantState::Pending,
    })
}

/// Atomically consumes one grant and writes a durable `started` audit row.
/// The executor may decrypt only after this call returns successfully.
pub fn reserve(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    grant_id: &str,
    binding: &OperationBinding,
) -> GrantResult<AttemptStatus> {
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    reserve_with_session(vault.db(), requester, grant_id, binding, &session)
}

/// Re-checks every mutable authority before the executor continues. A watcher
/// should call this throughout the operation and stop transport on any error.
pub fn attempt_still_authorized(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
) -> GrantResult<()> {
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    validate_live(vault.db(), requester, attempt, binding, &session).map(|_| ())
}

/// Stable, secret-free delivery marker for a destination object. Retries with
/// a newly approved grant for the same immutable input use the same marker;
/// grant and attempt IDs deliberately do not affect it.
pub fn delivery_revision(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
) -> GrantResult<String> {
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    delivery_revision_with_session(vault.db(), requester, attempt, binding, &session)
}

fn delivery_revision_with_session(
    db: &Connection,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
    session: &SessionLease,
) -> GrantResult<String> {
    let grant = validate_live(db, requester, attempt, binding, session)?;
    let mut hash = ring::digest::Context::new(&SHA256);
    hash.update(b"wispkey-operation-delivery-v1\0");
    for field in [
        grant.catalog_revision.as_str(),
        grant.operation.as_str(),
        grant.environment.as_str(),
        grant.target.as_str(),
        grant.project_id.as_str(),
        grant.credential_ref.as_str(),
        grant.credential_revision.as_str(),
    ] {
        hash.update(&(field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The sole grant-aware plaintext release for an SSH operation. The caller
/// must send the returned bytes only to the fixed helper's private stdin.
pub fn decrypt_reserved(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
) -> GrantResult<Vec<u8>> {
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    validate_live(&tx, requester, attempt, binding, &session)?;
    let changed = tx.execute(
        "UPDATE operation_attempts SET secret_released=1 WHERE id=?1 AND state='started' AND cancel_requested=0 AND secret_released=0",
        [attempt.attempt_id.as_str()],
    ).map_err(|_| "operation store unavailable")?;
    if changed != 1 {
        return Err("attempt unavailable");
    }
    let encoded: String = tx
        .query_row(
            "SELECT c.encrypted_value FROM credentials c JOIN partitions p ON p.id=c.partition_id WHERE c.id=?1 AND p.project_id=?2",
            params![binding.credential_id,binding.project_id],
            |row| row.get(0),
        )
        .map_err(|_| "credential unavailable")?;
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|_| "credential unavailable")?;
    let key = vault.ensure_unlocked().map_err(|_| "session unavailable")?;
    let mut plaintext = vault
        .decrypt_bytes(key, &ciphertext)
        .map_err(|_| "credential unavailable")?;
    let renewed = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable");
    if !renewed.is_ok_and(|current| {
        current.revision == session.revision && current.expires_at > Utc::now()
    }) {
        plaintext.fill(0);
        return Err("session unavailable");
    }
    if tx.commit().is_err() {
        plaintext.fill(0);
        return Err("operation store unavailable");
    }
    Ok(plaintext)
}

/// One-time release of the separately bound provider credential. The adapter
/// must verify pinned provider identity and posture before calling this.
pub fn decrypt_provider(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
) -> GrantResult<Vec<u8>> {
    let (Some(provider_project), Some(provider_credential)) = (
        &binding.provider_project_id,
        &binding.provider_credential_id,
    ) else {
        return Err("provider credential unavailable");
    };
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    validate_live(&tx, requester, attempt, binding, &session)?;
    let changed = tx.execute(
        "UPDATE operation_attempts SET provider_released=1 WHERE id=?1 AND state='started' AND cancel_requested=0 AND provider_released=0",
        [attempt.attempt_id.as_str()],
    ).map_err(|_| "operation store unavailable")?;
    if changed != 1 {
        return Err("provider credential unavailable");
    }
    let encoded: String = tx.query_row(
        "SELECT c.encrypted_value FROM credentials c JOIN partitions p ON p.id=c.partition_id WHERE c.id=?1 AND p.project_id=?2",
        params![provider_credential, provider_project],
        |row| row.get(0),
    ).map_err(|_| "provider credential unavailable")?;
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|_| "provider credential unavailable")?;
    let key = vault.ensure_unlocked().map_err(|_| "session unavailable")?;
    let mut plaintext = vault
        .decrypt_bytes(key, &ciphertext)
        .map_err(|_| "provider credential unavailable")?;
    let renewed = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable");
    if !renewed.is_ok_and(|current| {
        current.revision == session.revision && current.expires_at > Utc::now()
    }) {
        plaintext.fill(0);
        return Err("session unavailable");
    }
    if tx.commit().is_err() {
        plaintext.fill(0);
        return Err("operation store unavailable");
    }
    Ok(plaintext)
}

/// One-time release of the exact prior password for a separately approved
/// rotation. The caller must keep it in memory and use it only for old-login
/// verification; the selected credential remains the new password.
pub fn decrypt_previous(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
) -> GrantResult<Vec<u8>> {
    let Some(old_id) = &binding.old_password_credential_id else {
        return Err("previous credential unavailable");
    };
    let session = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable")?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    validate_live(&tx, requester, attempt, binding, &session)?;
    let changed = tx
        .execute(
            "UPDATE operation_attempts SET old_password_released=1 WHERE id=?1 AND state='started' AND cancel_requested=0 AND old_password_released=0",
            [attempt.attempt_id.as_str()],
        )
        .map_err(|_| "operation store unavailable")?;
    if changed != 1 {
        return Err("previous credential unavailable");
    }
    let encoded: String = tx
        .query_row(
            "SELECT c.encrypted_value FROM credentials c JOIN partitions p ON p.id=c.partition_id WHERE c.id=?1 AND p.project_id=?2",
            params![old_id, binding.project_id],
            |row| row.get(0),
        )
        .map_err(|_| "previous credential unavailable")?;
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|_| "previous credential unavailable")?;
    let key = vault.ensure_unlocked().map_err(|_| "session unavailable")?;
    let mut plaintext = vault
        .decrypt_bytes(key, &ciphertext)
        .map_err(|_| "previous credential unavailable")?;
    let renewed = vault
        .operation_session_binding()
        .map_err(|_| "session unavailable");
    if !renewed.is_ok_and(|current| {
        current.revision == session.revision && current.expires_at > Utc::now()
    }) {
        plaintext.fill(0);
        return Err("session unavailable");
    }
    if tx.commit().is_err() {
        plaintext.fill(0);
        return Err("operation store unavailable");
    }
    Ok(plaintext)
}

fn validate_live(
    db: &Connection,
    requester: &AuthenticatedRequester,
    attempt: &AttemptStatus,
    binding: &OperationBinding,
    session: &SessionLease,
) -> GrantResult<StoredGrant> {
    validate_binding(binding)?;
    let stored_attempt = load_attempt(db, &attempt.attempt_id)?;
    let grant = load_grant(db, &stored_attempt.grant_id)?;
    let now = Utc::now();
    if stored_attempt.state != GrantState::Started
        || stored_attempt.cancel_requested
        || grant.state != GrantState::Started
        || now >= stored_attempt.hard_deadline
        || now >= grant.expires_at
        || now >= binding.expires_at
        || now >= session.expires_at
        || grant.session_issued_at != session.revision
        || attempt.grant_id != stored_attempt.grant_id
        || attempt.hard_deadline != stored_attempt.hard_deadline
        || grant.operation != binding.operation
        || grant.target != binding.target
        || grant.environment != binding.environment
        || grant.credential_ref != binding.credential_id
        || grant.project_id != binding.project_id
        || grant.provider_credential_ref != binding.provider_credential_id
        || grant.provider_project_id != binding.provider_project_id
        || grant.old_password_credential_ref != binding.old_password_credential_id
        || grant.catalog_revision != binding.catalog_revision
        || grant.requester_instance_id != binding.requester_instance_id
        || grant.max_grant_seconds != binding.max_grant_seconds
        || grant.max_runtime_seconds != binding.max_runtime_seconds
        || requester.instance_id != grant.requester_instance_id
        || requester.generation != grant.instance_generation
        || instance_generation(db, &requester.instance_id)? != requester.generation
        || credential_revision(db, &binding.project_id, &binding.credential_id)?
            != grant.credential_revision
        || match (
            &binding.provider_project_id,
            &binding.provider_credential_id,
            &grant.provider_revision,
        ) {
            (Some(project), Some(credential), Some(revision)) => {
                credential_revision(db, project, credential)? != *revision
            }
            (None, None, None) => false,
            _ => true,
        }
        || match (
            &binding.old_password_credential_id,
            &grant.old_password_revision,
        ) {
            (Some(credential), Some(revision)) => {
                credential_revision(db, &binding.project_id, credential)? != *revision
            }
            (None, None) => false,
            _ => true,
        }
    {
        return Err("attempt unavailable");
    }
    Ok(grant)
}

fn reserve_with_session(
    db: &Connection,
    requester: &AuthenticatedRequester,
    grant_id: &str,
    binding: &OperationBinding,
    session: &SessionLease,
) -> GrantResult<AttemptStatus> {
    validate_binding(binding)?;
    if Uuid::parse_str(grant_id).is_err() {
        return Err("grant unavailable");
    }
    let tx = db
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let stored = load_grant(&tx, grant_id)?;
    let now = Utc::now();
    if stored.state != GrantState::Pending
        || stored.expires_at <= now
        || stored.session_issued_at != session.revision
        || session.expires_at <= now
        || stored.operation != binding.operation
        || stored.target != binding.target
        || stored.environment != binding.environment
        || stored.credential_ref != binding.credential_id
        || stored.project_id != binding.project_id
        || stored.provider_credential_ref != binding.provider_credential_id
        || stored.provider_project_id != binding.provider_project_id
        || stored.old_password_credential_ref != binding.old_password_credential_id
        || stored.catalog_revision != binding.catalog_revision
        || stored.requester_instance_id != binding.requester_instance_id
        || stored.max_runtime_seconds != binding.max_runtime_seconds
        || stored.max_grant_seconds != binding.max_grant_seconds
        || binding.expires_at <= now
        || requester.instance_id != stored.requester_instance_id
    {
        return Err("grant unavailable");
    }
    if instance_generation(&tx, &requester.instance_id)? != requester.generation
        || stored.instance_generation != requester.generation
        || credential_revision(&tx, &binding.project_id, &binding.credential_id)?
            != stored.credential_revision
        || match (
            &binding.provider_project_id,
            &binding.provider_credential_id,
            &stored.provider_revision,
        ) {
            (Some(project), Some(credential), Some(revision)) => {
                credential_revision(&tx, project, credential)? != *revision
            }
            (None, None, None) => false,
            _ => true,
        }
        || match (
            &binding.old_password_credential_id,
            &stored.old_password_revision,
        ) {
            (Some(credential), Some(revision)) => {
                credential_revision(&tx, &binding.project_id, credential)? != *revision
            }
            (None, None) => false,
            _ => true,
        }
    {
        return Err("grant unavailable");
    }
    let busy: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM operation_attempts a JOIN operation_grants g ON g.id=a.grant_id WHERE a.state='started' AND (g.operation=?1 OR g.target=?2)",
            params![binding.operation, binding.target],
            |row| row.get(0),
        )
        .map_err(|_| "operation store unavailable")?;
    if busy != 0 {
        return Err("operation busy");
    }
    let deadline = (now + Duration::seconds(i64::from(binding.max_runtime_seconds)))
        .min(stored.expires_at)
        .min(session.expires_at)
        .min(binding.expires_at);
    if deadline <= now {
        return Err("grant unavailable");
    }
    let changed = tx
        .execute(
            "UPDATE operation_grants SET state='started' WHERE id=?1 AND state='pending'",
            [grant_id],
        )
        .map_err(|_| "operation store unavailable")?;
    if changed != 1 {
        return Err("grant unavailable");
    }
    let attempt_id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO operation_attempts (id,grant_id,hard_deadline,state,updated_at) VALUES (?1,?2,?3,'started',?4)",
        params![attempt_id,grant_id,deadline.to_rfc3339(),now.to_rfc3339()],
    )
    .map_err(|_| "operation store unavailable")?;
    audit(
        &tx,
        &requester.instance_id,
        binding,
        stored.expires_at,
        "started",
    )?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    Ok(AttemptStatus {
        attempt_id,
        grant_id: grant_id.to_owned(),
        operation: binding.operation.clone(),
        target: binding.target.clone(),
        environment: binding.environment.clone(),
        credential_ref: binding.credential_id.clone(),
        expires_at: stored.expires_at,
        hard_deadline: deadline,
        state: GrantState::Started,
        cancel_requested: false,
        exit_code: None,
    })
}

/// Records the observed terminal result. On persistence failure the grant
/// remains consumed and the executor must report an uncertain outcome.
pub fn finish_attempt(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt_id: &str,
    outcome: GrantState,
    exit_code: Option<i32>,
) -> GrantResult<AttemptStatus> {
    if !outcome.terminal() || Uuid::parse_str(attempt_id).is_err() {
        return Err("invalid terminal result");
    }
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let mut status = load_attempt(&tx, attempt_id)?;
    let stored = load_grant(&tx, &status.grant_id)?;
    if status.state != GrantState::Started
        || stored.requester_instance_id != requester.instance_id
        || stored.instance_generation != requester.generation
        || instance_generation(&tx, &requester.instance_id)? != requester.generation
    {
        return Err("attempt unavailable");
    }
    let (result, safe_exit_code) = terminal_result(status.cancel_requested, outcome, exit_code);
    update_terminal(&tx, &stored, &status, result, safe_exit_code)?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    status.state = result;
    status.exit_code = safe_exit_code;
    Ok(status)
}

fn terminal_result(
    cancel_requested: bool,
    observed: GrantState,
    exit_code: Option<i32>,
) -> (GrantState, Option<i32>) {
    // The transport observes its own hard deadline. A delayed SQLite write
    // cannot turn an already observed success into a verified timeout.
    let result = if cancel_requested
        && matches!(
            observed,
            GrantState::Succeeded | GrantState::DeliveryAcknowledged
        ) {
        GrantState::OutcomeUnknown
    } else {
        observed
    };
    let safe_exit_code = if matches!(result, GrantState::Succeeded | GrantState::FailedChild) {
        exit_code
    } else {
        None
    };
    (result, safe_exit_code)
}

/// Owner-only cancellation of an unconsumed grant.
pub fn cancel_grant(vault: &Vault, grant_id: &str) -> GrantResult<GrantStatus> {
    if Uuid::parse_str(grant_id).is_err() {
        return Err("grant unavailable");
    }
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let stored = load_grant(&tx, grant_id)?;
    if stored.state != GrantState::Pending {
        return Err("grant unavailable");
    }
    tx.execute(
        "UPDATE operation_grants SET state='canceled' WHERE id=?1 AND state='pending'",
        [grant_id],
    )
    .map_err(|_| "operation store unavailable")?;
    audit_stored(&tx, &stored, "canceled")?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    Ok(stored.status(GrantState::Canceled))
}

/// Owner requests cancellation. The executor must observe the flag and stop
/// transport before recording `Canceled` or `OutcomeUnknown` as terminal.
pub fn request_cancel(vault: &Vault, attempt_id: &str) -> GrantResult<AttemptStatus> {
    if Uuid::parse_str(attempt_id).is_err() {
        return Err("attempt unavailable");
    }
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let mut status = load_attempt(&tx, attempt_id)?;
    let stored = load_grant(&tx, &status.grant_id)?;
    if status.state != GrantState::Started {
        return Err("attempt unavailable");
    }
    tx.execute("UPDATE operation_attempts SET cancel_requested=1,updated_at=?1 WHERE id=?2 AND state='started'", params![Utc::now().to_rfc3339(),attempt_id])
        .map_err(|_| "operation store unavailable")?;
    audit_stored(&tx, &stored, "cancel_requested")?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    status.cancel_requested = true;
    Ok(status)
}

/// Owner resolves a stranded attempt after its hard deadline. It remains
/// consumed; no second delivery is attempted.
pub fn reconcile_attempt(vault: &Vault, attempt_id: &str) -> GrantResult<AttemptStatus> {
    if Uuid::parse_str(attempt_id).is_err() {
        return Err("attempt unavailable");
    }
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "operation store unavailable")?;
    let mut status = load_attempt(&tx, attempt_id)?;
    let stored = load_grant(&tx, &status.grant_id)?;
    if status.state != GrantState::Started || Utc::now() < status.hard_deadline {
        return Err("attempt not ready for reconciliation");
    }
    update_terminal(&tx, &stored, &status, GrantState::OutcomeUnknown, None)?;
    tx.commit().map_err(|_| "operation store unavailable")?;
    status.state = GrantState::OutcomeUnknown;
    Ok(status)
}

/// Owner inspection. Agent-facing callers must use `requester_grant_status`.
pub fn owner_grant_status(vault: &Vault, grant_id: &str) -> GrantResult<GrantStatus> {
    Ok(load_grant(vault.db(), grant_id)?.status_from_self())
}

pub fn requester_grant_status(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    grant_id: &str,
) -> GrantResult<GrantStatus> {
    let stored = load_grant(vault.db(), grant_id)?;
    if stored.requester_instance_id != requester.instance_id
        || stored.instance_generation != requester.generation
        || instance_generation(vault.db(), &requester.instance_id)? != requester.generation
    {
        return Err("grant unavailable");
    }
    Ok(stored.status_from_self())
}

pub fn owner_attempt_status(vault: &Vault, attempt_id: &str) -> GrantResult<AttemptStatus> {
    load_attempt(vault.db(), attempt_id)
}

pub fn requester_attempt_status(
    vault: &Vault,
    requester: &AuthenticatedRequester,
    attempt_id: &str,
) -> GrantResult<AttemptStatus> {
    let status = load_attempt(vault.db(), attempt_id)?;
    let stored = load_grant(vault.db(), &status.grant_id)?;
    if stored.requester_instance_id != requester.instance_id
        || stored.instance_generation != requester.generation
        || instance_generation(vault.db(), &requester.instance_id)? != requester.generation
    {
        return Err("attempt unavailable");
    }
    Ok(status)
}

/// Exact eight-field export for owner review; never returns the internal IDs,
/// stored instance generation, encrypted revision, or arbitrary error text.
pub fn owner_audit(vault: &Vault, limit: usize) -> GrantResult<Vec<OperationAudit>> {
    if limit == 0 || limit > 1000 {
        return Err("invalid audit limit");
    }
    let mut statement = vault
        .db()
        .prepare("SELECT timestamp,requester,operation,target,environment,credential_ref,expires_at,result FROM operation_audit ORDER BY rowid DESC LIMIT ?1")
        .map_err(|_| "operation store unavailable")?;
    statement
        .query_map([limit as i64], |row| {
            let timestamp: String = row.get(0)?;
            let expires_at: String = row.get(6)?;
            Ok((
                timestamp,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                expires_at,
                row.get(7)?,
            ))
        })
        .map_err(|_| "operation store unavailable")?
        .map(|row| {
            let (
                timestamp,
                requester,
                operation,
                target,
                environment,
                credential_ref,
                expires_at,
                result,
            ): (
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                String,
                String,
            ) = row.map_err(|_| "operation store unavailable")?;
            Ok(OperationAudit {
                timestamp: parse_date(&timestamp)?,
                requester,
                operation,
                target,
                environment,
                credential_ref,
                expires_at: parse_date(&expires_at)?,
                result,
            })
        })
        .collect()
}

/// Writes a denial without reflecting an untrusted grant identifier or other
/// caller text. Authentication failures use `identity_missing` and fixed
/// unresolved metadata if no known grant can be safely selected.
pub fn record_denial(
    vault: &Vault,
    requester: Option<&AuthenticatedRequester>,
    grant_id: Option<&str>,
) -> GrantResult<()> {
    let stored = grant_id
        .filter(|id| Uuid::parse_str(id).is_ok())
        .and_then(|id| load_grant(vault.db(), id).ok());
    let requester_id = requester.map_or("identity_missing", |auth| auth.instance_id());
    let result = if requester.is_none() {
        "denied_identity"
    } else {
        "denied"
    };
    let now = Utc::now();
    let (operation, target, environment, credential_ref, expires_at) = if let Some(grant) = &stored
    {
        (
            grant.operation.as_str(),
            grant.target.as_str(),
            grant.environment.as_str(),
            Some(grant.credential_ref.as_str()),
            grant.expires_at,
        )
    } else {
        ("unresolved", "unresolved", "unresolved", None, now)
    };
    vault.db().execute(
        "INSERT INTO operation_audit(timestamp,requester,operation,target,environment,credential_ref,expires_at,result) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![now.to_rfc3339(),requester_id,operation,target,environment,credential_ref,expires_at.to_rfc3339(),result],
    ).map_err(|_| "operation audit unavailable")?;
    Ok(())
}

struct StoredGrant {
    id: String,
    operation: String,
    target: String,
    environment: String,
    credential_ref: String,
    project_id: String,
    catalog_revision: String,
    credential_revision: String,
    provider_credential_ref: Option<String>,
    provider_project_id: Option<String>,
    provider_revision: Option<String>,
    old_password_credential_ref: Option<String>,
    old_password_revision: Option<String>,
    requester_instance_id: String,
    instance_generation: String,
    session_issued_at: String,
    expires_at: DateTime<Utc>,
    max_runtime_seconds: u32,
    max_grant_seconds: u32,
    state: GrantState,
}

impl StoredGrant {
    fn status(&self, state: GrantState) -> GrantStatus {
        GrantStatus {
            grant_id: self.id.clone(),
            operation: self.operation.clone(),
            target: self.target.clone(),
            environment: self.environment.clone(),
            credential_ref: self.credential_ref.clone(),
            expires_at: self.expires_at,
            state,
        }
    }

    fn status_from_self(&self) -> GrantStatus {
        self.status(self.state)
    }
}

fn load_grant(db: &Connection, id: &str) -> GrantResult<StoredGrant> {
    let row = db
        .query_row(
            "SELECT id,operation,target,environment,credential_ref,project_id,catalog_revision,credential_revision,provider_credential_ref,provider_project_id,provider_revision,old_password_credential_ref,old_password_revision,requester_instance_id,instance_generation,session_issued_at,expires_at,max_grant_seconds,max_runtime_seconds,state FROM operation_grants WHERE id=?1",
            [id],
            |row| Ok((
                row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,row.get::<_, String>(5)?,row.get::<_, String>(6)?,row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,row.get::<_, Option<String>>(9)?,row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,row.get::<_, String>(14)?,row.get::<_, String>(15)?,row.get::<_, String>(16)?,
                row.get::<_, u32>(17)?,row.get::<_, u32>(18)?,row.get::<_, String>(19)?
            )),
        )
        .map_err(|_| "grant unavailable")?;
    Ok(StoredGrant {
        id: row.0,
        operation: row.1,
        target: row.2,
        environment: row.3,
        credential_ref: row.4,
        project_id: row.5,
        catalog_revision: row.6,
        credential_revision: row.7,
        provider_credential_ref: row.8,
        provider_project_id: row.9,
        provider_revision: row.10,
        old_password_credential_ref: row.11,
        old_password_revision: row.12,
        requester_instance_id: row.13,
        instance_generation: row.14,
        session_issued_at: row.15,
        expires_at: parse_date(&row.16)?,
        max_grant_seconds: row.17,
        max_runtime_seconds: row.18,
        state: GrantState::from_str(&row.19)?,
    })
}

fn load_attempt(db: &Connection, id: &str) -> GrantResult<AttemptStatus> {
    let (grant_id, hard_deadline, state, cancel_requested, exit_code): (String, String, String, bool, Option<i32>) = db
        .query_row(
            "SELECT grant_id,hard_deadline,state,cancel_requested,exit_code FROM operation_attempts WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .map_err(|_| "attempt unavailable")?;
    let grant = load_grant(db, &grant_id)?;
    Ok(AttemptStatus {
        attempt_id: id.to_owned(),
        grant_id,
        operation: grant.operation,
        target: grant.target,
        environment: grant.environment,
        credential_ref: grant.credential_ref,
        expires_at: grant.expires_at,
        hard_deadline: parse_date(&hard_deadline)?,
        state: GrantState::from_str(&state)?,
        cancel_requested,
        exit_code,
    })
}

fn validate_binding(binding: &OperationBinding) -> GrantResult<()> {
    let label = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !label(&binding.operation)
        || !label(&binding.target)
        || !label(&binding.environment)
        || (binding.project_id != "default" && Uuid::parse_str(&binding.project_id).is_err())
        || Uuid::parse_str(&binding.credential_id).is_err()
        || Uuid::parse_str(&binding.requester_instance_id).is_err()
        || binding.catalog_revision.len() != 64
        || !binding
            .catalog_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || !(1..=MAX_GRANT_SECONDS as u32).contains(&binding.max_grant_seconds)
        || !(1..=MAX_RUNTIME_SECONDS as u32).contains(&binding.max_runtime_seconds)
    {
        return Err("invalid operation binding");
    }
    match (
        &binding.provider_project_id,
        &binding.provider_credential_id,
    ) {
        (None, None) => {}
        (Some(project), Some(credential))
            if (project == "default" || Uuid::parse_str(project).is_ok())
                && Uuid::parse_str(credential).is_ok()
                && credential != &binding.credential_id => {}
        _ => return Err("invalid operation binding"),
    }
    if let Some(old_id) = &binding.old_password_credential_id
        && (Uuid::parse_str(old_id).is_err()
            || old_id == &binding.credential_id
            || binding.provider_credential_id.as_ref() == Some(old_id)
            || binding.provider_credential_id.is_none())
    {
        return Err("invalid operation binding");
    }
    Ok(())
}

fn instance_generation(db: &Connection, id: &str) -> GrantResult<String> {
    let (status, secret_hash): (String, String) = db
        .query_row(
            "SELECT status,secret_hash FROM instances WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "requester unavailable")?;
    if status != "active" {
        return Err("requester unavailable");
    }
    Ok(hash_text(&secret_hash))
}

fn credential_revision(db: &Connection, project_id: &str, id: &str) -> GrantResult<String> {
    let (encrypted, updated_at, lifecycle, kind): (String, String, String, String) = db
        .query_row(
            "SELECT c.encrypted_value,c.updated_at,c.lifecycle_state,c.credential_type FROM credentials c JOIN partitions p ON p.id=c.partition_id WHERE c.id=?1 AND p.project_id=?2",
            params![id,project_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        )
        .map_err(|_| "credential unavailable")?;
    if lifecycle == "archived" || kind.contains("website_login") {
        return Err("credential unavailable");
    }
    Ok(hash_text(&format!("{encrypted}\0{updated_at}")))
}

fn update_terminal(
    db: &Connection,
    grant: &StoredGrant,
    attempt: &AttemptStatus,
    outcome: GrantState,
    exit_code: Option<i32>,
) -> GrantResult<()> {
    let changed = db.execute(
        "UPDATE operation_attempts SET state=?1,exit_code=?2,updated_at=?3 WHERE id=?4 AND state='started'",
        params![outcome.as_str(),exit_code,Utc::now().to_rfc3339(),attempt.attempt_id],
    ).map_err(|_| "operation store unavailable")?;
    if changed != 1 {
        return Err("attempt unavailable");
    }
    db.execute(
        "UPDATE operation_grants SET state=?1 WHERE id=?2 AND state='started'",
        params![outcome.as_str(), grant.id],
    )
    .map_err(|_| "operation store unavailable")?;
    audit_stored(db, grant, outcome.as_str())
}

fn audit(
    db: &Connection,
    requester: &str,
    binding: &OperationBinding,
    expires_at: DateTime<Utc>,
    result: &str,
) -> GrantResult<()> {
    db.execute(
        "INSERT INTO operation_audit(timestamp,requester,operation,target,environment,credential_ref,expires_at,result) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![Utc::now().to_rfc3339(),requester,binding.operation,binding.target,binding.environment,binding.credential_id,expires_at.to_rfc3339(),result],
    ).map_err(|_| "operation audit unavailable")?;
    Ok(())
}

fn audit_stored(db: &Connection, stored: &StoredGrant, result: &str) -> GrantResult<()> {
    db.execute(
        "INSERT INTO operation_audit(timestamp,requester,operation,target,environment,credential_ref,expires_at,result) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![Utc::now().to_rfc3339(),stored.requester_instance_id,stored.operation,stored.target,stored.environment,stored.credential_ref,stored.expires_at.to_rfc3339(),result],
    ).map_err(|_| "operation audit unavailable")?;
    Ok(())
}

fn parse_date(value: &str) -> GrantResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .map_err(|_| "operation store unavailable")
}

fn hash_text(value: &str) -> String {
    let value = digest(&SHA256, value.as_bytes());
    value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCE_ID: &str = "00000000-0000-4000-8000-000000000001";
    const CREDENTIAL_ID: &str = "00000000-0000-4000-8000-000000000002";

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE instances(id TEXT PRIMARY KEY,status TEXT NOT NULL,secret_hash TEXT NOT NULL);
            CREATE TABLE partitions(id TEXT PRIMARY KEY,project_id TEXT NOT NULL);
            CREATE TABLE credentials(id TEXT PRIMARY KEY,partition_id TEXT NOT NULL,encrypted_value TEXT NOT NULL,updated_at TEXT NOT NULL,lifecycle_state TEXT NOT NULL,credential_type TEXT NOT NULL);
            INSERT INTO instances VALUES ('00000000-0000-4000-8000-000000000001','active','instance-hash-one');
            INSERT INTO partitions VALUES ('personal','default');
            INSERT INTO credentials VALUES ('00000000-0000-4000-8000-000000000002','personal','synthetic-ciphertext','2099-01-01T00:00:00Z','active','\"api_key\"');").unwrap();
        create_schema(&db).unwrap();
        db
    }

    fn binding() -> OperationBinding {
        OperationBinding {
            operation: "example-operation".into(),
            target: "example-target".into(),
            environment: "example-environment".into(),
            credential_id: CREDENTIAL_ID.into(),
            project_id: "default".into(),
            provider_credential_id: None,
            provider_project_id: None,
            old_password_credential_id: None,
            catalog_revision: "a".repeat(64),
            requester_instance_id: INSTANCE_ID.into(),
            expires_at: Utc::now() + Duration::minutes(5),
            max_grant_seconds: 300,
            max_runtime_seconds: 60,
        }
    }

    fn session() -> SessionLease {
        SessionLease {
            revision: "session-revision".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn requester() -> AuthenticatedRequester {
        AuthenticatedRequester {
            instance_id: INSTANCE_ID.into(),
            generation: hash_text("instance-hash-one"),
        }
    }

    #[test]
    fn one_use_reservation_records_exact_eight_field_audit() {
        let db = db();
        let binding = binding();
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let attempt =
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).unwrap();
        assert_eq!(attempt.state, GrantState::Started);
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM operation_attempts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
        let audit_count: i64 = db
            .query_row("SELECT COUNT(*) FROM operation_audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(audit_count, 2);
        let value: String = db
            .query_row(
                "SELECT credential_ref FROM operation_audit WHERE result='started'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, CREDENTIAL_ID);
        let mut statement = db.prepare("PRAGMA table_info(operation_audit)").unwrap();
        let columns: Vec<String> = statement
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            columns,
            [
                "timestamp",
                "requester",
                "operation",
                "target",
                "environment",
                "credential_ref",
                "expires_at",
                "result"
            ]
        );
    }

    #[test]
    fn expired_changed_and_revoked_bindings_deny() {
        let db = db();
        let binding = binding();
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let mut changed = binding.clone();
        changed.target = "other-target".into();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &changed, &session).is_err()
        );
        let mut changed_session = session.clone();
        changed_session.revision = "other-session".into();
        assert!(
            reserve_with_session(
                &db,
                &requester(),
                &grant.grant_id,
                &binding,
                &changed_session
            )
            .is_err()
        );
        db.execute(
            "UPDATE credentials SET encrypted_value='changed' WHERE id=?1",
            [CREDENTIAL_ID],
        )
        .unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        db.execute(
            "UPDATE credentials SET encrypted_value='synthetic-ciphertext' WHERE id=?1",
            [CREDENTIAL_ID],
        )
        .unwrap();
        db.execute(
            "UPDATE instances SET status='revoked' WHERE id=?1",
            [INSTANCE_ID],
        )
        .unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        db.execute(
            "UPDATE instances SET status='active' WHERE id=?1",
            [INSTANCE_ID],
        )
        .unwrap();
        db.execute(
            "UPDATE operation_grants SET expires_at='2020-01-01T00:00:00Z' WHERE id=?1",
            [&grant.grant_id],
        )
        .unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
    }

    #[test]
    fn wrong_identity_and_audit_failure_leave_grant_unused() {
        let db = db();
        let binding = binding();
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let wrong = AuthenticatedRequester {
            instance_id: Uuid::new_v4().to_string(),
            generation: "wrong".into(),
        };
        assert!(reserve_with_session(&db, &wrong, &grant.grant_id, &binding, &session).is_err());
        db.execute_batch("CREATE TRIGGER fail_operation_audit BEFORE INSERT ON operation_audit BEGIN SELECT RAISE(ABORT,'blocked'); END;").unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        let state: String = db
            .query_row(
                "SELECT state FROM operation_grants WHERE id=?1",
                [&grant.grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "pending");
        let attempts: i64 = db
            .query_row("SELECT COUNT(*) FROM operation_attempts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn cancellation_and_reconciliation_never_restore_one_use() {
        let db = db();
        let binding = binding();
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let attempt =
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).unwrap();
        db.execute(
            "UPDATE operation_attempts SET cancel_requested=1 WHERE id=?1",
            [&attempt.attempt_id],
        )
        .unwrap();
        assert!(validate_live(&db, &requester(), &attempt, &binding, &session).is_err());
        db.execute(
            "UPDATE operation_attempts SET hard_deadline='2020-01-01T00:00:00Z' WHERE id=?1",
            [&attempt.attempt_id],
        )
        .unwrap();
        let current = load_attempt(&db, &attempt.attempt_id).unwrap();
        let stored = load_grant(&db, &grant.grant_id).unwrap();
        let tx = db.unchecked_transaction().unwrap();
        update_terminal(&tx, &stored, &current, GrantState::OutcomeUnknown, None).unwrap();
        tx.commit().unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
    }

    #[test]
    fn provider_reference_and_revision_are_distinct_and_bound() {
        let db = db();
        let provider_id = "00000000-0000-4000-8000-000000000003";
        db.execute("INSERT INTO credentials VALUES (?1,'personal','provider-ciphertext','2099-01-01T00:00:00Z','active','\"api_key\"')", [provider_id]).unwrap();
        let mut binding = binding();
        binding.provider_credential_id = Some(provider_id.into());
        binding.provider_project_id = Some("default".into());
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let stored = load_grant(&db, &grant.grant_id).unwrap();
        assert_eq!(stored.provider_credential_ref.as_deref(), Some(provider_id));
        let mut changed = binding.clone();
        changed.provider_credential_id = Some(Uuid::new_v4().to_string());
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &changed, &session).is_err()
        );
        db.execute(
            "UPDATE credentials SET encrypted_value='rotated-provider' WHERE id=?1",
            [provider_id],
        )
        .unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        binding.provider_credential_id = Some(binding.credential_id.clone());
        assert!(validate_binding(&binding).is_err());
    }

    #[test]
    fn previous_password_is_distinct_and_revision_bound() {
        let db = db();
        let provider_id = "00000000-0000-4000-8000-000000000003";
        let previous_id = "00000000-0000-4000-8000-000000000004";
        for id in [provider_id, previous_id] {
            db.execute("INSERT INTO credentials VALUES (?1,'personal','synthetic-ciphertext','2099-01-01T00:00:00Z','active','\"api_key\"')", [id]).unwrap();
        }
        let mut binding = binding();
        binding.provider_credential_id = Some(provider_id.into());
        binding.provider_project_id = Some("default".into());
        binding.old_password_credential_id = Some(previous_id.into());
        let session = session();
        let grant =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let stored = load_grant(&db, &grant.grant_id).unwrap();
        assert_eq!(
            stored.old_password_credential_ref.as_deref(),
            Some(previous_id)
        );
        assert!(stored.old_password_revision.is_some());
        let mut changed = binding.clone();
        changed.old_password_credential_id = Some(Uuid::new_v4().to_string());
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &changed, &session).is_err()
        );
        db.execute(
            "UPDATE credentials SET encrypted_value='rotated-old' WHERE id=?1",
            [previous_id],
        )
        .unwrap();
        assert!(
            reserve_with_session(&db, &requester(), &grant.grant_id, &binding, &session).is_err()
        );
        binding.old_password_credential_id = Some(provider_id.into());
        assert!(validate_binding(&binding).is_err());
        binding.old_password_credential_id = Some(CREDENTIAL_ID.into());
        assert!(validate_binding(&binding).is_err());
    }

    #[test]
    fn terminal_result_does_not_infer_timeout_from_late_persistence() {
        assert_eq!(
            terminal_result(false, GrantState::Succeeded, Some(0)),
            (GrantState::Succeeded, Some(0))
        );
        assert_eq!(
            terminal_result(true, GrantState::Succeeded, Some(0)),
            (GrantState::OutcomeUnknown, None)
        );
        assert_eq!(
            terminal_result(true, GrantState::DeliveryAcknowledged, None),
            (GrantState::OutcomeUnknown, None)
        );
        for outcome in [
            GrantState::TimedOut,
            GrantState::Canceled,
            GrantState::OutcomeUnknown,
        ] {
            assert_eq!(terminal_result(false, outcome, Some(0)), (outcome, None));
        }
        assert_eq!(
            terminal_result(false, GrantState::FailedChild, Some(42)),
            (GrantState::FailedChild, Some(42))
        );
    }

    #[test]
    fn delivery_revision_is_stable_across_grants_and_changes_with_credential() {
        let db = db();
        let binding = binding();
        let session = session();
        let requester = requester();
        let first =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let second =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let first_attempt =
            reserve_with_session(&db, &requester, &first.grant_id, &binding, &session).unwrap();
        let first_revision =
            delivery_revision_with_session(&db, &requester, &first_attempt, &binding, &session)
                .unwrap();
        assert_eq!(first_revision.len(), 64);
        assert!(first_revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let first_stored = load_grant(&db, &first.grant_id).unwrap();
        update_terminal(
            &db,
            &first_stored,
            &first_attempt,
            GrantState::Succeeded,
            Some(0),
        )
        .unwrap();
        let second_attempt =
            reserve_with_session(&db, &requester, &second.grant_id, &binding, &session).unwrap();
        let second_revision =
            delivery_revision_with_session(&db, &requester, &second_attempt, &binding, &session)
                .unwrap();
        assert_eq!(first_revision, second_revision);
        db.execute(
            "UPDATE credentials SET encrypted_value='rotated-synthetic-ciphertext' WHERE id=?1",
            [CREDENTIAL_ID],
        )
        .unwrap();
        assert!(
            delivery_revision_with_session(&db, &requester, &second_attempt, &binding, &session)
                .is_err()
        );
        let second_stored = load_grant(&db, &second.grant_id).unwrap();
        update_terminal(
            &db,
            &second_stored,
            &second_attempt,
            GrantState::OutcomeUnknown,
            None,
        )
        .unwrap();
        let third =
            issue_with_session(&db, &binding, Utc::now() + Duration::minutes(5), &session).unwrap();
        let third_attempt =
            reserve_with_session(&db, &requester, &third.grant_id, &binding, &session).unwrap();
        let third_revision =
            delivery_revision_with_session(&db, &requester, &third_attempt, &binding, &session)
                .unwrap();
        assert_ne!(first_revision, third_revision);
    }
}
