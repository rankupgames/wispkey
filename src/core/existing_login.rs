//! Owner-supplied website logins; never generate, reveal, infer or upsert a password.
use base64::Engine;
use chrono::Utc;
use rusqlite::{Transaction, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use super::operation_session::OperationSessionBinding;
use super::session_store::session_store;
use super::{AddCredentialRequest, Credential, CredentialType, Result, Vault, VaultError};

pub const MAX_EXISTING_LOGIN_INPUT_BYTES: usize = 128 * 1024;
const MAX_USERNAME_BYTES: usize = 1024;
const MAX_PASSWORD_BYTES: usize = 16384;
fn rejected(message: &'static str) -> VaultError {
    VaultError::AuthRejected(message)
}
fn deserialize_secret<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn serialize_secret<S: Serializer>(
    value: &Zeroizing<String>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(value)
}

/// Strict input-only schema. No Debug, getters or plaintext command output.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingLoginInput {
    #[serde(
        deserialize_with = "deserialize_secret",
        serialize_with = "serialize_secret"
    )]
    username: Zeroizing<String>,
    #[serde(
        deserialize_with = "deserialize_secret",
        serialize_with = "serialize_secret"
    )]
    password: Zeroizing<String>,
}
impl ExistingLoginInput {
    pub fn new(username: String, password: String) -> Result<Self> {
        let input = Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        };
        input.validate()?;
        Ok(input)
    }
    fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty()
            || self.username.len() > MAX_USERNAME_BYTES
            || self.password.is_empty()
            || self.password.len() > MAX_PASSWORD_BYTES
            || self.username.chars().any(char::is_control)
            || self.password.chars().any(char::is_control)
        {
            return Err(rejected(
                "invalid login fields: require nonempty bounded strings without control characters",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExistingLoginMode {
    Create,
    Update,
}

/// Connection-bound, single-use ticket captured before owner input, with no secret payload.
pub struct PreparedExistingLogin<'a> {
    vault: &'a Vault,
    project: String,
    partition: String,
    name: String,
    origin: String,
    credential: Option<Credential>,
    data_version: i64,
    total_changes: u64,
    session: OperationSessionBinding,
}
impl Vault {
    pub fn prepare_existing_login(
        &self,
        project: &str,
        partition: &str,
        name: &str,
        origin: &str,
        mode: ExistingLoginMode,
    ) -> Result<PreparedExistingLogin<'_>> {
        if [project, partition, name]
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > 96 || v.chars().any(char::is_control))
            || origin.len() > 300
            || super::parse_https_origin(origin).ok().as_deref() != Some(origin)
        {
            return Err(rejected(
                "explicit bounded scope and exact HTTPS origin required",
            ));
        }
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let store = session_store();
        let _session_guard = store.lock()?;
        let session = self.operation_session_binding_from_record(store.load_locked()?)?;
        let partition_id = self.resolve_partition_id_for_insert(Some(partition), Some(project))?;
        let credential = if mode == ExistingLoginMode::Create {
            let exists: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM credentials c JOIN partitions p ON c.partition_id=p.id JOIN projects pr ON p.project_id=pr.id WHERE pr.name=?1 AND c.name=?2)", params![project, name], |r| r.get(0))?;
            if exists {
                return Err(rejected("credential already exists in selected project"));
            }
            None
        } else {
            let credential = self.get_credential_in_project(project, name)?;
            if credential.partition_id.as_deref() != Some(&partition_id)
                || credential.credential_type != CredentialType::WebsiteLogin
                || credential.origin != origin
                || ![super::LIFECYCLE_ACTIVE, super::LIFECYCLE_PENDING]
                    .contains(&credential.lifecycle_state.as_str())
            {
                return Err(rejected(
                    "login type, scope, origin or lifecycle does not match",
                ));
            }
            self.ensure_auth_usable(&credential.id, false, Some(origin))?;
            // Refuse unknown stored fields instead of silently dropping an extended/future schema.
            let old = Zeroizing::new(self.decrypt_credential_value_in_project(project, name)?);
            if old.len() > MAX_EXISTING_LOGIN_INPUT_BYTES {
                return Err(rejected("stored login schema unavailable"));
            }
            let parsed: ExistingLoginInput = serde_json::from_str(&old)
                .map_err(|_| rejected("stored login schema unavailable"))?;
            parsed.validate()?;
            Some(credential)
        };
        let data_version = self
            .db
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let total_changes = self.db.total_changes();
        tx.commit()?;
        Ok(PreparedExistingLogin {
            vault: self,
            project: project.into(),
            partition: partition.into(),
            name: name.into(),
            origin: origin.into(),
            credential,
            data_version,
            total_changes,
            session,
        })
    }
}
impl PreparedExistingLogin<'_> {
    pub fn commit(self, input: &ExistingLoginInput) -> Result<()> {
        input.validate()?;
        let value = Zeroizing::new(
            serde_json::to_string(input).map_err(|_| rejected("invalid login input"))?,
        );
        let vault = self.vault;
        let tx = Transaction::new_unchecked(&vault.db, TransactionBehavior::Immediate)?;
        let store = session_store();
        let _session_guard = store.lock()?;
        let version: i64 = vault
            .db
            .query_row("PRAGMA data_version", [], |r| r.get(0))?;
        if version != self.data_version || vault.db.total_changes() != self.total_changes {
            return Err(rejected(
                "vault changed while reading login input; start again",
            ));
        }
        if vault.operation_session_binding_from_record(store.load_locked()?)? != self.session {
            return Err(rejected(
                "owner session changed while reading login input; start again",
            ));
        }
        let event = if let Some(credential) = &self.credential {
            vault.ensure_auth_usable(&credential.id, false, Some(&self.origin))?;
            let ciphertext = vault.encrypt_bytes(vault.ensure_unlocked()?, value.as_bytes())?;
            let prefix = if vault.auth_metadata_for_id(&credential.id)?.is_some() {
                super::auth::CIPHERTEXT_PREFIX
            } else {
                ""
            };
            let encoded = format!("{prefix}{}", super::BASE64.encode(ciphertext));
            if vault.db.execute(
                "UPDATE credentials SET encrypted_value=?1, updated_at=?2 WHERE id=?3",
                params![encoded, Utc::now().to_rfc3339(), credential.id],
            )? != 1
            {
                return Err(rejected("login changed while reading input"));
            }
            "WebsiteLoginUpdated"
        } else {
            vault.insert_transport_credential(AddCredentialRequest {
                name: &self.name,
                credential_type: CredentialType::WebsiteLogin,
                value: &value,
                description: None,
                hosts: Some(&super::origin_host(&self.origin)),
                tags: None,
                partition: Some(&self.partition),
                project: Some(&self.project),
                origin: Some(&self.origin),
                lifecycle_state: Some(super::LIFECYCLE_PENDING),
                review_at: None,
            })?;
            "WebsiteLoginStored"
        };
        crate::audit::try_log_event(
            &vault.db,
            event,
            Some(&self.name),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(&self.project),
        )?;
        if let Some(credential) = &self.credential {
            vault.ensure_auth_usable(&credential.id, false, Some(&self.origin))?;
        }
        if vault.operation_session_binding_from_record(store.load_locked()?)? != self.session {
            return Err(rejected(
                "owner session changed while reading login input; start again",
            ));
        }
        tx.commit()?;
        Ok(())
    }
}
