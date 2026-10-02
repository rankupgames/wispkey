//! An owner-held, connection-bound update ticket. No plaintext or exportable revision.
use base64::Engine;
use chrono::Utc;
use rusqlite::{Transaction, TransactionBehavior, params};

use super::operation_session::OperationSessionBinding;
use super::session_store::session_store;
use super::{Credential, CredentialType, Result, Vault, VaultError};

pub const MAX_REPLACEMENT_VALUE_BYTES: usize = 1024 * 1024;

fn rejected(message: &'static str) -> VaultError {
    VaultError::AuthRejected(message)
}

/// Prepared before reading owner input; consumed exactly once on the same connection.
/// Any intervening database write invalidates this ticket, including an ABA change.
/// This deliberately errs on the side of retrying after unrelated vault activity.
pub struct PreparedValueUpdate<'a> {
    vault: &'a Vault,
    credential: Credential,
    project: String,
    data_version: i64,
    total_changes: u64,
    session: OperationSessionBinding,
}

impl Vault {
    pub fn prepare_value_update(
        &self,
        project: &str,
        partition: &str,
        name: &str,
    ) -> Result<PreparedValueUpdate<'_>> {
        if project.is_empty() || partition.is_empty() || name.is_empty() {
            return Err(rejected(
                "explicit credential, project and partition are required",
            ));
        }
        // Match other operation checks: database before session; hold neither over input.
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let store = session_store();
        let _session_guard = store.lock()?;
        let session = self.operation_session_binding_from_record(store.load_locked()?)?;
        let credential = self.get_credential_in_project(project, name)?;
        let partition_id = self.resolve_partition_id_for_insert(Some(partition), Some(project))?;
        if credential.partition_id.as_deref() != Some(&partition_id) {
            return Err(rejected("credential is not in the selected partition"));
        }
        if credential.credential_type == CredentialType::WebsiteLogin {
            return Err(rejected("website_login requires a structured login editor"));
        }
        if credential.lifecycle_state != super::LIFECYCLE_ACTIVE {
            return Err(rejected("credential is not active"));
        }
        self.ensure_auth_usable(&credential.id, false, None)?;
        let data_version = self
            .db
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let total_changes = self.db.total_changes();
        tx.commit()?;
        Ok(PreparedValueUpdate {
            vault: self,
            credential,
            project: project.to_owned(),
            data_version,
            total_changes,
            session,
        })
    }
}

impl PreparedValueUpdate<'_> {
    /// Replaces the entire opaque value, never a guessed password/JSON field.
    /// Only ciphertext and updated_at change; audit failure rolls both back.
    pub fn commit(self, value: &str) -> Result<()> {
        validate_value(&self.credential.credential_type, value)?;
        let vault = self.vault;
        let tx = Transaction::new_unchecked(&vault.db, TransactionBehavior::Immediate)?;
        let store = session_store();
        let _session_guard = store.lock()?;
        let current_version: i64 = vault
            .db
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        if current_version != self.data_version || vault.db.total_changes() != self.total_changes {
            return Err(rejected(
                "vault changed while reading input; retry replacement",
            ));
        }
        if vault.operation_session_binding_from_record(store.load_locked()?)? != self.session {
            return Err(rejected(
                "owner session changed while reading input; retry replacement",
            ));
        }
        vault.ensure_auth_usable(&self.credential.id, false, None)?;
        let key = vault.ensure_unlocked()?;
        let ciphertext = vault.encrypt_bytes(key, value.as_bytes())?;
        let prefix = if vault.auth_metadata_for_id(&self.credential.id)?.is_some() {
            super::auth::CIPHERTEXT_PREFIX
        } else {
            ""
        };
        let encoded = format!("{prefix}{}", super::BASE64.encode(ciphertext));
        let changed = vault.db.execute(
            "UPDATE credentials SET encrypted_value=?1, updated_at=?2 WHERE id=?3",
            params![encoded, Utc::now().to_rfc3339(), self.credential.id],
        )?;
        if changed != 1 {
            return Err(rejected(
                "credential changed while reading input; retry replacement",
            ));
        }
        crate::audit::try_log_event(
            &vault.db,
            "CredentialValueReplaced",
            Some(&self.credential.name),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(&self.project),
        )?;
        // Deadlines may expire while encryption/audit runs; recheck before commit.
        vault.ensure_auth_usable(&self.credential.id, false, None)?;
        if vault.operation_session_binding_from_record(store.load_locked()?)? != self.session {
            return Err(rejected(
                "owner session changed while reading input; retry replacement",
            ));
        }
        tx.commit()?;
        Ok(())
    }
}

fn validate_value(kind: &CredentialType, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_REPLACEMENT_VALUE_BYTES || value.contains('\0') {
        return Err(rejected(
            "replacement must contain 1 to 1048576 UTF-8 bytes without NUL",
        ));
    }
    match kind {
        CredentialType::WebsiteLogin => {
            Err(rejected("website_login requires a structured login editor"))
        }
        CredentialType::BasicAuth
            if !value
                .split_once(':')
                .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty()) =>
        {
            Err(rejected(
                "basic_auth replacement requires a complete username:password value",
            ))
        }
        CredentialType::BearerToken
        | CredentialType::BasicAuth
        | CredentialType::CustomHeader { .. }
            if value.contains(['\r', '\n']) =>
        {
            Err(rejected(
                "header credential replacement cannot contain line breaks",
            ))
        }
        _ => Ok(()),
    }
}
