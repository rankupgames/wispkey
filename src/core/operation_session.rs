//! Binding for grants that must die with the current unlocked vault session.

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ring::hmac;

use super::session_store::{SessionStore, session_store};
use super::{Result, Vault, VaultError};

const REVISION_DOMAIN: &[u8] = b"wispkey-operation-session-v1\0";
pub(super) const OWNER_CONFIRMATION_FAILED: &str = "operation owner confirmation failed";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationSessionBinding {
    pub(crate) revision: String,
    pub(crate) expires_at: DateTime<Utc>,
}

pub(super) struct OwnerPasswordConfirmation {
    password_hash: String,
    session: OperationSessionBinding,
}

impl Vault {
    /// Runs an owner-reviewed write while the current session is pinned. Database
    /// and session lock ordering matches guarded whole-value replacement.
    pub(crate) fn with_current_operation_session<T>(
        &self,
        revision: &str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let store = session_store();
        let _guard = store.lock()?;
        let binding = self.operation_session_binding_from_record(store.load_locked()?)?;
        if binding.revision != revision {
            return Err(VaultError::AuthRejected(
                "owner session changed after import review",
            ));
        }
        let result = action()?;
        if self.operation_session_binding_from_record(store.load_locked()?)? != binding {
            return Err(VaultError::AuthRejected(
                "owner session changed during import",
            ));
        }
        transaction.commit()?;
        Ok(result)
    }

    /// Binds an operation grant to the authenticated session file currently on
    /// disk. An in-memory master key by itself is insufficient: lock or session
    /// replacement in another process must invalidate an outstanding grant.
    pub(crate) fn operation_session_binding(&self) -> Result<OperationSessionBinding> {
        self.operation_session_binding_from_record(session_store().load()?)
    }

    pub(super) fn operation_session_binding_from_record(
        &self,
        record: super::session_store::SessionRecord,
    ) -> Result<OperationSessionBinding> {
        super::session::validate_session_key(self, &record)?;
        binding_from_record(
            &record.key,
            record.issued_at,
            record.timeout_minutes,
            Utc::now(),
        )
    }

    /// Checks a fresh owner password without renewing or replacing the session.
    /// The caller must obtain the password interactively, never from a CLI
    /// argument, environment variable, or password file.
    pub(crate) fn verify_operation_owner_password(
        &self,
        password: &str,
    ) -> std::result::Result<(), &'static str> {
        self.confirm_operation_owner_password(password).map(|_| ())
    }

    /// Verifies the expensive password proof before a caller reserves a writer.
    /// The caller must revalidate it under its database and session locks.
    pub(super) fn confirm_operation_owner_password(
        &self,
        password: &str,
    ) -> std::result::Result<OwnerPasswordConfirmation, &'static str> {
        let session = self
            .operation_session_binding()
            .map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        let stored_hash: String = self
            .db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'password_hash'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        let parsed =
            argon2::PasswordHash::new(&stored_hash).map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        let params =
            argon2::Params::new(65536, 3, 4, Some(32)).map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        Ok(OwnerPasswordConfirmation {
            password_hash: stored_hash,
            session,
        })
    }

    /// Requires the caller's writer reservation and already-held session lock.
    pub(super) fn revalidate_owner_password_confirmation(
        &self,
        proof: &OwnerPasswordConfirmation,
        record: super::session_store::SessionRecord,
    ) -> std::result::Result<(), &'static str> {
        let current_hash: String = self
            .db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'password_hash'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        let session = self
            .operation_session_binding_from_record(record)
            .map_err(|_| OWNER_CONFIRMATION_FAILED)?;
        if current_hash != proof.password_hash || session != proof.session {
            return Err(OWNER_CONFIRMATION_FAILED);
        }
        Ok(())
    }
}

fn binding_from_record(
    key: &[u8; 32],
    issued_at: DateTime<Utc>,
    timeout_minutes: i64,
    now: DateTime<Utc>,
) -> Result<OperationSessionBinding> {
    // Existing vault sessions may be unbounded (timeout 0), but one cannot
    // authorize a finite operation grant. This leaves normal sessions alone.
    if timeout_minutes <= 0 {
        return Err(VaultError::SessionInvalid);
    }
    let expires_at = Duration::try_minutes(timeout_minutes)
        .and_then(|duration| issued_at.checked_add_signed(duration))
        .ok_or(VaultError::SessionInvalid)?;
    if now >= expires_at {
        return Err(VaultError::SessionExpired);
    }

    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    context.update(REVISION_DOMAIN);
    context.update(
        issued_at
            .to_rfc3339_opts(SecondsFormat::Nanos, true)
            .as_bytes(),
    );
    context.update(&timeout_minutes.to_be_bytes());
    let revision = base64::engine::general_purpose::STANDARD_NO_PAD.encode(context.sign().as_ref());
    Ok(OperationSessionBinding {
        revision,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_confirmation_rejects_changed_hash_and_session() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "core::operation_session::tests::owner_confirmation_fixture_child",
                "--ignored",
            ])
            .env("WISPKEY_VAULT_PATH", dir.path())
            .env("WISPKEY_SESSION_TIMEOUT", "30")
            .env("WISPKEY_OWNER_CONFIRMATION_FIXTURE", "1")
            .env_remove("WISPKEY_PROJECT")
            .env_remove("WISPKEY_SESSION_PLAINTEXT")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owner confirmation fixture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[test]
    #[ignore = "isolated finite-session owner confirmation fixture"]
    fn owner_confirmation_fixture_child() {
        assert_eq!(
            std::env::var("WISPKEY_OWNER_CONFIRMATION_FIXTURE").as_deref(),
            Ok("1")
        );
        let password = "synthetic-owner-confirmation";
        let mut vault = Vault::init(password).unwrap();
        let proof = vault.confirm_operation_owner_password(password).unwrap();
        let revalidate = |vault: &Vault| {
            let transaction = rusqlite::Transaction::new_unchecked(
                vault.db(),
                rusqlite::TransactionBehavior::Immediate,
            )
            .unwrap();
            let store = session_store();
            let _guard = store.lock().unwrap();
            let result =
                vault.revalidate_owner_password_confirmation(&proof, store.load_locked().unwrap());
            transaction.commit().unwrap();
            result
        };
        assert_eq!(revalidate(&vault), Ok(()));
        assert_eq!(
            vault
                .db()
                .execute(
                    "UPDATE vault_meta SET value=value || '-changed' WHERE key='password_hash'",
                    []
                )
                .unwrap(),
            1
        );
        assert_eq!(revalidate(&vault), Err(OWNER_CONFIRMATION_FAILED));
        assert_eq!(
            vault
                .db()
                .execute(
                    "UPDATE vault_meta SET value=?1 WHERE key='password_hash'",
                    [&proof.password_hash]
                )
                .unwrap(),
            1
        );
        assert_eq!(revalidate(&vault), Ok(()));
        vault.unlock_with_timeout(password, Some(30)).unwrap();
        assert_eq!(revalidate(&vault), Err(OWNER_CONFIRMATION_FAILED));
        assert!(vault.confirm_operation_owner_password(password).is_ok());
    }

    #[test]
    fn finite_session_revision_changes_on_renewal_and_timeout() {
        let key = [9u8; 32];
        let issued_at = "2026-01-01T00:00:00Z".parse().unwrap();
        let now = "2026-01-01T00:00:30Z".parse().unwrap();
        let first = binding_from_record(&key, issued_at, 30, now).unwrap();
        assert_eq!(
            first.expires_at,
            "2026-01-01T00:30:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            first,
            binding_from_record(&key, issued_at, 30, now).unwrap()
        );
        assert_ne!(
            first.revision,
            binding_from_record(&key, issued_at + Duration::seconds(1), 30, now)
                .unwrap()
                .revision
        );
        assert_ne!(
            first.revision,
            binding_from_record(&key, issued_at, 60, now)
                .unwrap()
                .revision
        );
        assert!(binding_from_record(&key, issued_at, 0, now).is_err());
        assert!(binding_from_record(&key, issued_at, 30, first.expires_at).is_err());
    }
}
