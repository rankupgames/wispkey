//! Binding for grants that must die with the current unlocked vault session.

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ring::hmac;

use super::session_store::{SessionStore, session_store};
use super::{Result, Vault, VaultError};

const REVISION_DOMAIN: &[u8] = b"wispkey-operation-session-v1\0";
const KEY_CHECK_DOMAIN: &[u8] = b"wispkey-operation-session-key-check-v1";
const OWNER_CONFIRMATION_FAILED: &str = "operation owner confirmation failed";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationSessionBinding {
    pub(crate) revision: String,
    pub(crate) expires_at: DateTime<Utc>,
}

impl Vault {
    /// Binds an operation grant to the authenticated session file currently on
    /// disk. An in-memory master key by itself is insufficient: lock or session
    /// replacement in another process must invalidate an outstanding grant.
    pub(crate) fn operation_session_binding(&self) -> Result<OperationSessionBinding> {
        let loaded_key = self.ensure_unlocked()?;
        let record = session_store().load()?;
        let expected = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, loaded_key),
            KEY_CHECK_DOMAIN,
        );
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &record.key),
            KEY_CHECK_DOMAIN,
            expected.as_ref(),
        )
        .map_err(|_| VaultError::SessionInvalid)?;
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
        self.operation_session_binding()
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
            .map_err(|_| OWNER_CONFIRMATION_FAILED)
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
