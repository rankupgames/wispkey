use argon2::{Argon2, PasswordVerifier};
use chrono::Utc;

use super::session_store::{SessionStore, session_store};
use super::{Result, Vault, VaultError};

impl Vault {
    /// Unlocks with the master password using the default session timeout from env.
    #[allow(dead_code)]
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.unlock_with_timeout(password, None)
    }

    /// Unlocks with the master password and optional per-call session timeout override (minutes).
    pub fn unlock_with_timeout(
        &mut self,
        password: &str,
        timeout_minutes: Option<i64>,
    ) -> Result<()> {
        let stored_hash: String = self.db.query_row(
            "SELECT value FROM vault_meta WHERE key = 'password_hash'",
            [],
            |row| row.get(0),
        )?;

        let parsed_hash = argon2::PasswordHash::new(&stored_hash)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
        );
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| VaultError::InvalidPassword)?;

        let salt = parsed_hash
            .salt
            .ok_or_else(|| VaultError::Encryption("missing salt in hash".into()))?
            .to_string();
        self.master_key = Some(Self::derive_key(password, &salt));
        self.session_timeout_override = timeout_minutes;
        self.write_session()?;

        tracing::info!("Vault unlocked");
        Ok(())
    }

    /// Whether the derived master key is currently loaded in memory.
    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub(super) fn ensure_unlocked(&self) -> Result<&[u8; 32]> {
        self.master_key.as_ref().ok_or(VaultError::Locked)
    }

    pub(crate) fn derive_key(password: &str, salt_str: &str) -> [u8; 32] {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
        );
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt_str.as_bytes(), &mut key)
            .expect("key derivation failed");
        key
    }

    /// Default session lifetime in minutes (`WISPKEY_SESSION_TIMEOUT`, else 30).
    #[must_use]
    pub fn session_timeout_minutes() -> i64 {
        std::env::var("WISPKEY_SESSION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30)
    }

    pub(super) fn write_session(&self) -> Result<()> {
        let key = self.ensure_unlocked()?;
        let timeout = self
            .session_timeout_override
            .unwrap_or_else(Self::session_timeout_minutes);
        session_store().save(key, Utc::now(), timeout)?;
        Ok(())
    }

    pub(super) fn load_session(&mut self) -> Result<()> {
        let store = session_store();
        let record = store.load()?;
        self.master_key = Some(record.key);
        if store.should_upgrade(&record) {
            store.save(&record.key, record.issued_at, record.timeout_minutes)?;
        }
        Ok(())
    }

    /// Reports the configured session-at-rest protection backend.
    #[must_use]
    pub fn session_protection_label() -> &'static str {
        session_store().protection_label()
    }
}
