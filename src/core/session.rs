use argon2::{Argon2, PasswordVerifier};
use chrono::{DateTime, Utc};

use crate::audit;

use super::protector::{self, ProtectorBackend, ProtectorStatus};
use super::session_store::{SessionStore, session_store, validate_timeout_minutes};
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
        if let Some(timeout_minutes) = timeout_minutes {
            validate_timeout_minutes(timeout_minutes)?;
        }
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

    /// Reloads a valid session and optionally refreshes its timeout.
    pub fn restore_or_refresh_session(&mut self, timeout_minutes: Option<i64>) -> Result<()> {
        self.load_session()?;
        if let Some(timeout_minutes) = timeout_minutes {
            validate_timeout_minutes(timeout_minutes)?;
            self.session_timeout_override = Some(timeout_minutes);
            self.write_session()?;
        }
        Ok(())
    }

    /// Restores an unlocked session from a remembered OS or file protector.
    pub fn unlock_from_protector(
        &mut self,
        timeout_minutes: Option<i64>,
    ) -> Result<ProtectorBackend> {
        if let Some(timeout_minutes) = timeout_minutes {
            validate_timeout_minutes(timeout_minutes)?;
        }
        let record = protector::load_protector()?;
        self.master_key = Some(record.key);
        self.session_timeout_override = timeout_minutes;
        self.write_session()?;
        tracing::info!("Vault unlocked from {} protector", record.backend.label());
        Ok(record.backend)
    }

    /// Stores the derived vault key in the preferred session protector. Never stores the password.
    pub fn remember_protector(&self, timeout_minutes: Option<i64>) -> Result<ProtectorBackend> {
        let key = self.ensure_unlocked()?;
        let timeout = match timeout_minutes {
            Some(timeout) => validate_timeout_minutes(timeout)?,
            None => protector::default_protector_timeout_minutes(),
        };
        protector::save_protector(key, timeout)
    }

    /// Deletes the local unlocked session file without touching a remembered protector.
    pub fn lock_session() -> Result<()> {
        session_store().clear()
    }

    /// Deletes any remembered OS or file protector.
    pub fn forget_protector() -> Result<()> {
        protector::clear_protector()
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
        let record = match store.load() {
            Ok(record) => record,
            Err(VaultError::SessionExpired) => {
                audit::log_event(
                    &self.db,
                    "SessionExpired",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    true,
                    Some("session_expired"),
                    None,
                );
                return Err(VaultError::SessionExpired);
            }
            Err(error) => return Err(error),
        };
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

    /// Clears the on-disk session and drops the in-memory master key.
    pub fn lock(&mut self) -> Result<()> {
        session_store().clear()?;
        self.master_key = None;
        Ok(())
    }

    /// Issued-at and timeout for the current session file, if it is still valid.
    pub fn session_metadata() -> Result<(DateTime<Utc>, i64)> {
        let record = session_store().load()?;
        Ok((record.issued_at, record.timeout_minutes))
    }

    /// Status of a remembered OS or file protector, if any.
    #[must_use]
    pub fn protector_status() -> ProtectorStatus {
        protector::protector_status()
    }

    /// Default remembered-protector lifetime in minutes (`WISPKEY_PROTECTOR_TIMEOUT`, else 480).
    #[must_use]
    pub fn protector_timeout_minutes() -> i64 {
        protector::default_protector_timeout_minutes()
    }
}
