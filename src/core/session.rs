use std::fs;
use std::path::Path;

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};

use crate::secure_files;

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
        let session_data = format!(
            "{}\n{}\n{}",
            BASE64.encode(key),
            Utc::now().to_rfc3339(),
            timeout
        );
        let session_path = Self::session_path();
        secure_files::write_private(&session_path, session_data.as_bytes())?;
        Ok(())
    }

    pub(super) fn load_session(&mut self) -> Result<()> {
        let session_path = Self::session_path();
        if !session_path.exists() {
            return Err(VaultError::Locked);
        }

        let session_data = fs::read_to_string(&session_path)?;
        let lines: Vec<&str> = session_data.lines().collect();

        let (key_b64, timestamp_str, timeout) = if lines.len() >= 3 {
            let timeout = match lines[2].parse::<i64>() {
                Ok(timeout) => timeout,
                Err(_) => {
                    clear_invalid_session_file(&session_path)?;
                    return Err(VaultError::SessionInvalid);
                }
            };
            (lines[0], lines[1], timeout)
        } else if lines.len() == 1 {
            let parts: Vec<&str> = session_data.splitn(2, ':').collect();
            if parts.len() != 2 {
                clear_invalid_session_file(&session_path)?;
                return Err(VaultError::SessionInvalid);
            }
            (parts[0], parts[1], 30i64)
        } else {
            clear_invalid_session_file(&session_path)?;
            return Err(VaultError::SessionInvalid);
        };

        let timestamp = match DateTime::parse_from_rfc3339(timestamp_str) {
            Ok(timestamp) => timestamp,
            Err(_) => {
                clear_invalid_session_file(&session_path)?;
                return Err(VaultError::SessionInvalid);
            }
        };

        let age = Utc::now() - timestamp.with_timezone(&Utc);
        if timeout > 0 && age.num_minutes() > timeout {
            clear_invalid_session_file(&session_path)?;
            return Err(VaultError::SessionInvalid);
        }

        let key_bytes = match BASE64.decode(key_b64) {
            Ok(key_bytes) => key_bytes,
            Err(_) => {
                clear_invalid_session_file(&session_path)?;
                return Err(VaultError::SessionInvalid);
            }
        };
        if key_bytes.len() != 32 {
            clear_invalid_session_file(&session_path)?;
            return Err(VaultError::SessionInvalid);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        self.master_key = Some(key);
        Ok(())
    }
}

fn clear_invalid_session_file(session_path: &Path) -> Result<()> {
    match fs::remove_file(session_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VaultError::Io(error)),
    }
}
