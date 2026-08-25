use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
#[cfg(any(target_os = "macos", windows))]
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::secure_files;

use super::session_store::{is_timeout_expired, session_store, validate_timeout_minutes};
use super::{Result, Vault, VaultError};

const PROTECTOR_FILE_NAME: &str = "session-protector";
const PROTECTOR_FILE_HEADER: &str = "v1:protector";
const PROTECTOR_ENV: &str = "WISPKEY_PROTECTOR";
const PROTECTOR_TIMEOUT_ENV: &str = "WISPKEY_PROTECTOR_TIMEOUT";
const DEFAULT_PROTECTOR_TIMEOUT_MINUTES: i64 = 480;
#[cfg(any(target_os = "macos", windows))]
const KEYRING_SERVICE: &str = "wispkey.session-protector";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectorBackend {
    Os,
    File,
}

impl ProtectorBackend {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectorPreference {
    Auto,
    Os,
    File,
}

impl ProtectorPreference {
    fn from_env() -> Self {
        match std::env::var(PROTECTOR_ENV).as_deref() {
            Ok("os") => Self::Os,
            Ok("file") => Self::File,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectorRecord {
    pub key: [u8; 32],
    pub issued_at: DateTime<Utc>,
    pub timeout_minutes: i64,
    pub backend: ProtectorBackend,
}

#[derive(Debug, Clone)]
pub struct ProtectorStatus {
    pub available: bool,
    pub backend: Option<ProtectorBackend>,
    pub expires_at: Option<DateTime<Utc>>,
    pub timeout_minutes: Option<i64>,
    pub preference: &'static str,
}

#[derive(Serialize, Deserialize)]
struct ProtectorPayload {
    key: String,
    issued_at: String,
    timeout_minutes: i64,
}

pub(super) fn default_protector_timeout_minutes() -> i64 {
    std::env::var(PROTECTOR_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value >= 0)
        .unwrap_or(DEFAULT_PROTECTOR_TIMEOUT_MINUTES)
}

pub(super) fn preference_label() -> &'static str {
    match ProtectorPreference::from_env() {
        ProtectorPreference::Auto => "auto",
        ProtectorPreference::Os => "os",
        ProtectorPreference::File => "file",
    }
}

pub(super) fn save_protector(key: &[u8; 32], timeout_minutes: i64) -> Result<ProtectorBackend> {
    let timeout_minutes = validate_timeout_minutes(timeout_minutes)?;
    let payload = encode_payload(key, Utc::now(), timeout_minutes)?;
    match ProtectorPreference::from_env() {
        ProtectorPreference::File => {
            save_file_protector(&payload)?;
            clear_os_protector();
            Ok(ProtectorBackend::File)
        }
        ProtectorPreference::Os => match save_os_protector(&payload) {
            Ok(()) => {
                clear_file_protector()?;
                Ok(ProtectorBackend::Os)
            }
            Err(error) => Err(VaultError::ProtectorUnavailableOs(format!(
                "OS session protector is unavailable ({error}). Recovery: unset {PROTECTOR_ENV} or set {PROTECTOR_ENV}=file for a machine-bound local protector, or unlock with --password-file."
            ))),
        },
        ProtectorPreference::Auto => match save_os_protector(&payload) {
            Ok(()) => {
                clear_file_protector()?;
                Ok(ProtectorBackend::Os)
            }
            Err(error) => {
                tracing::info!(
                    "OS session protector unavailable ({error}); writing machine-bound file protector"
                );
                save_file_protector(&payload)?;
                Ok(ProtectorBackend::File)
            }
        },
    }
}

pub(super) fn load_protector() -> Result<ProtectorRecord> {
    match ProtectorPreference::from_env() {
        ProtectorPreference::File => load_file_protector(),
        ProtectorPreference::Os => load_os_protector().map_err(|error| match error {
            VaultError::ProtectorUnavailable | VaultError::ProtectorExpired => error,
            other => VaultError::ProtectorUnavailableOs(format!(
                "OS session protector is unavailable ({other}). Recovery: unset {PROTECTOR_ENV} or set {PROTECTOR_ENV}=file for a machine-bound local protector, or unlock with --password-file."
            )),
        }),
        ProtectorPreference::Auto => match load_os_protector() {
            Ok(record) => Ok(record),
            Err(VaultError::ProtectorExpired) => Err(VaultError::ProtectorExpired),
            Err(_) => load_file_protector(),
        },
    }
}

pub(super) fn clear_protector() -> Result<()> {
    clear_file_protector()?;
    clear_os_protector();
    Ok(())
}

pub(super) fn protector_status() -> ProtectorStatus {
    match load_protector() {
        Ok(record) => ProtectorStatus {
            available: true,
            backend: Some(record.backend),
            expires_at: expiry_timestamp(record.issued_at, record.timeout_minutes),
            timeout_minutes: Some(record.timeout_minutes),
            preference: preference_label(),
        },
        Err(_) => ProtectorStatus {
            available: false,
            backend: None,
            expires_at: None,
            timeout_minutes: None,
            preference: preference_label(),
        },
    }
}

fn encode_payload(
    key: &[u8; 32],
    issued_at: DateTime<Utc>,
    timeout_minutes: i64,
) -> Result<String> {
    let payload = ProtectorPayload {
        key: BASE64.encode(key),
        issued_at: issued_at.to_rfc3339(),
        timeout_minutes,
    };
    serde_json::to_string(&payload).map_err(|error| VaultError::Encryption(error.to_string()))
}

fn decode_payload(raw: &str, backend: ProtectorBackend) -> Result<ProtectorRecord> {
    let payload: ProtectorPayload =
        serde_json::from_str(raw).map_err(|_| VaultError::ProtectorUnavailable)?;
    let issued_at = DateTime::parse_from_rfc3339(&payload.issued_at)
        .map_err(|_| VaultError::ProtectorUnavailable)?
        .with_timezone(&Utc);
    if is_timeout_expired(issued_at, payload.timeout_minutes) {
        return Err(VaultError::ProtectorExpired);
    }
    let key_bytes = BASE64
        .decode(payload.key)
        .map_err(|_| VaultError::ProtectorUnavailable)?;
    if key_bytes.len() != 32 {
        return Err(VaultError::ProtectorUnavailable);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(ProtectorRecord {
        key,
        issued_at,
        timeout_minutes: payload.timeout_minutes,
        backend,
    })
}

fn protector_file_path() -> PathBuf {
    Vault::vault_dir().join(PROTECTOR_FILE_NAME)
}

fn save_file_protector(payload: &str) -> Result<()> {
    let encrypted = session_store().encrypt_for_device(payload.as_bytes())?;
    let session_data = format!("{PROTECTOR_FILE_HEADER}\n{}", BASE64.encode(encrypted));
    secure_files::write_private(&protector_file_path(), session_data.as_bytes())
}

fn load_file_protector() -> Result<ProtectorRecord> {
    let path = protector_file_path();
    if !path.exists() {
        return Err(VaultError::ProtectorUnavailable);
    }
    let session_data = fs::read_to_string(&path)?;
    let mut lines = session_data.lines();
    let header = lines.next().ok_or(VaultError::ProtectorUnavailable)?;
    if header != PROTECTOR_FILE_HEADER {
        let _ = fs::remove_file(&path);
        return Err(VaultError::ProtectorUnavailable);
    }
    let encrypted_payload = lines.next().ok_or(VaultError::ProtectorUnavailable)?;
    if lines.next().is_some() {
        let _ = fs::remove_file(&path);
        return Err(VaultError::ProtectorUnavailable);
    }
    let encrypted_payload = BASE64
        .decode(encrypted_payload)
        .map_err(|_| VaultError::ProtectorUnavailable)?;
    let payload = session_store()
        .decrypt_for_device(&encrypted_payload)
        .map_err(|_| VaultError::ProtectorUnavailable)?;
    let payload = String::from_utf8(payload).map_err(|_| VaultError::ProtectorUnavailable)?;
    match decode_payload(&payload, ProtectorBackend::File) {
        Ok(record) => Ok(record),
        Err(VaultError::ProtectorExpired) => {
            let _ = fs::remove_file(&path);
            Err(VaultError::ProtectorExpired)
        }
        Err(error) => {
            let _ = fs::remove_file(&path);
            Err(error)
        }
    }
}

fn clear_file_protector() -> Result<()> {
    match fs::remove_file(protector_file_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VaultError::Io(error)),
    }
}

#[cfg(any(target_os = "macos", windows))]
fn keyring_user() -> String {
    let path = Vault::vault_dir();
    let digest = digest(&SHA256, path.to_string_lossy().as_bytes());
    format!("vault:{}", BASE64.encode(digest.as_ref()))
}

#[cfg(any(target_os = "macos", windows))]
fn save_os_protector(payload: &str) -> Result<()> {
    os_entry()?.set_password(payload).map_err(map_keyring_error)
}

#[cfg(any(target_os = "macos", windows))]
fn load_os_protector() -> Result<ProtectorRecord> {
    let raw = os_entry()?.get_password().map_err(map_keyring_error)?;
    match decode_payload(&raw, ProtectorBackend::Os) {
        Ok(record) => Ok(record),
        Err(VaultError::ProtectorExpired) => {
            clear_os_protector();
            Err(VaultError::ProtectorExpired)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "macos", windows))]
fn clear_os_protector() {
    if let Ok(entry) = os_entry() {
        let _ = entry.delete_credential();
    }
}

#[cfg(any(target_os = "macos", windows))]
fn os_entry() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, &keyring_user()).map_err(map_keyring_error)
}

#[cfg(any(target_os = "macos", windows))]
fn map_keyring_error(error: keyring::Error) -> VaultError {
    match error {
        keyring::Error::NoEntry => VaultError::ProtectorUnavailable,
        other => VaultError::ProtectorUnavailableOs(other.to_string()),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn save_os_protector(_payload: &str) -> Result<()> {
    Err(VaultError::ProtectorUnavailableOs(
        "OS session protector is not compiled in on this platform. Recovery: unset WISPKEY_PROTECTOR or set WISPKEY_PROTECTOR=file for a machine-bound local protector, or unlock with --password-file.".into(),
    ))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn load_os_protector() -> Result<ProtectorRecord> {
    Err(VaultError::ProtectorUnavailable)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn clear_os_protector() {}

fn expiry_timestamp(issued_at: DateTime<Utc>, timeout_minutes: i64) -> Option<DateTime<Utc>> {
    if timeout_minutes <= 0 {
        return None;
    }
    issued_at.checked_add_signed(chrono::Duration::minutes(timeout_minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_payload_rejects_expired_entries() {
        let key = [9u8; 32];
        let payload =
            encode_payload(&key, Utc::now() - chrono::Duration::minutes(500), 480).unwrap();
        assert!(matches!(
            decode_payload(&payload, ProtectorBackend::File),
            Err(VaultError::ProtectorExpired)
        ));
    }

    #[test]
    fn decode_payload_round_trips_active_entries() {
        let key = [2u8; 32];
        let payload = encode_payload(&key, Utc::now(), 30).unwrap();
        let record = decode_payload(&payload, ProtectorBackend::Os).unwrap();
        assert_eq!(record.key, key);
        assert_eq!(record.backend, ProtectorBackend::Os);
        assert_eq!(record.timeout_minutes, 30);
    }
}
