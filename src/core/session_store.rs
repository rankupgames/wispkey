use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::secure_files;

use super::{Result, Vault, VaultError};

const SESSION_DEVICE_SEED_FILE: &str = "session-device-seed";
const SESSION_V2_MACHINE_HEADER: &str = "v2:machine";
const SESSION_PLAINTEXT_ENV: &str = "WISPKEY_SESSION_PLAINTEXT";
const SESSION_HKDF_INFO: &[u8] = b"wispkey-session-v2";
const SESSION_SEED_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionBackend {
    MachineBound,
    Plaintext,
}

impl SessionBackend {
    fn label(self) -> &'static str {
        match self {
            Self::MachineBound => "machine-bound",
            Self::Plaintext => "plaintext",
        }
    }
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    pub(super) key: [u8; 32],
    pub(super) issued_at: DateTime<Utc>,
    pub(super) timeout_minutes: i64,
    backend: SessionBackend,
}

pub(super) trait SessionStore {
    fn save(&self, key: &[u8; 32], issued_at: DateTime<Utc>, timeout_minutes: i64) -> Result<()>;
    fn load(&self) -> Result<SessionRecord>;
    fn clear(&self) -> Result<()>;
}

pub(super) struct SessionFileStore {
    session_path: PathBuf,
    device_seed_path: PathBuf,
    preferred_backend: SessionBackend,
}

#[derive(Serialize, Deserialize)]
struct MachineSessionPayload {
    key: String,
    issued_at: String,
    timeout_minutes: i64,
}

struct HkdfKeyLen;

impl hkdf::KeyType for HkdfKeyLen {
    fn len(&self) -> usize {
        32
    }
}

pub(super) fn session_store() -> SessionFileStore {
    let preferred_backend = if std::env::var(SESSION_PLAINTEXT_ENV).as_deref() == Ok("1") {
        SessionBackend::Plaintext
    } else {
        SessionBackend::MachineBound
    };
    SessionFileStore {
        session_path: Vault::session_path(),
        device_seed_path: Vault::vault_dir().join(SESSION_DEVICE_SEED_FILE),
        preferred_backend,
    }
}

impl SessionFileStore {
    #[must_use]
    pub(super) fn should_upgrade(&self, record: &SessionRecord) -> bool {
        record.backend == SessionBackend::Plaintext
            && self.preferred_backend == SessionBackend::MachineBound
    }

    #[must_use]
    pub(super) fn protection_label(&self) -> &'static str {
        self.preferred_backend.label()
    }

    #[cfg(test)]
    fn new_for_test(
        session_path: PathBuf,
        device_seed_path: PathBuf,
        preferred_backend: SessionBackend,
    ) -> Self {
        Self {
            session_path,
            device_seed_path,
            preferred_backend,
        }
    }

    fn save_plaintext(
        &self,
        key: &[u8; 32],
        issued_at: DateTime<Utc>,
        timeout_minutes: i64,
    ) -> Result<()> {
        let session_data = format!(
            "{}\n{}\n{}",
            BASE64.encode(key),
            issued_at.to_rfc3339(),
            timeout_minutes
        );
        secure_files::write_private(&self.session_path, session_data.as_bytes())
    }

    fn save_machine_bound(
        &self,
        key: &[u8; 32],
        issued_at: DateTime<Utc>,
        timeout_minutes: i64,
    ) -> Result<()> {
        let payload = MachineSessionPayload {
            key: BASE64.encode(key),
            issued_at: issued_at.to_rfc3339(),
            timeout_minutes,
        };
        let payload = serde_json::to_vec(&payload)
            .map_err(|error| VaultError::Encryption(error.to_string()))?;
        let wrap_key = self.derive_wrap_key(true)?;
        let encrypted_payload = encrypt_session_payload(&wrap_key, &payload)?;
        let session_data = format!(
            "{}\n{}",
            SESSION_V2_MACHINE_HEADER,
            BASE64.encode(encrypted_payload)
        );
        secure_files::write_private(&self.session_path, session_data.as_bytes())
    }

    fn load_machine_bound(&self, session_data: &str) -> Result<SessionRecord> {
        let mut lines = session_data.lines();
        let header = lines.next().ok_or(VaultError::SessionInvalid)?;
        if header != SESSION_V2_MACHINE_HEADER {
            return Err(VaultError::SessionInvalid);
        }
        let encrypted_payload = lines.next().ok_or(VaultError::SessionInvalid)?;
        if lines.next().is_some() {
            return Err(VaultError::SessionInvalid);
        }

        let encrypted_payload = BASE64
            .decode(encrypted_payload)
            .map_err(|_| VaultError::SessionInvalid)?;
        let wrap_key = self.derive_wrap_key(false)?;
        let payload = decrypt_session_payload(&wrap_key, &encrypted_payload)
            .map_err(|_| VaultError::SessionInvalid)?;
        let payload: MachineSessionPayload =
            serde_json::from_slice(&payload).map_err(|_| VaultError::SessionInvalid)?;
        session_record_from_parts(
            &payload.key,
            &payload.issued_at,
            payload.timeout_minutes,
            SessionBackend::MachineBound,
        )
    }

    fn derive_wrap_key(&self, create_seed: bool) -> Result<[u8; 32]> {
        let seed = if create_seed {
            self.load_or_create_device_seed()?
        } else {
            self.load_device_seed()?
        };
        let salt_input = machine_binding_salt();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_input.as_bytes());
        let prk = salt.extract(&seed);
        let okm = prk
            .expand(&[SESSION_HKDF_INFO], HkdfKeyLen)
            .map_err(|_| VaultError::Encryption("session key expansion failed".into()))?;
        let mut key = [0u8; 32];
        okm.fill(&mut key)
            .map_err(|_| VaultError::Encryption("session key fill failed".into()))?;
        Ok(key)
    }

    fn load_or_create_device_seed(&self) -> Result<[u8; SESSION_SEED_LEN]> {
        match self.load_device_seed() {
            Ok(seed) => Ok(seed),
            Err(VaultError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let seed = random_device_seed()?;
                secure_files::write_private(&self.device_seed_path, &seed)?;
                Ok(seed)
            }
            Err(error) => Err(error),
        }
    }

    fn load_device_seed(&self) -> Result<[u8; SESSION_SEED_LEN]> {
        let seed = fs::read(&self.device_seed_path)?;
        seed.try_into().map_err(|_| VaultError::SessionInvalid)
    }

    pub(super) fn encrypt_for_device(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let wrap_key = self.derive_wrap_key(true)?;
        encrypt_session_payload(&wrap_key, plaintext)
    }

    pub(super) fn decrypt_for_device(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let wrap_key = self.derive_wrap_key(false)?;
        decrypt_session_payload(&wrap_key, ciphertext)
    }
}

impl SessionStore for SessionFileStore {
    fn save(&self, key: &[u8; 32], issued_at: DateTime<Utc>, timeout_minutes: i64) -> Result<()> {
        match self.preferred_backend {
            SessionBackend::MachineBound => {
                self.save_machine_bound(key, issued_at, timeout_minutes)
            }
            SessionBackend::Plaintext => {
                tracing::warn!(
                    "{}=1 is enabled; writing legacy plaintext session key",
                    SESSION_PLAINTEXT_ENV
                );
                self.save_plaintext(key, issued_at, timeout_minutes)
            }
        }
    }

    fn load(&self) -> Result<SessionRecord> {
        if !self.session_path.exists() {
            return Err(VaultError::Locked);
        }

        let session_data = fs::read_to_string(&self.session_path)?;
        let record = if session_data.starts_with(SESSION_V2_MACHINE_HEADER) {
            self.load_machine_bound(&session_data)
        } else if is_version_header(session_data.lines().next().unwrap_or("")) {
            Err(VaultError::SessionInvalid)
        } else {
            load_plaintext_record(&session_data)
        };

        match record {
            Ok(record) => validate_session_record(record, self),
            Err(error) => {
                self.clear()?;
                Err(error)
            }
        }
    }

    fn clear(&self) -> Result<()> {
        clear_invalid_session_file(&self.session_path)
    }
}

fn load_plaintext_record(session_data: &str) -> Result<SessionRecord> {
    let lines: Vec<&str> = session_data.lines().collect();

    let (key_b64, timestamp_str, timeout) = if lines.len() >= 3 {
        let timeout = lines[2]
            .parse::<i64>()
            .map_err(|_| VaultError::SessionInvalid)?;
        (lines[0], lines[1], timeout)
    } else if lines.len() == 1 {
        let parts: Vec<&str> = session_data.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(VaultError::SessionInvalid);
        }
        (parts[0], parts[1], 30i64)
    } else {
        return Err(VaultError::SessionInvalid);
    };

    session_record_from_parts(key_b64, timestamp_str, timeout, SessionBackend::Plaintext)
}

fn is_version_header(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 3 && bytes[0] == b'v' && bytes[1].is_ascii_digit() && bytes[2] == b':'
}

fn session_record_from_parts(
    key_b64: &str,
    timestamp_str: &str,
    timeout_minutes: i64,
    backend: SessionBackend,
) -> Result<SessionRecord> {
    let issued_at = DateTime::parse_from_rfc3339(timestamp_str)
        .map_err(|_| VaultError::SessionInvalid)?
        .with_timezone(&Utc);
    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|_| VaultError::SessionInvalid)?;
    if key_bytes.len() != 32 {
        return Err(VaultError::SessionInvalid);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(SessionRecord {
        key,
        issued_at,
        timeout_minutes,
        backend,
    })
}

fn validate_session_record(
    record: SessionRecord,
    store: &SessionFileStore,
) -> Result<SessionRecord> {
    if is_timeout_expired(record.issued_at, record.timeout_minutes) {
        store.clear()?;
        return Err(VaultError::SessionExpired);
    }
    Ok(record)
}

pub(super) fn is_timeout_expired(issued_at: DateTime<Utc>, timeout_minutes: i64) -> bool {
    is_timeout_expired_at(Utc::now(), issued_at, timeout_minutes)
}

fn is_timeout_expired_at(
    now: DateTime<Utc>,
    issued_at: DateTime<Utc>,
    timeout_minutes: i64,
) -> bool {
    if timeout_minutes <= 0 {
        return false;
    }
    chrono::Duration::try_minutes(timeout_minutes)
        .and_then(|duration| issued_at.checked_add_signed(duration))
        .is_none_or(|expires_at| now >= expires_at)
}

pub(super) fn validate_timeout_minutes(timeout_minutes: i64) -> Result<i64> {
    if timeout_minutes < 0 || chrono::Duration::try_minutes(timeout_minutes).is_none() {
        return Err(VaultError::InvalidSessionTimeout);
    }
    Ok(timeout_minutes)
}

fn encrypt_session_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| VaultError::Encryption("RNG failure".into()))?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Encryption("invalid session wrapping key".into()))?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::Encryption("session seal failed".into()))?;

    let mut result = Vec::with_capacity(12 + in_out.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);
    Ok(result)
}

fn decrypt_session_payload(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(VaultError::Encryption(
            "session ciphertext too short".into(),
        ));
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::Encryption("invalid session nonce".into()))?;
    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Encryption("invalid session wrapping key".into()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut in_out = encrypted.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::Encryption("session decrypt failed".into()))?;
    Ok(plaintext.to_vec())
}

fn random_device_seed() -> Result<[u8; SESSION_SEED_LEN]> {
    let rng = SystemRandom::new();
    let mut seed = [0u8; SESSION_SEED_LEN];
    rng.fill(&mut seed)
        .map_err(|_| VaultError::Encryption("RNG failure".into()))?;
    Ok(seed)
}

fn machine_binding_salt() -> &'static str {
    static MACHINE_BINDING_SALT: OnceLock<String> = OnceLock::new();
    MACHINE_BINDING_SALT
        .get_or_init(|| {
            let machine_id = read_machine_id().unwrap_or_else(|| "unknown-machine".to_string());
            let username = current_username().unwrap_or_else(|| "unknown-user".to_string());
            format!("{machine_id}:{username}")
        })
        .as_str()
}

#[cfg(target_os = "linux")]
fn read_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

#[cfg(target_os = "macos")]
fn read_machine_id() -> Option<String> {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    output.lines().find_map(|line| {
        let (_, value) = line.split_once("\"IOPlatformUUID\" = ")?;
        Some(value.trim().trim_matches('"').to_string()).filter(|id| !id.is_empty())
    })
}

#[cfg(target_os = "windows")]
fn read_machine_id() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|name| !name.is_empty())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_machine_id() -> Option<String> {
    None
}

fn current_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|name| !name.is_empty())
}

fn clear_invalid_session_file(session_path: &Path) -> Result<()> {
    match fs::remove_file(session_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VaultError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(preferred_backend: SessionBackend) -> (tempfile::TempDir, SessionFileStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionFileStore::new_for_test(
            dir.path().join("session"),
            dir.path().join("session-device-seed"),
            preferred_backend,
        );
        (dir, store)
    }

    #[test]
    fn machine_bound_session_round_trips_without_plaintext_key() {
        let (_dir, store) = test_store(SessionBackend::MachineBound);
        let key = [7u8; 32];
        let issued_at = Utc::now();

        store.save(&key, issued_at, 30).unwrap();

        let raw_session = fs::read_to_string(&store.session_path).unwrap();
        assert!(raw_session.starts_with(SESSION_V2_MACHINE_HEADER));
        assert!(!raw_session.contains(&BASE64.encode(key)));

        let record = store.load().unwrap();
        assert_eq!(record.key, key);
        assert_eq!(record.timeout_minutes, 30);
        assert_eq!(record.backend, SessionBackend::MachineBound);
    }

    #[test]
    fn legacy_plaintext_session_loads_and_rewrites_to_machine_bound() {
        let (_dir, store) = test_store(SessionBackend::MachineBound);
        let key = [9u8; 32];
        let issued_at = Utc::now();
        let legacy = format!("{}\n{}\n30", BASE64.encode(key), issued_at.to_rfc3339());
        secure_files::write_private(&store.session_path, legacy.as_bytes()).unwrap();

        let record = store.load().unwrap();
        assert_eq!(record.key, key);
        assert_eq!(record.backend, SessionBackend::Plaintext);
        store
            .save(&record.key, record.issued_at, record.timeout_minutes)
            .unwrap();

        let rewritten = fs::read_to_string(&store.session_path).unwrap();
        assert!(rewritten.starts_with(SESSION_V2_MACHINE_HEADER));
        assert!(!rewritten.contains(&BASE64.encode(key)));
    }

    #[test]
    fn invalid_machine_bound_session_is_cleared() {
        let (_dir, store) = test_store(SessionBackend::MachineBound);
        secure_files::write_private(
            &store.session_path,
            format!("{SESSION_V2_MACHINE_HEADER}\nnot-base64").as_bytes(),
        )
        .unwrap();

        assert!(matches!(store.load(), Err(VaultError::SessionInvalid)));
        assert!(!store.session_path.exists());
    }

    #[test]
    fn expired_session_is_cleared_with_distinct_error() {
        let (_dir, store) = test_store(SessionBackend::MachineBound);
        let key = [3u8; 32];
        store
            .save(&key, Utc::now() - chrono::Duration::minutes(45), 30)
            .unwrap();

        assert!(matches!(store.load(), Err(VaultError::SessionExpired)));
        assert!(!store.session_path.exists());
    }

    #[test]
    fn timeout_expires_at_the_exact_boundary() {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::minutes(30);

        assert!(!is_timeout_expired_at(
            expires_at - chrono::Duration::milliseconds(1),
            issued_at,
            30
        ));
        assert!(is_timeout_expired_at(expires_at, issued_at, 30));
    }
}
