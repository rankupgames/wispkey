/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Vault engine -- encrypted credential storage, AES-256-GCM encrypt/decrypt,
 *              Argon2id key derivation, phantom token generation, session management.
 * Created: 2026-04-07
 * Last Modified: 2026-04-08
 */

use std::fs;
use std::path::PathBuf;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use rand::Rng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_PARTITION_NAME: &str = "personal";

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found -- run `wispkey init` first")]
    NotFound,
    #[error("vault is locked -- run `wispkey unlock` first")]
    Locked,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("credential '{0}' already exists")]
    DuplicateCredential(String),
    #[error("credential '{0}' not found")]
    CredentialNotFound(String),
    #[error("invalid credential type: {0}")]
    InvalidCredentialType(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("session expired or invalid")]
    SessionInvalid,
    #[error("partition '{0}' already exists")]
    DuplicatePartition(String),
    #[error("partition '{0}' not found")]
    PartitionNotFound(String),
    #[error("cannot delete the default 'personal' partition")]
    CannotDeleteDefaultPartition,
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialType {
    BearerToken,
    ApiKey,
    BasicAuth,
    CustomHeader { header_name: String },
    QueryParam { param_name: String },
}

impl CredentialType {
    pub fn from_str_with_params(
        type_str: &str,
        header_name: Option<&str>,
        param_name: Option<&str>,
    ) -> Result<Self> {
        match type_str {
            "bearer_token" => Ok(Self::BearerToken),
            "api_key" => Ok(Self::ApiKey),
            "basic_auth" => Ok(Self::BasicAuth),
            "custom_header" => {
                let name = header_name.ok_or_else(|| {
                    VaultError::InvalidCredentialType("custom_header requires --header-name".into())
                })?;
                Ok(Self::CustomHeader {
                    header_name: name.to_string(),
                })
            }
            "query_param" => {
                let name = param_name.ok_or_else(|| {
                    VaultError::InvalidCredentialType("query_param requires --param-name".into())
                })?;
                Ok(Self::QueryParam {
                    param_name: name.to_string(),
                })
            }
            other => Err(VaultError::InvalidCredentialType(other.to_string())),
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::BearerToken => "bearer_token",
            Self::ApiKey => "api_key",
            Self::BasicAuth => "basic_auth",
            Self::CustomHeader { .. } => "custom_header",
            Self::QueryParam { .. } => "query_param",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub wisp_token: String,
    pub hosts: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub partition_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Vault {
    db: Connection,
    master_key: Option<[u8; 32]>,
    session_timeout_override: Option<i64>,
}

impl Vault {
    pub fn vault_dir() -> PathBuf {
        if let Ok(path) = std::env::var("WISPKEY_VAULT_PATH") {
            return PathBuf::from(path);
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wispkey")
    }

    fn db_path() -> PathBuf {
        Self::vault_dir().join("vault.db")
    }

    fn session_path() -> PathBuf {
        Self::vault_dir().join("session")
    }

    pub fn exists() -> bool {
        Self::db_path().exists()
    }

    pub fn init(password: &str) -> Result<Self> {
        let vault_dir = Self::vault_dir();
        let db_path = Self::db_path();

        if db_path.exists() {
            return Err(VaultError::AlreadyExists(db_path));
        }

        fs::create_dir_all(&vault_dir)?;

        let db = Connection::open(&db_path)?;
        Self::create_schema(&db)?;

        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
        );
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| VaultError::Encryption(e.to_string()))?
            .to_string();

        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('password_hash', ?1)",
            params![password_hash],
        )?;
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('version', '2')",
            [],
        )?;
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('created_at', ?1)",
            params![Utc::now().to_rfc3339()],
        )?;

        let now = Utc::now().to_rfc3339();
        db.execute(
			"INSERT INTO partitions (id, name, description, created_at, updated_at) VALUES ('personal', 'personal', '', ?1, ?2)",
			params![now, now],
		)?;

        let master_key = Self::derive_key(password, salt.as_ref());

        let vault = Self {
            db,
            master_key: Some(master_key),
            session_timeout_override: None,
        };
        vault.write_session()?;

        tracing::info!("Vault created at {}", db_path.display());
        Ok(vault)
    }

    pub fn open() -> Result<Self> {
        let db_path = Self::db_path();
        if !db_path.exists() {
            return Err(VaultError::NotFound);
        }
        let db = Connection::open(&db_path)?;
        Self::migrate_schema(&db)?;
        Ok(Self {
            db,
            master_key: None,
            session_timeout_override: None,
        })
    }

    pub fn open_with_session() -> Result<Self> {
        let mut vault = Self::open()?;
        vault.load_session()?;
        Ok(vault)
    }

    fn migrate_schema(db: &Connection) -> Result<()> {
        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "1".to_string());
        if version.as_str() != "1" {
            return Ok(());
        }

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS partitions (
				id TEXT PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);",
        )?;

        let now = Utc::now().to_rfc3339();
        db.execute(
			"INSERT OR IGNORE INTO partitions (id, name, description, created_at, updated_at) VALUES ('personal', 'personal', '', ?1, ?2)",
			params![now, now],
		)?;

        db.execute(
            "ALTER TABLE credentials ADD COLUMN partition_id TEXT REFERENCES partitions(id)",
            [],
        )?;

        db.execute(
            "UPDATE credentials SET partition_id = 'personal' WHERE partition_id IS NULL",
            [],
        )?;
        db.execute(
            "UPDATE vault_meta SET value = '2' WHERE key = 'version'",
            [],
        )?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.unlock_with_timeout(password, None)
    }

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
            argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
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

    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    fn ensure_unlocked(&self) -> Result<&[u8; 32]> {
        self.master_key.as_ref().ok_or(VaultError::Locked)
    }

    pub(crate) fn derive_key(password: &str, salt_str: &str) -> [u8; 32] {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
        );
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt_str.as_bytes(), &mut key)
            .expect("key derivation failed");
        key
    }

    pub fn session_timeout_minutes() -> i64 {
        std::env::var("WISPKEY_SESSION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30)
    }

    fn write_session(&self) -> Result<()> {
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
        fs::write(&session_path, session_data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&session_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn load_session(&mut self) -> Result<()> {
        let session_path = Self::session_path();
        if !session_path.exists() {
            return Err(VaultError::Locked);
        }

        let session_data = fs::read_to_string(&session_path)?;
        let lines: Vec<&str> = session_data.lines().collect();

        let (key_b64, timestamp_str, timeout) = if lines.len() >= 3 {
            (lines[0], lines[1], lines[2].parse::<i64>().unwrap_or(30))
        } else if lines.len() == 1 {
            let parts: Vec<&str> = session_data.splitn(2, ':').collect();
            if parts.len() != 2 {
                fs::remove_file(&session_path).ok();
                return Err(VaultError::SessionInvalid);
            }
            (parts[0], parts[1], 30i64)
        } else {
            fs::remove_file(&session_path).ok();
            return Err(VaultError::SessionInvalid);
        };

        let timestamp =
            DateTime::parse_from_rfc3339(timestamp_str).map_err(|_| VaultError::SessionInvalid)?;

        let age = Utc::now() - timestamp.with_timezone(&Utc);
        if timeout > 0 && age.num_minutes() > timeout {
            fs::remove_file(&session_path).ok();
            return Err(VaultError::SessionInvalid);
        }

        let key_bytes = BASE64
            .decode(key_b64)
            .map_err(|_| VaultError::SessionInvalid)?;
        if key_bytes.len() != 32 {
            fs::remove_file(&session_path).ok();
            return Err(VaultError::SessionInvalid);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        self.master_key = Some(key);
        Ok(())
    }

    fn resolve_partition_id_for_insert(&self, partition: Option<&str>) -> Result<String> {
        let name = partition.unwrap_or(DEFAULT_PARTITION_NAME);
        let id: String = self
            .db
            .query_row(
                "SELECT id FROM partitions WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::PartitionNotFound(name.to_string()))?;
        Ok(id)
    }

    pub fn add_credential(
        &self,
        name: &str,
        credential_type: CredentialType,
        value: &str,
        hosts: Option<&str>,
        tags: Option<&str>,
        partition: Option<&str>,
    ) -> Result<Credential> {
        let key = self.ensure_unlocked()?;

        let existing: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if existing {
            return Err(VaultError::DuplicateCredential(name.to_string()));
        }

        let partition_id = self.resolve_partition_id_for_insert(partition)?;

        let id = Uuid::new_v4().to_string();
        let encrypted_value = self.encrypt_bytes(key, value.as_bytes())?;
        let wisp_token = self.generate_wisp_token(name)?;
        let type_json = serde_json::to_string(&credential_type).unwrap();
        let hosts_csv = hosts.unwrap_or("");
        let tags_csv = tags.unwrap_or("");
        let now = Utc::now().to_rfc3339();

        self.db.execute(
			"INSERT INTO credentials (id, name, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, partition_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
			params![id, name, type_json, BASE64.encode(&encrypted_value), wisp_token, hosts_csv, tags_csv, now, now, partition_id],
		)?;

        Ok(Credential {
            id,
            name: name.to_string(),
            credential_type,
            wisp_token,
            hosts: parse_csv(hosts_csv),
            tags: parse_csv(tags_csv),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            partition_id: Some(partition_id),
        })
    }

    pub fn create_partition(&self, name: &str, description: &str) -> Result<Partition> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM partitions WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if exists {
            return Err(VaultError::DuplicatePartition(name.to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
			"INSERT INTO partitions (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
			params![id, name, description, now, now],
		)?;

        self.get_partition(name)
    }

    pub fn list_partitions(&self) -> Result<Vec<Partition>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, created_at, updated_at FROM partitions ORDER BY name",
        )?;
        let rows = stmt.query_map([], partition_from_row)?;

        let mut partitions = Vec::new();
        for row in rows {
            partitions.push(row?);
        }
        Ok(partitions)
    }

    pub fn get_partition(&self, name: &str) -> Result<Partition> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare(
            "SELECT id, name, description, created_at, updated_at FROM partitions WHERE name = ?1",
        )?;
        stmt.query_row(params![name], partition_from_row)
            .map_err(|_| VaultError::PartitionNotFound(name.to_string()))
    }

    pub fn delete_partition(&self, name: &str) -> Result<()> {
        let _ = self.ensure_unlocked()?;

        if name == DEFAULT_PARTITION_NAME {
            return Err(VaultError::CannotDeleteDefaultPartition);
        }

        let partition: Partition = self.get_partition(name)?;
        let personal_id: String = self.db.query_row(
            "SELECT id FROM partitions WHERE name = ?1",
            params![DEFAULT_PARTITION_NAME],
            |row| row.get(0),
        )?;

        self.db.execute(
            "UPDATE credentials SET partition_id = ?1, updated_at = ?2 WHERE partition_id = ?3",
            params![personal_id, Utc::now().to_rfc3339(), partition.id],
        )?;
        let affected = self.db.execute(
            "DELETE FROM partitions WHERE id = ?1",
            params![partition.id],
        )?;
        if affected == 0 {
            return Err(VaultError::PartitionNotFound(name.to_string()));
        }
        Ok(())
    }

    pub fn assign_credential_to_partition(
        &self,
        credential_name: &str,
        partition_name: &str,
    ) -> Result<()> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials WHERE name = ?1",
            params![credential_name],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::CredentialNotFound(credential_name.to_string()));
        }

        let partition_id = self.resolve_partition_id_for_insert(Some(partition_name))?;
        self.db.execute(
            "UPDATE credentials SET partition_id = ?1, updated_at = ?2 WHERE name = ?3",
            params![partition_id, Utc::now().to_rfc3339(), credential_name],
        )?;
        Ok(())
    }

    pub fn list_credentials_in_partition(&self, partition_name: &str) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let partition_id = self.resolve_partition_id_for_insert(Some(partition_name))?;
        let mut stmt = self.db.prepare(
			"SELECT id, name, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id FROM credentials WHERE partition_id = ?1 ORDER BY name",
		)?;
        let rows = stmt.query_map(params![partition_id], credential_from_row)?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(row?);
        }
        Ok(credentials)
    }

    pub fn partition_credential_count(&self, partition_id: &str) -> Result<usize> {
        let count: usize = self.db.query_row(
            "SELECT COUNT(*) FROM credentials WHERE partition_id = ?1",
            params![partition_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_credentials(&self) -> Result<Vec<Credential>> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare("SELECT id, name, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id FROM credentials ORDER BY name")?;
        let rows = stmt.query_map([], credential_from_row)?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(row?);
        }
        Ok(credentials)
    }

    pub fn get_credential(&self, name: &str) -> Result<Credential> {
        let _ = self.ensure_unlocked()?;
        let mut stmt = self.db.prepare("SELECT id, name, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id FROM credentials WHERE name = ?1")?;
        stmt.query_row(params![name], credential_from_row)
            .map_err(|_| VaultError::CredentialNotFound(name.to_string()))
    }

    #[allow(dead_code)]
    pub fn decrypt_credential_value(&self, name: &str) -> Result<String> {
        let key = self.ensure_unlocked()?;
        let encoded: String = self
            .db
            .query_row(
                "SELECT encrypted_value FROM credentials WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::CredentialNotFound(name.to_string()))?;
        let encrypted = BASE64
            .decode(&encoded)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let decrypted = self.decrypt_bytes(key, &encrypted)?;
        String::from_utf8(decrypted).map_err(|e| VaultError::Encryption(e.to_string()))
    }

    pub fn remove_credential(&self, name: &str) -> Result<()> {
        let _ = self.ensure_unlocked()?;
        let affected = self
            .db
            .execute("DELETE FROM credentials WHERE name = ?1", params![name])?;
        if affected == 0 {
            return Err(VaultError::CredentialNotFound(name.to_string()));
        }
        Ok(())
    }

    pub fn rotate_wisp_token(&self, name: &str) -> Result<String> {
        let _ = self.ensure_unlocked()?;

        let exists: bool = self.db.query_row(
            "SELECT COUNT(*) > 0 FROM credentials WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::CredentialNotFound(name.to_string()));
        }

        let new_token = self.generate_wisp_token(name)?;
        self.db.execute(
            "UPDATE credentials SET wisp_token = ?1, updated_at = ?2 WHERE name = ?3",
            params![new_token, Utc::now().to_rfc3339(), name],
        )?;
        Ok(new_token)
    }

    pub fn lookup_by_wisp_token(&self, token: &str) -> Result<(Credential, String)> {
        let key = self.ensure_unlocked()?;

        let mut stmt = self.db.prepare("SELECT id, name, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id, encrypted_value FROM credentials WHERE wisp_token = ?1")?;
        let (cred, encoded) = stmt
            .query_row(params![token], |row| {
                let encrypted_value: String = row.get(10)?;
                let cred = credential_from_row(row)?;
                Ok((cred, encrypted_value))
            })
            .map_err(|_| VaultError::CredentialNotFound(token.to_string()))?;

        let encrypted = BASE64
            .decode(&encoded)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let decrypted = self.decrypt_bytes(key, &encrypted)?;
        let value =
            String::from_utf8(decrypted).map_err(|e| VaultError::Encryption(e.to_string()))?;

        self.db.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE wisp_token = ?2",
            params![Utc::now().to_rfc3339(), token],
        )?;

        Ok((cred, value))
    }

    pub fn credential_count(&self) -> Result<usize> {
        let count: usize = self
            .db
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn vault_created_at(&self) -> Result<String> {
        let created: String = self.db.query_row(
            "SELECT value FROM vault_meta WHERE key = 'created_at'",
            [],
            |row| row.get(0),
        )?;
        Ok(created)
    }

    fn create_schema(db: &Connection) -> Result<()> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS partitions (
				id TEXT PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS credentials (
				id TEXT PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				credential_type TEXT NOT NULL,
				encrypted_value TEXT NOT NULL,
				wisp_token TEXT UNIQUE NOT NULL,
				hosts TEXT NOT NULL DEFAULT '',
				tags TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				last_used_at TEXT,
				partition_id TEXT REFERENCES partitions(id)
			);
			CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				event_type TEXT NOT NULL,
				credential_name TEXT,
				wisp_token TEXT,
				target_host TEXT,
				target_path TEXT,
				http_method TEXT,
				response_status INTEGER,
				denied INTEGER NOT NULL DEFAULT 0,
				deny_reason TEXT
			);",
        )?;
        Ok(())
    }

    fn generate_wisp_token(&self, name: &str) -> Result<String> {
        let slug: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        let slug = slug.trim_matches('_');

        loop {
            let random_part: String = rand::rng()
                .sample_iter(&rand::distr::Alphanumeric)
                .take(8)
                .map(|b| (b as char).to_ascii_lowercase())
                .collect();
            let token = format!("wk_{}_{}", slug, random_part);

            let exists: bool = self.db.query_row(
                "SELECT COUNT(*) > 0 FROM credentials WHERE wisp_token = ?1",
                params![token],
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(token);
            }
        }
    }

    pub(crate) fn encrypt_bytes(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| VaultError::Encryption("RNG failure".into()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| VaultError::Encryption("invalid key".into()))?;
        let sealing_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| VaultError::Encryption("seal failed".into()))?;

        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    pub(crate) fn decrypt_bytes(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(VaultError::Encryption("ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce_arr: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| VaultError::Encryption("invalid nonce".into()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| VaultError::Encryption("invalid key".into()))?;
        let opening_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut in_out = encrypted.to_vec();
        let plaintext = opening_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| VaultError::Encryption("decryption failed -- wrong password?".into()))?;
        Ok(plaintext.to_vec())
    }

    pub fn db(&self) -> &Connection {
        &self.db
    }
}

fn partition_from_row(row: &Row<'_>) -> rusqlite::Result<Partition> {
    let created_str: String = row.get(3)?;
    let updated_str: String = row.get(4)?;
    Ok(Partition {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        updated_at: DateTime::parse_from_rfc3339(&updated_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn credential_from_row(row: &Row<'_>) -> rusqlite::Result<Credential> {
    let type_json: String = row.get(2)?;
    let hosts_csv: String = row.get(4)?;
    let tags_csv: String = row.get(5)?;
    let created_str: String = row.get(6)?;
    let updated_str: String = row.get(7)?;
    let last_used_str: Option<String> = row.get(8)?;
    let partition_id: Option<String> = row.get(9)?;

    Ok(Credential {
        id: row.get(0)?,
        name: row.get(1)?,
        credential_type: serde_json::from_str(&type_json).unwrap_or(CredentialType::BearerToken),
        wisp_token: row.get(3)?,
        hosts: parse_csv(&hosts_csv),
        tags: parse_csv(&tags_csv),
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        updated_at: DateTime::parse_from_rfc3339(&updated_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        last_used_at: last_used_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }),
        partition_id,
    })
}

fn parse_csv(csv: &str) -> Vec<String> {
    csv.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault(password: &str) -> Vault {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let db = Connection::open(&db_path).unwrap();
        Vault::create_schema(&db).unwrap();

        let salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng,
        );
        let argon2_hasher = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
        );
        let password_hash = argon2_hasher
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('password_hash', ?1)",
            params![password_hash],
        )
        .unwrap();
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('version', '2')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('created_at', ?1)",
            params![Utc::now().to_rfc3339()],
        )
        .unwrap();
        let now = Utc::now().to_rfc3339();
        db.execute("INSERT INTO partitions (id, name, description, created_at, updated_at) VALUES ('personal', 'personal', '', ?1, ?2)", params![now, now]).unwrap();

        let master_key = Vault::derive_key(password, salt.as_ref());
        std::mem::forget(dir);
        Vault {
            db,
            master_key: Some(master_key),
            session_timeout_override: None,
        }
    }

    #[test]
    fn init_creates_vault() {
        let vault = test_vault("test-password");
        assert!(vault.is_unlocked());
        assert_eq!(vault.credential_count().unwrap(), 0);
    }

    #[test]
    fn add_and_get_credential() {
        let vault = test_vault("pw");
        let cred = vault
            .add_credential(
                "my-key",
                CredentialType::BearerToken,
                "secret-value",
                Some("api.example.com"),
                Some("prod,api"),
                None,
            )
            .unwrap();
        assert!(cred.wisp_token.starts_with("wk_"));
        assert_eq!(cred.hosts, vec!["api.example.com"]);
        assert_eq!(cred.tags, vec!["prod", "api"]);

        let fetched = vault.get_credential("my-key").unwrap();
        assert_eq!(fetched.name, "my-key");
        assert_eq!(fetched.wisp_token, cred.wisp_token);
    }

    #[test]
    fn duplicate_credential_rejected() {
        let vault = test_vault("pw");
        vault
            .add_credential("dup", CredentialType::ApiKey, "val1", None, None, None)
            .unwrap();
        let result = vault.add_credential("dup", CredentialType::ApiKey, "val2", None, None, None);
        assert!(matches!(result, Err(VaultError::DuplicateCredential(_))));
    }

    #[test]
    fn remove_credential() {
        let vault = test_vault("pw");
        vault
            .add_credential("rm-me", CredentialType::ApiKey, "val", None, None, None)
            .unwrap();
        assert_eq!(vault.credential_count().unwrap(), 1);
        vault.remove_credential("rm-me").unwrap();
        assert_eq!(vault.credential_count().unwrap(), 0);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let vault = test_vault("pw");
        let result = vault.remove_credential("ghost");
        assert!(matches!(result, Err(VaultError::CredentialNotFound(_))));
    }

    #[test]
    fn rotate_wisp_token() {
        let vault = test_vault("pw");
        let original = vault
            .add_credential(
                "rotate-me",
                CredentialType::BearerToken,
                "secret",
                None,
                None,
                None,
            )
            .unwrap();
        let new_token = vault.rotate_wisp_token("rotate-me").unwrap();
        assert_ne!(original.wisp_token, new_token);
        assert!(new_token.starts_with("wk_"));

        let fetched = vault.get_credential("rotate-me").unwrap();
        assert_eq!(fetched.wisp_token, new_token);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let vault = test_vault("pw");
        let key = vault.ensure_unlocked().unwrap();
        let plaintext = b"hello world, this is a secret";
        let encrypted = vault.encrypt_bytes(key, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = vault.decrypt_bytes(key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn lookup_by_wisp_token_decrypts() {
        let vault = test_vault("pw");
        let cred = vault
            .add_credential(
                "lookup-test",
                CredentialType::ApiKey,
                "the-real-secret",
                None,
                None,
                None,
            )
            .unwrap();
        let (found, value) = vault.lookup_by_wisp_token(&cred.wisp_token).unwrap();
        assert_eq!(found.name, "lookup-test");
        assert_eq!(value, "the-real-secret");
    }

    #[test]
    fn partitions_crud() {
        let vault = test_vault("pw");
        let partitions = vault.list_partitions().unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].name, "personal");

        vault
            .create_partition("infra", "infrastructure creds")
            .unwrap();
        let partitions = vault.list_partitions().unwrap();
        assert_eq!(partitions.len(), 2);

        let dup = vault.create_partition("infra", "dup");
        assert!(matches!(dup, Err(VaultError::DuplicatePartition(_))));

        vault
            .add_credential(
                "infra-cred",
                CredentialType::ApiKey,
                "val",
                None,
                None,
                Some("infra"),
            )
            .unwrap();
        let infra_creds = vault.list_credentials_in_partition("infra").unwrap();
        assert_eq!(infra_creds.len(), 1);

        vault.delete_partition("infra").unwrap();
        let personal_creds = vault.list_credentials_in_partition("personal").unwrap();
        assert_eq!(personal_creds.len(), 1);
    }

    #[test]
    fn cannot_delete_personal_partition() {
        let vault = test_vault("pw");
        let result = vault.delete_partition("personal");
        assert!(matches!(
            result,
            Err(VaultError::CannotDeleteDefaultPartition)
        ));
    }

    #[test]
    fn credential_type_parsing() {
        assert!(matches!(
            CredentialType::from_str_with_params("bearer_token", None, None).unwrap(),
            CredentialType::BearerToken
        ));
        assert!(matches!(
            CredentialType::from_str_with_params("api_key", None, None).unwrap(),
            CredentialType::ApiKey
        ));
        assert!(matches!(
            CredentialType::from_str_with_params("basic_auth", None, None).unwrap(),
            CredentialType::BasicAuth
        ));
        assert!(matches!(
            CredentialType::from_str_with_params("custom_header", Some("X-Api-Key"), None).unwrap(),
            CredentialType::CustomHeader { .. }
        ));
        assert!(CredentialType::from_str_with_params("custom_header", None, None).is_err());
        assert!(CredentialType::from_str_with_params("bogus", None, None).is_err());
    }

    #[test]
    fn parse_csv_works() {
        assert_eq!(parse_csv("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(parse_csv(""), Vec::<String>::new());
        assert_eq!(parse_csv("solo"), vec!["solo"]);
        assert_eq!(parse_csv(" a , b "), vec!["a", "b"]);
    }
}
