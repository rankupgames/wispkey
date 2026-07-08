use std::path::{Path, PathBuf};

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono::Utc;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::secure_files;

use super::rows::table_has_column;
use super::{CURRENT_SCHEMA_VERSION, Result, Vault, VaultError};

impl Vault {
    pub fn vault_dir() -> PathBuf {
        if let Ok(path) = std::env::var("WISPKEY_VAULT_PATH") {
            return PathBuf::from(path);
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wispkey")
    }

    pub(super) fn db_path() -> PathBuf {
        Self::vault_dir().join("vault.db")
    }

    pub(super) fn session_path() -> PathBuf {
        Self::vault_dir().join("session")
    }

    /// Whether the vault database file already exists on disk.
    #[must_use]
    pub fn exists() -> bool {
        Self::db_path().exists()
    }

    /// Creates a new vault on disk with schema, default project/partition, and an unlocked session.
    pub fn init(password: &str) -> Result<Self> {
        let vault_dir = Self::vault_dir();
        let db_path = Self::db_path();

        if db_path.exists() {
            return Err(VaultError::AlreadyExists(db_path));
        }

        secure_files::ensure_private_directory(&vault_dir)?;

        let db = Connection::open(&db_path)?;
        harden_db_file(&db_path)?;
        Self::create_schema(&db)?;

        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
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
            "INSERT INTO vault_meta (key, value) VALUES ('version', ?1)",
            params![CURRENT_SCHEMA_VERSION],
        )?;
        db.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('created_at', ?1)",
            params![Utc::now().to_rfc3339()],
        )?;

        let now = Utc::now().to_rfc3339();
        db.execute(
			"INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', 'Default project', ?1, ?2)",
			params![now, now],
		)?;
        db.execute(
            "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES ('personal', 'personal', '', 'default', ?1, ?2)",
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

    /// Opens an existing vault database without loading or verifying a session (locked until [`Self::unlock`]).
    pub fn open() -> Result<Self> {
        let db_path = Self::db_path();
        if !db_path.exists() {
            return Err(VaultError::NotFound);
        }
        let db = Connection::open(&db_path)?;
        harden_db_file(&db_path)?;
        Self::migrate_schema(&db)?;
        Ok(Self {
            db,
            master_key: None,
            session_timeout_override: None,
        })
    }

    /// Opens the vault and restores the master key from a valid, non-expired session file if present.
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

        if version.as_str() == "1" {
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
        }

        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "2".to_string());

        if version.as_str() == "2" {
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS projects (
					id TEXT PRIMARY KEY,
					name TEXT UNIQUE NOT NULL,
					description TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL
				);",
            )?;

            let now = Utc::now().to_rfc3339();
            db.execute(
				"INSERT OR IGNORE INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', 'Default project', ?1, ?2)",
				params![now, now],
			)?;

            let has_project_id = table_has_column(db, "partitions", "project_id")?;

            if !has_project_id {
                db.execute(
                    "ALTER TABLE partitions ADD COLUMN project_id TEXT REFERENCES projects(id)",
                    [],
                )?;
            }

            db.execute(
                "UPDATE partitions SET project_id = 'default' WHERE project_id IS NULL",
                [],
            )?;

            let has_project_name = table_has_column(db, "audit_log", "project_name")?;

            if !has_project_name {
                db.execute("ALTER TABLE audit_log ADD COLUMN project_name TEXT", [])?;
            }

            db.execute(
                "UPDATE vault_meta SET value = '3' WHERE key = 'version'",
                [],
            )?;
        }

        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "3".to_string());

        if version.as_str() == "3" {
            let has_description = table_has_column(db, "credentials", "description")?;

            if !has_description {
                db.execute(
                    "ALTER TABLE credentials ADD COLUMN description TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }

            db.execute(
                "UPDATE vault_meta SET value = '4' WHERE key = 'version'",
                [],
            )?;
        }

        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "4".to_string());

        if version.as_str() == "4" {
            db.execute(
                "UPDATE partitions SET project_id = 'default' WHERE project_id IS NULL",
                [],
            )?;

            db.execute_batch(
                "PRAGMA foreign_keys = OFF;
                CREATE TABLE IF NOT EXISTS partitions_v5 (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(project_id, name)
                );
                INSERT OR IGNORE INTO partitions_v5 (id, name, description, project_id, created_at, updated_at)
                    SELECT id, name, description, COALESCE(project_id, 'default'), created_at, updated_at
                    FROM partitions;
                DROP TABLE partitions;
                ALTER TABLE partitions_v5 RENAME TO partitions;
                PRAGMA foreign_keys = ON;",
            )?;

            let now = Utc::now().to_rfc3339();
            let mut stmt = db.prepare(
                "SELECT id FROM projects WHERE id NOT IN (
                    SELECT project_id FROM partitions WHERE name = 'personal'
                )",
            )?;
            let project_ids = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);

            for project_id in project_ids {
                db.execute(
                    "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES (?1, 'personal', '', ?2, ?3, ?4)",
                    params![Uuid::new_v4().to_string(), project_id, now, now],
                )?;
            }

            db.execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = 'version'",
                params!["5"],
            )?;
        }

        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "5".to_string());

        if version.as_str() == "5" {
            db.execute_batch(
                "PRAGMA foreign_keys = OFF;
                CREATE TABLE IF NOT EXISTS credentials_v6 (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
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
                INSERT INTO credentials_v6 (id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id)
                    SELECT id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id
                    FROM credentials;
                DROP TABLE credentials;
                ALTER TABLE credentials_v6 RENAME TO credentials;
                PRAGMA foreign_keys = ON;",
            )?;

            db.execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = 'version'",
                params![CURRENT_SCHEMA_VERSION],
            )?;
        }

        Ok(())
    }

    pub(super) fn create_schema(db: &Connection) -> Result<()> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS projects (
				id TEXT PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS partitions (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				project_id TEXT NOT NULL REFERENCES projects(id),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE(project_id, name)
				);
				CREATE TABLE IF NOT EXISTS credentials (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					description TEXT NOT NULL DEFAULT '',
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
				deny_reason TEXT,
				project_name TEXT
			);",
        )?;
        Ok(())
    }
}

#[cfg(unix)]
fn harden_db_file(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_db_file(_path: &Path) -> Result<()> {
    Ok(())
}
