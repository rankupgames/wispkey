use super::*;
use argon2::{Argon2, PasswordHasher};

fn test_vault(password: &str) -> Vault {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let db = Connection::open(&db_path).unwrap();
    Vault::create_schema(&db).unwrap();

    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2_hasher = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
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
        "INSERT INTO vault_meta (key, value) VALUES ('version', ?1)",
        params![CURRENT_SCHEMA_VERSION],
    )
    .unwrap();
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('created_at', ?1)",
        params![Utc::now().to_rfc3339()],
    )
    .unwrap();
    let now = Utc::now().to_rfc3339();
    db.execute("INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', 'Default project', ?1, ?2)", params![now, now]).unwrap();
    db.execute("INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES ('personal', 'personal', '', 'default', ?1, ?2)", params![now, now]).unwrap();

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
            AddCredentialRequest::new("my-key", CredentialType::BearerToken, "secret-value")
                .description(Some("test credential"))
                .hosts(Some("api.example.com"))
                .tags(Some("prod,api"))
                .project(Some("default")),
        )
        .unwrap();
    assert!(cred.wisp_token.starts_with("wk_"));
    assert_eq!(cred.description, "test credential");
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
        .add_credential(
            AddCredentialRequest::new("dup", CredentialType::ApiKey, "val1")
                .project(Some("default")),
        )
        .unwrap();
    let result = vault.add_credential(
        AddCredentialRequest::new("dup", CredentialType::ApiKey, "val2").project(Some("default")),
    );
    assert!(matches!(result, Err(VaultError::DuplicateCredential(_))));
}

#[test]
fn remove_credential() {
    let vault = test_vault("pw");
    vault
        .add_credential(
            AddCredentialRequest::new("rm-me", CredentialType::ApiKey, "val")
                .project(Some("default")),
        )
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
            AddCredentialRequest::new("rotate-me", CredentialType::BearerToken, "secret")
                .project(Some("default")),
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
            AddCredentialRequest::new("lookup-test", CredentialType::ApiKey, "the-real-secret")
                .project(Some("default")),
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
        .create_partition("infra", "infrastructure creds", Some("default"))
        .unwrap();
    let partitions = vault.list_partitions().unwrap();
    assert_eq!(partitions.len(), 2);

    let dup = vault.create_partition("infra", "dup", Some("default"));
    assert!(matches!(dup, Err(VaultError::DuplicatePartition(_))));

    vault
        .add_credential(
            AddCredentialRequest::new("infra-cred", CredentialType::ApiKey, "val")
                .partition(Some("infra"))
                .project(Some("default")),
        )
        .unwrap();
    let infra_creds = vault
        .list_credentials_in_partition_for_project("default", "infra")
        .unwrap();
    assert_eq!(infra_creds.len(), 1);

    vault
        .delete_partition_in_project("default", "infra")
        .unwrap();
    let personal_creds = vault
        .list_credentials_in_partition_for_project("default", "personal")
        .unwrap();
    assert_eq!(personal_creds.len(), 1);
}

#[test]
fn cannot_delete_personal_partition() {
    let vault = test_vault("pw");
    let result = vault.delete_partition_in_project("default", "personal");
    assert!(matches!(
        result,
        Err(VaultError::CannotDeleteDefaultPartition)
    ));
}

#[test]
fn project_crud_basics() {
    let vault = test_vault("pw");

    let projects = vault.list_projects().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "default");

    let proj = vault
        .create_project("team-alpha", "Alpha team creds")
        .unwrap();
    assert_eq!(proj.name, "team-alpha");
    assert_eq!(proj.description, "Alpha team creds");

    let fetched = vault.get_project("team-alpha").unwrap();
    assert_eq!(fetched.id, proj.id);

    let projects = vault.list_projects().unwrap();
    assert_eq!(projects.len(), 2);
}

#[test]
fn duplicate_project_rejected() {
    let vault = test_vault("pw");
    vault.create_project("dup-proj", "").unwrap();
    let result = vault.create_project("dup-proj", "");
    assert!(matches!(result, Err(VaultError::DuplicateProject(_))));
}

#[test]
fn cannot_delete_default_project() {
    let vault = test_vault("pw");
    let result = vault.delete_project("default");
    assert!(matches!(
        result,
        Err(VaultError::CannotDeleteDefaultProject)
    ));
}

#[test]
fn project_delete_moves_partitions_to_default() {
    let vault = test_vault("pw");
    vault.create_project("ephemeral", "").unwrap();
    vault
        .create_partition("eph-part", "temp", Some("ephemeral"))
        .unwrap();

    vault
        .add_credential(
            AddCredentialRequest::new("eph-cred", CredentialType::ApiKey, "val")
                .partition(Some("eph-part"))
                .project(Some("ephemeral")),
        )
        .unwrap();

    vault.delete_project("ephemeral").unwrap();

    let partition = vault
        .get_partition_in_project("default", "eph-part")
        .unwrap();
    let default_proj = vault.get_project("default").unwrap();
    assert_eq!(
        partition.project_id.as_deref(),
        Some(default_proj.id.as_str())
    );

    let cred = vault.get_credential("eph-cred").unwrap();
    assert_eq!(cred.partition_id.as_deref(), Some(partition.id.as_str()));
}

#[test]
fn partition_linked_to_project() {
    let vault = test_vault("pw");
    vault.create_project("proj-b", "").unwrap();
    let partition = vault
        .create_partition("proj-b-part", "", Some("proj-b"))
        .unwrap();

    let project = vault.get_project("proj-b").unwrap();
    assert_eq!(partition.project_id.as_deref(), Some(project.id.as_str()));
}

#[test]
fn partition_names_are_project_scoped() {
    let vault = test_vault("pw");
    vault.create_project("alpha", "").unwrap();
    vault.create_project("beta", "").unwrap();

    let alpha_personal = vault.get_partition_in_project("alpha", "personal").unwrap();
    let beta_personal = vault.get_partition_in_project("beta", "personal").unwrap();
    assert_ne!(alpha_personal.id, beta_personal.id);

    vault
        .create_partition("shared-name", "", Some("alpha"))
        .unwrap();
    vault
        .create_partition("shared-name", "", Some("beta"))
        .unwrap();

    let duplicate = vault.create_partition("shared-name", "", Some("alpha"));
    assert!(matches!(duplicate, Err(VaultError::DuplicatePartition(_))));
}

#[test]
fn add_credential_respects_project_default_partition() {
    let vault = test_vault("pw");
    vault.create_project("client", "").unwrap();

    let credential = vault
        .add_credential(
            AddCredentialRequest::new("client-key", CredentialType::ApiKey, "secret")
                .project(Some("client")),
        )
        .unwrap();
    let client_personal = vault
        .get_partition_in_project("client", "personal")
        .unwrap();
    assert_eq!(
        credential.partition_id.as_deref(),
        Some(client_personal.id.as_str())
    );

    let default_creds = vault.list_credentials_in_project("default").unwrap();
    let client_creds = vault.list_credentials_in_project("client").unwrap();
    assert!(default_creds.is_empty());
    assert_eq!(client_creds.len(), 1);
    assert_eq!(client_creds[0].name, "client-key");
}

#[test]
fn duplicate_credential_names_are_scoped_to_project() {
    let vault = test_vault("pw");
    vault.create_project("client-alpha", "").unwrap();
    vault.create_project("client-beta", "").unwrap();

    let alpha = vault
        .add_credential(
            AddCredentialRequest::new("openai-key", CredentialType::ApiKey, "alpha-secret")
                .project(Some("client-alpha")),
        )
        .unwrap();
    let beta = vault
        .add_credential(
            AddCredentialRequest::new("openai-key", CredentialType::ApiKey, "beta-secret")
                .project(Some("client-beta")),
        )
        .unwrap();

    assert_ne!(alpha.id, beta.id);
    assert_ne!(alpha.wisp_token, beta.wisp_token);
    assert_eq!(
        vault
            .get_credential_in_project("client-alpha", "openai-key")
            .unwrap()
            .id,
        alpha.id
    );
    assert_eq!(
        vault
            .get_credential_in_project("client-beta", "openai-key")
            .unwrap()
            .id,
        beta.id
    );

    let duplicate = vault.add_credential(
        AddCredentialRequest::new("openai-key", CredentialType::ApiKey, "alpha-dupe")
            .project(Some("client-alpha")),
    );
    assert!(matches!(duplicate, Err(VaultError::DuplicateCredential(_))));

    vault
        .remove_credential_in_project("client-beta", "openai-key")
        .unwrap();
    assert!(matches!(
        vault.get_credential_in_project("client-beta", "openai-key"),
        Err(VaultError::CredentialNotFound(_))
    ));
    assert_eq!(
        vault
            .get_credential_in_project("client-alpha", "openai-key")
            .unwrap()
            .id,
        alpha.id
    );
}

#[test]
fn list_partitions_in_project_scoping() {
    let vault = test_vault("pw");
    vault.create_project("alpha", "").unwrap();
    vault.create_project("beta", "").unwrap();
    vault
        .create_partition("alpha-keys", "", Some("alpha"))
        .unwrap();
    vault
        .create_partition("beta-keys", "", Some("beta"))
        .unwrap();

    let alpha_parts = vault.list_partitions_in_project("alpha").unwrap();
    assert_eq!(alpha_parts.len(), 2);
    assert!(alpha_parts.iter().any(|p| p.name == "alpha-keys"));
    assert!(alpha_parts.iter().any(|p| p.name == "personal"));

    let beta_parts = vault.list_partitions_in_project("beta").unwrap();
    assert_eq!(beta_parts.len(), 2);
    assert!(beta_parts.iter().any(|p| p.name == "beta-keys"));
    assert!(beta_parts.iter().any(|p| p.name == "personal"));

    let default_parts = vault.list_partitions_in_project("default").unwrap();
    assert_eq!(default_parts.len(), 1);
    assert_eq!(default_parts[0].name, "personal");

    let all = vault.list_partitions().unwrap();
    assert_eq!(all.len(), 5);
}

#[test]
fn list_credentials_in_project_scoping() {
    let vault = test_vault("pw");
    vault.create_project("proj-x", "").unwrap();
    vault
        .create_partition("x-part", "", Some("proj-x"))
        .unwrap();

    vault
        .add_credential(
            AddCredentialRequest::new("default-cred", CredentialType::ApiKey, "v1")
                .project(Some("default")),
        )
        .unwrap();
    vault
        .add_credential(
            AddCredentialRequest::new("x-cred", CredentialType::ApiKey, "v2")
                .partition(Some("x-part"))
                .project(Some("proj-x")),
        )
        .unwrap();

    let default_creds = vault.list_credentials_in_project("default").unwrap();
    assert_eq!(default_creds.len(), 1);
    assert_eq!(default_creds[0].name, "default-cred");

    let x_creds = vault.list_credentials_in_project("proj-x").unwrap();
    assert_eq!(x_creds.len(), 1);
    assert_eq!(x_creds[0].name, "x-cred");

    let all_creds = vault.list_credentials().unwrap();
    assert_eq!(all_creds.len(), 2);
}

#[test]
fn get_partition_project_name_returns_correct_name() {
    let vault = test_vault("pw");
    vault.create_project("named-proj", "").unwrap();
    let partition = vault
        .create_partition("named-part", "", Some("named-proj"))
        .unwrap();

    let project_name = vault.get_partition_project_name(&partition.id).unwrap();
    assert_eq!(project_name.as_deref(), Some("named-proj"));
}

#[test]
fn project_partition_count_tracks_correctly() {
    let vault = test_vault("pw");
    let default_proj = vault.get_project("default").unwrap();
    assert_eq!(vault.project_partition_count(&default_proj.id).unwrap(), 1);

    vault.create_project("counted", "").unwrap();
    let counted = vault.get_project("counted").unwrap();
    assert_eq!(vault.project_partition_count(&counted.id).unwrap(), 1);

    vault
        .create_partition("c-part-1", "", Some("counted"))
        .unwrap();
    vault
        .create_partition("c-part-2", "", Some("counted"))
        .unwrap();
    assert_eq!(vault.project_partition_count(&counted.id).unwrap(), 3);
}

#[test]
fn get_nonexistent_project_fails() {
    let vault = test_vault("pw");
    let result = vault.get_project("ghost-project");
    assert!(matches!(result, Err(VaultError::ProjectNotFound(_))));
}

#[test]
fn delete_nonexistent_project_fails() {
    let vault = test_vault("pw");
    let result = vault.delete_project("ghost-project");
    assert!(matches!(result, Err(VaultError::ProjectNotFound(_))));
}

#[test]
fn partition_in_nonexistent_project_fails() {
    let vault = test_vault("pw");
    let result = vault.create_partition("orphan", "", Some("no-such-project"));
    assert!(matches!(result, Err(VaultError::ProjectNotFound(_))));
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
    assert!(matches!(
        CredentialType::from_str_with_params("website_login", None, None).unwrap(),
        CredentialType::WebsiteLogin
    ));
}

#[test]
fn credential_type_column_accepts_json_and_legacy_labels() {
    assert!(matches!(
        parse_credential_type_column(3, "\"BearerToken\"").unwrap(),
        CredentialType::BearerToken
    ));
    assert!(matches!(
        parse_credential_type_column(3, "api_key").unwrap(),
        CredentialType::ApiKey
    ));
}

#[test]
fn credential_type_column_rejects_malformed_values() {
    assert!(parse_credential_type_column(3, "not-a-real-type").is_err());
}

#[test]
fn datetime_column_rejects_malformed_timestamps() {
    assert!(parse_datetime_column(7, "not-a-timestamp").is_err());
}

#[test]
fn parse_csv_works() {
    assert_eq!(parse_csv("a,b,c"), vec!["a", "b", "c"]);
    assert_eq!(parse_csv(""), Vec::<String>::new());
    assert_eq!(parse_csv("solo"), vec!["solo"]);
    assert_eq!(parse_csv(" a , b "), vec!["a", "b"]);
}

#[test]
fn schema_v6_to_current_migration_adds_instance_and_bootstrap_tables_without_touching_data() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let db = Connection::open(&db_path).unwrap();
    db.execute_batch(
        "CREATE TABLE vault_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE partitions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            project_id TEXT NOT NULL REFERENCES projects(id),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, name)
        );
        CREATE TABLE credentials (
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
        CREATE TABLE audit_log (
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
    )
    .unwrap();

    let now = Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('version', '6')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('password_hash', 'migration-test-key')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', 'Default project', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES ('personal', 'personal', '', 'default', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO credentials (id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, partition_id) VALUES ('cred-1', 'kept', '', 'api_key', 'encrypted', 'wk_kept_12345678', '', '', ?1, ?2, 'personal')",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO audit_log (timestamp, event_type, credential_name, wisp_token, target_path, deny_reason) VALUES (?1, 'CredentialUsed', 'kept', 'wk_kept_12345678', '/use/wk_kept_12345678', 'denied wk_kept_12345678')",
        params![now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO audit_log (timestamp, event_type, credential_name, target_path) VALUES (?1, 'CredentialDenied', 'missing', '/use/foowk_missing_12345678')",
        params![now],
    )
    .unwrap();

    Vault::migrate_schema(&db).unwrap();

    let version: String = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);

    let audit_token: String = db
        .query_row("SELECT wisp_token FROM audit_log", [], |row| row.get(0))
        .unwrap();
    assert!(audit_token.starts_with("hmac-sha256:"));
    assert!(!audit_token.contains("wk_kept_12345678"));
    let (audit_path, audit_reason): (String, String) = db
        .query_row(
            "SELECT target_path, deny_reason FROM audit_log",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(audit_path, "/use/[wisp-token]");
    assert_eq!(audit_reason, "denied [wisp-token]");
    let free_text_path: String = db
        .query_row(
            "SELECT target_path FROM audit_log WHERE id = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(free_text_path, "/use/foo[wisp-token]");

    for table in [
        "instances",
        "instance_scopes",
        "access_requests",
        "bootstrap_tokens",
    ] {
        let count: usize = db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    let credential_count: usize = db
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE name = 'kept'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(credential_count, 1);
}

#[test]
fn schema_v7_to_current_migration_adds_bootstrap_and_rotation_columns_without_touching_data() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let db = Connection::open(&db_path).unwrap();
    db.execute_batch(
        "CREATE TABLE vault_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE partitions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            project_id TEXT NOT NULL REFERENCES projects(id),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, name)
        );
        CREATE TABLE credentials (
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
        CREATE TABLE audit_log (
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
        );
        CREATE TABLE instances (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            secret_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        CREATE TABLE instance_scopes (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            scope_type TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(instance_id, scope_type, scope_value)
        );
        CREATE TABLE access_requests (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            credential_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            decided_at TEXT
        );",
    )
    .unwrap();

    let now = Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('version', '7')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', 'Default project', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES ('personal', 'personal', '', 'default', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO credentials (id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, partition_id) VALUES ('cred-1', 'kept', '', 'api_key', 'encrypted', 'wk_kept_12345678', '', '', ?1, ?2, 'personal')",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO instances (id, name, secret_hash, status, description, created_at, updated_at) VALUES ('inst-1', 'worker', 'hash', 'active', '', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO instance_scopes (id, instance_id, scope_type, scope_value, created_at) VALUES ('scope-1', 'inst-1', 'tag', 'company:acme', ?1)",
        params![now],
    )
    .unwrap();

    Vault::migrate_schema(&db).unwrap();

    let version: String = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);

    let (secret_rotated_at, previous_secret_hash, previous_secret_expires_at): (
        String,
        Option<String>,
        Option<String>,
    ) = db
        .query_row(
            "SELECT secret_rotated_at, previous_secret_hash, previous_secret_expires_at FROM instances WHERE id = 'inst-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(secret_rotated_at, now);
    assert!(previous_secret_hash.is_none());
    assert!(previous_secret_expires_at.is_none());

    let bootstrap_table_count: usize = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'bootstrap_tokens'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bootstrap_table_count, 1);

    let credential_count: usize = db
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE name = 'kept'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(credential_count, 1);
    let instance_scope_count: usize = db
        .query_row(
            "SELECT COUNT(*) FROM instance_scopes WHERE instance_id = 'inst-1' AND scope_type = 'tag'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(instance_scope_count, 1);
}

#[test]
fn schema_v9_to_current_binds_only_unambiguous_legacy_credential_names() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE vault_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE credentials (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE instances (
            id TEXT PRIMARY KEY
        );
        CREATE TABLE instance_scopes (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            scope_type TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(instance_id, scope_type, scope_value)
        );
        CREATE TABLE access_requests (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            credential_name TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            decided_at TEXT
        );
        INSERT INTO vault_meta (key, value) VALUES ('version', '9');
        INSERT INTO credentials (id, name) VALUES
            ('shared-default', 'shared'),
            ('shared-client', 'shared'),
            ('unique-id', 'unique');
        INSERT INTO instances (id) VALUES ('worker');
        INSERT INTO instance_scopes (id, instance_id, scope_type, scope_value, created_at) VALUES
            ('shared-scope', 'worker', 'credential', 'shared', '2026-07-10T00:00:00Z'),
            ('unique-scope', 'worker', 'credential', 'unique', '2026-07-10T00:00:00Z');
        INSERT INTO access_requests (id, instance_id, credential_name, status, reason, created_at) VALUES
            ('shared-request', 'worker', 'shared', 'approved', '', '2026-07-10T00:00:00Z'),
            ('unique-request', 'worker', 'unique', 'approved', '', '2026-07-10T00:00:00Z');",
    )
    .unwrap();

    Vault::migrate_schema(&db).unwrap();

    let version: String = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let shared_scope_id: Option<String> = db
        .query_row(
            "SELECT credential_id FROM instance_scopes WHERE id = 'shared-scope'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let unique_scope_id: Option<String> = db
        .query_row(
            "SELECT credential_id FROM instance_scopes WHERE id = 'unique-scope'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let shared_request_id: Option<String> = db
        .query_row(
            "SELECT credential_id FROM access_requests WHERE id = 'shared-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let unique_request_id: Option<String> = db
        .query_row(
            "SELECT credential_id FROM access_requests WHERE id = 'unique-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert!(shared_scope_id.is_none());
    assert_eq!(unique_scope_id.as_deref(), Some("unique-id"));
    assert!(shared_request_id.is_none());
    assert_eq!(unique_request_id.as_deref(), Some("unique-id"));
}

#[test]
fn enroll_instance_creates_instance_and_scopes() {
    let vault = test_vault("pw");
    let credential = vault
        .add_credential(AddCredentialRequest::new(
            "openai-key",
            CredentialType::ApiKey,
            "secret",
        ))
        .unwrap();
    let enrolled = vault
        .enroll_instance(
            "vm-one",
            "ephemeral worker",
            &[
                InstanceScopeInput::new("partition", "personal"),
                InstanceScopeInput::new("project", "default"),
                InstanceScopeInput::new("credential", "openai-key"),
                InstanceScopeInput::new("tag", "company:acme"),
            ],
        )
        .unwrap();

    assert!(enrolled.instance.scopes.iter().any(|scope| {
        scope.scope_type == "credential"
            && scope.credential_id.as_deref() == Some(credential.id.as_str())
    }));

    assert_eq!(enrolled.instance.name, "vm-one");
    assert_eq!(enrolled.instance.description, "ephemeral worker");
    assert_eq!(enrolled.secret.len(), 48);
    assert_eq!(enrolled.instance.scopes.len(), 4);

    let fetched = vault.get_instance("vm-one").unwrap();
    assert_eq!(fetched.id, enrolled.instance.id);
    assert!(
        fetched
            .scopes
            .iter()
            .any(|scope| { scope.scope_type == "partition" && scope.scope_value == "personal" })
    );
}

#[test]
fn bootstrap_token_redeems_once_and_copies_scope() {
    let vault = test_vault("pw");
    let created = vault
        .create_bootstrap_token(
            "worker fleet",
            &[InstanceScopeInput::new("tag", "company:acme")],
            Some(1),
            Some(chrono::Duration::hours(1)),
        )
        .unwrap();

    assert_eq!(created.plaintext_token.len(), 48);
    let joined = vault
        .redeem_bootstrap_token(&created.plaintext_token, "fleet-worker-1")
        .unwrap();
    assert_eq!(joined.bootstrap_token_id, created.token.id);
    assert_eq!(joined.secret.len(), 48);
    assert!(
        joined
            .instance
            .scopes
            .iter()
            .any(|scope| scope.scope_type == "tag" && scope.scope_value == "company:acme")
    );

    let second = vault.redeem_bootstrap_token(&created.plaintext_token, "fleet-worker-2");
    assert!(matches!(second, Err(VaultError::InvalidBootstrapToken)));

    let tokens = vault.list_bootstrap_tokens().unwrap();
    assert_eq!(tokens[0].used_count, 1);
}

#[test]
fn bootstrap_token_expired_and_revoked_fail_closed() {
    let vault = test_vault("pw");
    let expired = vault
        .create_bootstrap_token(
            "expired",
            &[InstanceScopeInput::new("tag", "company:acme")],
            None,
            None,
        )
        .unwrap();
    vault
        .db
        .execute(
            "UPDATE bootstrap_tokens SET expires_at = ?1 WHERE id = ?2",
            params![
                (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
                expired.token.id
            ],
        )
        .unwrap();
    let expired_join = vault.redeem_bootstrap_token(&expired.plaintext_token, "expired-worker");
    assert!(matches!(
        expired_join,
        Err(VaultError::InvalidBootstrapToken)
    ));

    let revoked = vault
        .create_bootstrap_token(
            "revoked",
            &[InstanceScopeInput::new("tag", "company:acme")],
            None,
            Some(chrono::Duration::hours(1)),
        )
        .unwrap();
    vault.revoke_bootstrap_token(&revoked.token.id).unwrap();
    let revoked_join = vault.redeem_bootstrap_token(&revoked.plaintext_token, "revoked-worker");
    assert!(matches!(
        revoked_join,
        Err(VaultError::InvalidBootstrapToken)
    ));
}

#[test]
fn instance_secret_verifies_and_wrong_secret_fails() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-auth", "", &[]).unwrap();

    assert!(
        vault
            .verify_instance_secret(&enrolled.instance.id, &enrolled.secret)
            .unwrap()
    );
    assert!(
        !vault
            .verify_instance_secret(&enrolled.instance.id, "wrong-secret")
            .unwrap()
    );

    let fetched = vault.get_instance(&enrolled.instance.id).unwrap();
    assert!(fetched.last_seen_at.is_some());
}

#[test]
fn instance_secret_rotation_is_due_aware_and_retires_grace_on_new_secret_use() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-rotate", "", &[]).unwrap();

    let not_due = vault
        .rotate_instance_secret(
            &enrolled.instance.id,
            Some(chrono::Duration::days(30)),
            chrono::Duration::minutes(10),
        )
        .unwrap();
    assert!(!not_due.rotated);
    assert!(not_due.secret.is_none());

    let rotated = vault
        .rotate_instance_secret(&enrolled.instance.id, None, chrono::Duration::minutes(10))
        .unwrap();
    let new_secret = rotated.secret.as_deref().unwrap();
    assert!(rotated.rotated);
    assert!(rotated.instance.previous_secret_expires_at.is_some());
    assert_ne!(new_secret, enrolled.secret);

    assert!(
        vault
            .verify_instance_secret(&enrolled.instance.id, &enrolled.secret)
            .unwrap()
    );
    assert!(
        vault
            .verify_instance_secret(&enrolled.instance.id, new_secret)
            .unwrap()
    );
    assert!(
        !vault
            .verify_instance_secret(&enrolled.instance.id, &enrolled.secret)
            .unwrap()
    );

    let confirmed = vault.get_instance(&enrolled.instance.id).unwrap();
    assert!(confirmed.previous_secret_expires_at.is_none());
}

#[test]
fn revoked_instance_secret_cannot_rotate() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-rotate-revoked", "", &[]).unwrap();
    vault.revoke_instance(&enrolled.instance.id).unwrap();

    let result =
        vault.rotate_instance_secret(&enrolled.instance.id, None, chrono::Duration::minutes(10));

    assert!(matches!(result, Err(VaultError::InstanceNotActive(_))));
}

#[test]
fn instance_secret_rotation_rejects_an_unrepresentable_grace_deadline() {
    let vault = test_vault("pw");
    let enrolled = vault
        .enroll_instance("vm-rotate-overflow", "", &[])
        .unwrap();
    let huge_grace = chrono::Duration::try_days(100_000_000).unwrap();

    let result = vault.rotate_instance_secret(&enrolled.instance.id, None, huge_grace);

    assert!(matches!(
        result,
        Err(VaultError::InvalidInstanceSecretRotation)
    ));
    assert!(
        vault
            .verify_instance_secret(&enrolled.instance.id, &enrolled.secret)
            .unwrap()
    );
}

#[test]
fn previous_instance_secret_expiring_during_verification_fails_closed() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-rotate-expiry", "", &[]).unwrap();
    vault
        .rotate_instance_secret(&enrolled.instance.id, None, chrono::Duration::minutes(10))
        .unwrap();

    let verified = vault
        .verify_instance_secret_with_hook(&enrolled.instance.id, &enrolled.secret, |db| {
            db.execute(
                "UPDATE instances SET previous_secret_expires_at = ?1 WHERE id = ?2",
                params![
                    (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
                    enrolled.instance.id
                ],
            )?;
            Ok(())
        })
        .unwrap();

    assert!(!verified);
}

#[test]
fn credential_in_scope_matches_each_selector_type() {
    let vault = test_vault("pw");
    vault.create_project("client", "").unwrap();
    vault
        .create_partition("infra", "", Some("default"))
        .unwrap();

    let partition_credential = vault
        .add_credential(
            AddCredentialRequest::new("partition-cred", CredentialType::ApiKey, "secret")
                .partition(Some("infra"))
                .project(Some("default")),
        )
        .unwrap();
    let project_credential = vault
        .add_credential(
            AddCredentialRequest::new("project-cred", CredentialType::ApiKey, "secret")
                .project(Some("client")),
        )
        .unwrap();
    let explicitly_scoped_credential = vault
        .add_credential(
            AddCredentialRequest::new("credential-cred", CredentialType::ApiKey, "secret")
                .project(Some("default")),
        )
        .unwrap();
    let tagged_credential = vault
        .add_credential(
            AddCredentialRequest::new("tagged-cred", CredentialType::ApiKey, "secret")
                .tags(Some("company:acme,prod"))
                .project(Some("default")),
        )
        .unwrap();
    let outside_credential = vault
        .add_credential(
            AddCredentialRequest::new("outside-cred", CredentialType::ApiKey, "secret")
                .project(Some("default")),
        )
        .unwrap();

    let enrolled = vault
        .enroll_instance(
            "vm-scoped",
            "",
            &[
                InstanceScopeInput::new("partition", "infra"),
                InstanceScopeInput::new("project", "client"),
                InstanceScopeInput::new("credential", "credential-cred"),
                InstanceScopeInput::new("tag", "company:acme"),
            ],
        )
        .unwrap();

    assert!(
        vault
            .credential_in_scope(&enrolled.instance.id, &partition_credential.id)
            .unwrap()
    );
    assert!(
        vault
            .credential_in_scope(&enrolled.instance.id, &project_credential.id)
            .unwrap()
    );
    assert!(
        vault
            .credential_in_scope(&enrolled.instance.id, &explicitly_scoped_credential.id)
            .unwrap()
    );
    assert!(
        vault
            .credential_in_scope(&enrolled.instance.id, &tagged_credential.id)
            .unwrap()
    );
    assert!(
        !vault
            .credential_in_scope(&enrolled.instance.id, &outside_credential.id)
            .unwrap()
    );
    assert!(
        !vault
            .credential_in_scope(&enrolled.instance.id, "missing-cred")
            .unwrap()
    );
}

#[test]
fn approved_access_request_grants_scope_and_duplicate_pending_reuses() {
    let vault = test_vault("pw");
    let credential = vault
        .add_credential(
            AddCredentialRequest::new("needs-approval", CredentialType::ApiKey, "secret")
                .project(Some("default")),
        )
        .unwrap();
    let enrolled = vault.enroll_instance("vm-requester", "", &[]).unwrap();

    assert!(
        !vault
            .credential_in_scope(&enrolled.instance.id, &credential.id)
            .unwrap()
    );

    let first = vault
        .create_or_reuse_access_request(&enrolled.instance.id, &credential.id, "deploy needs it")
        .unwrap();
    let second = vault
        .create_or_reuse_access_request(&enrolled.instance.id, &credential.id, "same request")
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.credential_id.as_deref(), Some(credential.id.as_str()));

    let pending = vault
        .list_access_requests(Some("vm-requester"), true)
        .unwrap();
    assert_eq!(pending.len(), 1);

    let approved = vault.decide_access_request(&first.id, true).unwrap();
    assert_eq!(approved.status, "approved");
    assert!(approved.decided_at.is_some());
    assert!(
        vault
            .credential_in_scope(&enrolled.instance.id, &credential.id)
            .unwrap()
    );
}

#[test]
fn denied_access_request_does_not_grant_scope() {
    let vault = test_vault("pw");
    let credential = vault
        .add_credential(
            AddCredentialRequest::new("denied-cred", CredentialType::ApiKey, "secret")
                .project(Some("default")),
        )
        .unwrap();
    let enrolled = vault.enroll_instance("vm-denied", "", &[]).unwrap();
    let request = vault
        .create_or_reuse_access_request(&enrolled.instance.id, &credential.id, "")
        .unwrap();

    let denied = vault.decide_access_request(&request.id, false).unwrap();
    assert_eq!(denied.status, "denied");
    assert!(
        !vault
            .credential_in_scope(&enrolled.instance.id, &credential.id)
            .unwrap()
    );
}

#[test]
fn revoke_instance_flips_status_and_fails_auth() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-revoke", "", &[]).unwrap();

    let revoked = vault.revoke_instance("vm-revoke").unwrap();
    assert_eq!(revoked.status, "revoked");
    assert!(
        !vault
            .verify_instance_secret(&enrolled.instance.id, &enrolled.secret)
            .unwrap()
    );
}

#[test]
fn revoke_during_instance_secret_verification_fails_closed() {
    let vault = test_vault("pw");
    let enrolled = vault.enroll_instance("vm-revoke-race", "", &[]).unwrap();
    let instance_id = enrolled.instance.id.clone();

    let verified = vault
        .verify_instance_secret_with_hook(&instance_id, &enrolled.secret, |db| {
            db.execute(
                "UPDATE instances SET status = 'revoked' WHERE id = ?1",
                params![instance_id],
            )?;
            Ok(())
        })
        .unwrap();

    assert!(!verified);
    assert_eq!(
        vault.get_instance(&enrolled.instance.id).unwrap().status,
        "revoked"
    );
}

#[test]
fn add_credential_rejects_empty_value() {
    let vault = test_vault("pw");
    let result = vault.add_credential(
        AddCredentialRequest::new("empty-val", CredentialType::ApiKey, "").project(Some("default")),
    );
    assert!(matches!(result, Err(VaultError::EmptyCredentialValue)));
    assert_eq!(vault.credential_count().unwrap(), 0);
}

#[test]
fn add_credential_rejects_whitespace_value() {
    let vault = test_vault("pw");
    let result = vault.add_credential(
        AddCredentialRequest::new("blank-val", CredentialType::ApiKey, "   ")
            .project(Some("default")),
    );
    assert!(matches!(result, Err(VaultError::EmptyCredentialValue)));
}

#[test]
fn add_credential_rejects_empty_name() {
    let vault = test_vault("pw");
    let result = vault.add_credential(
        AddCredentialRequest::new("  ", CredentialType::ApiKey, "secret").project(Some("default")),
    );
    assert!(matches!(result, Err(VaultError::EmptyCredentialName)));
}

#[test]
fn add_credentials_atomic_saves_all() {
    let vault = test_vault("pw");
    let first =
        AddCredentialRequest::new("ovh-ak", CredentialType::ApiKey, "ak").project(Some("default"));
    let second =
        AddCredentialRequest::new("ovh-as", CredentialType::ApiKey, "as").project(Some("default"));
    let created = vault.add_credentials_atomic(&[first, second]).unwrap();
    assert_eq!(created.len(), 2);
    assert_eq!(vault.credential_count().unwrap(), 2);
    assert_eq!(
        vault
            .decrypt_credential_value_in_project("default", "ovh-ak")
            .unwrap(),
        "ak"
    );
}

#[test]
fn add_credentials_atomic_rolls_back_duplicate() {
    let vault = test_vault("pw");
    vault
        .add_credential(
            AddCredentialRequest::new("keep-me", CredentialType::ApiKey, "original")
                .project(Some("default")),
        )
        .unwrap();
    let first = AddCredentialRequest::new("new-one", CredentialType::ApiKey, "one")
        .project(Some("default"));
    let second = AddCredentialRequest::new("keep-me", CredentialType::ApiKey, "two")
        .project(Some("default"));
    let result = vault.add_credentials_atomic(&[first, second]);
    assert!(matches!(result, Err(VaultError::DuplicateCredential(_))));
    assert_eq!(vault.credential_count().unwrap(), 1);
    assert!(vault.get_credential("new-one").is_err());
}

#[test]
fn add_credentials_atomic_rolls_back_invalid_later_value() {
    let vault = test_vault("pw");
    let first = AddCredentialRequest::new("batch-ok", CredentialType::ApiKey, "ok")
        .project(Some("default"));
    let second =
        AddCredentialRequest::new("batch-bad", CredentialType::ApiKey, "").project(Some("default"));
    let result = vault.add_credentials_atomic(&[first, second]);
    assert!(matches!(result, Err(VaultError::EmptyCredentialValue)));
    assert_eq!(vault.credential_count().unwrap(), 0);
}

#[test]
fn ovh_template_expands_three_api_keys() {
    let requests = expand_credential_template(
        OVH_API_TEMPLATE,
        OvhApiTemplate {
            name_prefix: "ovh-prod",
            application_key: "ak-secret",
            application_secret: "as-secret",
            consumer_key: "ck-secret",
            description: None,
            hosts: Some("api.ovh.com"),
            tags: None,
            partition: None,
            project: Some("default"),
        },
    )
    .unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].name, "ovh-prod-application-key");
    assert_eq!(requests[1].name, "ovh-prod-application-secret");
    assert_eq!(requests[2].name, "ovh-prod-consumer-key");
    assert!(
        requests
            .iter()
            .all(|request| request.credential_type == CredentialType::ApiKey)
    );
}

#[test]
fn ovh_template_save_is_atomic() {
    let vault = test_vault("pw");
    let owned = expand_credential_template(
        OVH_API_TEMPLATE,
        OvhApiTemplate {
            name_prefix: "ovh-prod",
            application_key: "ak-secret",
            application_secret: "as-secret",
            consumer_key: "ck-secret",
            description: None,
            hosts: None,
            tags: Some("ovh"),
            partition: None,
            project: Some("default"),
        },
    )
    .unwrap();
    let requests: Vec<_> = owned
        .iter()
        .map(OwnedAddCredentialRequest::as_request)
        .collect();
    let created = vault.add_credentials_atomic(&requests).unwrap();
    assert_eq!(created.len(), 3);
    assert_eq!(vault.credential_count().unwrap(), 3);
}

#[test]
fn ovh_template_unknown_id_fails() {
    let result = expand_credential_template(
        "not-a-template",
        OvhApiTemplate {
            name_prefix: "ovh-prod",
            application_key: "ak",
            application_secret: "as",
            consumer_key: "ck",
            description: None,
            hosts: None,
            tags: None,
            partition: None,
            project: None,
        },
    );
    assert!(matches!(
        result,
        Err(VaultError::InvalidCredentialTemplate(_))
    ));
}

#[test]
fn parse_https_origin_requires_https_and_strips_path() {
    assert_eq!(
        parse_https_origin("https://careers.example.com/jobs?id=1").unwrap(),
        "https://careers.example.com"
    );
    assert_eq!(
        parse_https_origin("https://Careers.Example.com:8443/path").unwrap(),
        "https://careers.example.com:8443"
    );
    assert!(parse_https_origin("http://careers.example.com").is_err());
    assert!(parse_https_origin("https://user:pass@careers.example.com").is_err());
    assert!(parse_https_origin("https://*.example.com").is_err());
    assert!(parse_https_origin("https://example..com").is_err());
}

#[test]
fn generate_website_login_stores_encrypted_payload_without_sharing_password() {
    let vault = test_vault("pw");
    let first = vault
        .generate_website_login(GenerateWebsiteLoginRequest {
            name: "acme-careers",
            username: "user@example.com",
            url: "https://careers.example.com/apply",
            project: Some("default"),
            partition: None,
            review_at: Some(Utc::now() + chrono::Duration::days(180)),
            length: None,
            symbols: true,
        })
        .unwrap();
    let second = vault
        .generate_website_login(GenerateWebsiteLoginRequest {
            name: "other-careers",
            username: "user@example.com",
            url: "https://jobs.example.net",
            project: Some("default"),
            partition: None,
            review_at: None,
            length: None,
            symbols: true,
        })
        .unwrap();

    assert_eq!(first.credential_type, CredentialType::WebsiteLogin);
    assert_eq!(first.origin, "https://careers.example.com");
    assert_eq!(first.lifecycle_state, LIFECYCLE_PENDING);
    assert_eq!(first.hosts, vec!["careers.example.com"]);
    assert!(first.review_at.is_some());
    assert!(first.description.is_empty());
    assert!(first.tags.is_empty());

    let first_payload: WebsiteLoginPayload =
        serde_json::from_str(&vault.decrypt_credential_value("acme-careers").unwrap()).unwrap();
    let second_payload: WebsiteLoginPayload =
        serde_json::from_str(&vault.decrypt_credential_value("other-careers").unwrap()).unwrap();
    assert_eq!(first_payload.username, "user@example.com");
    assert_eq!(second_payload.username, "user@example.com");
    assert_ne!(first_payload.password, second_payload.password);
    assert_eq!(first_payload.password.len(), 24);
    assert_ne!(first.wisp_token, second.wisp_token);
}

#[test]
fn website_login_lifecycle_archive_restore_activate_never_auto_deletes() {
    let vault = test_vault("pw");
    vault
        .generate_website_login(GenerateWebsiteLoginRequest {
            name: "lifecycle-login",
            username: "user@example.com",
            url: "https://careers.example.com",
            project: Some("default"),
            partition: None,
            review_at: Some(Utc::now() - chrono::Duration::days(1)),
            length: None,
            symbols: true,
        })
        .unwrap();

    let due = vault.list_due_website_logins(Some("default")).unwrap();
    assert_eq!(due.len(), 1);

    vault
        .set_credential_lifecycle("lifecycle-login", LIFECYCLE_ARCHIVED, Some("default"))
        .unwrap();
    let due_after_archive = vault.list_due_website_logins(Some("default")).unwrap();
    assert!(due_after_archive.is_empty());
    assert!(
        vault
            .get_credential("lifecycle-login")
            .unwrap()
            .lifecycle_state
            == LIFECYCLE_ARCHIVED
    );

    vault
        .set_credential_lifecycle("lifecycle-login", LIFECYCLE_PENDING, Some("default"))
        .unwrap();
    vault
        .set_credential_lifecycle("lifecycle-login", LIFECYCLE_ACTIVE, Some("default"))
        .unwrap();
    assert_eq!(
        vault
            .get_credential("lifecycle-login")
            .unwrap()
            .lifecycle_state,
        LIFECYCLE_ACTIVE
    );
    assert!(vault.get_credential("lifecycle-login").is_ok());
}

#[test]
fn schema_v10_to_current_adds_website_login_columns_without_touching_data() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let db = Connection::open(&db_path).unwrap();
    let now = Utc::now().to_rfc3339();
    db.execute_batch(
        "CREATE TABLE vault_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE partitions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            project_id TEXT NOT NULL REFERENCES projects(id),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, name)
        );
        CREATE TABLE credentials (
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
        );",
    )
    .unwrap();
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('version', '10')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ('default', 'default', '', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO partitions (id, name, description, project_id, created_at, updated_at) VALUES ('personal', 'personal', '', 'default', ?1, ?2)",
        params![now, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO credentials (id, name, description, credential_type, encrypted_value, wisp_token, hosts, tags, created_at, updated_at, partition_id) VALUES ('cred-1', 'kept', '', 'api_key', 'encrypted', 'wk_kept_12345678', '', '', ?1, ?2, 'personal')",
        params![now, now],
    )
    .unwrap();

    Vault::migrate_schema(&db).unwrap();
    let version: String = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let origin: String = db
        .query_row(
            "SELECT origin FROM credentials WHERE name = 'kept'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let lifecycle: String = db
        .query_row(
            "SELECT lifecycle_state FROM credentials WHERE name = 'kept'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(origin, "");
    assert_eq!(lifecycle, "active");
}
