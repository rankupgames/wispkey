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
