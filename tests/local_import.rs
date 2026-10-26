mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use serde_json::{Value, json};
use wispkey::core::{AddCredentialRequest, CredentialType, Vault};
use wispkey::local_import::{
    CommitRequest, ImportPreview, ImportSession, ImportSource, InputFormat, PreviewRequest,
};

const SECRET: &str = "synthetic-import-secret-canary";
const SECOND: &str = "synthetic-other-secret-canary";

// Each case gets a process and an owned vault. Session-store environment never
// races another integration test and no test hook enters the import engine.
#[test]
fn local_import_owner_boundary() {
    for case in [
        "store",
        "strict",
        "stale",
        "conflicts",
        "rollback",
        "bounds",
    ] {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_import_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("WISPKEY_VAULT_PATH", dir.path())
            .env("WISPKEY_SESSION_TIMEOUT", "30")
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PROJECT")
            .env_remove("WISPKEY_PASSWORD")
            .env("LOCAL_IMPORT_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(SECRET));
            assert!(!text.contains(SECOND));
        }
    }
}

#[test]
#[ignore = "isolated child invoked by local_import_owner_boundary"]
fn local_import_fixture() {
    let case = std::env::var("LOCAL_IMPORT_CASE").expect("parent supplies isolated fixture");
    let dir = PathBuf::from(std::env::var_os("WISPKEY_VAULT_PATH").unwrap());
    let mut vault = Vault::open_with_session().unwrap();
    vault
        .unlock_with_timeout("test-password", Some(30))
        .unwrap();
    let mut session = ImportSession::new();
    match case.as_str() {
        "store" => {
            let source = dir.join(".env.dev");
            let original = format!(
                "# preserve this\nAPI_KEY='{SECRET}'\nDATABASE_URL=postgres://fixture.invalid/db\nPORT=8123\nSERVICE_PORT=service-port\nRETRIES=3\nRATIO=0.5\nDEBUG=true\nENABLED=off\nSSH_KEY=ssh-fixture-key\nSSH_PASSWORD=fixture-password\nPASSWORD=fixture-password\nCREDENTIAL_FILE=relative.key\nAUTH_PATH=relative-file\nKEY_MATERIAL=ssh-ed25519 fixture-public-key\n"
            );
            write_private_test_file(&source, &original);
            let plan = file_plan(&mut session, &vault, &source);
            assert!(plan.items[0].tokenizable);
            assert!(plan.items[1..].iter().all(|item| !item.tokenizable));
            let wire = serde_json::to_value(&plan).unwrap();
            assert_eq!(wire["items"][0]["type"], "api_key");
            assert!(wire["items"][0].get("value").is_none());
            assert!(wire["items"][0].get("hash").is_none());
            redacted(&wire);
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, true, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "invalid_selection"
            );
            assert!(vault.list_credentials().unwrap().is_empty());
            assert_eq!(std::fs::read_to_string(&source).unwrap(), original);
            let plan = file_plan(&mut session, &vault, &source);
            let mut request = commit(&plan, false, "unresolved");
            for (item, selection) in plan.items.iter().zip(&mut request.items) {
                if !item.tokenizable {
                    selection.hosts.clear();
                }
            }
            let outcome = session.commit(&vault, request).unwrap();
            assert_eq!(
                (outcome.stored, outcome.reused, outcome.skipped),
                (plan.items.len(), 0, 0)
            );
            redacted(&serde_json::to_value(outcome).unwrap());
            assert_eq!(std::fs::read_to_string(&source).unwrap(), original);
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-api-key")
                    .unwrap(),
                SECRET
            );
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, false, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "plan_unavailable"
            );
            let db = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
            let encrypted: String = db
                .query_row(
                    "SELECT encrypted_value FROM credentials WHERE name='dev-api-key'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(!encrypted.contains(SECRET));
            let audit: String = db
                .query_row(
                    "SELECT coalesce(group_concat(credential_name), '') FROM audit_log",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(!audit.contains(SECRET));

            let json_plan = clipboard_plan(
                &mut session,
                &vault,
                &format!(r#"{{"JSON_KEY":"{SECOND}"}}"#),
                InputFormat::Json,
            )
            .unwrap();
            session
                .commit(&vault, commit(&json_plan, false, "unresolved"))
                .unwrap();
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-json-key")
                    .unwrap(),
                SECOND
            );
            let keyfile = dir.join("identity.key");
            write_private_test_file(&keyfile, SECRET);
            let opaque = file_plan(&mut session, &vault, &keyfile);
            assert!(!opaque.items[0].tokenizable);
            session
                .commit(&vault, commit(&opaque, false, "unresolved"))
                .unwrap();
            assert_eq!(std::fs::read_to_string(keyfile).unwrap(), SECRET);
            let mixed = dir.join("mixed");
            std::fs::create_dir(&mixed).unwrap();
            write_private_test_file(&mixed.join(".env.dev"), &format!("MIXED_KEY={SECRET}\n"));
            write_private_test_file(
                &mixed.join(".env.production"),
                &format!("MIXED_KEY={SECOND}\n"),
            );
            let plan = session
                .preview(
                    &vault,
                    PreviewRequest {
                        source: ImportSource::Directory { path: mixed },
                        project: "fixture".into(),
                        environment: None,
                    },
                )
                .unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan.items.iter().any(|item| item.environment == "dev"));
            assert!(
                plan.items
                    .iter()
                    .any(|item| item.environment == "production")
            );
            let result = session
                .commit(&vault, commit(&plan, false, "unresolved"))
                .unwrap();
            assert_eq!(result.stored, 2);
            for (environment, value) in [("dev", SECRET), ("production", SECOND)] {
                let name = format!("{environment}-mixed-key");
                let credential = vault.get_credential_in_project("fixture", &name).unwrap();
                let partition = vault
                    .get_partition_in_project("fixture", environment)
                    .unwrap();
                assert_eq!(
                    credential.partition_id.as_deref(),
                    Some(partition.id.as_str())
                );
                assert_eq!(
                    vault
                        .decrypt_credential_value_in_project("fixture", &name)
                        .unwrap(),
                    value
                );
            }
        }
        "strict" => {
            for content in [
                format!("GOOD={SECRET}\nbroken row"),
                format!("KEY={SECRET}\nKEY={SECOND}"),
                "EMPTY=".into(),
                "1BAD=abc".into(),
                "KEY='unclosed".into(),
            ] {
                let error = clipboard_plan(&mut session, &vault, &content, InputFormat::Env)
                    .err()
                    .unwrap();
                assert_eq!(error.code(), "invalid_input");
                assert!(!error.to_string().contains(SECRET));
            }
            for content in [
                r#"{"KEY":"one","KEY":"two"}"#,
                r#"{"KEY":12}"#,
                r#"{"KEY":{"nested":"value"}}"#,
                r#"{"KEY":""}"#,
                "{}",
            ] {
                assert_eq!(
                    clipboard_plan(&mut session, &vault, content, InputFormat::Json)
                        .err()
                        .unwrap()
                        .code(),
                    "invalid_input"
                );
            }
            assert!(vault.list_credentials().unwrap().is_empty());
        }
        "stale" => {
            let source = dir.join(".env.dev");
            write_private_test_file(&source, &format!("KEY={SECRET}\n"));
            let plan = file_plan(&mut session, &vault, &source);
            write_private_test_file(&source, &format!("KEY={SECOND}\n"));
            assert_eq!(
                session.review(&vault, &plan.plan_id).err().unwrap().code(),
                "source_changed"
            );
            let plan = file_plan(&mut session, &vault, &source);
            write_private_test_file(&source, &format!("KEY={SECRET}\n"));
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, true, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "source_changed"
            );
            assert_eq!(
                std::fs::read_to_string(&source).unwrap(),
                format!("KEY={SECRET}\n")
            );
            assert!(vault.list_credentials().unwrap().is_empty());
            let plan = file_plan(&mut session, &vault, &source);
            vault
                .create_project("fixture", "changed after preview")
                .unwrap();
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, false, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "import_failed"
            );
            let plan = file_plan(&mut session, &vault, &source);
            vault.lock().unwrap();
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, false, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "locked"
            );
        }
        "conflicts" => {
            let source = dir.join(".env.dev");
            write_private_test_file(&source, &format!("KEY={SECRET}\n"));
            let first = file_plan(&mut session, &vault, &source);
            session
                .commit(&vault, commit(&first, false, "unresolved"))
                .unwrap();
            let original = vault
                .get_credential_in_project("fixture", "dev-key")
                .unwrap();
            write_private_test_file(&source, &format!("KEY={SECOND}\n"));
            let plan = file_plan(&mut session, &vault, &source);
            assert_eq!(plan.items[0].conflict, "different");
            assert_eq!(plan.items[0].hosts, original.hosts);
            session
                .commit(&vault, commit(&plan, false, "keep"))
                .unwrap();
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-key")
                    .unwrap(),
                SECRET
            );
            let plan = file_plan(&mut session, &vault, &source);
            session
                .commit(&vault, commit(&plan, true, "replace"))
                .unwrap();
            let replaced = vault
                .get_credential_in_project("fixture", "dev-key")
                .unwrap();
            assert_eq!(replaced.id, original.id);
            assert_eq!(replaced.wisp_token, original.wisp_token);
            assert_eq!(replaced.hosts, original.hosts);
            assert_eq!(replaced.tags, original.tags);
            assert_eq!(replaced.created_at, original.created_at);
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-key")
                    .unwrap(),
                SECOND
            );
            assert_eq!(
                std::fs::read_to_string(&source).unwrap(),
                format!("KEY={}\n", replaced.wisp_token)
            );
            let again = file_plan(&mut session, &vault, &source);
            assert_eq!(again.items[0].conflict, "same");
            let outcome = session
                .commit(&vault, commit(&again, true, "keep"))
                .unwrap();
            assert_eq!((outcome.stored, outcome.reused), (0, 1));
            assert_eq!(outcome.sources[0].status, "unchanged");
            let unscoped = vault
                .add_credential(AddCredentialRequest {
                    name: "dev-unscoped",
                    credential_type: CredentialType::ApiKey,
                    value: SECRET,
                    description: None,
                    hosts: None,
                    tags: None,
                    partition: Some("dev"),
                    project: Some("fixture"),
                    origin: None,
                    lifecycle_state: None,
                    review_at: None,
                })
                .unwrap();
            write_private_test_file(&source, &format!("UNSCOPED={SECOND}\n"));
            let plan = file_plan(&mut session, &vault, &source);
            assert!(plan.items[0].hosts.is_empty());
            assert!(!plan.items[0].tokenizable);
            session
                .commit(&vault, commit(&plan, false, "replace"))
                .unwrap();
            let saved = vault
                .get_credential_in_project("fixture", "dev-unscoped")
                .unwrap();
            assert_eq!(saved.id, unscoped.id);
            assert_eq!(saved.wisp_token, unscoped.wisp_token);
            assert!(saved.hosts.is_empty());
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-unscoped")
                    .unwrap(),
                SECOND
            );
            assert_eq!(
                std::fs::read_to_string(&source).unwrap(),
                format!("UNSCOPED={SECOND}\n")
            );
            // A valid source can be read but an overlong temporary filename
            // cannot be created. The vault success must remain visible.
            #[cfg(unix)]
            {
                let long = dir.join(format!(".env.{}", "x".repeat(230)));
                write_private_test_file(&long, &format!("OTHER={SECRET}\n"));
                let plan = file_plan(&mut session, &vault, &long);
                let outcome = session
                    .commit(&vault, commit(&plan, true, "unresolved"))
                    .unwrap();
                assert_eq!(outcome.stored, 1);
                assert!(outcome.source_update_failed);
                assert_eq!(outcome.sources[0].status, "not_changed");
                assert_eq!(
                    std::fs::read_to_string(long).unwrap(),
                    format!("OTHER={SECRET}\n")
                );
                assert_eq!(
                    vault
                        .decrypt_credential_value_in_project("fixture", "dev-other")
                        .unwrap(),
                    SECRET
                );
            }
        }
        "rollback" => {
            vault.create_project("fixture", "").unwrap();
            vault.create_partition("dev", "", Some("fixture")).unwrap();
            vault
                .add_credential(AddCredentialRequest {
                    name: "dev-basic",
                    credential_type: CredentialType::BasicAuth,
                    value: "fixture:password",
                    description: Some("preserve"),
                    hosts: Some("api.fixture.invalid"),
                    tags: Some("keep"),
                    partition: Some("dev"),
                    project: Some("fixture"),
                    origin: None,
                    lifecycle_state: None,
                    review_at: None,
                })
                .unwrap();
            let source = dir.join(".env.dev");
            write_private_test_file(
                &source,
                &format!("NEW={SECRET}\nBASIC=not-valid-basic-auth\n"),
            );
            let plan = file_plan(&mut session, &vault, &source);
            let error = session
                .commit(&vault, commit(&plan, true, "replace"))
                .err()
                .unwrap();
            assert_eq!(error.code(), "import_failed");
            assert_eq!(
                std::fs::read_to_string(&source).unwrap(),
                format!("NEW={SECRET}\nBASIC=not-valid-basic-auth\n")
            );
            assert!(
                vault
                    .get_credential_in_project("fixture", "dev-new")
                    .is_err()
            );
            assert_eq!(
                vault
                    .decrypt_credential_value_in_project("fixture", "dev-basic")
                    .unwrap(),
                "fixture:password"
            );
            assert_eq!(
                vault.list_credentials_in_project("fixture").unwrap().len(),
                1
            );
            let plan = file_plan(&mut session, &vault, &source);
            let mut request = commit(&plan, false, "replace");
            request.items[1].id = request.items[0].id.clone();
            assert_eq!(
                session.commit(&vault, request).err().unwrap().code(),
                "invalid_selection"
            );
            assert_eq!(
                vault.list_credentials_in_project("fixture").unwrap().len(),
                1
            );
        }
        "bounds" => {
            let source = dir.join(".env.dev");
            write_private_test_file(&source, &format!("KEY={SECRET}\n"));
            let plan = file_plan(&mut session, &vault, &source);
            let mut request = commit(&plan, false, "unresolved");
            request.items[0].hosts = vec!["*".into()];
            assert_eq!(
                session.commit(&vault, request).err().unwrap().code(),
                "hosts_required"
            );
            let plan = file_plan(&mut session, &vault, &source);
            session.cancel(&plan.plan_id).unwrap();
            assert_eq!(
                session.review(&vault, &plan.plan_id).err().unwrap().code(),
                "plan_unavailable"
            );
            write_private_test_file(&source, "DATABASE_URL=postgres://fixture.invalid/db\n");
            let plan = file_plan(&mut session, &vault, &source);
            assert_eq!(
                session
                    .commit(&vault, commit(&plan, true, "unresolved"))
                    .err()
                    .unwrap()
                    .code(),
                "invalid_selection"
            );
            assert!(vault.list_credentials().unwrap().is_empty());
            let too_large = "x".repeat(1024 * 1024 + 1);
            assert_eq!(
                clipboard_plan(&mut session, &vault, &too_large, InputFormat::Secret)
                    .err()
                    .unwrap()
                    .code(),
                "limit_exceeded"
            );
            #[cfg(unix)]
            {
                let linked = dir.join(".env.link");
                std::os::unix::fs::symlink(&source, &linked).unwrap();
                assert_eq!(
                    session
                        .preview(&vault, request_for_file(&linked))
                        .err()
                        .unwrap()
                        .code(),
                    "invalid_input"
                );
            }
        }
        _ => panic!("unknown fixture"),
    }
}

fn request_for_file(path: &Path) -> PreviewRequest {
    PreviewRequest {
        source: ImportSource::Files {
            paths: vec![path.to_path_buf()],
        },
        project: "fixture".into(),
        environment: Some("dev".into()),
    }
}
fn file_plan(session: &mut ImportSession, vault: &Vault, path: &Path) -> ImportPreview {
    session.preview(vault, request_for_file(path)).unwrap()
}
fn clipboard_plan(
    session: &mut ImportSession,
    vault: &Vault,
    content: &str,
    format: InputFormat,
) -> Result<ImportPreview, wispkey::local_import::ImportError> {
    session.preview(
        vault,
        PreviewRequest {
            source: ImportSource::Clipboard {
                content: content.into(),
                format,
                name: Some("clipboard-key".into()),
            },
            project: "fixture".into(),
            environment: Some("dev".into()),
        },
    )
}
fn commit(plan: &ImportPreview, rewrite: bool, action: &str) -> CommitRequest {
    serde_json::from_value(json!({"plan_id": plan.plan_id, "project": plan.project, "destination_confirmed":true,"replace_http_values":rewrite,"items":plan.items.iter().map(|item| json!({"id": item.id,"environment":item.environment,"selected":true,"hosts":["api.fixture.invalid"],"conflict_action":action})).collect::<Vec<_>>()})).unwrap()
}
fn redacted(value: &Value) {
    let text = value.to_string();
    assert!(!text.contains(SECRET));
    assert!(!text.contains(SECOND));
    assert!(!text.contains("wk_"));
}
