mod common;
use base64::Engine;
use common::*;
use rusqlite::{Connection, types::Value as SqlValue};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{ChildStderr, Command, Output, Stdio};

const USER: &str = "synthetic-username-canary";
const OLD: &str = "synthetic-old-password-canary+/&";
const NEW: &str = "synthetic-new-password-canary+/&";
const ORIGIN: &str = "https://login.example.com";
fn payload(password: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"username":USER,"password":password})).unwrap()
}
fn db(dir: &Path) -> Connection {
    Connection::open(dir.join("vault.db")).unwrap()
}
fn rows(dir: &Path, table: &str) -> Vec<Vec<SqlValue>> {
    let c = db(dir);
    let mut stmt = c
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| (0..n).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn no_canaries(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for secret in [USER, OLD, NEW] {
        assert!(!text.contains(secret), "plaintext leaked");
        assert!(
            !text.contains(&base64::engine::general_purpose::STANDARD.encode(secret)),
            "encoded plaintext leaked"
        );
    }
}
fn command(
    dir: &Path,
    operation: &str,
    name: &str,
    project: &str,
    partition: &str,
    origin: &str,
) -> Command {
    let mut cmd = wispkey_bin();
    cmd.args([
        "--format",
        "json",
        "login",
        operation,
        name,
        "--project",
        project,
        "--partition",
        partition,
        "--origin",
        origin,
        "--stdin",
    ])
    .env("WISPKEY_VAULT_PATH", dir)
    .env_remove("WISPKEY_PASSWORD")
    .env("WISPKEY_PROTECTOR", "file")
    .env("WISPKEY_SESSION_TIMEOUT", "30")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd
}
struct Pending {
    child: ChildGuard,
    stderr: BufReader<ChildStderr>,
}
impl Pending {
    fn begin(dir: &Path, operation: &str) -> Self {
        Self::scoped(dir, operation, "default", "personal")
    }
    fn scoped(dir: &Path, operation: &str, project: &str, partition: &str) -> Self {
        let mut child = ChildGuard(
            command(dir, operation, "entry", project, partition, ORIGIN)
                .spawn()
                .unwrap(),
        );
        let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
        let mut ready = String::new();
        stderr.read_line(&mut ready).unwrap();
        assert!(
            ready.starts_with("Ready for existing login input"),
            "input preparation refused"
        );
        Self { child, stderr }
    }
    fn finish(mut self, input: &[u8]) -> Output {
        let _ = self.child.0.stdin.as_mut().unwrap().write_all(input);
        drop(self.child.0.stdin.take());
        let mut stderr = Vec::new();
        self.stderr.read_to_end(&mut stderr).unwrap();
        let mut stdout = Vec::new();
        self.child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        let output = Output {
            status: self.child.0.wait().unwrap(),
            stdout,
            stderr,
        };
        no_canaries(&output.stdout);
        no_canaries(&output.stderr);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("wk_"));
        output
    }
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    assert!(
        Pending::begin(dir.path(), "add-existing")
            .finish(&payload(OLD))
            .status
            .success()
    );
    dir
}
fn assert_stored_pair(dir: &Path, password: &str) {
    // Existing owner egress is used only to verify a disposable fixture. Never print the captured payload.
    let template = dir.join("template");
    std::fs::write(&template, "{{ cred:entry }}").unwrap();
    let output = run_wispkey(
        dir,
        &[
            "inject",
            "-i",
            template.to_str().unwrap(),
            "--stdout",
            "--project",
            "default",
        ],
    );
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value == json!({"username": USER, "password": password}),
        "stored pair differs"
    );
}
fn register(dir: &Path) -> Value {
    run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "auth",
            "register",
            "entry",
            "--project",
            "default",
            "--provider",
            "synthetic",
            "--account",
            "synthetic-account",
            "--origin",
            ORIGIN,
            "--provider-expiry",
            "non-expiring",
        ],
    )["auth"]
        .clone()
}
#[test]
fn creates_existing_pair_without_generating_or_claiming_provider_authentication() {
    let dir = fixture();
    let dir = dir.path();
    let metadata = run_wispkey_json(dir, &["--format", "json", "list", "--project", "default"]);
    no_canaries(&serde_json::to_vec(&metadata).unwrap());
    let c = db(dir);
    let (kind, origin, lifecycle): (String, String, String) = c
        .query_row(
            "SELECT credential_type,origin,lifecycle_state FROM credentials",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(kind.contains("WebsiteLogin") || kind.contains("website_login"));
    assert_eq!(origin, ORIGIN);
    assert_eq!(lifecycle, "pending");
    assert_stored_pair(dir, OLD);
    let before = rows(dir, "credentials");
    let duplicate = command(dir, "add-existing", "entry", "default", "personal", ORIGIN)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    no_canaries(&duplicate.stderr);
    assert_eq!(before, rows(dir, "credentials"));
}
#[test]
fn updates_pair_preserving_all_other_columns_registry_and_bundle() {
    let dir = fixture();
    let dir = dir.path();
    let auth = register(dir);
    let bundle = json!({"name":"bundle","project":"default","partition":"personal","account":"synthetic-account",
        "alternatives":[{"name":"login","members":[{"auth_id":auth["id"],"revision":auth["revision"],"role":"password"}]}]});
    let file = dir.join("bundle.json");
    std::fs::write(&file, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(
        run_wispkey(
            dir,
            &["auth", "bundle", "set", "--file", file.to_str().unwrap()]
        )
        .status
        .success()
    );
    db(dir).execute("UPDATE credentials SET description='keep', tags='one,two', review_at='2030-01-01T00:00:00Z', last_used_at='2026-01-01T00:00:00Z'",[]).unwrap();
    let before = rows(dir, "credentials");
    let registry = rows(dir, "auth_registry");
    let bundles = rows(dir, "auth_bundles");
    let output = Pending::begin(dir, "update-existing").finish(&payload(NEW));
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"ok":true})
    );
    let after = rows(dir, "credentials");
    let c = db(dir);
    let stmt = c.prepare("SELECT * FROM credentials").unwrap();
    for (i, name) in stmt.column_names().iter().enumerate() {
        if ["encrypted_value", "updated_at"].contains(name) {
            assert_ne!(before[0][i], after[0][i], "{name}");
        } else {
            assert_eq!(before[0][i], after[0][i], "{name}");
        }
    }
    assert_eq!(registry, rows(dir, "auth_registry"));
    assert_eq!(bundles, rows(dir, "auth_bundles"));
    assert_stored_pair(dir, NEW);
    no_canaries(format!("{:?}", rows(dir, "audit_log")).as_bytes());
}
#[test]
fn scope_origin_type_and_lifecycle_fail_closed_without_upsert() {
    let dir = fixture();
    let dir = dir.path();
    assert!(
        run_wispkey(dir, &["project", "create", "other"])
            .status
            .success()
    );
    assert!(
        Pending::scoped(dir, "add-existing", "other", "personal")
            .finish(&payload(OLD))
            .status
            .success()
    );
    assert!(
        run_wispkey(
            dir,
            &["partition", "create", "wrong", "--project", "default"]
        )
        .status
        .success()
    );
    let before = rows(dir, "credentials");
    for (op, name, project, partition, origin) in [
        ("update-existing", "missing", "default", "personal", ORIGIN),
        ("add-existing", "entry", "missing", "personal", ORIGIN),
        ("update-existing", "entry", "default", "wrong", ORIGIN),
        (
            "update-existing",
            "entry",
            "default",
            "personal",
            "https://other.example.com",
        ),
        ("add-existing", "entry", "default", "wrong", ORIGIN),
        (
            "add-existing",
            "new",
            "default",
            "personal",
            "https://login.example.com/path",
        ),
        (
            "add-existing",
            "new",
            "default",
            "personal",
            "https://user:password@login.example.com",
        ),
    ] {
        let out = command(dir, op, name, project, partition, origin)
            .output()
            .unwrap();
        assert!(!out.status.success());
        no_canaries(&out.stderr);
    }
    assert_eq!(before, rows(dir, "credentials"));
    assert!(
        Pending::begin(dir, "update-existing")
            .finish(&payload(NEW))
            .status
            .success()
    );
    // Explicit row identity check by project, independent of UUID order.
    let other_id: String = db(dir).query_row("SELECT c.id FROM credentials c JOIN partitions p ON c.partition_id=p.id JOIN projects pr ON p.project_id=pr.id WHERE pr.name='other'",[],|r|r.get(0)).unwrap();
    assert_eq!(
        before
            .iter()
            .find(|r| r[0] == SqlValue::Text(other_id.clone())),
        rows(dir, "credentials")
            .iter()
            .find(|r| r[0] == SqlValue::Text(other_id.clone()))
    );
    assert!(
        run_wispkey(dir, &["login", "archive", "entry", "--project", "default"])
            .status
            .success()
    );
    let archived = rows(dir, "credentials");
    assert!(
        !command(
            dir,
            "update-existing",
            "entry",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(archived, rows(dir, "credentials"));
}
#[test]
fn concurrent_writes_rename_remove_scope_move_and_aba_invalidate_input() {
    for sql in [
        "UPDATE credentials SET description='changed'",
        "UPDATE credentials SET name='renamed'",
        "UPDATE credentials SET tags='temporary'; UPDATE credentials SET tags=''",
        "UPDATE credentials SET encrypted_value='changed'",
        "UPDATE credentials SET partition_id=NULL",
        "DELETE FROM credentials",
    ] {
        let dir = fixture();
        let dir = dir.path();
        let pending = Pending::begin(dir, "update-existing");
        db(dir).execute_batch(sql).unwrap();
        let changed = rows(dir, "credentials");
        assert!(!pending.finish(&payload(NEW)).status.success());
        assert_eq!(changed, rows(dir, "credentials"));
    }
}
#[test]
fn parallel_create_and_update_each_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    init_vault(dir);
    for operation in ["add-existing", "update-existing"] {
        let first = Pending::begin(dir, operation);
        let second = Pending::begin(dir, operation);
        assert!(first.finish(&payload(OLD)).status.success());
        let before = rows(dir, "credentials");
        assert!(!second.finish(&payload(NEW)).status.success());
        assert_eq!(before, rows(dir, "credentials"));
    }
    assert_stored_pair(dir, OLD);
}
#[test]
fn changed_session_and_revocation_block_both_input_modes() {
    for operation in ["add-existing", "update-existing"] {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        init_vault(dir);
        if operation == "update-existing" {
            assert!(
                Pending::begin(dir, "add-existing")
                    .finish(&payload(OLD))
                    .status
                    .success()
            );
        }
        for args in [vec!["lock"], vec!["unlock"]] {
            let before = rows(dir, "credentials");
            let p = Pending::begin(dir, operation);
            assert!(run_wispkey(dir, &args).status.success());
            assert!(!p.finish(&payload(NEW)).status.success());
            assert_eq!(before, rows(dir, "credentials"));
            assert!(run_wispkey(dir, &["unlock"]).status.success());
        }
    }
    let dir = fixture();
    let dir = dir.path();
    register(dir);
    let p = Pending::begin(dir, "update-existing");
    assert!(
        run_wispkey(dir, &["auth", "revoke", "entry", "--project", "default"])
            .status
            .success()
    );
    let revoked = rows(dir, "credentials");
    assert!(!p.finish(&payload(NEW)).status.success());
    assert_eq!(revoked, rows(dir, "credentials"));
    assert!(
        !command(
            dir,
            "update-existing",
            "entry",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
}
#[test]
fn malformed_or_cancelled_input_and_audit_failures_never_write() {
    for operation in ["add-existing", "update-existing"] {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        init_vault(dir);
        if operation == "update-existing" {
            assert!(
                Pending::begin(dir, "add-existing")
                    .finish(&payload(OLD))
                    .status
                    .success()
            );
        }
        let before = rows(dir, "credentials");
        for input in [
            Vec::new(),
            vec![255],
            br#"{"username":"u","password":"p","extra":true}"#.to_vec(),
            br#"{"username":"u","password":"p","password":"q"}"#.to_vec(),
            br#"{"username":"u","password":"a\u0000b"}"#.to_vec(),
            payload(&"x".repeat(16385)),
            vec![b'x'; 128 * 1024 + 1],
        ] {
            assert!(
                !Pending::begin(dir, operation)
                    .finish(&input)
                    .status
                    .success()
            );
            assert_eq!(before, rows(dir, "credentials"));
        }
        drop(Pending::begin(dir, operation));
        assert_eq!(before, rows(dir, "credentials"));
        db(dir).execute_batch("CREATE TRIGGER fail_login_audit BEFORE INSERT ON audit_log WHEN NEW.event_type IN ('WebsiteLoginStored','WebsiteLoginUpdated') BEGIN SELECT RAISE(ABORT,'synthetic-new-password-canary+/&'); END").unwrap();
        assert!(
            !Pending::begin(dir, operation)
                .finish(&payload(NEW))
                .status
                .success()
        );
        assert_eq!(before, rows(dir, "credentials"));
    }
}
#[test]
fn unknown_stored_schema_and_wrong_type_are_not_silently_converted() {
    let dir = fixture();
    let dir = dir.path();
    let path = dir.join("unsupported.json");
    write_private_test_file(
        &path,
        &json!({"username":USER,"password":OLD,"future":"preserve-me"}).to_string(),
    );
    assert!(
        run_wispkey(
            dir,
            &[
                "add",
                "generic",
                "--type",
                "api_key",
                "--project",
                "default",
                "--value-file",
                path.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    let before = rows(dir, "credentials");
    assert!(
        !command(
            dir,
            "update-existing",
            "generic",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
    db(dir).execute("UPDATE credentials SET encrypted_value=(SELECT encrypted_value FROM credentials WHERE name='generic') WHERE name='entry'",[]).unwrap();
    let before = rows(dir, "credentials");
    assert!(
        !command(
            dir,
            "update-existing",
            "entry",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
}

#[test]
fn expired_policy_and_missing_registry_marker_reject_update() {
    let dir = fixture();
    let dir = dir.path();
    register(dir);
    db(dir).execute("UPDATE auth_registry SET metadata_json=json_set(metadata_json,'$.use_until','2000-01-01T00:00:00Z')",[]).unwrap();
    let before = rows(dir, "credentials");
    assert!(
        !command(
            dir,
            "update-existing",
            "entry",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
    db(dir).execute("DELETE FROM auth_registry", []).unwrap();
    assert!(
        !command(
            dir,
            "update-existing",
            "entry",
            "default",
            "personal",
            ORIGIN
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
}
