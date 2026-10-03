mod common;

use common::*;
use rusqlite::{Connection, types::Value as SqlValue};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{ChildStderr, Output, Stdio};

const OLD: &str = "synthetic-old-value-canary";
const NEW: &str = "synthetic-replacement-value-canary";

fn add(dir: &Path, name: &str, project: &str, kind: &str) -> Value {
    let file = dir.join("input.txt");
    write_private_test_file(&file, OLD);
    run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "add",
            name,
            "--project",
            project,
            "--type",
            kind,
            "--value-file",
            file.to_str().unwrap(),
            "--description",
            "preserve description",
            "--hosts",
            "api.example.com",
            "--tags",
            "one,two",
        ],
    )["credential"]
        .clone()
}

fn db(dir: &Path) -> Connection {
    Connection::open(dir.join("vault.db")).unwrap()
}
fn rows(dir: &Path, table: &str) -> Vec<Vec<SqlValue>> {
    let connection = db(dir);
    let mut stmt = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |row| (0..n).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn no_canaries(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(OLD));
        assert!(!text.contains(NEW));
        assert!(!text.contains("wk_"));
    }
}
fn replacement_command(
    dir: &Path,
    name: &str,
    project: &str,
    partition: &str,
) -> std::process::Command {
    let mut cmd = wispkey_bin();
    cmd.args([
        "--format",
        "json",
        "replace-value",
        name,
        "--project",
        project,
        "--partition",
        partition,
        "--stdin",
    ])
    .env("WISPKEY_VAULT_PATH", dir)
    .env_remove("WISPKEY_PASSWORD")
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
    fn begin(dir: &Path) -> Self {
        let mut child = ChildGuard(
            replacement_command(dir, "entry", "default", "personal")
                .spawn()
                .unwrap(),
        );
        let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
        let mut ready = String::new();
        stderr.read_line(&mut ready).unwrap();
        assert!(
            ready.starts_with("Ready for complete replacement value"),
            "{ready}"
        );
        Self { child, stderr }
    }
    fn finish(mut self, bytes: &[u8]) -> Output {
        if !bytes.is_empty() {
            self.child
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
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
        let status = self.child.0.wait().unwrap();
        let output = Output {
            status,
            stdout,
            stderr,
        };
        no_canaries(&output);
        output
    }
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    add(dir.path(), "entry", "default", "api_key");
    dir
}
fn injected(dir: &Path) -> Vec<u8> {
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
    output.stdout
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
            "synthetic-provider",
            "--account",
            "synthetic-account",
            "--origin",
            "https://api.example.com",
            "--provider-expiry",
            "non-expiring",
        ],
    )["auth"]
        .clone()
}

#[test]
fn replaces_whole_value_preserving_every_other_column_and_registry_relationship() {
    let dir = fixture();
    let dir = dir.path();
    let auth = register(dir);
    let bundle = json!({"name":"bundle", "project":"default", "partition":"personal", "account":"synthetic-account",
        "alternatives":[{"name":"api", "members":[{"auth_id":auth["id"],"revision":auth["revision"],"role":"api-token"}]}]});
    let path = dir.join("bundle.json");
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let output = run_wispkey(
        dir,
        &["auth", "bundle", "set", "--file", path.to_str().unwrap()],
    );
    assert!(output.status.success());
    db(dir).execute("UPDATE credentials SET origin='https://api.example.com', review_at='2030-01-01T00:00:00Z', last_used_at='2026-01-01T00:00:00Z'", []).unwrap();
    let before = rows(dir, "credentials");
    let registry = rows(dir, "auth_registry");
    let bundles = rows(dir, "auth_bundles");
    let output = Pending::begin(dir).finish(NEW.as_bytes());
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"ok":true})
    );
    let after = rows(dir, "credentials");
    // Compare all columns by their schema name: newly added unrelated columns are covered too.
    let connection = db(dir);
    let stmt = connection.prepare("SELECT * FROM credentials").unwrap();
    for (i, name) in stmt.column_names().iter().enumerate() {
        if !["encrypted_value", "updated_at"].contains(name) {
            assert_eq!(before[0][i], after[0][i], "{name}");
        } else {
            assert_ne!(before[0][i], after[0][i], "{name}");
        }
    }
    assert_eq!(registry, rows(dir, "auth_registry"));
    assert_eq!(bundles, rows(dir, "auth_bundles"));
    assert_eq!(injected(dir), NEW.as_bytes());
    let audit = format!("{:?}", rows(dir, "audit_log"));
    assert!(audit.contains("CredentialValueReplaced"));
    assert!(!audit.contains(OLD) && !audit.contains(NEW) && !audit.contains("wk_"));
}

#[test]
fn generic_json_is_replaced_whole_and_is_not_a_password_field_patch() {
    let dir = fixture();
    let dir = dir.path();
    let json = br#"{"username":"synthetic-user","password":"synthetic-replacement-value-canary","extra":true}"#;
    assert!(Pending::begin(dir).finish(json).status.success());
    assert_eq!(injected(dir), json);
    assert!(Pending::begin(dir).finish(NEW.as_bytes()).status.success());
    assert_eq!(injected(dir), NEW.as_bytes()); // No guessed schema, merge, or retained username.
}

#[test]
fn missing_wrong_partition_and_cross_project_targets_never_upsert() {
    let dir = fixture();
    let dir = dir.path();
    assert!(
        run_wispkey(dir, &["project", "create", "other"])
            .status
            .success()
    );
    add(dir, "entry", "other", "api_key");
    assert!(
        run_wispkey(
            dir,
            &["partition", "create", "wrong", "--project", "default"]
        )
        .status
        .success()
    );
    let before = rows(dir, "credentials");
    for (name, project, partition) in [
        ("missing", "default", "personal"),
        ("entry", "missing", "personal"),
        ("entry", "default", "wrong"),
    ] {
        let output = replacement_command(dir, name, project, partition)
            .output()
            .unwrap();
        assert!(!output.status.success());
        no_canaries(&output);
    }
    assert_eq!(before, rows(dir, "credentials"));
    assert!(Pending::begin(dir).finish(NEW.as_bytes()).status.success());
    let after = rows(dir, "credentials");
    let other_id: String = db(dir).query_row("SELECT c.id FROM credentials c JOIN partitions p ON c.partition_id=p.id JOIN projects pr ON p.project_id=pr.id WHERE pr.name='other'", [], |r|r.get(0)).unwrap();
    let other = |r: &&Vec<SqlValue>| r[0] == SqlValue::Text(other_id.clone());
    assert_eq!(before.iter().find(other), after.iter().find(other));
}

#[test]
fn intervening_concurrent_mutations_including_aba_are_rejected() {
    let dir = fixture();
    let dir = dir.path();
    for sql in [
        "UPDATE credentials SET description='changed'",
        "UPDATE credentials SET name='renamed'",
        "UPDATE credentials SET encrypted_value='changed'",
        "UPDATE credentials SET tags='temporary'; UPDATE credentials SET tags='one,two'",
        "DELETE FROM credentials",
    ] {
        let pending = Pending::begin(dir);
        db(dir).execute_batch(sql).unwrap();
        let changed = rows(dir, "credentials");
        assert!(!pending.finish(NEW.as_bytes()).status.success());
        assert_eq!(changed, rows(dir, "credentials"));
        db(dir).execute("DELETE FROM credentials", []).unwrap();
        add(dir, "entry", "default", "api_key");
    }
}

#[test]
fn concurrent_replacements_only_one_wins() {
    let dir = fixture();
    let dir = dir.path();
    let first = Pending::begin(dir);
    let second = Pending::begin(dir);
    assert!(first.finish(NEW.as_bytes()).status.success());
    let updated = rows(dir, "credentials");
    assert!(!second.finish(b"synthetic-losing-value").status.success());
    assert_eq!(updated, rows(dir, "credentials"));
    assert_eq!(injected(dir), NEW.as_bytes());
}

#[test]
fn revocation_session_lock_and_session_replacement_invalidate_pending_input() {
    let dir = fixture();
    let dir = dir.path();
    let before = rows(dir, "credentials");
    for args in [vec!["lock"], vec!["unlock"]] {
        let pending = Pending::begin(dir);
        assert!(run_wispkey(dir, &args).status.success());
        assert!(!pending.finish(NEW.as_bytes()).status.success());
        assert_eq!(before, rows(dir, "credentials"));
        assert!(run_wispkey(dir, &["unlock"]).status.success());
    }
    register(dir);
    let pending = Pending::begin(dir);
    assert!(
        run_wispkey(dir, &["auth", "revoke", "entry", "--project", "default"])
            .status
            .success()
    );
    let revoked = rows(dir, "credentials");
    assert!(!pending.finish(NEW.as_bytes()).status.success());
    assert_eq!(revoked, rows(dir, "credentials"));
    assert!(
        !replacement_command(dir, "entry", "default", "personal")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn input_errors_and_process_cancellation_never_mutate_the_row() {
    let dir = fixture();
    let dir = dir.path();
    let before = rows(dir, "credentials");
    for value in [&b""[..], &b"\xff"[..], &b"a\0b"[..]] {
        assert!(!Pending::begin(dir).finish(value).status.success());
        assert_eq!(before, rows(dir, "credentials"));
    }
    // Bounded reads may close the pipe before the writer finishes: ignore BrokenPipe.
    let mut pending = Pending::begin(dir);
    let _ = pending
        .child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&vec![b'x'; 1024 * 1024 + 1]);
    assert!(!pending.finish(b"").status.success());
    assert_eq!(before, rows(dir, "credentials"));
    drop(Pending::begin(dir)); // owner aborts while input is pending
    assert_eq!(before, rows(dir, "credentials"));
    let output = wispkey_bin()
        .args([
            "replace-value",
            "entry",
            "--project",
            "default",
            "--partition",
            "personal",
        ])
        .env("WISPKEY_VAULT_PATH", dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    no_canaries(&output);
    assert_eq!(before, rows(dir, "credentials"));
}

#[test]
fn structured_login_rejected_and_basic_auth_requires_complete_pair() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    init_vault(dir);
    assert!(
        run_wispkey(
            dir,
            &[
                "login",
                "generate",
                "entry",
                "--username",
                "synthetic-user",
                "--url",
                "https://api.example.com",
                "--project",
                "default"
            ]
        )
        .status
        .success()
    );
    let before = rows(dir, "credentials");
    let output = replacement_command(dir, "entry", "default", "personal")
        .output()
        .unwrap();
    assert!(!output.status.success());
    no_canaries(&output);
    assert_eq!(before, rows(dir, "credentials"));
    db(dir).execute("DELETE FROM credentials", []).unwrap();
    add(dir, "entry", "default", "basic_auth");
    let before = rows(dir, "credentials");
    for value in [NEW, ":password", "user:", "user:pass\r\nInjected: header"] {
        assert!(
            !Pending::begin(dir)
                .finish(value.as_bytes())
                .status
                .success()
        );
        assert_eq!(before, rows(dir, "credentials"));
    }
    assert!(
        Pending::begin(dir)
            .finish(b"synthetic-user:synthetic-password")
            .status
            .success()
    );
}

#[test]
fn audit_failure_rolls_back_ciphertext_and_timestamp() {
    let dir = fixture();
    let dir = dir.path();
    db(dir).execute_batch("CREATE TRIGGER fail_replacement_audit BEFORE INSERT ON audit_log WHEN NEW.event_type='CredentialValueReplaced' BEGIN SELECT RAISE(ABORT, 'synthetic-replacement-value-canary'); END").unwrap();
    let before = rows(dir, "credentials");
    let output = Pending::begin(dir).finish(NEW.as_bytes());
    assert!(!output.status.success());
    no_canaries(&output);
    assert_eq!(before, rows(dir, "credentials"));
}

#[test]
fn expired_auth_and_corrupt_registry_marker_cannot_be_replaced() {
    let dir = fixture();
    let dir = dir.path();
    register(dir);
    db(dir).execute("UPDATE auth_registry SET metadata_json=json_set(metadata_json,'$.use_until','2000-01-01T00:00:00Z')", []).unwrap();
    let before = rows(dir, "credentials");
    assert!(
        !replacement_command(dir, "entry", "default", "personal")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
    db(dir).execute("DELETE FROM auth_registry", []).unwrap();
    assert!(
        !replacement_command(dir, "entry", "default", "personal")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(before, rows(dir, "credentials"));
}
