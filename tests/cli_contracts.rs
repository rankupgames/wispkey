mod common;

use common::*;
use serde_json::{Value, json};

fn add_secret(path: &std::path::Path, name: &str, project: &str) -> Value {
    let secret_path = path.join("synthetic-input.txt");
    write_private_test_file(&secret_path, "synthetic-cli-contract-secret");
    run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "add",
            name,
            "--type",
            "api_key",
            "--value-file",
            secret_path.to_str().unwrap(),
            "--project",
            project,
        ],
    )
}

#[test]
fn legacy_import_json_is_one_document_and_duplicate_retry_preserves_output() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let source = dir.path().join(".env");
    write_private_test_file(
        &source,
        "FIRST_KEY=synthetic-import-one\nSECOND_KEY=synthetic-import-two\n",
    );
    let args = [
        "--format",
        "json",
        "import",
        source.to_str().unwrap(),
        "--prefix",
        "legacy",
    ];
    let first = run_wispkey_json(dir.path(), &args);
    assert_eq!(first["imported"], 2);
    assert_eq!(first["errors"], 0);
    let output = std::fs::read(dir.path().join(".env.wispkey")).unwrap();
    let rendered = String::from_utf8(output.clone()).unwrap();
    assert!(rendered.contains("FIRST_KEY=wk_") && rendered.contains("SECOND_KEY=wk_"));
    assert!(!rendered.contains("synthetic-import-"));
    let retry = run_wispkey_json(dir.path(), &args);
    assert_eq!(retry["imported"], 0);
    assert_eq!(retry["skipped"], 2);
    assert_eq!(
        std::fs::read(dir.path().join(".env.wispkey")).unwrap(),
        output
    );
    assert!(
        std::fs::read_to_string(source)
            .unwrap()
            .contains("synthetic-import-one")
    );
    #[cfg(unix)]
    assert_eq!(file_mode(&dir.path().join(".env.wispkey")), 0o600);
}

#[test]
fn partition_assignment_json_and_deletion_preserve_credentials() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let added = add_secret(dir.path(), "partition-key", "default");
    let token = &added["credential"]["wisp_token"];
    run_wispkey_json(
        dir.path(),
        &["--format", "json", "partition", "create", "production"],
    );
    let assigned = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "assign",
            "partition-key",
            "--to",
            "production",
        ],
    );
    assert_eq!(assigned["ok"], true);
    assert_eq!(assigned["partition"], "production");
    let selected = run_wispkey_json(
        dir.path(),
        &["--format", "json", "list", "--partition", "production"],
    );
    assert_eq!(credential_names(&selected), vec!["partition-key"]);
    run_wispkey_json(
        dir.path(),
        &["--format", "json", "partition", "delete", "production"],
    );
    let moved = run_wispkey_json(
        dir.path(),
        &["--format", "json", "list", "--partition", "personal"],
    );
    assert_eq!(credential_names(&moved), vec!["partition-key"]);
    assert_eq!(&moved["credentials"][0]["wisp_token"], token);
    assert!(
        !run_wispkey(dir.path(), &["partition", "delete", "personal"])
            .status
            .success()
    );
}

#[test]
fn credential_get_rotate_and_remove_are_project_scoped_and_redacted() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    run_wispkey_json(
        dir.path(),
        &["--format", "json", "project", "create", "second"],
    );
    let first = add_secret(dir.path(), "same-key", "default");
    let second = add_secret(dir.path(), "same-key", "second");
    let hidden = run_wispkey_json(dir.path(), &["--format", "json", "get", "same-key"]);
    assert!(hidden["credential"].get("wisp_token").is_none());
    assert!(!hidden.to_string().contains("synthetic-cli-contract-secret"));
    let rotated = run_wispkey_json(dir.path(), &["--format", "json", "rotate", "same-key"]);
    assert_ne!(rotated["wisp_token"], first["credential"]["wisp_token"]);
    let db = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    let old_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE wisp_token=?1",
            [first["credential"]["wisp_token"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_count, 0);
    run_wispkey_json(dir.path(), &["--format", "json", "remove", "same-key"]);
    assert!(
        !run_wispkey(dir.path(), &["get", "same-key"])
            .status
            .success()
    );
    run_wispkey_json(
        dir.path(),
        &["--format", "json", "project", "use", "second"],
    );
    let remaining = run_wispkey_json(
        dir.path(),
        &["--format", "json", "get", "same-key", "--show-token"],
    );
    assert_eq!(
        remaining["credential"]["wisp_token"],
        second["credential"]["wisp_token"]
    );
}

#[test]
fn cloud_status_and_logout_json_report_local_state_without_session_token() {
    let dir = tempfile::tempdir().unwrap();
    let disconnected = run_wispkey_json(dir.path(), &["--format", "json", "cloud", "status"]);
    assert_eq!(disconnected["authenticated"], false);
    assert_eq!(disconnected["sync_available"], true);
    let config = json!({"api_url":"https://example.test/api", "clerk_session_token":"synthetic-session-canary", "user_id":"synthetic-user", "org_id":null, "tier":"Cloud", "last_sync":null});
    write_private_test_file(&dir.path().join("cloud.json"), &config.to_string());
    let connected = run_wispkey_json(dir.path(), &["--format", "json", "cloud", "status"]);
    assert_eq!(connected["authenticated"], true);
    assert_eq!(connected["source"], "local");
    assert_eq!(connected["remote_verified"], false);
    assert!(!connected.to_string().contains("synthetic-session-canary"));
    let logout = run_wispkey_json(dir.path(), &["--format", "json", "cloud", "logout"]);
    assert_eq!(logout["authenticated"], false);
    let stored: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("cloud.json")).unwrap()).unwrap();
    assert!(stored["clerk_session_token"].is_null());
    assert!(stored["user_id"].is_null());
    assert_eq!(stored["tier"], "Personal");
}

#[test]
fn unauthenticated_cloud_sync_does_not_contact_server_or_claim_success() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = json!({"api_url":format!("http://{}", listener.local_addr().unwrap()), "clerk_session_token":null, "user_id":"synthetic-user", "org_id":null, "tier":"Enterprise", "last_sync":null}).to_string();
    write_private_test_file(&dir.path().join("cloud.json"), &config);
    for args in [
        vec!["cloud", "push", "personal"],
        vec!["cloud", "pull", "personal"],
        vec!["cloud", "sync"],
    ] {
        let output = run_wispkey_bundle(dir.path(), &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("not authenticated"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-session-canary"));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("cloud.json")).unwrap(),
        config
    );
    assert!(!dir.path().join("cloud-manifests.json").exists());
}
