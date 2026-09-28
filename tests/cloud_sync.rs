mod common;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use common::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    net::TcpListener,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

const SECRET: &str = "synthetic-cloud-secret-canary";
const SESSION: &str = "synthetic-session-canary";
const SECOND_SESSION: &str = "synthetic-second-session-canary";

fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Record {
    owner: &'static str,
    metadata: Value,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct ServerState {
    records: BTreeMap<String, Record>,
    uploads: Vec<Value>,
    lose_ack: bool,
    expired: bool,
    corrupt: bool,
    before_download: Option<Box<dyn FnOnce() + Send>>,
}
struct Server {
    url: String,
    state: Arc<Mutex<ServerState>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(ServerState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let state_worker = state.clone();
        let stop_worker = stop.clone();
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    while !stop_worker.load(Ordering::Relaxed) {
                        if let Ok(Ok((stream, _))) =
                            tokio::time::timeout(Duration::from_millis(25), listener.accept()).await
                        {
                            let state = state_worker.clone();
                            tokio::spawn(async move {
                                let service = hyper::service::service_fn(move |request| {
                                    handle(request, state.clone())
                                });
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .keep_alive(false)
                                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                                    .await;
                            });
                        }
                    }
                });
        });
        Self {
            url,
            state,
            stop,
            worker: Some(worker),
        }
    }
    fn configure(&self, path: &Path) {
        self.configure_account(path, "fixture-account", SESSION);
    }
    fn configure_account(&self, path: &Path, account: &str, session: &str) {
        write_private_test_file(&path.join("cloud.json"), &json!({"api_url":self.url,"clerk_session_token":session,"user_id":account,"org_id":null,"tier":"Cloud","last_sync":null}).to_string());
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

async fn handle(
    request: hyper::Request<hyper::body::Incoming>,
    state: Arc<Mutex<ServerState>>,
) -> std::io::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>> {
    use http_body_util::BodyExt;
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let headers: BTreeMap<String, String> = request
        .headers()
        .iter()
        .map(|(key, value)| (key.as_str().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(std::io::Error::other)?
        .to_bytes();
    let mut state = state.lock().unwrap();
    let authorization = headers.get("authorization").map(String::as_str);
    let owner = if authorization == Some(format!("Bearer {SESSION}").as_str()) {
        Some("fixture-account")
    } else if authorization == Some(format!("Bearer {SECOND_SESSION}").as_str()) {
        Some("second-account")
    } else {
        None
    };
    if state.expired || owner.is_none() {
        return reply(
            401,
            &json!({"error":format!("{SECRET} {SESSION}")})
                .to_string()
                .into_bytes(),
            None,
        );
    }
    let owner = owner.unwrap();
    if path == "/api/v1/partitions" {
        let rows: Vec<_> = state
            .records
            .values()
            .filter(|record| record.owner == owner)
            .map(|record| record.metadata.clone())
            .collect();
        return reply(200, &json!({"data":rows}).to_string().into_bytes(), None);
    }
    let id = path
        .trim_start_matches("/api/v1/partitions/")
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    if state
        .records
        .get(&id)
        .is_some_and(|record| record.owner != owner)
    {
        return reply(404, b"missing", None);
    }
    if path.ends_with("/payload")
        && let Some(callback) = state.before_download.take()
    {
        callback();
    }
    if method == "PUT" {
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(!body.to_string().contains(SECRET));
        assert!(!body.to_string().contains("test-password"));
        state.uploads.push(body.clone());
        if let Some(record) = state.records.get(&id) {
            if record.metadata["last_mutation_id"] == body["mutationId"] {
                return reply(
                    200,
                    &json!({"data":record.metadata}).to_string().into_bytes(),
                    None,
                );
            }
            if headers.get("if-match")
                != Some(&format!(
                    "\"{}\"",
                    record.metadata["revision"].as_str().unwrap()
                ))
            {
                return reply(409, b"conflict", None);
            }
        } else if headers.get("if-none-match").map(String::as_str) != Some("*") {
            return reply(409, b"conflict", None);
        }
        let bytes = BASE64
            .decode(body["encryptedPayloadBase64"].as_str().unwrap())
            .unwrap();
        assert_eq!(hash(&bytes), body["contentHash"]);
        let metadata = json!({"id":id,"revision":uuid::Uuid::new_v4().to_string(),"content_hash":hash(&bytes),"size_bytes":bytes.len(),"last_mutation_id":body["mutationId"]});
        state.records.insert(
            id,
            Record {
                owner,
                metadata: metadata.clone(),
                bytes,
            },
        );
        if state.lose_ack {
            state.lose_ack = false;
            return Err(std::io::Error::other("synthetic lost acknowledgement"));
        }
        reply(
            200,
            &json!({"data":metadata}).to_string().into_bytes(),
            None,
        )
    } else if let Some(record) = state.records.get(&id) {
        if path.ends_with("/payload") {
            let revision = format!("\"{}\"", record.metadata["revision"].as_str().unwrap());
            if headers.get("if-match") != Some(&revision) {
                return reply(409, b"conflict", None);
            }
            let mut bytes = record.bytes.clone();
            if state.corrupt {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            reply(200, &bytes, Some(&revision))
        } else {
            reply(
                200,
                &json!({"data":record.metadata}).to_string().into_bytes(),
                None,
            )
        }
    } else {
        reply(404, b"missing", None)
    }
}
fn reply(
    status: u16,
    bytes: &[u8],
    etag: Option<&str>,
) -> std::io::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>> {
    let mut response = hyper::Response::builder().status(status);
    if let Some(etag) = etag {
        response = response.header("ETag", etag);
    }
    Ok(response
        .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
            bytes,
        )))
        .unwrap())
}

fn add(path: &Path, name: &str, value: &str, partition: &str) {
    let input = path.join("input.txt");
    write_private_test_file(&input, value);
    run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "add",
            name,
            "--value-file",
            input.to_str().unwrap(),
            "--partition",
            partition,
        ],
    );
}
fn transfer(path: &Path, command: &str) -> Value {
    run_wispkey_bundle_json(path, &["--format", "json", "cloud", command, "personal"])
}
fn status(path: &Path) -> Value {
    run_wispkey_json(path, &["--format", "json", "cloud", "status", "--remote"])
}
fn verify_secret(path: &Path, name: &str, expected: &str) {
    let output = wispkey_bin()
        .args(["exec", "--credential", name, "--stdin", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "decrypted_cloud_secret_child"])
        .env("WISPKEY_VAULT_PATH", path)
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_PROTECTOR", "file")
        .env("WK_EXPECTED_HASH", hash(format!("{expected}\n").as_bytes()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "secret handoff validation failed: {} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
}
#[test]
#[ignore = "invoked by cloud round-trip tests with synthetic stdin and expected digest"]
fn decrypted_cloud_secret_child() {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    assert!(
        hash(&bytes) == std::env::var("WK_EXPECTED_HASH").unwrap(),
        "decrypted secret digest differs"
    );
}

#[test]
fn different_accounts_can_sync_the_same_project_and_partition_names() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let first_reader = tempfile::tempdir().unwrap();
    let second_reader = tempfile::tempdir().unwrap();
    for dir in [&first, &first_reader] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    for dir in [&second, &second_reader] {
        init_vault(dir.path());
        server.configure_account(dir.path(), "second-account", SECOND_SESSION);
    }
    add(first.path(), "same-key", SECRET, "personal");
    add(
        second.path(),
        "same-key",
        "synthetic-second-account-value",
        "personal",
    );
    transfer(first.path(), "push");
    transfer(second.path(), "push");
    assert_eq!(server.state.lock().unwrap().records.len(), 2);
    transfer(first_reader.path(), "pull");
    transfer(second_reader.path(), "pull");
    verify_secret(first_reader.path(), "same-key", SECRET);
    verify_secret(
        second_reader.path(),
        "same-key",
        "synthetic-second-account-value",
    );
    for dir in [&first, &second] {
        let report = status(dir.path());
        assert_eq!(report["tracked_partitions"], 1);
        assert_eq!(report["partitions"][0]["local_changes_pending"], false);
        assert_eq!(report["partitions"][0]["remote_changes_pending"], false);
    }
}

#[test]
fn encrypted_roundtrip_preserves_tokens_and_repeated_operations_are_noops() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "cloud-key", SECRET, "personal");
    let token = run_wispkey_json(
        first.path(),
        &["--format", "json", "get", "cloud-key", "--show-token"],
    )["credential"]["wisp_token"]
        .clone();
    let pushed = transfer(first.path(), "push");
    assert_eq!(pushed["partitions"][0]["outcome"], "uploaded");
    assert_eq!(
        transfer(first.path(), "push")["partitions"][0]["outcome"],
        "unchanged"
    );
    assert_eq!(
        transfer(second.path(), "pull")["partitions"][0]["outcome"],
        "downloaded"
    );
    verify_secret(second.path(), "cloud-key", SECRET);
    assert_eq!(
        run_wispkey_json(
            second.path(),
            &["--format", "json", "get", "cloud-key", "--show-token"]
        )["credential"]["wisp_token"],
        token
    );
    assert_eq!(
        transfer(second.path(), "pull")["partitions"][0]["outcome"],
        "unchanged"
    );
    let result = run_wispkey_bundle_json(second.path(), &["--format", "json", "cloud", "sync"]);
    assert_eq!(result["partitions"][0]["outcome"], "unchanged");
    assert_eq!(server.state.lock().unwrap().uploads.len(), 1);
    let report = status(second.path());
    assert_eq!(report["remote_verified"], true);
    assert_eq!(report["partitions"][0]["local_changes_pending"], false);
    assert!(!report.to_string().contains(SECRET));
    assert!(!report.to_string().contains(SESSION));
    add(first.path(), "next-key", "synthetic-next-value", "personal");
    let pushed = run_wispkey_bundle_json(first.path(), &["--format", "json", "cloud", "sync"]);
    assert_eq!(pushed["partitions"][0]["outcome"], "uploaded");
    let pulled = run_wispkey_bundle_json(second.path(), &["--format", "json", "cloud", "sync"]);
    assert_eq!(pulled["partitions"][0]["outcome"], "downloaded");
    verify_secret(second.path(), "next-key", "synthetic-next-value");
}

#[test]
fn interrupted_upload_retries_identical_ciphertext_without_advancing_revision() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    server.configure(dir.path());
    add(dir.path(), "cloud-key", SECRET, "personal");
    server.state.lock().unwrap().lose_ack = true;
    let failed = run_wispkey_bundle(
        dir.path(),
        &["--format", "json", "cloud", "push", "personal"],
    );
    assert!(!failed.status.success());
    assert_eq!(
        status(dir.path())["partitions"][0]["upload_pending"],
        true,
        "failed upload: {}",
        String::from_utf8_lossy(&failed.stdout)
    );
    let revision = server
        .state
        .lock()
        .unwrap()
        .records
        .values()
        .next()
        .unwrap()
        .metadata["revision"]
        .clone();
    let retry = transfer(dir.path(), "push");
    assert_eq!(retry["partitions"][0]["remote_revision"], revision);
    let state = server.state.lock().unwrap();
    assert_eq!(state.uploads.len(), 2);
    assert_eq!(state.uploads[0], state.uploads[1]);
    drop(state);
    assert_eq!(status(dir.path())["partitions"][0]["upload_pending"], false);
    let db = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    let journal: String = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key LIKE 'cloud_sync_v1:%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!journal.contains(SECRET));
    assert!(!journal.contains(SESSION));
    assert!(!journal.contains("test-password"));
}

#[test]
fn concurrent_edits_conflict_and_explicit_remote_resolution_keeps_encrypted_recovery() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "base-key", SECRET, "personal");
    transfer(first.path(), "push");
    transfer(second.path(), "pull");
    add(
        first.path(),
        "remote-change",
        "synthetic-remote-change",
        "personal",
    );
    transfer(first.path(), "push");
    add(
        second.path(),
        "local-change",
        "synthetic-local-change",
        "personal",
    );
    let failed = run_wispkey_bundle(
        second.path(),
        &["--format", "json", "cloud", "push", "personal"],
    );
    assert!(!failed.status.success());
    let report = status(second.path());
    assert_eq!(report["partitions"][0]["conflict"], true);
    let revision = report["partitions"][0]["remote_revision"].as_str().unwrap();
    let stale = run_wispkey_bundle(
        second.path(),
        &[
            "cloud",
            "resolve",
            "personal",
            "--keep",
            "remote",
            "--remote-revision",
            "absent",
        ],
    );
    assert!(!stale.status.success());
    verify_secret(second.path(), "local-change", "synthetic-local-change");
    let resolved = run_wispkey_bundle_json(
        second.path(),
        &[
            "--format",
            "json",
            "cloud",
            "resolve",
            "personal",
            "--keep",
            "remote",
            "--remote-revision",
            revision,
        ],
    );
    let recovery = resolved["partitions"][0]["recovery_path"].as_str().unwrap();
    let bytes = std::fs::read(recovery).unwrap();
    assert!(bytes.starts_with(b"WKCS"));
    assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-local-change"));
    verify_secret(second.path(), "remote-change", "synthetic-remote-change");
    assert!(
        !run_wispkey(second.path(), &["get", "local-change"])
            .status
            .success()
    );
    assert_eq!(status(second.path())["partitions"][0]["conflict"], false);
    let recovered = run_wispkey_bundle_json(
        second.path(),
        &["--format", "json", "cloud", "recover", recovery],
    );
    assert_eq!(recovered["remote_modified"], false);
    verify_secret(second.path(), "local-change", "synthetic-local-change");
    assert_eq!(
        status(second.path())["partitions"][0]["local_changes_pending"],
        true
    );
}

#[test]
fn local_change_during_download_is_not_overwritten() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "remote-key", SECRET, "personal");
    transfer(first.path(), "push");
    let destination = second.path().to_path_buf();
    server.state.lock().unwrap().before_download = Some(Box::new(move || {
        add(
            &destination,
            "new-local-key",
            "synthetic-concurrent-local",
            "personal",
        )
    }));
    assert!(
        !run_wispkey_bundle(second.path(), &["cloud", "pull", "personal"])
            .status
            .success()
    );
    let listed = run_wispkey_json(second.path(), &["--format", "json", "list"]);
    assert_eq!(credential_names(&listed), vec!["new-local-key"]);
    verify_secret(second.path(), "new-local-key", "synthetic-concurrent-local");
}

#[test]
fn explicit_local_resolution_preserves_remote_copy_and_sync_respects_active_project() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "base-key", SECRET, "personal");
    transfer(first.path(), "push");
    transfer(second.path(), "pull");
    add(
        first.path(),
        "remote-only",
        "synthetic-remote-only",
        "personal",
    );
    transfer(first.path(), "push");
    add(
        second.path(),
        "local-only",
        "synthetic-local-only",
        "personal",
    );
    let report = status(second.path());
    let revision = report["partitions"][0]["remote_revision"].as_str().unwrap();
    let resolved = run_wispkey_bundle_json(
        second.path(),
        &[
            "--format",
            "json",
            "cloud",
            "resolve",
            "personal",
            "--keep",
            "local",
            "--remote-revision",
            revision,
        ],
    );
    assert_eq!(resolved["partitions"][0]["outcome"], "uploaded");
    let recovery = resolved["partitions"][0]["recovery_path"].as_str().unwrap();
    transfer(first.path(), "pull");
    verify_secret(first.path(), "local-only", "synthetic-local-only");
    run_wispkey_bundle_json(
        second.path(),
        &["--format", "json", "cloud", "recover", recovery],
    );
    verify_secret(second.path(), "remote-only", "synthetic-remote-only");
    run_wispkey_json(
        second.path(),
        &["--format", "json", "project", "create", "isolated"],
    );
    run_wispkey_json(
        second.path(),
        &["--format", "json", "project", "use", "isolated"],
    );
    let result = run_wispkey_bundle_json(second.path(), &["--format", "json", "cloud", "sync"]);
    assert_eq!(result["partitions"], json!([]));
}

#[test]
fn corrupt_or_wrong_passphrase_downloads_never_modify_the_vault() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "cloud-key", SECRET, "personal");
    transfer(first.path(), "push");
    server.state.lock().unwrap().corrupt = true;
    assert!(
        !run_wispkey_bundle(second.path(), &["cloud", "pull", "personal"])
            .status
            .success()
    );
    server.state.lock().unwrap().corrupt = false;
    assert!(
        !run_wispkey_with_bundle_passphrase(
            second.path(),
            &["cloud", "pull", "personal"],
            "wrong-passphrase-here"
        )
        .status
        .success()
    );
    assert!(
        credential_names(&run_wispkey_json(
            second.path(),
            &["--format", "json", "list"]
        ))
        .is_empty()
    );
    transfer(second.path(), "pull");
    verify_secret(second.path(), "cloud-key", SECRET);
}

#[test]
fn later_import_failure_rolls_back_earlier_rows_and_preserves_other_partitions() {
    let server = Server::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for dir in [&first, &second] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(first.path(), "a-first", SECRET, "personal");
    add(first.path(), "z-collision", SECRET, "personal");
    transfer(first.path(), "push");
    run_wispkey_json(
        second.path(),
        &["--format", "json", "partition", "create", "other"],
    );
    add(
        second.path(),
        "z-collision",
        "synthetic-other-partition",
        "other",
    );
    let output = run_wispkey_bundle(second.path(), &["cloud", "pull", "personal"]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    let personal = run_wispkey_json(
        second.path(),
        &["--format", "json", "list", "--partition", "personal"],
    );
    assert!(credential_names(&personal).is_empty());
    verify_secret(second.path(), "z-collision", "synthetic-other-partition");
    assert!(status(second.path())["partitions"][0]["last_success"].is_null());
}

#[test]
fn expired_authentication_does_not_echo_response_secrets_or_claim_remote_success() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    server.configure(dir.path());
    server.state.lock().unwrap().expired = true;
    let result = run_wispkey(
        dir.path(),
        &["--format", "json", "cloud", "status", "--remote"],
    );
    assert!(!result.status.success());
    for bytes in [&result.stdout, &result.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(SECRET));
        assert!(!text.contains(SESSION));
    }
}
