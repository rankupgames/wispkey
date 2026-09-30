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
    requests: Vec<(String, String)>,
    lose_ack: bool,
    expired: bool,
    corrupt: bool,
    before_download: Option<Box<dyn FnOnce() + Send>>,
    before_upload_ack: Option<Box<dyn FnOnce() + Send>>,
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
    state.requests.push((method.clone(), path.clone()));
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
    if path == "/api/v1/billing/status" {
        return reply(
            200,
            &json!({"data":{"clerkUserId":owner,"sessionClaims":{"plan":"cloud","features":["cloud_sync"]}}})
                .to_string()
                .into_bytes(),
            None,
        );
    }
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
        if let Some(callback) = state.before_upload_ack.take() {
            callback();
        }
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

#[test]
fn registered_auth_roundtrip_preserves_revocation_and_final_deletion() {
    let server = Server::new();
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    for dir in [&source, &destination] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    add(source.path(), "cloud-auth", SECRET, "personal");
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "auth",
            "register",
            "cloud-auth",
            "--project",
            "default",
            "--provider",
            "synthetic-provider",
            "--account",
            "synthetic-account",
            "--origin",
            "https://api.example.test",
            "--provider-expiry",
            "non-expiring",
            "--use-until",
            "2000-01-01T00:00:00Z",
        ],
    );
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "auth",
            "revoke",
            "cloud-auth",
            "--project",
            "default",
        ],
    );
    let original = run_wispkey_json(source.path(), &["--format", "json", "auth", "list"]);
    assert_eq!(
        transfer(source.path(), "push")["partitions"][0]["outcome"],
        "uploaded"
    );
    assert_eq!(
        transfer(destination.path(), "pull")["partitions"][0]["outcome"],
        "downloaded"
    );
    let restored = run_wispkey_json(destination.path(), &["--format", "json", "auth", "list"]);
    assert_eq!(original, restored);
    assert!(!restored["credentials"][0]["auth"]["revoked_at"].is_null());
    assert_eq!(
        transfer(destination.path(), "pull")["partitions"][0]["outcome"],
        "unchanged"
    );
    for record in server.state.lock().unwrap().records.values() {
        assert!(
            !record
                .bytes
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
    }

    run_wispkey_json(source.path(), &["--format", "json", "remove", "cloud-auth"]);
    assert_eq!(
        transfer(source.path(), "push")["partitions"][0]["outcome"],
        "uploaded"
    );
    assert_eq!(
        transfer(destination.path(), "pull")["partitions"][0]["outcome"],
        "downloaded"
    );
    let empty = run_wispkey_json(destination.path(), &["--format", "json", "auth", "list"]);
    assert!(empty["credentials"].as_array().unwrap().is_empty());
}

#[cfg(not(feature = "experimental-sync"))]
#[test]
fn foreground_watch_is_unavailable_without_experimental_feature() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_wispkey(
        dir.path(),
        &["cloud", "watch", "personal", "--for-seconds", "1"],
    );
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("unrecognized subcommand") || diagnostic.contains("experimental-sync")
    );
    assert!(!dir.path().join("vault.db").exists());
}

#[cfg(feature = "experimental-sync")]
mod foreground_watch {
    use super::*;
    use std::process::{Command, Output, Stdio};
    use std::time::Instant;

    fn command(path: &Path, args: &[&str]) -> Command {
        let mut command = wispkey_bin();
        command
            .args(args)
            .env("WISPKEY_VAULT_PATH", path)
            // Intentionally present: watch must never use this to unlock a vault.
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_BUNDLE_PASSPHRASE")
            .env_remove("WISPKEY_PROJECT")
            .env_remove("WISPKEY_SESSION_TIMEOUT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn initialize(server: &Server, path: &Path) {
        let output = command(path, &["init"]).output().unwrap();
        assert_success(&output);
        server.configure(path);
        write_private_test_file(&path.join("watch-passphrase"), TEST_BUNDLE_PASSPHRASE);
    }

    fn watch_command(path: &Path, seconds: &str) -> Command {
        command(
            path,
            &[
                "--format",
                "json",
                "cloud",
                "watch",
                "personal",
                "--bundle-passphrase-file",
                path.join("watch-passphrase").to_str().unwrap(),
                "--for-seconds",
                seconds,
            ],
        )
    }

    fn finish(child: &mut ChildGuard) -> Output {
        let status = wait_for_child_exit(&mut child.0, Duration::from_secs(20))
            .expect("bounded foreground watch failed to terminate");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn watch(path: &Path) -> Output {
        let mut child = ChildGuard(watch_command(path, "5").spawn().unwrap());
        finish(&mut child)
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "command failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_redacted(output);
    }

    fn assert_redacted(output: &Output) {
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for secret in [
                SECRET,
                SESSION,
                SECOND_SESSION,
                "test-password",
                TEST_BUNDLE_PASSPHRASE,
            ] {
                assert!(
                    !text.contains(secret),
                    "watch output disclosed synthetic secret material"
                );
            }
        }
    }

    fn journal(path: &Path) -> Value {
        let db = rusqlite::Connection::open(path.join("vault.db")).unwrap();
        let raw: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key LIKE 'cloud_sync_v1:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn tracked_pair() -> (Server, tempfile::TempDir, tempfile::TempDir) {
        let server = Server::new();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for dir in [&first, &second] {
            initialize(&server, dir.path());
        }
        add(first.path(), "base-key", SECRET, "personal");
        transfer(first.path(), "push");
        transfer(second.path(), "pull");
        (server, first, second)
    }

    #[test]
    fn two_clients_propagate_encrypted_edits_deletions_and_auth_revocation() {
        let (server, first, second) = tracked_pair();
        add(first.path(), "cloud-auth", SECRET, "personal");
        run_wispkey_json(
            first.path(),
            &[
                "--format",
                "json",
                "auth",
                "register",
                "cloud-auth",
                "--project",
                "default",
                "--provider",
                "synthetic-provider",
                "--account",
                "synthetic-account",
                "--origin",
                "https://api.example.test",
                "--provider-expiry",
                "non-expiring",
                "--use-until",
                "2099-01-01T00:00:00Z",
            ],
        );
        let original_token = run_wispkey_json(
            first.path(),
            &["--format", "json", "get", "base-key", "--show-token"],
        )["credential"]["wisp_token"]
            .clone();
        let rotated = run_wispkey_json(first.path(), &[
            "--format", "json", "rotate", "base-key",
        ])["wisp_token"].clone();
        assert_ne!(rotated, original_token);
        assert_success(&watch(first.path()));
        assert_success(&watch(second.path()));
        assert_eq!(
            run_wispkey_json(
                second.path(),
                &["--format", "json", "get", "base-key", "--show-token",]
            )["credential"]["wisp_token"],
            rotated
        );
        verify_secret(second.path(), "base-key", SECRET);
        verify_secret(second.path(), "cloud-auth", SECRET);

        run_wispkey_json(second.path(), &["--format", "json", "remove", "base-key"]);
        run_wispkey_json(
            second.path(),
            &[
                "--format",
                "json",
                "auth",
                "revoke",
                "cloud-auth",
                "--project",
                "default",
            ],
        );
        assert_success(&watch(second.path()));
        assert_success(&watch(first.path()));
        let first_auth = run_wispkey_json(first.path(), &["--format", "json", "auth", "list"]);
        let second_auth = run_wispkey_json(second.path(), &["--format", "json", "auth", "list"]);
        assert_eq!(first_auth, second_auth);
        assert!(!first_auth["credentials"][0]["auth"]["revoked_at"].is_null());
        assert_eq!(credential_names(&first_auth), vec!["cloud-auth"]);
        for dir in [&first, &second] {
            let output = command(
                dir.path(),
                &["exec", "--credential", "cloud-auth", "--stdin", "--"],
            )
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "decrypted_cloud_secret_child"])
            .env("WK_EXPECTED_HASH", hash(format!("{SECRET}\n").as_bytes()))
            .output()
            .unwrap();
            assert!(!output.status.success(), "revoked credential was released");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .to_lowercase()
                    .contains("revok")
            );
            assert_redacted(&output);
        }
        for record in server.state.lock().unwrap().records.values() {
            assert!(record.bytes.starts_with(b"WKCS"));
            assert!(
                !record
                    .bytes
                    .windows(SECRET.len())
                    .any(|bytes| bytes == SECRET.as_bytes())
            );
        }
        for dir in [&first, &second] {
            let report = status(dir.path());
            assert_eq!(report["partitions"][0]["local_changes_pending"], false);
            assert_eq!(report["partitions"][0]["remote_changes_pending"], false);
        }
    }

    #[test]
    fn simultaneous_watches_propagate_an_edit_before_either_process_exits() {
        let (server, first, second) = tracked_pair();
        let requests_before = server.state.lock().unwrap().requests.len();
        let mut first_watch = ChildGuard(watch_command(first.path(), "10").spawn().unwrap());
        let mut second_watch = ChildGuard(watch_command(second.path(), "10").spawn().unwrap());
        let startup_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let verified_accounts = server.state.lock().unwrap().requests[requests_before..]
                .iter()
                .filter(|(method, path)| method == "GET" && path == "/api/v1/billing/status")
                .count();
            if verified_accounts == 2 {
                break;
            }
            assert!(
                Instant::now() < startup_deadline,
                "both watches did not verify their account"
            );
            assert!(
                first_watch.0.try_wait().unwrap().is_none(),
                "first watch exited during startup"
            );
            assert!(
                second_watch.0.try_wait().unwrap().is_none(),
                "second watch exited during startup"
            );
            thread::sleep(Duration::from_millis(20));
        }
        add(first.path(), "live-edit", "synthetic-live-edit", "personal");
        let deadline = Instant::now() + Duration::from_secs(7);
        let destination = rusqlite::Connection::open(second.path().join("vault.db")).unwrap();
        loop {
            let count: i64 = destination
                .query_row(
                    "SELECT COUNT(*) FROM credentials WHERE name = 'live-edit'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if count == 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "concurrent reader never received the live edit"
            );
            assert!(
                first_watch.0.try_wait().unwrap().is_none(),
                "writer stopped before propagation"
            );
            assert!(
                second_watch.0.try_wait().unwrap().is_none(),
                "reader stopped before propagation"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            first_watch.0.try_wait().unwrap().is_none(),
            "writer exited before the live assertion"
        );
        assert!(
            second_watch.0.try_wait().unwrap().is_none(),
            "reader exited before the live assertion"
        );
        verify_secret(second.path(), "live-edit", "synthetic-live-edit");
        assert_success(&finish(&mut first_watch));
        assert_success(&finish(&mut second_watch));
        assert_eq!(server.state.lock().unwrap().uploads.len(), 2);
    }

    #[test]
    fn polling_uploads_an_edit_made_after_watch_started() {
        let (server, first, _second) = tracked_pair();
        let (requests_before, uploads_before) = {
            let state = server.state.lock().unwrap();
            (state.requests.len(), state.uploads.len())
        };
        let mut child = ChildGuard(watch_command(first.path(), "5").spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let reached_first_poll = server.state.lock().unwrap().requests[requests_before..]
                .iter()
                .any(|(method, path)| method == "GET" && path.starts_with("/api/v1/partitions/"));
            if reached_first_poll {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "watch did not poll the acknowledged partition"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "watch exited before its first poll"
            );
            thread::sleep(Duration::from_millis(20));
        }
        add(
            first.path(),
            "while-watching",
            "synthetic-later-edit",
            "personal",
        );
        assert_success(&finish(&mut child));
        let state = server.state.lock().unwrap();
        assert_eq!(
            state.uploads.len(),
            uploads_before + 1,
            "periodic watch missed the later edit"
        );
        assert!(
            state.requests[requests_before..]
                .iter()
                .filter(|(method, path)| method == "GET" && path.starts_with("/api/v1/partitions/"))
                .count()
                >= 2,
            "watch never performed a later poll"
        );
    }

    #[test]
    fn locked_watch_never_uses_password_environment_to_unlock_or_contact_cloud() {
        let (server, first, _second) = tracked_pair();
        assert_success(&command(first.path(), &["lock"]).output().unwrap());
        let before = server.state.lock().unwrap().requests.len();
        let output = watch(first.path());
        assert!(!output.status.success());
        assert_redacted(&output);
        assert!(
            !first.path().join("session").exists(),
            "watch reminted a revoked session"
        );
        assert_eq!(server.state.lock().unwrap().requests.len(), before);
    }

    #[test]
    fn untracked_partition_requires_a_manually_acknowledged_baseline() {
        let server = Server::new();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for dir in [&first, &second] {
            initialize(&server, dir.path());
        }
        add(first.path(), "remote-only", SECRET, "personal");
        transfer(first.path(), "push");
        let before = server.state.lock().unwrap().requests.len();
        let output = watch(second.path());
        assert!(!output.status.success());
        assert_redacted(&output);
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_lowercase();
        assert!(
            diagnostic.contains("manual")
                || diagnostic.contains("acknowledg")
                || diagnostic.contains("untracked"),
            "missing first-use guidance: {diagnostic}"
        );
        assert!(
            credential_names(&run_wispkey_json(
                second.path(),
                &["--format", "json", "list"]
            ))
            .is_empty()
        );
        let state = server.state.lock().unwrap();
        assert_eq!(state.uploads.len(), 1);
        assert!(
            !state.requests[before..]
                .iter()
                .any(|(method, path)| method == "PUT" || path.ends_with("/payload"))
        );
    }

    #[test]
    fn watch_requires_a_protected_passphrase_file_and_bounded_duration() {
        let (server, first, _second) = tracked_pair();
        let before = server.state.lock().unwrap().requests.len();
        let output = command(
            first.path(),
            &["cloud", "watch", "personal", "--for-seconds", "1"],
        )
        .env("WISPKEY_BUNDLE_PASSPHRASE", TEST_BUNDLE_PASSPHRASE)
        .output()
        .unwrap();
        assert!(
            !output.status.success(),
            "watch accepted environment-only bundle credentials"
        );
        assert_redacted(&output);
        for invalid in ["0", "3601"] {
            let output = watch_command(first.path(), invalid).output().unwrap();
            assert!(
                !output.status.success(),
                "watch accepted an out-of-range duration"
            );
            assert_redacted(&output);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                first.path().join("watch-passphrase"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            let output = watch(first.path());
            assert!(
                !output.status.success(),
                "watch accepted a public passphrase file"
            );
            assert_redacted(&output);
        }
        assert_eq!(server.state.lock().unwrap().requests.len(), before);
    }

    #[test]
    fn watch_rejects_an_unbounded_vault_session() {
        let (server, first, _second) = tracked_pair();
        assert_success(
            &command(first.path(), &["unlock", "--timeout", "0"])
                .output()
                .unwrap(),
        );
        let before = server.state.lock().unwrap().requests.len();
        let output = watch(first.path());
        assert!(
            !output.status.success(),
            "watch accepted a session with no expiry"
        );
        assert_redacted(&output);
        assert_eq!(server.state.lock().unwrap().requests.len(), before);
    }

    #[test]
    fn concurrent_edits_remain_visible_and_neither_side_is_overwritten() {
        let (server, first, second) = tracked_pair();
        add(
            first.path(),
            "remote-change",
            "synthetic-remote-change",
            "personal",
        );
        add(
            second.path(),
            "local-change",
            "synthetic-local-change",
            "personal",
        );
        assert_success(&watch(first.path()));
        let uploads = server.state.lock().unwrap().uploads.len();
        let before = journal(second.path());
        let output = watch(second.path());
        assert!(
            !output.status.success(),
            "conflicting watch claimed success"
        );
        assert_redacted(&output);
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_lowercase();
        assert!(
            diagnostic.contains("conflict"),
            "watch hid the conflict: {diagnostic}"
        );
        assert_eq!(status(second.path())["partitions"][0]["conflict"], true);
        assert_eq!(journal(second.path())["revision"], before["revision"]);
        assert_eq!(server.state.lock().unwrap().uploads.len(), uploads);
        verify_secret(second.path(), "local-change", "synthetic-local-change");
        verify_secret(first.path(), "remote-change", "synthetic-remote-change");
        assert!(
            !run_wispkey(second.path(), &["get", "remote-change"])
                .status
                .success()
        );
        assert!(
            !run_wispkey(first.path(), &["get", "local-change"])
                .status
                .success()
        );
    }

    fn rejects_changed_authority_before_import(change: &'static str) {
        let (server, first, second) = tracked_pair();
        add(
            first.path(),
            "remote-change",
            "synthetic-remote-change",
            "personal",
        );
        transfer(first.path(), "push");
        let before = journal(second.path());
        let destination = second.path().to_path_buf();
        let url = server.url.clone();
        let callback_ran = Arc::new(AtomicBool::new(false));
        let callback_marker = callback_ran.clone();
        server.state.lock().unwrap().before_download = Some(Box::new(move || {
            match change {
                "lock" => assert_success(&command(&destination, &["lock"]).output().unwrap()),
                "account" => write_private_test_file(&destination.join("cloud.json"), &json!({
                    "api_url":url,"clerk_session_token":SECOND_SESSION,"user_id":"second-account",
                    "org_id":null,"tier":"Cloud","last_sync":null,
                }).to_string()),
                "project" => {
                    assert_success(&command(&destination, &["project", "create", "isolated"]).output().unwrap());
                    assert_success(&command(&destination, &["project", "use", "isolated"]).output().unwrap());
                }
                "session" => assert_success(&command(&destination, &["unlock", "--timeout", "30"]).output().unwrap()),
                _ => unreachable!(),
            }
            callback_marker.store(true, Ordering::SeqCst);
        }));
        // Authority rejection is the event under test, not a short transfer deadline.
        // In particular, renewing a session performs Argon2 work inside the callback;
        // let it finish even when other crypto-heavy tests are running in parallel.
        let mut child = ChildGuard(watch_command(second.path(), "30").spawn().unwrap());
        let output = finish(&mut child);
        assert!(
            callback_ran.load(Ordering::SeqCst),
            "download guard fixture was not exercised"
        );
        assert!(
            !output.status.success(),
            "watch accepted changed {change} authority"
        );
        assert_redacted(&output);
        if change == "lock" {
            assert!(
                !second.path().join("session").exists(),
                "watch unlocked after explicit lock"
            );
            assert_success(
                &command(second.path(), &["unlock", "--timeout", "30"])
                    .output()
                    .unwrap(),
            );
        }
        let after = journal(second.path());
        for field in ["revision", "local_hash", "last_success"] {
            assert_eq!(
                after[field], before[field],
                "watch acknowledged remote data after {change}"
            );
        }
        let list = run_wispkey_json(
            second.path(),
            &["--format", "json", "list", "--project", "default"],
        );
        assert_eq!(
            credential_names(&list),
            vec!["base-key"],
            "watch imported after {change}"
        );
        assert_eq!(server.state.lock().unwrap().uploads.len(), 2);
    }

    #[test]
    fn locking_during_download_prevents_import() {
        rejects_changed_authority_before_import("lock");
    }

    #[test]
    fn account_switch_during_download_prevents_import() {
        rejects_changed_authority_before_import("account");
    }

    #[test]
    fn active_project_switch_during_download_prevents_import() {
        rejects_changed_authority_before_import("project");
    }

    #[test]
    fn session_renewal_during_download_prevents_import() {
        rejects_changed_authority_before_import("session");
    }

    #[test]
    fn duration_deadline_cancels_in_flight_download_without_import_or_acknowledgement() {
        let (server, first, second) = tracked_pair();
        add(
            first.path(),
            "remote-change",
            "synthetic-remote-change",
            "personal",
        );
        transfer(first.path(), "push");
        let before = journal(second.path());
        let download_started = Arc::new(AtomicBool::new(false));
        let callback_marker = download_started.clone();
        server.state.lock().unwrap().before_download = Some(Box::new(move || {
            callback_marker.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(3));
        }));
        let started = Instant::now();
        let mut child = ChildGuard(watch_command(second.path(), "1").spawn().unwrap());
        let output = finish(&mut child);
        assert!(
            download_started.load(Ordering::SeqCst),
            "deadline did not interrupt a real download"
        );
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "watch waited beyond its deadline for the stalled download"
        );
        assert_redacted(&output);
        let after = journal(second.path());
        for field in ["revision", "local_hash", "last_success"] {
            assert_eq!(
                after[field], before[field],
                "deadline incorrectly acknowledged remote data"
            );
        }
        assert_eq!(
            credential_names(&run_wispkey_json(
                second.path(),
                &["--format", "json", "list"]
            )),
            vec!["base-key"]
        );
    }

    #[test]
    fn upload_deadline_preserves_pending_ciphertext_for_manual_reconciliation() {
        let (server, first, _second) = tracked_pair();
        add(
            first.path(),
            "local-edit",
            "synthetic-local-edit",
            "personal",
        );
        let upload_accepted = Arc::new(AtomicBool::new(false));
        let callback_marker = upload_accepted.clone();
        server.state.lock().unwrap().before_upload_ack = Some(Box::new(move || {
            callback_marker.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(6));
        }));
        let before = journal(first.path());
        let stopped = watch(first.path());
        assert_success(&stopped);
        assert!(
            upload_accepted.load(Ordering::SeqCst),
            "deadline did not interrupt a real upload"
        );
        let report: Value = serde_json::from_slice(&stopped.stdout).unwrap();
        assert_eq!(report["watch"]["stopped"], "duration");
        assert_eq!(report["watch"]["reconciliation_required"], true);
        assert_eq!(journal(first.path())["revision"], before["revision"]);
        assert!(!journal(first.path())["pending"].is_null());
        let uploads = server.state.lock().unwrap().uploads.len();
        assert_eq!(uploads, 2, "fixture never accepted the uncertain upload");
        let rejected = watch(first.path());
        assert!(
            !rejected.status.success(),
            "watch silently enrolled an uncertain baseline"
        );
        assert_redacted(&rejected);
        assert_eq!(server.state.lock().unwrap().uploads.len(), uploads);
        transfer(first.path(), "push");
        assert!(journal(first.path())["pending"].is_null());
        let state = server.state.lock().unwrap();
        assert_eq!(state.uploads.len(), uploads + 1);
        assert_eq!(
            state.uploads[1], state.uploads[2],
            "manual reconciliation changed uncertain ciphertext"
        );
    }

    #[test]
    fn revoked_cloud_authentication_stops_watch_without_echoing_server_secrets() {
        let (server, first, _second) = tracked_pair();
        let before = journal(first.path());
        let uploads = server.state.lock().unwrap().uploads.len();
        add(
            first.path(),
            "pending-local",
            "synthetic-pending-local",
            "personal",
        );
        server.state.lock().unwrap().expired = true;
        let output = watch(first.path());
        assert!(!output.status.success());
        assert_redacted(&output);
        assert_eq!(server.state.lock().unwrap().uploads.len(), uploads);
        assert_eq!(journal(first.path())["revision"], before["revision"]);
        verify_secret(first.path(), "pending-local", "synthetic-pending-local");
    }
}
