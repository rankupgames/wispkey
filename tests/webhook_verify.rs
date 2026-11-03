/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Boundary tests for instance-authenticated Standard Webhooks verification.
 * Created: 2026-11-03
 * Last Modified: 2026-11-03
 */

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::*;
use ring::hmac;

const VERIFY_PATH: &str = "/api/webhooks/verify";
const KEY_A: &[u8] = b"synthetic-webhook-signing-key-01";
const KEY_B: &[u8] = b"synthetic-webhook-signing-key-02";
const MESSAGE_ID: &str = "msg_synthetic_0001";
const BODY: &[u8] = br#"{"event":"synthetic.created","canary":"synthetic-webhook-body-never-log"}"#;
const BODY_CANARY: &str = "synthetic-webhook-body-never-log";
const ABSENT_CREDENTIAL_ID: &str = "2c5ea4c0-4067-41e9-8bad-9b1deb4d3b7d";
const UNKNOWN_INSTANCE_ID: &str = "6b3f2a10-8c7d-4e5f-9a1b-2c3d4e5f6a7b";
const MAX_BODY_BYTES: usize = 1024 * 1024;

const MALFORMED: &str = r#"{"error":"malformed verification request"}"#;
const UNAUTHENTICATED: &str = r#"{"error":"instance authentication failed"}"#;
const FORBIDDEN: &str = r#"{"error":"credential not permitted"}"#;
const TOO_LARGE: &str = r#"{"error":"webhook body too large"}"#;
const UNAVAILABLE: &str = r#"{"error":"verifier unavailable"}"#;
const VALID: &str = r#"{"result":"valid"}"#;
const INVALID: &str = r#"{"result":"invalid"}"#;
const STALE: &str = r#"{"result":"stale"}"#;
const METHOD_NOT_ALLOWED: &str = r#"{"error":"method not allowed"}"#;
const BROWSER_ORIGIN: &str = "https://webhook.invalid";
const WRONG_INSTANCE_SECRET: &str = "synthetic-wrong-instance-secret";

struct Worker {
    id: String,
    secret: String,
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

/// One raw HTTP request to the verifier. Headers are sent in order, so a
/// test can send duplicates, empty values or explicit framing.
#[derive(Clone)]
struct Delivery {
    method: &'static str,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Delivery {
    fn signed(
        worker: &Worker,
        credential_id: &str,
        key: &[u8],
        timestamp: i64,
        body: &[u8],
    ) -> Self {
        let timestamp = timestamp.to_string();
        Self {
            method: "POST",
            target: VERIFY_PATH.to_owned(),
            headers: vec![
                ("x-wispkey-instance-id".into(), worker.id.clone()),
                ("x-wispkey-instance-secret".into(), worker.secret.clone()),
                ("x-wispkey-credential-id".into(), credential_id.to_owned()),
                ("webhook-id".into(), MESSAGE_ID.into()),
                ("webhook-timestamp".into(), timestamp.clone()),
                (
                    "webhook-signature".into(),
                    sign(key, MESSAGE_ID, &timestamp, body),
                ),
            ],
            body: body.to_vec(),
        }
    }

    /// Replaces every value of `name` with one value.
    fn with(self, name: &str, value: &str) -> Self {
        self.without(name).plus(name, value)
    }

    fn without(mut self, name: &str) -> Self {
        self.headers.retain(|(existing, _)| existing != name);
        self
    }

    fn plus(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    fn method(mut self, method: &'static str) -> Self {
        self.method = method;
        self
    }

    fn target(mut self, target: &str) -> Self {
        self.target = target.to_owned();
        self
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn signing_secret(key: &[u8]) -> String {
    format!("whsec_{}", BASE64.encode(key))
}

fn sign(key: &[u8], id: &str, timestamp: &str, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut message = format!("{id}.{timestamp}.").into_bytes();
    message.extend_from_slice(body);
    format!("v1,{}", BASE64.encode(hmac::sign(&key, &message).as_ref()))
}

fn add_key(dir: &Path, name: &str, credential_type: &str, value: &str) -> String {
    let value_file = dir.join(format!("{name}.value"));
    write_private_test_file(&value_file, value);
    let added = run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "add",
            name,
            "--type",
            credential_type,
            "--value-file",
            value_file.to_str().unwrap(),
            "--hosts",
            "webhook-signing.invalid",
        ],
    );
    std::fs::remove_file(&value_file).expect("remove synthetic value file");
    added["credential"]["id"]
        .as_str()
        .expect("credential id")
        .to_owned()
}

fn enroll(dir: &Path, name: &str, credentials: &[&str]) -> Worker {
    let mut args = vec!["--format", "json", "instance", "enroll", name];
    for credential in credentials {
        args.extend(["--credential", credential]);
    }
    let enrolled = run_wispkey_json(dir, &args);
    Worker {
        id: enrolled["id"].as_str().expect("instance id").to_owned(),
        secret: enrolled["secret"]
            .as_str()
            .expect("instance secret")
            .to_owned(),
    }
}

fn run_ok(dir: &Path, args: &[&str]) {
    let output = run_wispkey(dir, args);
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn proxy(dir: &Path) -> (ChildGuard, u16) {
    proxy_in_project(dir, None)
}

fn proxy_in_project(dir: &Path, project: Option<&str>) -> (ChildGuard, u16) {
    let mut command = wispkey_bin();
    if let Some(project) = project {
        command.args(["--project", project]);
    }
    let child = command
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_PROTECTOR", "file")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let info = wait_for_proxy_info(dir);
    (
        ChildGuard(child),
        info["port"].as_u64().expect("proxy port") as u16,
    )
}

fn request_head(delivery: &Delivery) -> Vec<u8> {
    let mut request = format!(
        "{} {} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n",
        delivery.method, delivery.target
    )
    .into_bytes();
    for (name, value) in &delivery.headers {
        request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    let explicit_framing = delivery
        .headers
        .iter()
        .any(|(name, _)| name == "content-length" || name == "transfer-encoding");
    if !explicit_framing {
        let length_header = format!("content-length: {}\r\n", delivery.body.len());
        request.extend_from_slice(length_header.as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    request
}

fn send(port: u16, delivery: &Delivery) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut request = request_head(delivery);
    request.extend_from_slice(&delivery.body);
    // The server can close an oversized request before it reads every byte.
    // The response is still read below, so a write error is not a result.
    let _ = stream.write_all(&request);

    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
    }
    parse_reply(raw)
}

fn parse_reply(raw: Vec<u8>) -> Reply {
    let text = String::from_utf8(raw).expect("utf-8 response");
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("incomplete response: {text:?}"));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status: {head:?}"));
    Reply {
        status,
        head: head.to_ascii_lowercase(),
        body: body.to_owned(),
    }
}

fn assert_reply(port: u16, label: &str, delivery: &Delivery, status: u16, body: &str) -> Reply {
    let reply = send(port, delivery);
    assert_eq!(
        (reply.status, reply.body.as_str()),
        (status, body),
        "{label}"
    );
    assert!(
        reply.head.contains("content-type: application/json")
            && reply.head.contains("cache-control: no-store"),
        "{label}: {}",
        reply.head
    );
    assert!(
        !reply.head.contains("access-control-"),
        "{label}: verifier must not send CORS headers"
    );
    reply
}

fn audit_log(dir: &Path) -> (String, Vec<serde_json::Value>) {
    let output = run_wispkey(dir, &["--format", "json", "log", "--last", "1000"]);
    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let entries = output_json(&["log"], output)["entries"]
        .as_array()
        .expect("audit entries")
        .clone();
    (raw, entries)
}

#[test]
fn verifier_returns_semantic_results_and_fails_closed_at_the_boundary() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let secret_a = signing_secret(KEY_A);
    let raw_key_a = BASE64.encode(KEY_A);
    let signing = add_key(dir.path(), "webhook-a", "api_key", &secret_a);
    let unscoped = add_key(dir.path(), "webhook-unscoped", "api_key", &secret_a);
    let bearer = add_key(dir.path(), "webhook-bearer", "bearer_token", &secret_a);
    let raw_key = add_key(dir.path(), "webhook-raw", "api_key", &raw_key_a);
    let worker = enroll(
        dir.path(),
        "webhook-worker",
        &["webhook-a", "webhook-bearer", "webhook-raw"],
    );
    let other_worker = enroll(dir.path(), "webhook-other", &["webhook-unscoped"]);
    let (_proxy, port) = proxy(dir.path());

    let signed_at = now();
    let base = || Delivery::signed(&worker, &signing, KEY_A, signed_at, BODY);
    let timestamp = signed_at.to_string();
    let signature = sign(KEY_A, MESSAGE_ID, &timestamp, BODY);
    let other_signature = sign(KEY_B, MESSAGE_ID, &timestamp, BODY);
    let second_candidate = format!("{other_signature} {signature}");
    let seventeen = vec![signature.as_str(); 17].join(" ");
    let mut oversized_body = format!("{:x}\r\n", MAX_BODY_BYTES + 1).into_bytes();
    oversized_body.resize(oversized_body.len() + MAX_BODY_BYTES + 1, b'a');
    oversized_body.extend_from_slice(b"\r\n0\r\n\r\n");
    let absolute_target = format!("http://127.0.0.1:{port}{VERIFY_PATH}");
    let query_target = format!("{VERIFY_PATH}?id=1");
    let next_second = (signed_at + 1).to_string();
    let v2_signature = signature.replacen("v1,", "v2,", 1);
    let uppercase_id = signing.to_ascii_uppercase();
    let other_secret = other_worker.secret.as_str();
    let oversized_length = (MAX_BODY_BYTES + 1).to_string();

    let cases: Vec<(&str, Delivery, u16, &str)> = vec![
        ("exact signature", base(), 200, VALID),
        (
            "second candidate",
            base().with("webhook-signature", &second_candidate),
            200,
            VALID,
        ),
        (
            "wrong key",
            Delivery::signed(&worker, &signing, KEY_B, signed_at, BODY),
            200,
            INVALID,
        ),
        (
            "modified id",
            base().with("webhook-id", "msg_synthetic_0002"),
            200,
            INVALID,
        ),
        (
            "modified timestamp",
            base().with("webhook-timestamp", &next_second),
            200,
            INVALID,
        ),
        (
            "modified body",
            base().body(br#"{"event":"synthetic.created"}"#),
            200,
            INVALID,
        ),
        (
            "past timestamp",
            Delivery::signed(&worker, &signing, KEY_A, signed_at - 3600, BODY),
            200,
            STALE,
        ),
        (
            "future timestamp",
            Delivery::signed(&worker, &signing, KEY_A, signed_at + 3600, BODY),
            200,
            STALE,
        ),
        (
            "missing webhook id",
            base().without("webhook-id"),
            400,
            MALFORMED,
        ),
        (
            "empty signature",
            base().with("webhook-signature", ""),
            400,
            MALFORMED,
        ),
        (
            "duplicate timestamp",
            base().plus("webhook-timestamp", &timestamp),
            400,
            MALFORMED,
        ),
        (
            "unsupported version",
            base().with("webhook-signature", &v2_signature),
            400,
            MALFORMED,
        ),
        (
            "invalid base64",
            base().with("webhook-signature", "v1,not-base64!"),
            400,
            MALFORMED,
        ),
        (
            "17 candidates",
            base().with("webhook-signature", &seventeen),
            400,
            MALFORMED,
        ),
        (
            "negative timestamp",
            base().with("webhook-timestamp", "-1"),
            400,
            MALFORMED,
        ),
        (
            "timestamp overflow",
            base().with("webhook-timestamp", "253402300800"),
            400,
            MALFORMED,
        ),
        (
            "non-canonical credential id",
            base().with("x-wispkey-credential-id", &uppercase_id),
            400,
            MALFORMED,
        ),
        (
            "missing credential id",
            base().without("x-wispkey-credential-id"),
            400,
            MALFORMED,
        ),
        ("with query", base().target(&query_target), 400, MALFORMED),
        (
            "absolute target",
            base().target(&absolute_target),
            400,
            MALFORMED,
        ),
        (
            "browser origin",
            base().plus("origin", BROWSER_ORIGIN),
            400,
            MALFORMED,
        ),
        (
            "missing instance",
            base().without("x-wispkey-instance-id"),
            401,
            UNAUTHENTICATED,
        ),
        (
            "unknown instance",
            base().with("x-wispkey-instance-id", UNKNOWN_INSTANCE_ID),
            401,
            UNAUTHENTICATED,
        ),
        (
            "wrong instance secret",
            base().with("x-wispkey-instance-secret", WRONG_INSTANCE_SECRET),
            401,
            UNAUTHENTICATED,
        ),
        (
            "other instance secret",
            base().with("x-wispkey-instance-secret", other_secret),
            401,
            UNAUTHENTICATED,
        ),
        (
            "duplicate instance id",
            base().plus("x-wispkey-instance-id", &worker.id),
            401,
            UNAUTHENTICATED,
        ),
        (
            "out of scope",
            Delivery::signed(&worker, &unscoped, KEY_A, signed_at, BODY),
            403,
            FORBIDDEN,
        ),
        (
            "absent credential",
            Delivery::signed(&worker, ABSENT_CREDENTIAL_ID, KEY_A, signed_at, BODY),
            403,
            FORBIDDEN,
        ),
        (
            "bearer credential",
            Delivery::signed(&worker, &bearer, KEY_A, signed_at, BODY),
            403,
            FORBIDDEN,
        ),
        (
            "secret without whsec prefix",
            Delivery::signed(&worker, &raw_key, KEY_A, signed_at, BODY),
            403,
            FORBIDDEN,
        ),
        (
            "declared oversized body",
            base().body(b"").plus("content-length", &oversized_length),
            413,
            TOO_LARGE,
        ),
        (
            "streamed oversized body",
            base()
                .plus("transfer-encoding", "chunked")
                .body(&oversized_body),
            413,
            TOO_LARGE,
        ),
        (
            "get",
            base().method("GET").body(b""),
            405,
            METHOD_NOT_ALLOWED,
        ),
        (
            "preflight",
            base()
                .method("OPTIONS")
                .body(b"")
                .plus("origin", BROWSER_ORIGIN),
            405,
            METHOD_NOT_ALLOWED,
        ),
    ];

    for (label, delivery, status, body) in &cases {
        let reply = assert_reply(port, label, delivery, *status, body);
        if *status == 405 {
            assert!(reply.head.contains("allow: post"), "{label}");
        }
        for leaked in [
            BODY_CANARY,
            signature.as_str(),
            secret_a.as_str(),
            worker.secret.as_str(),
        ] {
            let lowercase = leaked.to_ascii_lowercase();
            assert!(!reply.head.contains(&lowercase), "{label}");
            assert!(!reply.body.contains(leaked), "{label}");
        }
    }

    let (raw_log, entries) = audit_log(dir.path());
    let principal = format!("instance:{}", worker.id);
    let verified = entries
        .iter()
        .find(|entry| entry["event_type"] == "WebhookVerified")
        .expect("valid result must be audited");
    assert_eq!(verified["credential_name"], signing.as_str());
    assert_eq!(verified["target_host"], principal.as_str());
    assert_eq!(verified["denied"], false);
    for (event, reason) in [
        ("WebhookRejected", "signature_mismatch"),
        ("WebhookRejected", "timestamp_outside_tolerance"),
        ("WebhookDenied", "instance_authentication_failed"),
        ("WebhookDenied", "credential_not_permitted"),
    ] {
        assert!(
            entries
                .iter()
                .any(|entry| entry["event_type"] == event && entry["deny_reason"] == reason),
            "missing {event} {reason}"
        );
    }
    for leaked in [
        BODY_CANARY,
        signature.as_str(),
        other_signature.as_str(),
        secret_a.as_str(),
        raw_key_a.as_str(),
        worker.secret.as_str(),
        other_worker.secret.as_str(),
    ] {
        assert!(!raw_log.contains(leaked), "audit log leaked material");
    }

    run_ok(dir.path(), &["lock"]);
    assert_reply(port, "locked vault", &base(), 503, UNAVAILABLE);
}

#[test]
fn auth_registry_expiry_and_revocation_deny_verification() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let secret_a = signing_secret(KEY_A);
    let active = add_key(dir.path(), "webhook-active", "api_key", &secret_a);
    let expired = add_key(dir.path(), "webhook-expired", "api_key", &secret_a);
    for (name, provider_expiry) in [
        ("webhook-active", "non-expiring"),
        ("webhook-expired", "2000-01-01T00:00:00Z"),
    ] {
        run_ok(
            dir.path(),
            &[
                "auth",
                "register",
                name,
                "--project",
                "default",
                "--provider",
                "fixture",
                "--account",
                "test",
                "--origin",
                "https://127.0.0.1",
                "--provider-expiry",
                provider_expiry,
                "--use-until",
                "2100-01-01T00:00:00Z",
            ],
        );
    }
    let worker = enroll(
        dir.path(),
        "webhook-worker",
        &["webhook-active", "webhook-expired"],
    );
    let (_proxy, port) = proxy(dir.path());
    let signed_at = now();

    let registered = Delivery::signed(&worker, &active, KEY_A, signed_at, BODY);
    assert_reply(port, "registered and usable", &registered, 200, VALID);
    let expired_delivery = Delivery::signed(&worker, &expired, KEY_A, signed_at, BODY);
    assert_reply(port, "provider expired", &expired_delivery, 403, FORBIDDEN);

    run_ok(
        dir.path(),
        &["auth", "revoke", "webhook-active", "--project", "default"],
    );
    assert_reply(port, "auth revoked", &registered, 403, FORBIDDEN);
}

#[test]
fn instance_scope_does_not_override_the_proxy_project() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let signing = add_key(dir.path(), "webhook-a", "api_key", &signing_secret(KEY_A));
    let worker = enroll(dir.path(), "webhook-worker", &["webhook-a"]);
    run_ok(
        dir.path(),
        &["project", "create", "isolated-webhook-project"],
    );
    let (_proxy, port) = proxy_in_project(dir.path(), Some("isolated-webhook-project"));
    let delivery = Delivery::signed(&worker, &signing, KEY_A, now(), BODY);
    assert_reply(port, "different proxy project", &delivery, 403, FORBIDDEN);
    let (_, entries) = audit_log(dir.path());
    assert!(
        !entries
            .iter()
            .any(|row| row["event_type"] == "WebhookVerified")
    );
}

#[test]
fn locking_during_upload_invalidates_the_authenticated_session() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let signing = add_key(dir.path(), "webhook-a", "api_key", &signing_secret(KEY_A));
    let worker = enroll(dir.path(), "webhook-worker", &["webhook-a"]);
    let (_proxy, port) = proxy(dir.path());
    let delivery =
        Delivery::signed(&worker, &signing, KEY_A, now(), BODY).plus("expect", "100-continue");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(&request_head(&delivery)).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "HTTP/1.1 100 Continue\r\n");
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, "\r\n");
    // Hyper emits Continue when the authenticated handler polls the body.
    // Lock only after that signal; no timing assumptions or test-only hooks.
    run_ok(dir.path(), &["lock"]);
    stream.write_all(BODY).unwrap();
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw).unwrap();
    let reply = parse_reply(raw);
    assert_eq!((reply.status, reply.body.as_str()), (503, UNAVAILABLE));
}

#[test]
fn audit_write_failure_prevents_a_valid_acknowledgement() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let signing = add_key(dir.path(), "webhook-a", "api_key", &signing_secret(KEY_A));
    let worker = enroll(dir.path(), "webhook-worker", &["webhook-a"]);
    let (_proxy, port) = proxy(dir.path());
    let delivery = Delivery::signed(&worker, &signing, KEY_A, now(), BODY);
    assert_reply(port, "before audit failure", &delivery, 200, VALID);
    let database = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    database
        .execute_batch(
            "CREATE TRIGGER reject_webhook_audit BEFORE INSERT ON audit_log
         WHEN NEW.event_type = 'WebhookVerified'
         BEGIN SELECT RAISE(FAIL, 'synthetic audit failure'); END;",
        )
        .unwrap();
    assert_reply(port, "audit failure", &delivery, 503, UNAVAILABLE);
    let count: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE event_type = 'WebhookVerified'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn rotation_uses_two_explicit_credentials_without_fallback() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let secret_a = signing_secret(KEY_A);
    let secret_b = signing_secret(KEY_B);
    let old = add_key(dir.path(), "webhook-old", "api_key", &secret_a);
    let new = add_key(dir.path(), "webhook-new", "api_key", &secret_b);
    let worker = enroll(
        dir.path(),
        "webhook-worker",
        &["webhook-old", "webhook-new"],
    );
    let (_proxy, port) = proxy(dir.path());

    let signed_at = now();
    let timestamp = signed_at.to_string();
    let both = format!(
        "{} {}",
        sign(KEY_A, MESSAGE_ID, &timestamp, BODY),
        sign(KEY_B, MESSAGE_ID, &timestamp, BODY)
    );
    let dual = |credential_id: &str| {
        Delivery::signed(&worker, credential_id, KEY_A, signed_at, BODY)
            .with("webhook-signature", &both)
    };
    let new_only_against_old = Delivery::signed(&worker, &old, KEY_B, signed_at, BODY);

    assert_reply(port, "overlap old", &dual(&old), 200, VALID);
    assert_reply(port, "overlap new", &dual(&new), 200, VALID);
    assert_reply(port, "no fallback", &new_only_against_old, 200, INVALID);

    run_wispkey_json(dir.path(), &["--format", "json", "remove", "webhook-old"]);
    assert_reply(port, "old removed", &dual(&old), 403, FORBIDDEN);
    assert_reply(port, "new remains", &dual(&new), 200, VALID);

    run_ok(dir.path(), &["instance", "revoke", "webhook-worker"]);
    assert_reply(port, "instance revoked", &dual(&new), 401, UNAUTHENTICATED);
}
