#![cfg(unix)]

mod common;

use common::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use std::net::TcpListener;

fn start_uds_proxy(vault_dir: &std::path::Path, socket_path: &std::path::Path) -> ChildGuard {
    let child = wispkey_bin()
        .args([
            "serve",
            "--listen",
            &format!("unix:{}", socket_path.display()),
        ])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn uds proxy");
    let _ = wait_for_proxy_info(vault_dir);
    wait_for_socket(socket_path);
    ChildGuard(child)
}

fn wait_for_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if path.exists() {
            return;
        }
        assert!(Instant::now() < deadline, "proxy did not bind unix socket");
        thread::sleep(Duration::from_millis(50));
    }
}

fn send_uds_request(socket_path: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path).expect("connect to uds proxy");
    stream
        .write_all(request.as_bytes())
        .expect("write uds request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read uds response");
    response
}

fn request_with_identity(
    upstream_port: u16,
    token: &str,
    instance_id: &str,
    instance_secret: &str,
) -> String {
    format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         x-wispkey-instance-id: {instance_id}\r\n\
         x-wispkey-instance-secret: {instance_secret}\r\n\
         Connection: close\r\n\r\n"
    )
}

fn request_without_identity(upstream_port: u16, token: &str) -> String {
    format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    )
}

fn join_request(bootstrap_token: &str, name: &str) -> String {
    let body = serde_json::json!({
        "bootstrap_token": bootstrap_token,
        "name": name,
    })
    .to_string();
    format!(
        "POST /api/instances/join HTTP/1.1\r\n\
         Host: wispkey.local\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn assert_injected_over_uds(
    socket_path: &std::path::Path,
    token: &str,
    expected_secret: &str,
    instance_id: &str,
    instance_secret: &str,
) {
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let expected_secret = expected_secret.to_string();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request.contains(&expected_secret),
            "upstream should receive real secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_") && !request.contains("x-wispkey-instance-secret"),
            "upstream must not receive unresolved token or instance secret:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let request = request_with_identity(upstream_port, token, instance_id, instance_secret);
    let response = send_uds_request(socket_path, &request);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );
    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn uds_join_endpoint_allows_bootstrap_self_enrollment_without_instance_identity() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let socket_dir = tempfile::tempdir().expect("socket dir");
    let socket_path = socket_dir.path().join("wispkey.sock");
    init_vault(vault_dir.path());

    let created = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "create",
            "--tag",
            "company:acme",
            "--uses",
            "1",
        ],
    );
    let bootstrap_token = created["token"].as_str().expect("bootstrap token");
    let _proxy = start_uds_proxy(vault_dir.path(), &socket_path);

    let joined = send_uds_request(
        &socket_path,
        &join_request(bootstrap_token, "joined-worker"),
    );
    assert!(
        joined.starts_with("HTTP/1.1 201 Created"),
        "join should succeed without management or instance auth:\n{joined}"
    );
    let joined_json: serde_json::Value =
        serde_json::from_str(response_body(&joined)).expect("join response json");
    assert!(joined_json["id"].as_str().is_some());
    assert_eq!(joined_json["secret"].as_str().expect("secret").len(), 48);
    assert!(
        joined_json["scopes"]
            .as_array()
            .expect("scopes")
            .iter()
            .any(|scope| scope["scope_type"] == "tag" && scope["scope_value"] == "company:acme")
    );

    let exhausted = send_uds_request(&socket_path, &join_request(bootstrap_token, "joined-again"));
    assert!(
        exhausted.starts_with("HTTP/1.1 401 Unauthorized")
            && exhausted.contains("invalid bootstrap token"),
        "exhausted token should fail closed:\n{exhausted}"
    );

    let log = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "log", "--last", "10"],
    );
    assert!(
        log["entries"]
            .as_array()
            .expect("audit entries")
            .iter()
            .any(|entry| entry["event_type"] == "InstanceJoined"
                && entry["credential_name"] == "joined-worker"),
        "join endpoint should audit InstanceJoined"
    );
    let raw_log = serde_json::to_string(&log).expect("audit json");
    assert!(!raw_log.contains(bootstrap_token));
    assert!(!raw_log.contains(joined_json["secret"].as_str().expect("secret")));
}

#[test]
fn uds_listener_requires_instance_identity_and_enforces_scopes() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let socket_dir = tempfile::tempdir().expect("socket dir");
    let socket_path = socket_dir.path().join("wispkey.sock");
    init_vault(vault_dir.path());

    let scoped_a = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "scoped-a",
            "--type",
            "bearer_token",
            "--value",
            "real-a",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let scoped_b = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "scoped-b",
            "--type",
            "bearer_token",
            "--value",
            "real-b",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let token_a = scoped_a["credential"]["wisp_token"].as_str().unwrap();
    let token_b = scoped_b["credential"]["wisp_token"].as_str().unwrap();

    let enrolled = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "worker-one",
            "--credential",
            "scoped-a",
        ],
    );
    let instance_id = enrolled["id"].as_str().unwrap().to_string();
    let instance_secret = enrolled["secret"].as_str().unwrap().to_string();

    let _proxy = start_uds_proxy(vault_dir.path(), &socket_path);

    let missing_identity = send_uds_request(&socket_path, &request_without_identity(9, token_a));
    assert!(
        missing_identity.starts_with("HTTP/1.1 401 Unauthorized")
            && missing_identity.contains("instance authentication failed"),
        "missing identity should be rejected:\n{missing_identity}"
    );

    let wrong_secret = send_uds_request(
        &socket_path,
        &request_with_identity(9, token_a, &instance_id, "wrong"),
    );
    assert!(
        wrong_secret.starts_with("HTTP/1.1 401 Unauthorized")
            && wrong_secret.contains("instance authentication failed"),
        "wrong secret should be rejected:\n{wrong_secret}"
    );

    let unknown_instance = send_uds_request(
        &socket_path,
        &request_with_identity(9, token_a, "unknown-instance", &instance_secret),
    );
    assert!(
        unknown_instance.starts_with("HTTP/1.1 401 Unauthorized"),
        "unknown instance should be rejected:\n{unknown_instance}"
    );

    assert_injected_over_uds(
        &socket_path,
        token_a,
        "real-a",
        &instance_id,
        &instance_secret,
    );

    let out_of_scope = send_uds_request(
        &socket_path,
        &request_with_identity(9, token_b, &instance_id, &instance_secret),
    );
    assert!(
        out_of_scope.starts_with("HTTP/1.1 403 Forbidden")
            && out_of_scope.contains("\"error\":\"out_of_scope\"")
            && out_of_scope.contains("\"credential\":\"scoped-b\"")
            && out_of_scope.contains("\"instance\":\"worker-one\""),
        "out-of-scope credential should be denied and queued:\n{out_of_scope}"
    );

    let requests = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "requests", "--pending"],
    );
    let request_id = requests["requests"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(requests["requests"][0]["credential_name"], "scoped-b");

    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "approve", &request_id],
    );
    assert_injected_over_uds(
        &socket_path,
        token_b,
        "real-b",
        &instance_id,
        &instance_secret,
    );

    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "revoke", "worker-one"],
    );
    let revoked = send_uds_request(
        &socket_path,
        &request_with_identity(9, token_a, &instance_id, &instance_secret),
    );
    assert!(
        revoked.starts_with("HTTP/1.1 401 Unauthorized"),
        "revoked instance should be rejected:\n{revoked}"
    );
}
