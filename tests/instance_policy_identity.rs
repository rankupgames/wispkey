mod common;

use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "proxy did not bind TCP listener");
        thread::sleep(Duration::from_millis(50));
    }
}

fn request(
    proxy_port: u16,
    upstream_port: u16,
    token: &str,
    identity: Option<(&str, &str)>,
    forged_agent: Option<&str>,
) -> String {
    let identity_headers = identity.map_or_else(String::new, |(id, secret)| {
        format!("x-wispkey-instance-id: {id}\r\nx-wispkey-instance-secret: {secret}\r\n")
    });
    let forged_header =
        forged_agent.map_or_else(String::new, |agent| format!("x-wispkey-agent: {agent}\r\n"));
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/policy HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         {identity_headers}{forged_header}\
         Connection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn agent_policy_uses_authenticated_instance_id_only() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let credential = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "add",
            "policy-token",
            "--type",
            "bearer_token",
            "--value",
            "synthetic-policy-secret",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let token = credential["credential"]["wisp_token"].as_str().unwrap();
    let denied = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "denied-worker",
            "--credential",
            "policy-token",
        ],
    );
    let allowed = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "allowed-worker",
            "--credential",
            "policy-token",
        ],
    );
    let denied_id = denied["id"].as_str().unwrap();
    let denied_secret = denied["secret"].as_str().unwrap();
    let allowed_id = allowed["id"].as_str().unwrap();
    let allowed_secret = allowed["secret"].as_str().unwrap();
    let forged_agent = format!("instance:{denied_id}");

    write_private_test_file(
        &dir.path().join("policies.toml"),
        &format!(
            "[[policy]]\nname = \"deny-one-instance\"\ncredential = \"policy-token\"\nagent = \"{forged_agent}\"\ndeny = true\n"
        ),
    );
    let proxy_port = reserve_port();
    let listener = format!("tcp://127.0.0.1:{proxy_port}");
    let child = wispkey_bin()
        .args(["serve", "--listen", &listener, "--require-identity"])
        .env("WISPKEY_VAULT_PATH", dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _proxy = ChildGuard(child);
    let _ = wait_for_proxy_info(dir.path());
    wait_for_tcp(proxy_port);

    let blocked = request(proxy_port, 9, token, Some((denied_id, denied_secret)), None);
    assert!(
        blocked.starts_with("HTTP/1.1 403 Forbidden") && blocked.contains("deny-one-instance"),
        "authenticated denied instance should match policy: {blocked}"
    );
    let missing = request(proxy_port, 9, token, None, Some(&forged_agent));
    assert!(missing.starts_with("HTTP/1.1 401 Unauthorized"));
    let wrong_secret = request(
        proxy_port,
        9,
        token,
        Some((denied_id, "incorrect-secret")),
        Some(&forged_agent),
    );
    assert!(wrong_secret.starts_with("HTTP/1.1 401 Unauthorized"));

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_thread = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut bytes = [0u8; 8192];
        let count = stream.read(&mut bytes).unwrap();
        let seen = String::from_utf8_lossy(&bytes[..count]);
        assert!(seen.contains("synthetic-policy-secret"));
        assert!(!seen.contains("x-wispkey-instance-secret"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let other = request(
        proxy_port,
        upstream_port,
        token,
        Some((allowed_id, allowed_secret)),
        Some(&forged_agent),
    );
    assert!(
        other.starts_with("HTTP/1.1 200 OK"),
        "another authenticated instance should not match targeted deny: {other}"
    );
    upstream_thread.join().unwrap();
}
