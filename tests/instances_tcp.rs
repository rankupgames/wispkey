mod common;

use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .expect("reserved TCP address")
        .port()
}

fn start_tcp_proxy(vault_dir: &std::path::Path, port: u16) -> ChildGuard {
    let listen_spec = format!("tcp://127.0.0.1:{port}");
    let child = wispkey_bin()
        .args(["serve", "--listen", &listen_spec, "--require-identity"])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn identity-required TCP proxy");
    let _ = wait_for_proxy_info(vault_dir);
    wait_for_tcp(port);
    ChildGuard(child)
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "proxy did not bind TCP listener");
        thread::sleep(Duration::from_millis(50));
    }
}

fn send_tcp_request(proxy_port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to TCP proxy");
    stream
        .write_all(request.as_bytes())
        .expect("write TCP request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read TCP response");
    response
}

fn request(upstream_port: u16, token: &str, instance: Option<(&str, &str)>) -> String {
    let identity_headers = instance.map_or_else(String::new, |(id, secret)| {
        format!("x-wispkey-instance-id: {id}\r\nx-wispkey-instance-secret: {secret}\r\n")
    });
    format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         {identity_headers}\
         Connection: close\r\n\r\n"
    )
}

fn assert_injected(
    proxy_port: u16,
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
        assert!(request.contains(&expected_secret));
        assert!(!request.contains("wk_") && !request.contains("x-wispkey-instance-secret"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let response = send_tcp_request(
        proxy_port,
        &request(upstream_port, token, Some((instance_id, instance_secret))),
    );
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );
    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn identity_required_tcp_enforces_scope_on_every_supported_os() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let scoped = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "tcp-scoped",
            "--type",
            "bearer_token",
            "--value",
            "tcp-real-scoped",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let outside = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "tcp-outside",
            "--type",
            "bearer_token",
            "--value",
            "tcp-real-outside",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let scoped_token = scoped["credential"]["wisp_token"].as_str().unwrap();
    let outside_token = outside["credential"]["wisp_token"].as_str().unwrap();
    let enrolled = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "tcp-worker",
            "--credential",
            "tcp-scoped",
        ],
    );
    let instance_id = enrolled["id"].as_str().unwrap();
    let instance_secret = enrolled["secret"].as_str().unwrap();

    let proxy_port = reserve_port();
    let _proxy = start_tcp_proxy(vault_dir.path(), proxy_port);

    let missing = send_tcp_request(proxy_port, &request(9, scoped_token, None));
    assert!(
        missing.starts_with("HTTP/1.1 401 Unauthorized"),
        "missing identity should fail closed:\n{missing}"
    );

    let wrong = send_tcp_request(
        proxy_port,
        &request(9, scoped_token, Some((instance_id, "wrong-secret"))),
    );
    assert!(
        wrong.starts_with("HTTP/1.1 401 Unauthorized"),
        "wrong identity secret should fail closed:\n{wrong}"
    );

    assert_injected(
        proxy_port,
        scoped_token,
        "tcp-real-scoped",
        instance_id,
        instance_secret,
    );

    let out_of_scope = send_tcp_request(
        proxy_port,
        &request(9, outside_token, Some((instance_id, instance_secret))),
    );
    assert!(
        out_of_scope.starts_with("HTTP/1.1 403 Forbidden")
            && out_of_scope.contains("\"error\":\"out_of_scope\"")
            && out_of_scope.contains("\"credential\":\"tcp-outside\"")
    );

    let requests = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "requests", "--pending"],
    );
    let request_id = requests["requests"][0]["id"].as_str().unwrap();
    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "approve", request_id],
    );
    assert_injected(
        proxy_port,
        outside_token,
        "tcp-real-outside",
        instance_id,
        instance_secret,
    );

    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "revoke", "tcp-worker"],
    );
    let revoked = send_tcp_request(
        proxy_port,
        &request(9, scoped_token, Some((instance_id, instance_secret))),
    );
    assert!(
        revoked.starts_with("HTTP/1.1 401 Unauthorized"),
        "revoked identity should fail closed:\n{revoked}"
    );
}
