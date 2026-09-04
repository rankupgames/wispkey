mod common;

use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::thread;

fn start_proxy(vault_dir: &std::path::Path) -> (ChildGuard, u16) {
    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let proxy_info = wait_for_proxy_info(vault_dir);
    let proxy_port = proxy_info["port"].as_u64().expect("proxy port") as u16;
    (ChildGuard(child), proxy_port)
}

#[test]
fn proxy_refuses_generic_website_login_token_substitution() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let generated = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "login",
            "generate",
            "blocked-login",
            "--username",
            "user@example.com",
            "--url",
            "https://example.com",
        ],
    );
    let token = generated["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token");
    let (_guard, proxy_port) = start_proxy(vault_dir.path());
    let request = format!(
        "POST http://example.com/login HTTP/1.1\r\n\
         Host: example.com\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        token.len(),
        token
    );
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    assert!(response.contains("approved local fill flow"), "{response}");
}

#[test]
fn bundle_passphrase_file_roundtrips_multiline_secret_through_proxy() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let secret_file = bundle_dir.path().join("private-key.txt");
    let passphrase_file = bundle_dir.path().join("bundle-passphrase.txt");
    let credential_bundle = bundle_dir.path().join("ssh-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();
    let secret_file_path = secret_file.to_string_lossy().to_string();
    let passphrase_file_path = passphrase_file.to_string_lossy().to_string();
    let expected_secret = "-----BEGIN PRIVATE KEY-----\nline-two\n-----END PRIVATE KEY-----\n";

    write_private_test_file(&secret_file, expected_secret);
    write_private_test_file(&passphrase_file, TEST_BUNDLE_PASSPHRASE);

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "ssh-key",
            "--type",
            "api_key",
            "--value-file",
            &secret_file_path,
            "--hosts",
            "127.0.0.1",
        ],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "ssh-key",
            "--output",
            &credential_bundle_path,
            "--bundle-passphrase-file",
            &passphrase_file_path,
        ],
    );

    init_vault(destination_dir.path());
    run_wispkey_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
            "--bundle-passphrase-file",
            &passphrase_file_path,
        ],
    );
    let imported = run_wispkey_json(
        destination_dir.path(),
        &["--format", "json", "get", "ssh-key", "--show-token"],
    );
    let token = imported["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let expected_secret_for_thread = expected_secret.to_string();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request.contains(&expected_secret_for_thread),
            "upstream should receive imported multiline secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_"),
            "upstream must not receive unresolved wisp token:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let (_guard, proxy_port) = start_proxy(destination_dir.path());

    let body = token;
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn proxy_swaps_wisp_token_before_local_upstream_receives_request() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        let normalized_request = request.to_ascii_lowercase();
        assert!(
            normalized_request.contains("authorization: bearer real-secret"),
            "upstream should receive real secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_"),
            "upstream must not receive unresolved wisp token:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let added = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "proxy-key",
            "--type",
            "bearer_token",
            "--value",
            "real-secret",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let token = added["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    let (_guard, proxy_port) = start_proxy(vault_dir.path());

    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    );
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn proxy_resolves_token_adjacent_to_lowercase_suffix() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let added = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "adjacent-key",
            "--type",
            "api_key",
            "--value",
            "real-secret",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let token = added["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request.contains("payload=real-secretsuffix_more"),
            "upstream should receive token prefix replaced and adjacent suffix preserved:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let (_guard, proxy_port) = start_proxy(vault_dir.path());
    let body = format!("payload={token}suffix_more");
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn proxy_does_not_rewrite_tokens_embedded_in_injected_secret() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let secondary = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "secondary-key",
            "--type",
            "api_key",
            "--value",
            "real-secondary",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let secondary_token = secondary["credential"]["wisp_token"]
        .as_str()
        .expect("secondary wisp token")
        .to_string();
    let primary_value = format!("literal-{secondary_token}-inside");
    let primary = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "primary-key",
            "--type",
            "api_key",
            "--value",
            &primary_value,
            "--hosts",
            "127.0.0.1",
        ],
    );
    let primary_token = primary["credential"]["wisp_token"]
        .as_str()
        .expect("primary wisp token")
        .to_string();

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let expected_body = format!("first=literal-{secondary_token}-inside&second=real-secondary");
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request.contains(&expected_body),
            "injected secret should not be rescanned for later tokens:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let (_guard, proxy_port) = start_proxy(vault_dir.path());
    let body = format!("first={primary_token}&second={secondary_token}");
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}
