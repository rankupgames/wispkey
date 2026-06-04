mod common;

use common::*;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn mcp_serve_returns_env_sideload_token_without_master_password() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "wispkey_get_token",
            "arguments": { "name": "openai" }
        }
    });

    let mut child = wispkey_bin()
        .args(["mcp", "serve"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_SIDELOAD_OPENAI", "sideload-secret")
        .env_remove("WISPKEY_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp server");

    {
        let stdin = child.stdin.as_mut().expect("mcp stdin");
        writeln!(stdin, "{request}").expect("write mcp request");
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for mcp server");
    assert!(
        output.status.success(),
        "mcp serve failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: Value = serde_json::from_str(stdout.trim()).expect("mcp response json");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text response");

    assert!(
        text.contains("wk_env_openai"),
        "expected sideload token: {text}"
    );
    assert!(
        text.contains("WISPKEY_SIDELOAD_OPENAI"),
        "expected source env key: {text}"
    );
    assert!(
        !text.contains("sideload-secret"),
        "MCP response must not expose env secret: {text}"
    );
}

#[test]
fn proxy_uses_env_sideload_token_without_master_password() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        let normalized_request = request.to_ascii_lowercase();
        assert!(
            normalized_request.contains("authorization: bearer sideload-secret"),
            "upstream should receive env sideload secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_env_openai"),
            "upstream must not receive unresolved sideload token:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_SIDELOAD_OPENAI", "sideload-secret")
        .env_remove("WISPKEY_PASSWORD")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let _guard = ChildGuard(child);

    let proxy_info_path = vault_dir.path().join("proxy.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let proxy_port = loop {
        if let Ok(raw) = std::fs::read_to_string(&proxy_info_path) {
            let value: Value = serde_json::from_str(&raw).expect("proxy info json");
            if let Some(port) = value["port"].as_u64() {
                break port as u16;
            }
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not write proxy.json in time"
        );
        thread::sleep(Duration::from_millis(50));
    };

    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer wk_env_openai\r\n\
         Connection: close\r\n\r\n"
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
