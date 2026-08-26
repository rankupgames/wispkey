mod common;

use common::*;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::thread;

fn start_sideload_proxy(vault_dir: &Path, unlock_vault: bool) -> (ChildGuard, u16) {
    let mut command = wispkey_bin();
    command
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_SIDELOAD_OPENAI", "sideload-secret")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if unlock_vault {
        command.env("WISPKEY_PASSWORD", "test-password");
    } else {
        command.env_remove("WISPKEY_PASSWORD");
    }

    let child = command.spawn().expect("spawn proxy");
    let proxy_info = wait_for_proxy_info(vault_dir);
    let proxy_port = proxy_info["port"].as_u64().expect("proxy port") as u16;
    (ChildGuard(child), proxy_port)
}

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

    let (_guard, proxy_port) = start_sideload_proxy(vault_dir.path(), false);

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

    let fallback_audit = std::fs::read_to_string(vault_dir.path().join("sideload-audit.jsonl"))
        .expect("fallback sideload audit log");
    assert!(
        fallback_audit.contains("\"event_type\":\"SideloadUsed\""),
        "expected sideload audit event:\n{fallback_audit}"
    );
    assert!(
        fallback_audit.contains("WISPKEY_SIDELOAD_OPENAI"),
        "expected sideload env key in audit event:\n{fallback_audit}"
    );
    assert!(fallback_audit.contains("token_fingerprint"));
    assert!(!fallback_audit.contains("wk_env_openai"));
    assert!(
        !fallback_audit.contains("sideload-secret"),
        "fallback audit must not expose env secret:\n{fallback_audit}"
    );

    let log_output = wispkey_bin()
        .args(["--format", "json", "log", "--credential", "openai"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env_remove("WISPKEY_PASSWORD")
        .output()
        .expect("query fallback audit log");
    assert!(
        log_output.status.success(),
        "log command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&log_output.stdout),
        String::from_utf8_lossy(&log_output.stderr)
    );
    let log_json: Value = serde_json::from_slice(&log_output.stdout).expect("log json");
    let entries = log_json["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event_type"], "SideloadUsed");
    assert_eq!(entries[0]["credential_name"], "WISPKEY_SIDELOAD_OPENAI");
    assert!(
        entries[0]["token_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("hmac-sha256:"))
    );
    assert!(entries[0].get("wisp_token").is_none());
    assert_eq!(entries[0]["source"], "sideload-fallback-jsonl");
    assert!(
        !String::from_utf8_lossy(&log_output.stdout).contains("sideload-secret"),
        "log output must not expose env secret"
    );
}

#[test]
fn management_logs_include_vaultless_sideload_fallback_rows_without_secret() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer sideload-secret"),
            "upstream should receive env sideload secret, got:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let (_guard, proxy_port) = start_sideload_proxy(vault_dir.path(), false);
    let proxy_info = wait_for_proxy_info(vault_dir.path());
    let management_token = proxy_info["management_token"]
        .as_str()
        .expect("management token")
        .to_string();

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
    let mut proxy_response = String::new();
    proxy_stream
        .read_to_string(&mut proxy_response)
        .expect("read proxy response");
    assert!(
        proxy_response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{proxy_response}"
    );
    upstream_handle.join().expect("upstream assertion");

    let management_request = format!(
        "GET /api/logs?last=5&credential=openai HTTP/1.1\r\n\
         Host: 127.0.0.1:{proxy_port}\r\n\
         x-wispkey-management-token: {management_token}\r\n\
         Connection: close\r\n\r\n"
    );
    let mut management_stream =
        TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to management API");
    management_stream
        .write_all(management_request.as_bytes())
        .expect("write management request");
    let mut management_response = String::new();
    management_stream
        .read_to_string(&mut management_response)
        .expect("read management response");
    assert!(
        management_response.starts_with("HTTP/1.1 200 OK"),
        "expected successful management response, got:\n{management_response}"
    );
    assert!(
        !management_response.contains("sideload-secret"),
        "management log response must not expose env secret:\n{management_response}"
    );

    let body = management_response
        .split("\r\n\r\n")
        .nth(1)
        .expect("management response body");
    let log_json: Value = serde_json::from_str(body.trim()).expect("management log json");
    let entries = log_json["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event_type"], "SideloadUsed");
    assert_eq!(entries[0]["credential_name"], "WISPKEY_SIDELOAD_OPENAI");
    assert!(
        entries[0]["token_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("hmac-sha256:"))
    );
    assert!(entries[0].get("wisp_token").is_none());
    assert_eq!(entries[0]["source"], "sideload-fallback-jsonl");
}

#[test]
fn proxy_returns_policy_denial_for_env_sideload_with_unlocked_vault() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    std::fs::write(
        vault_dir.path().join("policies.toml"),
        r#"
[[policy]]
name = "block-openai-sideload"
credential = "openai"
deny = true
"#,
    )
    .expect("write policy");

    let (_guard, proxy_port) = start_sideload_proxy(vault_dir.path(), true);
    let request = "GET http://127.0.0.1:9/test HTTP/1.1\r\n\
                   Host: 127.0.0.1:9\r\n\
                   Authorization: Bearer wk_env_openai\r\n\
                   Connection: close\r\n\r\n";
    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");

    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden"),
        "expected policy denial, got:\n{response}"
    );
    assert!(
        response.contains("blocked by deny policy"),
        "expected policy reason to survive env sideload resolution:\n{response}"
    );
    assert!(
        !response.contains("not found"),
        "policy-denied sideload token must not be reported as missing:\n{response}"
    );
}
