mod common;

use common::*;
use serde_json::Value;
use std::net::TcpListener;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn spawn_proxy(vault_dir: &std::path::Path, args: &[&str]) -> ChildGuard {
    let child = wispkey_bin()
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    ChildGuard(child)
}

#[test]
fn serve_cleans_stale_proxy_metadata_before_starting() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    std::fs::write(vault_dir.path().join("proxy.pid"), "999999").expect("write stale pid");
    // Use a closed loopback port so a parallel --random-port proxy cannot make
    // this stale metadata look like a live owner or a healthy foreign listener.
    std::fs::write(
        vault_dir.path().join("proxy.json"),
        serde_json::to_string(&serde_json::json!({
            "pid": 999999_u32,
            "port": 1_u16,
            "address": "http://127.0.0.1:1",
            "management_token": "stale-token"
        }))
        .expect("stale metadata json"),
    )
    .expect("write stale proxy metadata");

    let _proxy = spawn_proxy(vault_dir.path(), &["serve", "--random-port"]);
    let deadline = Instant::now() + Duration::from_secs(15);
    let info = loop {
        let value = wait_for_proxy_info(vault_dir.path());
        if value["schema_version"].as_u64() == Some(1) {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not replace stale metadata"
        );
        thread::sleep(Duration::from_millis(50));
    };

    assert_eq!(info["schema_version"], 1);
    assert_ne!(info["pid"], 999999);
    assert_ne!(info["management_token"], "stale-token");
    assert!(
        vault_dir.path().join("proxy-events.jsonl").exists(),
        "proxy lifecycle events should be logged"
    );
}

#[test]
fn proxy_stop_uses_management_api_and_removes_metadata() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let mut proxy = spawn_proxy(vault_dir.path(), &["serve", "--random-port"]);
    let info = wait_for_proxy_info(vault_dir.path());
    assert!(info["management_token"].as_str().is_some());

    let output = run_wispkey(vault_dir.path(), &["proxy", "stop"]);
    assert!(
        output.status.success(),
        "proxy stop failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wait_for_child_exit(&mut proxy.0, Duration::from_secs(5)).is_some(),
        "proxy process should exit after management stop"
    );
    assert!(!vault_dir.path().join("proxy.json").exists());
    assert!(!vault_dir.path().join("proxy.pid").exists());
}

#[test]
fn serve_reports_healthy_existing_proxy_instead_of_spawning_duplicate() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let _proxy = spawn_proxy(vault_dir.path(), &["serve", "--random-port"]);
    let info = wait_for_proxy_info(vault_dir.path());
    let port = info["port"].as_u64().expect("proxy port").to_string();

    let mut child = wispkey_bin()
        .args(["serve", "--port", &port])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second serve");
    assert!(
        wait_for_child_exit(&mut child, Duration::from_secs(5)).is_some(),
        "second serve should return promptly when proxy is already healthy"
    );
    let output = child.wait_with_output().expect("second serve output");
    assert!(
        output.status.success(),
        "second serve failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("already running"),
        "expected already running message"
    );
}

#[test]
fn serve_replaces_unhealthy_owned_proxy_before_starting() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let mut old_proxy = spawn_proxy(vault_dir.path(), &["serve", "--random-port"]);
    let mut old_info = wait_for_proxy_info(vault_dir.path());
    let old_pid = old_info["pid"].as_u64().expect("old proxy pid");

    old_info["address"] = Value::String("http://127.0.0.1:1".to_string());
    std::fs::write(
        vault_dir.path().join("proxy.json"),
        serde_json::to_string(&old_info).expect("corrupted metadata json"),
    )
    .expect("write unhealthy owned metadata");

    let new_port_listener = TcpListener::bind("127.0.0.1:0").expect("reserve new proxy port");
    let new_port = new_port_listener
        .local_addr()
        .expect("new proxy addr")
        .port();
    drop(new_port_listener);

    let _new_proxy = spawn_proxy(
        vault_dir.path(),
        &["serve", "--port", &new_port.to_string()],
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let new_info = loop {
        let value = wait_for_proxy_info(vault_dir.path());
        if value["port"].as_u64() == Some(u64::from(new_port)) {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not replace unhealthy owned metadata"
        );
        thread::sleep(Duration::from_millis(50));
    };

    assert_ne!(new_info["pid"].as_u64(), Some(old_pid));
    assert!(
        wait_for_child_exit(&mut old_proxy.0, Duration::from_secs(5)).is_some(),
        "old unhealthy proxy should be terminated"
    );
}

#[test]
fn cli_and_mcp_status_share_lifecycle_status_and_ignore_http_proxy_env() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let _proxy = spawn_proxy(vault_dir.path(), &["serve", "--random-port"]);
    let info = wait_for_proxy_info(vault_dir.path());
    let port = info["port"].as_u64().expect("proxy port");

    let cli_output = wispkey_bin()
        .args(["--format", "json", "status"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .env("HTTP_PROXY", format!("http://127.0.0.1:{port}"))
        .output()
        .expect("run status");
    let cli_status = output_json(&["--format", "json", "status"], cli_output);
    assert_eq!(cli_status["proxy_running"], true);
    assert_eq!(cli_status["proxy"]["port"], port);

    let mcp_status = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_proxy_status",
                "arguments": {}
            }
        }),
    );
    let text = mcp_status["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp status text");
    let mcp_payload: Value = serde_json::from_str(text).expect("mcp proxy status json text");
    assert_eq!(mcp_payload["proxy"]["running"], true);
    assert_eq!(mcp_payload["proxy"]["proxy"]["port"], port);
}

fn call_mcp_tool(vault_dir: &std::path::Path, request: Value) -> Value {
    use std::io::Write;

    let mut child = wispkey_bin()
        .args(["mcp", "serve"])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
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

    serde_json::from_slice(&output.stdout).expect("mcp response json")
}
