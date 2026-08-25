mod common;

use common::*;
use serde_json::Value;
use std::io::Write;
use std::process::Stdio;

#[test]
fn get_token_suggests_hyphenated_name_for_underscore_lookup() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "amp-vm-ssh-dudetru25",
            "--type",
            "api_key",
            "--value",
            "fake-test-secret",
        ],
    );

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_get_token",
                "arguments": { "name": "amp_vm_ssh_dudetru25" }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text response");
    assert!(
        text.contains("Did you mean: amp-vm-ssh-dudetru25?"),
        "expected credential suggestion, got: {text}"
    );
}

#[test]
fn set_creates_credential_and_returns_wisp_token() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": {
                    "name": "test-api-key",
                    "value": "sk-secret-12345",
                    "type": "bearer_token",
                    "description": "Test key",
                    "hosts": "api.example.com"
                }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text response");
    let parsed: Value = serde_json::from_str(text).expect("parse inner json");
    assert_eq!(parsed["action"], "created");
    assert_eq!(parsed["name"], "test-api-key");
    assert_eq!(parsed["type"], "bearer_token");
    assert!(
        parsed["wisp_token"]
            .as_str()
            .expect("wisp_token")
            .starts_with("wk_"),
        "wisp token should start with wk_"
    );

    let verify = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "get", "test-api-key", "--show-token"],
    );
    assert_eq!(verify["credential"]["name"], "test-api-key");
    assert_eq!(verify["credential"]["type"], "bearer_token");
}

#[test]
fn set_refuses_overwrite_by_default() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": { "name": "dup-key", "value": "first-value" }
            }
        }),
    );

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": { "name": "dup-key", "value": "second-value" }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(
        text.contains("already exists"),
        "expected duplicate error, got: {text}"
    );
    assert!(
        response["result"]["isError"].as_bool().unwrap_or(false),
        "expected isError flag"
    );
}

#[test]
fn set_overwrites_when_flag_is_true_and_preserves_wisp_token() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let create_resp = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": { "name": "rotate-me", "value": "old-secret", "description": "version 1" }
            }
        }),
    );
    let create_text = create_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("create text");
    let created: Value = serde_json::from_str(create_text).expect("parse create json");
    let original_token = created["wisp_token"].as_str().expect("original token");

    let update_resp = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": {
                    "name": "rotate-me",
                    "value": "new-secret",
                    "description": "version 2",
                    "overwrite": true
                }
            }
        }),
    );
    let update_text = update_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("update text");
    let updated: Value = serde_json::from_str(update_text).expect("parse update json");
    assert_eq!(updated["action"], "updated");
    assert_eq!(
        updated["wisp_token"].as_str().expect("updated token"),
        original_token,
        "wisp token must be preserved on overwrite"
    );
}

#[test]
fn delete_removes_credential() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": { "name": "ephemeral-key", "value": "temp-secret" }
            }
        }),
    );

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wispkey_delete",
                "arguments": { "name": "ephemeral-key" }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("delete text");
    let parsed: Value = serde_json::from_str(text).expect("parse delete json");
    assert_eq!(parsed["action"], "deleted");
    assert_eq!(parsed["name"], "ephemeral-key");

    let list = run_wispkey_json(vault_dir.path(), &["--format", "json", "list"]);
    let names = credential_names(&list);
    assert!(
        !names.contains(&"ephemeral-key".to_string()),
        "credential should be gone after delete"
    );
}

#[test]
fn delete_returns_error_for_missing_credential() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_delete",
                "arguments": { "name": "nonexistent" }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(
        text.contains("not found"),
        "expected not-found error, got: {text}"
    );
    assert!(
        response["result"]["isError"].as_bool().unwrap_or(false),
        "expected isError flag"
    );
}

fn call_mcp_tool(vault_dir: &std::path::Path, request: Value) -> Value {
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
