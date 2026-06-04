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
