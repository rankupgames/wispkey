mod common;

use common::*;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn mcp(dir: &Path, tool: &str, arguments: Value) -> Value {
    let mut child = ChildGuard(
        wispkey_bin()
            .args(["mcp", "serve"])
            .env("WISPKEY_VAULT_PATH", dir)
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PASSWORD")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    writeln!(child.0.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":arguments}})).unwrap();
    let mut output = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(child.0.wait().unwrap().success());
    let response: Value = serde_json::from_str(output.trim()).unwrap();
    response["result"].clone()
}

fn native(dir: &Path, requests: &[Value]) -> (Vec<Value>, String) {
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_wispkey-browser-host"))
            .env("WISPKEY_VAULT_PATH", dir)
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PASSWORD")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut input = child.0.stdin.take().unwrap();
    for request in requests {
        let bytes = serde_json::to_vec(request).unwrap();
        input
            .write_all(&(bytes.len() as u32).to_ne_bytes())
            .unwrap();
        input.write_all(&bytes).unwrap();
    }
    drop(input);
    let mut output = child.0.stdout.take().unwrap();
    let mut responses = Vec::new();
    for _ in requests {
        let mut length = [0; 4];
        output.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_ne_bytes(length) as usize];
        output.read_exact(&mut bytes).unwrap();
        responses.push(serde_json::from_slice(&bytes).unwrap());
    }
    assert!(child.0.wait().unwrap().success());
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (responses, stderr)
}

fn inner(response: Value) -> Value {
    assert_ne!(response["isError"], true, "{response}");
    serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn mcp_request_native_listing_denial_and_status_are_metadata_only() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let generated = mcp(
        dir.path(),
        "wispkey_generate_login",
        json!({"name":"careers","username":"test@example.com","url":"https://jobs.example.com"}),
    );
    inner(generated);
    let request = inner(mcp(
        dir.path(),
        "wispkey_request_browser_fill",
        json!({
            "name":"careers", "origin":"https://jobs.example.com", "requester":"test-agent", "reason":"Apply for a job"
        }),
    ));
    assert_eq!(request.as_object().unwrap().len(), 1);
    let id = request["request_id"].as_str().unwrap();
    let (responses, stderr) = native(
        dir.path(),
        &[
            json!({"method":"pending", "origin":"https://evil.example.com"}),
            json!({"method":"pending", "origin":"https://jobs.example.com"}),
            json!({"method":"complete", "request_id":id,"completed":true}),
            // Wrong origins must fail before any OS approval prompt.
            json!({"method":"fill", "request_id":id,"origin":"http://jobs.example.com"}),
            json!({"method":"deny", "request_id":id}),
            json!({"method":"fill", "request_id":id,"origin":"https://jobs.example.com"}),
        ],
    );
    assert!(
        responses[0]["result"]["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(responses[1]["result"]["requests"][0]["request_id"], id);
    assert_eq!(responses[2]["ok"], false);
    assert_eq!(responses[3]["ok"], false);
    assert_eq!(responses[4]["result"]["status"], "denied");
    assert_eq!(responses[5]["ok"], false);
    let status = inner(mcp(
        dir.path(),
        "wispkey_browser_fill_status",
        json!({"request_id":id}),
    ));
    assert_eq!(status["status"], "denied");
    assert!(stderr.is_empty());
    for response in &responses {
        let text = response.to_string();
        assert!(!text.contains("password"));
        assert!(!text.contains("username"));
        assert!(!text.contains("wisp_token"));
        assert!(!text.contains("encrypted_value"));
    }
    assert!(run_wispkey(dir.path(), &["lock"]).status.success());
    let (locked, _) = native(
        dir.path(),
        &[json!({"method":"pending","origin":"https://jobs.example.com"})],
    );
    assert_eq!(locked[0]["ok"], false);
    assert_eq!(
        mcp(
            dir.path(),
            "wispkey_browser_fill_status",
            json!({"request_id":id})
        )["isError"],
        true
    );
}
