mod common;

use common::*;
use serde_json::Value;

#[test]
fn login_generate_stores_metadata_without_emitting_password() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "create",
            "career-ops",
            "--description",
            "Career Ops",
        ],
    );
    run_wispkey(
        vault_dir.path(),
        &[
            "partition",
            "create",
            "job-applications",
            "--project",
            "career-ops",
        ],
    );

    let generated = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "login",
            "generate",
            "acme-careers",
            "--username",
            "user@example.com",
            "--url",
            "https://careers.example.com/apply",
            "--project",
            "career-ops",
            "--partition",
            "job-applications",
            "--review-after",
            "180d",
        ],
    );

    assert_eq!(generated["ok"], true);
    assert_eq!(generated["credential"]["name"], "acme-careers");
    assert_eq!(generated["credential"]["type"], "website_login");
    assert_eq!(
        generated["credential"]["origin"],
        "https://careers.example.com"
    );
    assert_eq!(generated["credential"]["lifecycle_state"], "pending");
    assert_eq!(generated["username"], "user@example.com");
    assert!(generated["credential"].get("password").is_none());
    assert!(generated["credential"].get("value").is_none());

    let template = vault_dir.path().join("login.template");
    std::fs::write(&template, "{{ cred:acme-careers }}").expect("write template");
    let rendered = run_wispkey(
        vault_dir.path(),
        &[
            "inject",
            "-i",
            template.to_str().expect("template path"),
            "--stdout",
            "--project",
            "career-ops",
        ],
    );
    assert!(rendered.status.success());
    let payload: Value = serde_json::from_slice(&rendered.stdout).expect("payload json");
    let password = payload["password"].as_str().expect("password");
    assert!(!password.is_empty());

    let generate_stdout = serde_json::to_string(&generated).expect("serialize generate");
    assert!(!generate_stdout.contains(password));
    let generate_raw = run_wispkey(
        vault_dir.path(),
        &[
            "login",
            "generate",
            "other-careers",
            "--username",
            "user@example.com",
            "--url",
            "https://jobs.example.net",
            "--project",
            "career-ops",
            "--partition",
            "job-applications",
        ],
    );
    let stdout = String::from_utf8_lossy(&generate_raw.stdout);
    let stderr = String::from_utf8_lossy(&generate_raw.stderr);
    let other_template = vault_dir.path().join("other.template");
    std::fs::write(&other_template, "{{ cred:other-careers }}").expect("write other template");
    let other_rendered = run_wispkey(
        vault_dir.path(),
        &[
            "inject",
            "-i",
            other_template.to_str().expect("template path"),
            "--stdout",
            "--project",
            "career-ops",
        ],
    );
    let other_payload: Value =
        serde_json::from_slice(&other_rendered.stdout).expect("other payload");
    let other_password = other_payload["password"].as_str().expect("other password");
    assert_ne!(password, other_password);
    assert!(!stdout.contains(other_password));
    assert!(!stderr.contains(other_password));

    let log = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "log", "--last", "20"],
    );
    let log_text = serde_json::to_string(&log).expect("serialize log");
    assert!(!log_text.contains(password));
    assert!(!log_text.contains(other_password));
    assert!(log_text.contains("WebsiteLoginCreated"));
}

#[test]
fn login_rejects_http_and_add_bypass() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let http = run_wispkey(
        vault_dir.path(),
        &[
            "login",
            "generate",
            "insecure",
            "--username",
            "user@example.com",
            "--url",
            "http://careers.example.com",
        ],
    );
    assert!(!http.status.success());
    let stderr = String::from_utf8_lossy(&http.stderr);
    assert!(
        stderr.contains("https"),
        "expected https error, got {stderr}"
    );

    let add = run_wispkey(
        vault_dir.path(),
        &[
            "add",
            "manual-login",
            "--type",
            "website_login",
            "--value",
            "should-not-work",
        ],
    );
    assert!(!add.status.success());
    let add_err = String::from_utf8_lossy(&add.stderr);
    assert!(
        add_err.contains("login generate"),
        "expected generate-path error, got {add_err}"
    );
}

#[test]
fn login_archive_restore_and_due_list_never_delete() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "login",
            "generate",
            "review-login",
            "--username",
            "user@example.com",
            "--url",
            "https://careers.example.com",
            "--review-after",
            "1s",
        ],
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    let due = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "login", "list", "--due"],
    );
    assert_eq!(due["logins"].as_array().expect("logins").len(), 1);

    let archived = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "login", "archive", "review-login"],
    );
    assert_eq!(archived["credential"]["lifecycle_state"], "archived");
    let due_after = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "login", "list", "--due"],
    );
    assert!(due_after["logins"].as_array().expect("logins").is_empty());

    let restored = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "login", "restore", "review-login"],
    );
    assert_eq!(restored["credential"]["lifecycle_state"], "pending");
    let listed = run_wispkey_json(vault_dir.path(), &["--format", "json", "login", "list"]);
    assert_eq!(listed["logins"].as_array().expect("logins").len(), 1);
}

#[test]
fn mcp_generate_login_returns_metadata_without_password() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_generate_login",
                "arguments": {
                    "name": "mcp-login",
                    "username": "user@example.com",
                    "url": "https://careers.example.com"
                }
            }
        }),
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text");
    let parsed: Value = serde_json::from_str(text).expect("parse mcp json");
    assert_eq!(parsed["action"], "created");
    assert_eq!(parsed["type"], "website_login");
    assert_eq!(parsed["origin"], "https://careers.example.com");
    assert!(parsed.get("password").is_none());
    assert!(parsed.get("value").is_none());
    assert!(!text.contains("password"));

    let refused = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wispkey_set",
                "arguments": {
                    "name": "bypass-login",
                    "value": "plaintext-password",
                    "type": "website_login"
                }
            }
        }),
    );
    let refused_text = refused["result"]["content"][0]["text"]
        .as_str()
        .expect("refused text");
    assert!(
        refused_text.contains("wispkey_generate_login"),
        "expected generate-path refusal, got {refused_text}"
    );
}

fn call_mcp_tool(vault_dir: &std::path::Path, request: Value) -> Value {
    use std::io::Write;
    use std::process::Stdio;

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
