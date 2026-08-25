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

#[test]
fn tools_list_includes_issue_cert() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );

    let names = response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_string())
        .collect::<Vec<_>>();
    assert!(
        names.contains(&"wispkey_issue_cert".to_string()),
        "expected wispkey_issue_cert in {names:?}"
    );
}

#[test]
fn issue_cert_returns_leaf_and_never_ca_key() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let (bundle, ca_key_pem) = test_ca_bundle();
    add_ca_credential(vault_dir.path(), "lab-ca", &bundle);

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_issue_cert",
                "arguments": {
                    "ca_credential": "lab-ca",
                    "common_name": "blackbox-exporter",
                    "san": ["blackbox.internal"],
                    "validity_days": 30,
                    "key_type": "ec-p256"
                }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text response");
    assert!(
        !response["result"]["isError"].as_bool().unwrap_or(false),
        "issue_cert failed: {text}"
    );
    let parsed: Value = serde_json::from_str(text).expect("parse inner json");
    assert_eq!(parsed["action"], "issued");
    assert_eq!(parsed["common_name"], "blackbox-exporter");
    assert_eq!(parsed["source"], "generated");
    assert!(
        parsed["certificate_pem"]
            .as_str()
            .expect("certificate_pem")
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        parsed["private_key_pem"]
            .as_str()
            .expect("private_key_pem")
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(
        !compact_text(text).contains(&ca_private_key_body(&ca_key_pem)),
        "response leaked CA private key material"
    );

    let log = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "log",
            "--last",
            "20",
            "--credential",
            "lab-ca",
        ],
    );
    let entries = log["entries"].as_array().expect("audit entries");
    assert!(
        entries
            .iter()
            .any(|entry| entry["event_type"] == "CertificateIssued"
                && entry["credential_name"] == "lab-ca"
                && entry["target_host"] == "blackbox-exporter"),
        "expected CertificateIssued audit row, got {log}"
    );
    let serialized = serde_json::to_string(&log).expect("serialize audit");
    assert!(!compact_text(&serialized).contains(&ca_private_key_body(&ca_key_pem)));
    assert!(!serialized.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn issue_cert_signs_csr_without_leaf_key() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let (bundle, ca_key_pem) = test_ca_bundle();
    add_ca_credential(vault_dir.path(), "csr-ca", &bundle);

    let mut params = rcgen::CertificateParams::new(vec!["csr.internal".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "csr-leaf");
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = params.serialize_request(&leaf_key).unwrap().pem().unwrap();

    let response = call_mcp_tool(
        vault_dir.path(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wispkey_issue_cert",
                "arguments": {
                    "ca_credential": "csr-ca",
                    "csr": csr
                }
            }
        }),
    );

    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text response");
    let parsed: Value = serde_json::from_str(text).expect("parse inner json");
    assert_eq!(parsed["action"], "issued");
    assert_eq!(parsed["source"], "csr");
    assert_eq!(parsed["common_name"], "csr-leaf");
    assert!(parsed.get("private_key_pem").is_none());
    assert!(!compact_text(text).contains(&ca_private_key_body(&ca_key_pem)));
}

#[test]
fn issue_cert_rejects_missing_ca_and_does_not_use_sideload() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let mut child = wispkey_bin()
        .args(["mcp", "serve"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_SIDELOAD_LAB_CA", "sideload-is-not-a-ca")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp server");
    {
        let stdin = child.stdin.as_mut().expect("mcp stdin");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "wispkey_issue_cert",
                    "arguments": {
                        "ca_credential": "lab-ca",
                        "common_name": "svc.internal"
                    }
                }
            })
        )
        .expect("write mcp request");
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for mcp server");
    let response: Value = serde_json::from_slice(&output.stdout).expect("mcp response json");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(
        text.contains("not found"),
        "expected missing CA credential, got: {text}"
    );
    assert!(response["result"]["isError"].as_bool().unwrap_or(false));
}

fn add_ca_credential(vault_dir: &std::path::Path, name: &str, bundle: &str) {
    let pem_path = vault_dir.join(format!("{name}.pem"));
    write_private_test_file(&pem_path, bundle);
    run_wispkey_json(
        vault_dir,
        &[
            "--format",
            "json",
            "add",
            name,
            "--type",
            "api_key",
            "--value-file",
            pem_path.to_str().expect("utf8 pem path"),
            "--tags",
            "pki,ca",
        ],
    );
}

fn test_ca_bundle() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "WispKey Test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let key_pem = key.serialize_pem();
    (format!("{}{key_pem}", cert.pem()), key_pem)
}

fn ca_private_key_body(key_pem: &str) -> String {
    key_pem
        .lines()
        .filter(|line| !line.contains("-----"))
        .collect::<String>()
}

fn compact_text(value: &str) -> String {
    value.chars().filter(|ch| !ch.is_whitespace()).collect()
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
