mod common;

use common::*;
use serde_json::Value;
use wispkey::doctor::STABLE_CHECK_IDS;

fn doctor_json(vault_dir: &std::path::Path) -> (bool, Value) {
    let output = run_wispkey(vault_dir, &["--format", "json", "doctor"]);
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "doctor json parse failed: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.success(), value)
}

fn check_ids(report: &Value) -> Vec<String> {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .map(|check| check["id"].as_str().expect("check id").to_string())
        .collect()
}

fn check_named<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("missing check {id}"))
}

#[test]
fn doctor_json_has_stable_ids_without_a_vault() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let (ok, report) = doctor_json(vault_dir.path());
    assert!(!ok);
    assert_eq!(report["ok"], false);
    assert_eq!(check_ids(&report), STABLE_CHECK_IDS);
    assert_eq!(check_named(&report, "vault.permissions")["status"], "fail");
    assert!(
        check_named(&report, "vault.permissions")["remediation"]
            .as_str()
            .expect("remediation")
            .contains("wispkey init")
    );
    assert_eq!(check_named(&report, "proxy.substitution")["status"], "pass");
    assert_eq!(check_named(&report, "mcp.transport")["status"], "pass");
    let serialized = report.to_string();
    assert!(!serialized.contains("WISPKEY_PASSWORD"));
    assert!(!serialized.contains("test-password"));
}

#[test]
fn doctor_passes_core_checks_on_an_unlocked_vault() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let (ok, report) = doctor_json(vault_dir.path());
    assert_eq!(check_ids(&report), STABLE_CHECK_IDS);
    assert_eq!(check_named(&report, "binary.version")["status"], "pass");
    assert_eq!(check_named(&report, "vault.permissions")["status"], "pass");
    assert_eq!(check_named(&report, "session.state")["status"], "pass");
    assert_eq!(check_named(&report, "policy.validity")["status"], "pass");
    assert_eq!(check_named(&report, "audit.writability")["status"], "pass");
    assert_eq!(check_named(&report, "mcp.initialization")["status"], "pass");
    assert_eq!(check_named(&report, "proxy.substitution")["status"], "pass");
    assert!(
        ok || report["summary"]["failed"].as_u64().unwrap_or(0) == 0,
        "unexpected doctor failures: {report}"
    );
    let serialized = serde_json::to_string(&report).expect("serialize");
    assert!(!serialized.contains("WISPKEY_PASSWORD"));
    assert!(!serialized.contains("test-password"));
}

#[test]
fn doctor_warns_when_session_is_locked() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let lock = run_wispkey(vault_dir.path(), &["lock"]);
    assert!(
        lock.status.success(),
        "lock failed\n{}",
        String::from_utf8_lossy(&lock.stderr)
    );

    let (_ok, report) = doctor_json(vault_dir.path());
    let session = check_named(&report, "session.state");
    assert_eq!(session["status"], "warn");
    assert!(
        session["remediation"]
            .as_str()
            .expect("remediation")
            .contains("wispkey unlock")
    );
    assert!(
        !session["remediation"]
            .as_str()
            .expect("remediation")
            .contains("password-file")
    );
}

#[test]
fn doctor_fails_invalid_policy_file() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    std::fs::write(
        vault_dir.path().join("policies.toml"),
        "[[policy]]\nname = \"bad\"\nrate_limit = \"not-a-limit\"\n",
    )
    .expect("write policies");

    let (ok, report) = doctor_json(vault_dir.path());
    assert!(!ok);
    let policy = check_named(&report, "policy.validity");
    assert_eq!(policy["status"], "fail");
    assert!(
        policy["message"]
            .as_str()
            .expect("message")
            .contains("rate_limit")
    );
}

#[cfg(unix)]
#[test]
fn doctor_fails_world_writable_vault_dir() {
    use std::os::unix::fs::PermissionsExt;

    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    std::fs::set_permissions(vault_dir.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod vault dir");

    let (ok, report) = doctor_json(vault_dir.path());
    assert!(!ok);
    let permissions = check_named(&report, "vault.permissions");
    assert_eq!(permissions["status"], "fail");
    assert!(
        permissions["message"]
            .as_str()
            .expect("message")
            .contains("permissions")
    );
}
