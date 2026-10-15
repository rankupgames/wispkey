mod common;

use common::*;
use serde_json::Value;

const AUDIT_SECRET: &str = "audit-secret-value";

#[test]
fn audit_export_jsonl_outputs_matching_range_without_secret_values() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let created = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "audit-key",
            "--type",
            "api_key",
            "--value",
            AUDIT_SECRET,
        ],
    );
    let wisp_token = created["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token");

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "audit",
            "export",
            "--encoding",
            "jsonl",
            "--since",
            "1970-01-01",
            "--credential",
            "audit-key",
        ],
    );
    assert!(
        output.status.success(),
        "audit export failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert!(!lines.is_empty(), "expected jsonl audit rows");
    for line in &lines {
        let entry: Value = serde_json::from_str(line).expect("jsonl entry");
        assert_eq!(entry["credential_name"], "audit-key");
    }
    assert!(!stdout.contains(AUDIT_SECRET));
    assert!(!stdout.contains(wisp_token));
    assert!(lines.iter().all(|line| line.contains("token_fingerprint")));

    let empty = run_wispkey(
        vault_dir.path(),
        &[
            "audit",
            "export",
            "--encoding",
            "jsonl",
            "--since",
            "2999-01-01",
            "--credential",
            "audit-key",
        ],
    );
    assert!(empty.status.success(), "future range export should succeed");
    assert!(
        String::from_utf8_lossy(&empty.stdout).trim().is_empty(),
        "future range should produce no jsonl rows"
    );
}

#[test]
fn audit_export_json_array_writes_output_file_and_tail_prints_jsonl() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let output_dir = tempfile::tempdir().expect("output dir");
    let export_path = output_dir.path().join("audit.json");
    let export_path_string = export_path.to_string_lossy().to_string();
    init_vault(vault_dir.path());

    let created = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "tail-key",
            "--type",
            "api_key",
            "--value",
            AUDIT_SECRET,
        ],
    );
    let wisp_token = created["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token");

    let export = run_wispkey(
        vault_dir.path(),
        &[
            "audit",
            "export",
            "--encoding",
            "json",
            "--credential",
            "tail-key",
            "-o",
            &export_path_string,
        ],
    );
    assert!(
        export.status.success(),
        "audit json export failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&export.stdout),
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = std::fs::read_to_string(&export_path).expect("audit export file");
    let array: Value = serde_json::from_str(&exported).expect("json array");
    assert!(array.as_array().expect("array").iter().any(|entry| {
        entry["event_type"] == "CredentialAdded" && entry["credential_name"] == "tail-key"
    }));
    assert!(!exported.contains(AUDIT_SECRET));
    assert!(!exported.contains(wisp_token));

    let tail = run_wispkey(
        vault_dir.path(),
        &["audit", "tail", "--credential", "tail-key"],
    );
    assert!(
        tail.status.success(),
        "audit tail failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&tail.stdout),
        String::from_utf8_lossy(&tail.stderr)
    );
    let tail_stdout = String::from_utf8_lossy(&tail.stdout);
    assert!(!tail_stdout.contains(AUDIT_SECRET));
    assert!(!tail_stdout.contains(wisp_token));
    let first_line = tail_stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("tail jsonl line");
    let entry: Value = serde_json::from_str(first_line).expect("tail jsonl");
    assert_eq!(entry["credential_name"], "tail-key");
}

#[cfg(unix)]
#[test]
fn audit_remediation_cli_is_offline_metadata_only_and_non_destructive() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.path().join("original.jsonl");
    let destination = directory.path().join("redacted.jsonl");
    let contents = serde_json::json!({
        "timestamp":"2026-10-15T00:00:00Z", "event_type":"Use",
        "wisp_token":"wk_legacy_secret", "denied":false,
        "target_path":"/wk_legacy_secret", "unknown":"wk_other_secret"
    })
    .to_string();
    std::fs::write(&source, &contents).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let args = [
        "audit",
        "remediate-fallback",
        "--input",
        source.to_str().unwrap(),
        "--output",
        destination.to_str().unwrap(),
    ];
    // Deliberately no init: this must not open, unlock, or mutate a vault.
    let result = run_wispkey(directory.path(), &args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["records_written"], 1);
    assert_eq!(report["legacy_token_fields_removed"], 1);
    assert_eq!(report["source_preserved"], true);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("wk_"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("wk_"));
    assert_eq!(std::fs::read_to_string(&source).unwrap(), contents);
    let safe = std::fs::read_to_string(&destination).unwrap();
    assert!(!safe.contains("wk_"));
    assert!(!directory.path().join("vault.db").exists());
    let duplicate = run_wispkey(directory.path(), &args);
    assert!(!duplicate.status.success());
    assert_eq!(std::fs::read_to_string(&destination).unwrap(), safe);
}

#[test]
fn malformed_fallback_reader_never_echoes_secret_in_parser_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let malformed = serde_json::json!({
        "timestamp":"2026-10-15T00:00:00Z", "event_type":"Use",
        "denied":"wk_parser_diagnostic_secret"
    })
    .to_string();
    std::fs::write(directory.path().join("sideload-audit.jsonl"), malformed).unwrap();
    let result = run_wispkey(directory.path(), &["audit", "export"]);
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("wk_parser_diagnostic_secret"));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!stderr.contains("wk_parser_diagnostic_secret"));
    assert!(stderr.contains("Failed to parse fallback audit log line"));
}
