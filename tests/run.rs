#![cfg(unix)]

mod common;

use common::*;
use std::io::Write;
use std::process::{Command, Stdio};

const RUN_SECRET_ONE_NAME: &str = "run-secret-one";
const RUN_SECRET_ONE_VALUE: &str = "run-secret-value-one";
const RUN_SECRET_TWO_NAME: &str = "run-secret-two";
const RUN_SECRET_TWO_VALUE: &str = "run-secret-value-two";

fn add_run_secrets(vault_dir: &std::path::Path) {
    for (name, value) in [
        (RUN_SECRET_ONE_NAME, RUN_SECRET_ONE_VALUE),
        (RUN_SECRET_TWO_NAME, RUN_SECRET_TWO_VALUE),
    ] {
        run_wispkey_json(
            vault_dir,
            &[
                "--format", "json", "add", name, "--type", "api_key", "--value", value,
            ],
        );
    }
}

fn cksum_parts(value: &str) -> (String, String) {
    let mut child = Command::new("cksum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cksum");
    child
        .stdin
        .as_mut()
        .expect("cksum stdin")
        .write_all(value.as_bytes())
        .expect("write cksum stdin");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for cksum");
    assert!(
        output.status.success(),
        "cksum failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = String::from_utf8(output.stdout).expect("cksum utf8");
    let mut parts = raw.split_whitespace();
    let checksum = parts.next().expect("cksum checksum").to_string();
    let length = parts.next().expect("cksum length").to_string();
    (checksum, length)
}

#[test]
fn run_manifest_injects_credential_refs_and_literals_child_only_and_audits() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let manifest_dir = tempfile::tempdir().expect("manifest dir");
    init_vault(vault_dir.path());
    add_run_secrets(vault_dir.path());

    let manifest = manifest_dir.path().join("wispkey.toml");
    std::fs::write(
        &manifest,
        format!(
            r#"[env]
WISPKEY_TEST_RUN_ONE = "cred:{RUN_SECRET_ONE_NAME}"
WISPKEY_TEST_RUN_TWO = "cred:{RUN_SECRET_TWO_NAME}"
WISPKEY_TEST_RUN_LITERAL = "literal-safe"
"#
        ),
    )
    .expect("write manifest");
    let manifest_arg = manifest.to_string_lossy().to_string();
    let (one_checksum, one_length) = cksum_parts(RUN_SECRET_ONE_VALUE);
    let (two_checksum, two_length) = cksum_parts(RUN_SECRET_TWO_VALUE);
    let script = r#"set -eu
test "${WISPKEY_TEST_RUN_ONE+x}" = x
test "${WISPKEY_TEST_RUN_TWO+x}" = x
test "${WISPKEY_TEST_RUN_LITERAL+x}" = x
actual_one=$(printf %s "$WISPKEY_TEST_RUN_ONE" | cksum)
actual_two=$(printf %s "$WISPKEY_TEST_RUN_TWO" | cksum)
test "$actual_one" = "$1 $2"
test "$actual_two" = "$3 $4"
test "$WISPKEY_TEST_RUN_LITERAL" = literal-safe
case "$0 $*" in *"$WISPKEY_TEST_RUN_ONE"*|*"$WISPKEY_TEST_RUN_TWO"*) exit 1;; esac
"#;

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "run",
            "--manifest",
            &manifest_arg,
            "--",
            "sh",
            "-c",
            script,
            "run-env",
            &one_checksum,
            &one_length,
            &two_checksum,
            &two_length,
        ],
    );
    assert!(
        output.status.success(),
        "run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::env::var("WISPKEY_TEST_RUN_ONE").is_err());
    assert!(std::env::var("WISPKEY_TEST_RUN_TWO").is_err());
    assert!(std::env::var("WISPKEY_TEST_RUN_LITERAL").is_err());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RUN_SECRET_ONE_VALUE));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RUN_SECRET_ONE_VALUE));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RUN_SECRET_TWO_VALUE));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RUN_SECRET_TWO_VALUE));

    let log = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "log", "--last", "10"],
    );
    let entries = log["entries"].as_array().expect("entries array");
    let run_entry = entries
        .iter()
        .find(|entry| entry["event_type"] == "CredentialRun")
        .expect("CredentialRun audit entry");
    let credential_names = run_entry["credential_name"]
        .as_str()
        .expect("credential names");
    assert!(credential_names.contains(RUN_SECRET_ONE_NAME));
    assert!(credential_names.contains(RUN_SECRET_TWO_NAME));
    assert_eq!(run_entry["target_host"], "sh");
    assert_eq!(run_entry["http_method"], "run");
    assert_eq!(run_entry["response_status"], 0);
    let raw_log = serde_json::to_string(&log).expect("log json");
    assert!(!raw_log.contains(RUN_SECRET_ONE_VALUE));
    assert!(!raw_log.contains(RUN_SECRET_TWO_VALUE));
}

#[test]
fn run_missing_credential_fails_without_spawning_child() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let manifest_dir = tempfile::tempdir().expect("manifest dir");
    let marker_dir = tempfile::tempdir().expect("marker dir");
    let marker = marker_dir.path().join("spawned");
    let marker_arg = marker.to_string_lossy().to_string();
    init_vault(vault_dir.path());

    let manifest = manifest_dir.path().join("wispkey.toml");
    std::fs::write(
        &manifest,
        r#"[env]
WISPKEY_TEST_RUN_MISSING = "cred:missing-secret"
"#,
    )
    .expect("write manifest");
    let manifest_arg = manifest.to_string_lossy().to_string();

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "run",
            "--manifest",
            &manifest_arg,
            "--",
            "sh",
            "-c",
            "touch \"$1\"",
            "marker",
            &marker_arg,
        ],
    );
    assert!(!output.status.success());
    assert!(!marker.exists(), "child command should not have spawned");
}
