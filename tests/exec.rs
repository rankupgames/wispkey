#![cfg(unix)]

mod common;

use common::*;
use std::io::Write;
use std::process::{Command, Stdio};

const EXEC_SECRET_NAME: &str = "exec-secret";
const EXEC_SECRET_VALUE: &str = "exec-channel-secret";

fn add_exec_secret(vault_dir: &std::path::Path) {
    run_wispkey_json(
        vault_dir,
        &[
            "--format",
            "json",
            "add",
            EXEC_SECRET_NAME,
            "--type",
            "api_key",
            "--value",
            EXEC_SECRET_VALUE,
        ],
    );
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
fn exec_env_sets_child_only_env_without_secret_in_argv_and_audits() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    add_exec_secret(vault_dir.path());
    let (checksum, length) = cksum_parts(EXEC_SECRET_VALUE);
    let script = r#"set -eu
test "${WK_EXEC_SECRET+x}" = x
actual=$(printf %s "$WK_EXEC_SECRET" | cksum)
test "$actual" = "$1 $2"
case "$0 $*" in *"$WK_EXEC_SECRET"*) exit 1;; esac
"#;

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "exec",
            "--credential",
            EXEC_SECRET_NAME,
            "--env",
            "WK_EXEC_SECRET",
            "--",
            "sh",
            "-c",
            script,
            "exec-env",
            &checksum,
            &length,
        ],
    );
    assert!(
        output.status.success(),
        "exec --env failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::env::var("WK_EXEC_SECRET").is_err());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(EXEC_SECRET_VALUE));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(EXEC_SECRET_VALUE));

    let log = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "log",
            "--credential",
            EXEC_SECRET_NAME,
            "--last",
            "5",
        ],
    );
    let entries = log["entries"].as_array().expect("entries array");
    let exec_entry = entries
        .iter()
        .find(|entry| entry["event_type"] == "CredentialExec")
        .expect("CredentialExec audit entry");
    assert_eq!(exec_entry["credential_name"], EXEC_SECRET_NAME);
    assert_eq!(exec_entry["target_host"], "sh");
    assert_eq!(exec_entry["target_path"], "env");
    assert_eq!(exec_entry["response_status"], 0);
    assert!(
        !serde_json::to_string(&log)
            .unwrap()
            .contains(EXEC_SECRET_VALUE)
    );
}

#[test]
fn exec_stdin_writes_one_secret_line() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    add_exec_secret(vault_dir.path());
    let (checksum, length) = cksum_parts(EXEC_SECRET_VALUE);
    let script = r#"set -eu
IFS= read -r line
actual=$(printf %s "$line" | cksum)
test "$actual" = "$1 $2"
case "$0 $*" in *"$line"*) exit 1;; esac
"#;

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "exec",
            "--credential",
            EXEC_SECRET_NAME,
            "--stdin",
            "--",
            "sh",
            "-c",
            script,
            "exec-stdin",
            &checksum,
            &length,
        ],
    );
    assert!(
        output.status.success(),
        "exec --stdin failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(EXEC_SECRET_VALUE));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(EXEC_SECRET_VALUE));
}

#[test]
fn exec_askpass_sets_helper_environment_and_hidden_helper_resolves_secret() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    add_exec_secret(vault_dir.path());
    let script = r#"set -eu
test -n "${SUDO_ASKPASS:-}"
test "$SUDO_ASKPASS" = "$SSH_ASKPASS"
test "$SUDO_ASKPASS" = "$GIT_ASKPASS"
test "$SSH_ASKPASS_REQUIRE" = force
test -z "${WISPKEY_ASKPASS_CRED:-}"
test -z "${WISPKEY_ASKPASS_PROJECT:-}"
test -n "${WISPKEY_ASKPASS_HANDOFF:-}"
test -f "$WISPKEY_ASKPASS_HANDOFF"
secret="$("$SUDO_ASKPASS")"
test "$secret" = "exec-channel-secret"
test ! -e "$WISPKEY_ASKPASS_HANDOFF"
"#;

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "exec",
            "--credential",
            EXEC_SECRET_NAME,
            "--askpass",
            "--",
            "sh",
            "-c",
            script,
        ],
    );
    assert!(
        output.status.success(),
        "exec --askpass failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let oracle = wispkey_bin()
        .arg("askpass")
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_ASKPASS_CRED", EXEC_SECRET_NAME)
        .output()
        .expect("run askpass helper");
    assert!(
        !oracle.status.success(),
        "askpass env oracle should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&oracle.stdout),
        String::from_utf8_lossy(&oracle.stderr)
    );
    assert!(oracle.stdout.is_empty());
}

#[test]
fn exec_missing_credential_fails_without_spawning_child() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let marker_dir = tempfile::tempdir().expect("marker dir");
    let marker = marker_dir.path().join("spawned");
    let marker_arg = marker.to_string_lossy().to_string();
    init_vault(vault_dir.path());

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "exec",
            "--credential",
            "missing-secret",
            "--env",
            "WK_EXEC_SECRET",
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

#[test]
fn exec_requires_at_least_one_channel_without_spawning_child() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let marker_dir = tempfile::tempdir().expect("marker dir");
    let marker = marker_dir.path().join("spawned");
    let marker_arg = marker.to_string_lossy().to_string();
    init_vault(vault_dir.path());
    add_exec_secret(vault_dir.path());

    let output = run_wispkey(
        vault_dir.path(),
        &[
            "exec",
            "--credential",
            EXEC_SECRET_NAME,
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
