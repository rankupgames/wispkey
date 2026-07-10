mod common;

use common::*;

#[test]
fn version_flag_prints_version() {
    let output = wispkey_bin()
        .arg("--version")
        .output()
        .expect("failed to run wispkey");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wispkey"),
        "expected version output, got: {stdout}"
    );
}

#[test]
fn help_flag_shows_commands() {
    let output = wispkey_bin()
        .arg("--help")
        .output()
        .expect("failed to run wispkey");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("init"));
    assert!(stdout.contains("add"));
    assert!(stdout.contains("serve"));
    assert!(stdout.contains("import"));
    assert!(stdout.contains("cloud"));
    assert!(stdout.contains("mcp"));
}

#[test]
fn status_without_vault_shows_error() {
    let output = wispkey_bin()
        .arg("status")
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("vault")
            || combined.contains("Vault")
            || combined.contains("No vault")
            || combined.contains("not found"),
        "expected vault-related output, got: {combined}"
    );
}

#[test]
fn cloud_status_shows_coming_soon_or_status() {
    let output = wispkey_bin()
        .args(["cloud", "status"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Cloud") || combined.contains("cloud") || combined.contains("vault"),
        "expected cloud-related output, got: {combined}"
    );
}

#[test]
fn policy_list_without_vault_fails_gracefully() {
    let output = wispkey_bin()
        .args(["policy", "list"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("polic") || combined.contains("No") || combined.contains("vault"),
        "expected policy or vault output, got: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn vault_directory_and_session_file_are_owner_only_on_unix() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    assert_eq!(file_mode(vault_dir.path()), 0o700);
    assert_eq!(file_mode(&vault_dir.path().join("session")), 0o600);
}

#[test]
fn format_flag_is_global_after_subcommands() {
    // Guards against dropping `global = true` on the top-level --format flag,
    // which would make `--format` after a subcommand fail to parse.
    for args in [
        vec!["status", "--format", "json"],
        vec!["instance", "list", "--format", "json"],
        vec!["audit", "export", "--format", "jsonl"],
    ] {
        let output = wispkey_bin()
            .args(&args)
            .env("HOME", "/tmp/wispkey-test-nonexistent")
            .output()
            .expect("failed to run wispkey");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument '--format'"),
            "--format must be accepted after `{}`; got: {stderr}",
            args.join(" ")
        );
    }
}
