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
    assert!(stdout.contains("unlock"));
    assert!(stdout.contains("lock"));
    assert!(stdout.contains("add"));
    assert!(stdout.contains("serve"));
    assert!(stdout.contains("import"));
    assert!(stdout.contains("env"));
    assert!(stdout.contains("cloud"));
    assert!(stdout.contains("backup"));
    assert!(stdout.contains("mcp"));
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("integrate"));
}

#[test]
fn status_without_vault_reports_uninitialized() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_wispkey(dir.path(), &["status"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Vault: not initialized"));
    assert!(!dir.path().join("vault.db").exists());
}

#[test]
fn cloud_status_without_config_reports_disconnected() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_wispkey(dir.path(), &["cloud", "status"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("WispKey Cloud: not connected"));
    assert!(!dir.path().join("cloud.json").exists());
}

#[test]
fn policy_list_without_configuration_reports_empty() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_wispkey(dir.path(), &["policy", "list"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("No policies configured."));
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
    let dir = tempfile::tempdir().unwrap();
    // Guards against dropping `global = true` on the top-level --format flag,
    // which would make `--format` after a subcommand fail to parse.
    for args in [
        vec!["status", "--format", "json"],
        vec!["instance", "list", "--format", "json"],
        vec!["audit", "export", "--format", "jsonl"],
        vec!["guard", "shell", "--format", "json"],
    ] {
        let output = run_wispkey(dir.path(), &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument '--format'"),
            "--format must be accepted after `{}`; got: {stderr}",
            args.join(" ")
        );
    }
}
