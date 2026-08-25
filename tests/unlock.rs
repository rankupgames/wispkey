mod common;

use common::*;

#[test]
fn unlock_accepts_owner_only_password_file_and_not_cli_password_flag() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let help = wispkey_bin()
        .args(["unlock", "--help"])
        .output()
        .expect("unlock help");
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--password-file"));
    assert!(
        !help_text.contains("--password ") && !help_text.contains("--password\n"),
        "master password must not be accepted as a CLI argument: {help_text}"
    );

    let password_path = vault_dir.path().join("master.pass");
    write_private_test_file(&password_path, "test-password\n");

    let output = run_wispkey_without_password(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "unlock",
            "--password-file",
            password_path.to_str().expect("utf8 path"),
        ],
    );
    let value = output_json(&["unlock", "--password-file"], output);
    assert_eq!(value["unlocked"], true);
    assert_eq!(value["source"], "password");
}

#[test]
fn remembered_file_protector_reunlocks_after_lock_until_forgotten() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format", "json", "add", "demo", "--type", "api_key", "--value", "secret",
        ],
    );

    let remembered = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "unlock",
            "--remember",
            "--protector-timeout",
            "60",
        ],
    );
    assert_eq!(remembered["unlocked"], true);
    assert_eq!(remembered["protector"], "file");

    let locked = run_wispkey_json(vault_dir.path(), &["--format", "json", "lock"]);
    assert_eq!(locked["locked"], true);
    assert_eq!(locked["forgotten"], false);

    let list_locked = run_wispkey_without_password(vault_dir.path(), &["--format", "json", "list"]);
    assert!(
        !list_locked.status.success(),
        "locked vault must fail closed"
    );
    let locked_err = format!(
        "{}{}",
        String::from_utf8_lossy(&list_locked.stdout),
        String::from_utf8_lossy(&list_locked.stderr)
    );
    assert!(
        locked_err.contains("locked") || locked_err.contains("unlock"),
        "expected locked error, got: {locked_err}"
    );

    let reunlocked =
        run_wispkey_without_password(vault_dir.path(), &["--format", "json", "unlock"]);
    let reunlocked = output_json(&["unlock"], reunlocked);
    assert_eq!(reunlocked["unlocked"], true);
    assert_eq!(reunlocked["source"], "protector");
    assert_eq!(reunlocked["protector"], "file");

    let listed = run_wispkey_without_password(vault_dir.path(), &["--format", "json", "list"]);
    let listed = output_json(&["list"], listed);
    assert!(credential_names(&listed).contains(&"demo".to_string()));

    let forgotten = run_wispkey_json(vault_dir.path(), &["--format", "json", "lock", "--forget"]);
    assert_eq!(forgotten["forgotten"], true);

    let denied = run_wispkey_without_password(vault_dir.path(), &["--format", "json", "unlock"]);
    assert!(
        !denied.status.success(),
        "forgotten protector must fail closed"
    );
    let denied_err = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_err.contains("remembered unlock")
            || denied_err.contains("password-file")
            || denied_err.contains("locked"),
        "expected protector-unavailable error, got: {denied_err}"
    );
}

#[test]
fn unlock_and_lock_emit_audit_events_without_password() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    run_wispkey(
        vault_dir.path(),
        &["unlock", "--remember", "--protector-timeout", "30"],
    );
    run_wispkey(vault_dir.path(), &["lock"]);
    run_wispkey_without_password(vault_dir.path(), &["unlock"]);
    run_wispkey(vault_dir.path(), &["lock", "--forget"]);

    let output = run_wispkey(
        vault_dir.path(),
        &["--format", "json", "log", "--last", "20"],
    );
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VaultUnlocked"));
    assert!(stdout.contains("VaultLocked"));
    assert!(stdout.contains("ProtectorRemembered"));
    assert!(stdout.contains("ProtectorForgotten"));
    assert!(!stdout.contains("test-password"));
}

#[test]
fn status_reports_session_and_protector_state() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    run_wispkey(
        vault_dir.path(),
        &[
            "unlock",
            "--remember",
            "--timeout",
            "30",
            "--protector-timeout",
            "60",
        ],
    );

    let status = run_wispkey_json(vault_dir.path(), &["--format", "json", "status"]);
    assert_eq!(status["session_active"], true);
    assert_eq!(status["session_timeout_minutes"], 30);
    assert_eq!(status["protector_available"], true);
    assert_eq!(status["protector_backend"], "file");
    assert!(status["session_expires_at"].as_str().is_some());
}

#[test]
fn unlock_rejects_negative_timeout() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let output = run_wispkey(vault_dir.path(), &["unlock", "--timeout=-1"]);
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("timeout") || err.contains("positive"),
        "expected timeout validation error, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn file_protector_is_owner_only() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    run_wispkey(vault_dir.path(), &["unlock", "--remember"]);
    assert_eq!(
        file_mode(&vault_dir.path().join("session-protector")),
        0o600
    );
}
