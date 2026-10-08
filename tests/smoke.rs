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

#[cfg(target_os = "linux")]
#[test]
fn cli_starts_with_a_bounded_main_stack() {
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["add", "--help"],
        vec!["exec", "--help"],
        vec!["serve", "--help"],
        vec!["auth", "bundle", "resolve", "--help"],
        vec!["init"],
        vec!["--format", "json", "auth", "list"],
    ] {
        let mut command = wispkey_bin();
        command
            .args(&args)
            .env("WISPKEY_VAULT_PATH", dir.path())
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file");
        // Exercise the real entry point, including Tokio and clap's generated
        // command tree, below Windows's default 1 MiB main-thread stack. Leave
        // 128 KiB of headroom for platform-specific stack usage.
        // SAFETY: the post-fork closure only calls async-signal-safe setrlimit
        // and reads errno; it does not allocate or acquire locks.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 896 * 1024,
                    rlim_max: 896 * 1024,
                };
                if libc::setrlimit(libc::RLIMIT_STACK, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().expect("failed to run wispkey");
        assert!(
            output.status.success(),
            "bounded-stack command {args:?} failed: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    assert!(dir.path().join("vault.db").exists());
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

#[test]
fn personal_credential_lifecycle_is_accountless_and_redacted() {
    use base64::Engine;
    use std::io::Write;
    use std::process::Stdio;

    let vault = tempfile::tempdir().unwrap();
    let canary = "synthetic-offline-secret-never-agent-output";
    let encoded = base64::engine::general_purpose::STANDARD.encode(canary);
    let command = |args: &[&str]| {
        let mut child = wispkey_bin();
        child
            .args(["--format", "json"])
            .args(args)
            .env("WISPKEY_VAULT_PATH", vault.path())
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PROJECT");
        child
    };
    let safe = |output: &std::process::Output| {
        for bytes in [&output.stdout, &output.stderr] {
            for value in [canary.as_bytes(), encoded.as_bytes()] {
                assert!(
                    !bytes.windows(value.len()).any(|part| part == value),
                    "plaintext reached CLI output"
                );
            }
        }
    };
    let run = |args: &[&str]| {
        let output = command(args).output().unwrap();
        safe(&output);
        assert!(output.status.success(), "accountless local command failed");
        output
    };
    let json =
        |args: &[&str]| serde_json::from_slice::<serde_json::Value>(&run(args).stdout).unwrap();
    run(&["init"]);
    run(&["project", "create", "offline"]);
    run(&["project", "use", "offline"]);
    run(&["partition", "create", "environment"]);
    let mut add = command(&[
        "add",
        "offline-key",
        "--partition",
        "environment",
        "--hosts",
        "127.0.0.1",
        "--value-file",
        "-",
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(canary.as_bytes())
        .unwrap();
    let added = add.wait_with_output().unwrap();
    safe(&added);
    assert!(
        added.status.success(),
        "accountless credential input failed"
    );
    let original =
        json(&["get", "offline-key", "--show-token"])["credential"]["wisp_token"].clone();
    let rotated = json(&["rotate", "offline-key"])["wisp_token"].clone();
    assert!(original.as_str().unwrap().starts_with("wk_"));
    assert!(rotated.as_str().unwrap().starts_with("wk_"));
    assert_ne!(original, rotated);
    run(&["list"]);
    run(&["lock"]);
    let locked = command(&["get", "offline-key"])
        .env_remove("WISPKEY_PASSWORD")
        .output()
        .unwrap();
    safe(&locked);
    assert!(
        !locked.status.success(),
        "locked vault unexpectedly released metadata"
    );
    run(&["unlock"]);
    assert_eq!(
        json(&["get", "offline-key", "--show-token"])["credential"]["wisp_token"],
        rotated
    );
    run(&["audit", "export", "--encoding", "json"]);
    for entry in std::fs::read_dir(vault.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            for value in [canary.as_bytes(), encoded.as_bytes()] {
                assert!(
                    !bytes.windows(value.len()).any(|part| part == value),
                    "plaintext reached persisted local state"
                );
            }
        }
    }
    assert!(!vault.path().join("cloud.json").exists());
    run(&["remove", "offline-key"]);
    assert!(
        json(&["list"])["credentials"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
