mod common;

use common::*;
use serde_json::Value;

fn add_named_secret(vault_dir: &std::path::Path, name: &str, value: &str) {
    run_wispkey_json(
        vault_dir,
        &[
            "--format",
            "json",
            "add",
            name,
            "--type",
            "api_key",
            "--value",
            value,
            "--hosts",
            "api.example.com",
            "--tags",
            "backup,test",
        ],
    );
}

fn create_backup(vault_dir: &std::path::Path, output: &str) -> Value {
    run_wispkey_bundle_json(
        vault_dir,
        &["--format", "json", "backup", "create", "--output", output],
    )
}

fn unlock_vault(vault_dir: &std::path::Path) {
    let output = run_wispkey(vault_dir, &["unlock"]);
    assert!(
        output.status.success(),
        "unlock failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn inspect_json_has_no_secrets(inspect: &Value, secret: &str) {
    let encoded = inspect.to_string();
    assert!(!encoded.contains(secret), "inspect leaked secret value");
    assert!(
        !encoded.contains("encrypted_value"),
        "inspect leaked encrypted_value"
    );
    assert!(
        !encoded.contains("password_hash"),
        "inspect leaked password_hash"
    );
    assert!(
        !encoded.contains("secret_hash"),
        "inspect leaked secret_hash"
    );
    assert!(!encoded.contains("token_hash"), "inspect leaked token_hash");
    assert!(
        !encoded.contains("clerk_session_token"),
        "inspect leaked cloud session token field"
    );
}

#[test]
fn backup_roundtrip_to_separate_vault_preserves_token_and_secret() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    std::fs::write(
        source.path().join("policies.toml"),
        "[[policy]]\nname = \"allow-example\"\ncredential = \"backup-key\"\nallowed_hosts = [\"api.example.com\"]\n",
    )
    .expect("policies");
    std::fs::write(
        source.path().join("cloud.json"),
        r#"{"api_url":"https://api.wispkey.com","clerk_session_token":"clerk-secret-token","tier":"Personal"}"#,
    )
    .expect("cloud json");
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    let original = run_wispkey_json(
        source.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    let original_token = original["credential"]["wisp_token"]
        .as_str()
        .expect("token")
        .to_string();

    let created = create_backup(source.path(), &backup);
    assert_eq!(created["counts"]["credentials"], 1);
    assert!(backup_path.exists());

    let inspect = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "inspect", &backup],
    );
    inspect_json_has_no_secrets(&inspect, "backup-secret-value");
    inspect_json_has_no_secrets(&inspect, "clerk-secret-token");
    assert_eq!(inspect["credentials"][0]["name"], "backup-key");
    assert_eq!(inspect["sidecars"]["cloud_session_token_present"], true);

    let verified = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "verify", &backup],
    );
    assert_eq!(verified["ok"], true);

    let restored = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &backup, "--target", &dest_path,
        ],
    );
    assert_eq!(restored["mode"], "replace");
    assert_eq!(restored["imported"]["credentials"], 1);
    assert!(dest.path().join("vault.db").exists());
    unlock_vault(dest.path());
    assert!(dest.path().join("policies.toml").exists());
    let policies = std::fs::read_to_string(dest.path().join("policies.toml")).expect("policies");
    assert!(policies.contains("allow-example"));
    let cloud = std::fs::read_to_string(dest.path().join("cloud.json")).expect("cloud");
    assert!(cloud.contains("clerk-secret-token"));

    let listed = run_wispkey_json(
        dest.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    assert_eq!(listed["credential"]["wisp_token"], original_token);

    let template = dest.path().join("template.txt");
    let rendered = dest.path().join("rendered.txt");
    std::fs::write(&template, "{{ cred:backup-key }}\n").expect("template");
    let inject = run_wispkey(
        dest.path(),
        &[
            "inject",
            "-i",
            &template.to_string_lossy(),
            "-o",
            &rendered.to_string_lossy(),
        ],
    );
    assert!(
        inject.status.success(),
        "inject after restore failed\n{}",
        String::from_utf8_lossy(&inject.stderr)
    );
    let plaintext = std::fs::read_to_string(&rendered).expect("rendered");
    assert_eq!(plaintext, "backup-secret-value\n");
}

#[test]
fn backup_wrong_passphrase_and_corrupt_archive_fail_closed() {
    let source = tempfile::tempdir().expect("source");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    create_backup(source.path(), &backup);

    let wrong = run_wispkey_with_bundle_passphrase(
        source.path(),
        &["backup", "inspect", &backup],
        "definitely-wrong-passphrase",
    );
    assert!(!wrong.status.success(), "wrong passphrase should fail");

    let mut bytes = std::fs::read(&backup_path).expect("read backup");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&backup_path, bytes).expect("corrupt backup");
    let corrupt = run_wispkey_bundle(source.path(), &["backup", "verify", &backup]);
    assert!(!corrupt.status.success(), "corrupt backup should fail");
}

#[test]
fn backup_dry_run_does_not_write_and_conflicts_do_not_overwrite() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "source-secret");
    create_backup(source.path(), &backup);

    let dry = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--dry-run",
            "--target",
            &dest_path,
        ],
    );
    assert_eq!(dry["dry_run"], true);
    assert!(!dest.path().join("vault.db").exists());

    init_vault(dest.path());
    add_named_secret(dest.path(), "backup-key", "dest-secret");
    let dest_before = run_wispkey_json(
        dest.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    let dest_token = dest_before["credential"]["wisp_token"]
        .as_str()
        .expect("dest token")
        .to_string();

    let conflicted = run_wispkey_bundle(
        dest.path(),
        &["backup", "restore", &backup, "--on-conflict", "fail"],
    );
    assert!(
        !conflicted.status.success(),
        "merge into a populated vault should fail without --replace\n{}",
        String::from_utf8_lossy(&conflicted.stderr)
    );
    let dest_after = run_wispkey_json(
        dest.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    assert_eq!(dest_after["credential"]["wisp_token"], dest_token);

    let leftover = dest.path().join(".wk-restore-interrupted");
    std::fs::create_dir_all(&leftover).expect("leftover staging");
    std::fs::write(leftover.join("vault.db"), b"partial").expect("partial staging db");

    let replaced = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--replace",
        ],
    );
    assert_eq!(replaced["mode"], "replace");
    unlock_vault(dest.path());
    let dest_replaced = run_wispkey_json(
        dest.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    let source_token = run_wispkey_json(
        source.path(),
        &["--format", "json", "get", "backup-key", "--show-token"],
    );
    assert_eq!(
        dest_replaced["credential"]["wisp_token"],
        source_token["credential"]["wisp_token"]
    );
    assert!(
        leftover.exists(),
        "unrelated leftover staging dir should not block restore"
    );
}

#[test]
fn backup_restore_marks_instances_for_reenrollment() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    let enrolled = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "worker-one",
            "--credential",
            "backup-key",
        ],
    );
    assert_eq!(enrolled["instance"]["status"], "active");
    let original_secret = enrolled["secret"].as_str().expect("secret").to_string();

    create_backup(source.path(), &backup);
    let restored = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &backup, "--target", &dest_path,
        ],
    );
    assert!(
        restored["instances_needing_reenrollment"]
            .as_array()
            .expect("names")
            .iter()
            .any(|name| name == "worker-one")
    );

    unlock_vault(dest.path());
    let listed = run_wispkey_json(dest.path(), &["--format", "json", "instance", "list"]);
    assert_eq!(listed["instances"][0]["name"], "worker-one");
    assert_eq!(listed["instances"][0]["status"], "needs_reenrollment");

    let rotated = run_wispkey_json(
        dest.path(),
        &[
            "--format",
            "json",
            "instance",
            "rotate-secret",
            "worker-one",
        ],
    );
    assert_eq!(rotated["rotated"], true);
    assert_eq!(rotated["instance"]["status"], "active");
    let new_secret = rotated["secret"].as_str().expect("new secret");
    assert_ne!(new_secret, original_secret);
}

#[test]
fn backup_exclude_omits_audits_from_scope() {
    let source = tempfile::tempdir().expect("source");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    let created = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "create",
            "--output",
            &backup,
            "--exclude",
            "audits,cloud",
        ],
    );
    assert_eq!(created["scope"]["audits"], false);
    assert_eq!(created["scope"]["cloud"], false);
    assert_eq!(created["scope"]["credentials"], true);
    let inspect = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "inspect", &backup],
    );
    assert_eq!(inspect["scope"]["audits"], false);
    assert_eq!(inspect["counts"]["audits"], 0);
}
