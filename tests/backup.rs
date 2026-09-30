mod common;

use common::*;
use rusqlite::Connection;
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

fn match_password_hash(source: &std::path::Path, destination: &std::path::Path) {
    let source_db = Connection::open(source.join("vault.db")).expect("source db");
    let password_hash: String = source_db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'password_hash'",
            [],
            |row| row.get(0),
        )
        .expect("source password hash");
    drop(source_db);

    let destination_db = Connection::open(destination.join("vault.db")).expect("destination db");
    destination_db
        .execute(
            "UPDATE vault_meta SET value = ?1 WHERE key = 'password_hash'",
            [password_hash],
        )
        .expect("destination password hash");
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
fn backup_create_refuses_existing_or_protected_output_without_clobbering() {
    let source = tempfile::tempdir().expect("source");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    create_backup(source.path(), &backup);
    let original = std::fs::read(&backup_path).expect("backup bytes");

    let overwrite = run_wispkey_bundle(source.path(), &["backup", "create", "--output", &backup]);
    assert!(
        !overwrite.status.success(),
        "existing backup must not be replaced"
    );
    assert_eq!(std::fs::read(&backup_path).expect("backup bytes"), original);

    let protected = source.path().join("vault.db-wal");
    let protected_output = protected.to_string_lossy().to_string();
    let protected_result = run_wispkey_bundle(
        source.path(),
        &["backup", "create", "--output", &protected_output],
    );
    assert!(
        !protected_result.status.success(),
        "protected vault files must be rejected"
    );
    assert!(!protected.exists());

    #[cfg(unix)]
    {
        let hardlink = bundle_dir.path().join("hardlink.wkbackup");
        std::fs::hard_link(&backup_path, &hardlink).expect("hard link");
        let hardlink_output = hardlink.to_string_lossy().to_string();
        let hardlink_result = run_wispkey_bundle(
            source.path(),
            &["backup", "create", "--output", &hardlink_output],
        );
        assert!(
            !hardlink_result.status.success(),
            "hardlink output must not be replaced"
        );
        assert_eq!(std::fs::read(&backup_path).expect("backup bytes"), original);

        let symlink = bundle_dir.path().join("symlink.wkbackup");
        std::os::unix::fs::symlink(&backup_path, &symlink).expect("symlink");
        let symlink_output = symlink.to_string_lossy().to_string();
        let symlink_result = run_wispkey_bundle(
            source.path(),
            &["backup", "create", "--output", &symlink_output],
        );
        assert!(
            !symlink_result.status.success(),
            "symlink output must not be replaced"
        );
        assert_eq!(std::fs::read(&backup_path).expect("backup bytes"), original);
    }
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
    let locked = run_wispkey_json(dest.path(), &["--format", "json", "lock", "--forget"]);
    assert_eq!(locked["locked"], true);

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
fn merge_skip_propagates_conflicting_project_to_children() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let base_path = bundle_dir.path().join("base.wkbackup");
    let backup_path = bundle_dir.path().join("shared.wkbackup");
    let base = base_path.to_string_lossy().to_string();
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    create_backup(source.path(), &base);
    let restored = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &base, "--target", &dest_path,
        ],
    );
    assert_eq!(restored["mode"], "replace");
    unlock_vault(dest.path());

    run_wispkey_json(
        source.path(),
        &["--format", "json", "project", "create", "shared-project"],
    );
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "add",
            "shared-key",
            "--type",
            "api_key",
            "--value",
            "shared-secret",
            "--project",
            "shared-project",
        ],
    );
    run_wispkey_json(
        dest.path(),
        &["--format", "json", "project", "create", "shared-project"],
    );
    create_backup(source.path(), &backup);

    let merged = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--on-conflict",
            "skip",
        ],
    );
    assert!(merged["skipped"]["partitions"].as_u64().unwrap_or(0) >= 1);
    assert!(merged["skipped"]["credentials"].as_u64().unwrap_or(0) >= 1);
    assert!(
        merged["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .any(|conflict| conflict["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("referenced project")))
    );

    let db = Connection::open(dest.path().join("vault.db")).expect("destination db");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE name = 'shared-key'",
            [],
            |row| row.get(0),
        )
        .expect("credential count");
    assert_eq!(
        count, 0,
        "skipped project must not leave an orphan credential"
    );
}

#[test]
fn merge_skip_propagated_dependency_counts_match_inserted_rows() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("source.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "shared-key", "source-secret");
    let enrolled = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "source-instance",
            "--credential",
            "shared-key",
        ],
    );
    let instance_id = enrolled["instance"]["id"]
        .as_str()
        .expect("instance id")
        .to_string();
    let source_db = Connection::open(source.path().join("vault.db")).expect("source db");
    let credential_id: String = source_db
        .query_row(
            "SELECT id FROM credentials WHERE name = 'shared-key'",
            [],
            |row| row.get(0),
        )
        .expect("source credential id");
    source_db
        .execute(
            "INSERT INTO access_requests (id, instance_id, credential_name, credential_id, status, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "source-request",
                instance_id,
                "shared-key",
                credential_id,
                "pending",
                "backup test",
                "2026-09-05T00:00:00Z",
            ],
        )
        .expect("source access request");
    drop(source_db);
    create_backup(source.path(), &backup);

    init_vault(dest.path());
    add_named_secret(dest.path(), "shared-key", "destination-secret");
    match_password_hash(source.path(), dest.path());
    let merged = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--on-conflict",
            "skip",
        ],
    );

    assert_eq!(merged["imported"]["instances"], 1);
    assert_eq!(merged["imported"]["scopes"], 0);
    assert_eq!(merged["imported"]["access_requests"], 0);
    assert_eq!(merged["skipped"]["scopes"], 1);
    assert_eq!(merged["skipped"]["access_requests"], 1);
    assert!(
        merged["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .filter_map(|conflict| conflict["reason"].as_str())
            .filter(|reason| reason.contains("referenced credential"))
            .count()
            >= 2
    );
}

#[test]
fn merge_dry_run_leaves_legacy_schema_bytes_unchanged() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("legacy-dry-run.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "legacy-dry-run-key", "source-secret");
    create_backup(source.path(), &backup);

    init_vault(dest.path());
    match_password_hash(source.path(), dest.path());
    let dest_db_path = dest.path().join("vault.db");
    let dest_db = Connection::open(&dest_db_path).expect("legacy destination db");
    dest_db
        .execute_batch(
            "ALTER TABLE credentials DROP COLUMN origin;
             ALTER TABLE credentials DROP COLUMN lifecycle_state;
             ALTER TABLE credentials DROP COLUMN review_at;
             UPDATE vault_meta SET value = '10' WHERE key = 'version';",
        )
        .expect("create legacy schema");
    drop(dest_db);
    let before = std::fs::read(&dest_db_path).expect("legacy bytes before dry run");

    let dry = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--dry-run",
        ],
    );

    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        std::fs::read(&dest_db_path).expect("legacy bytes after dry run"),
        before,
        "dry-run merge must not persist schema migration"
    );
}

#[test]
fn merge_sidecar_conflict_is_reported_and_rolls_back_database_rows() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let base_path = bundle_dir.path().join("base.wkbackup");
    let backup_path = bundle_dir.path().join("new.wkbackup");
    let base = base_path.to_string_lossy().to_string();
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    std::fs::write(
        source.path().join("policies.toml"),
        "[[policy]]\nname = \"base\"\n",
    )
    .expect("policies");
    create_backup(source.path(), &base);
    run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &base, "--target", &dest_path,
        ],
    );
    unlock_vault(dest.path());

    add_named_secret(source.path(), "new-source-key", "new-source-secret");
    create_backup(source.path(), &backup);

    let dry = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--dry-run",
        ],
    );
    assert!(
        dry["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .any(|conflict| conflict["entity"] == "sidecar"
                && conflict["identity"] == "policies.toml")
    );

    let failed = run_wispkey_bundle(dest.path(), &["backup", "restore", &backup]);
    assert!(
        !failed.status.success(),
        "sidecar conflict must fail the merge"
    );
    let db = Connection::open(dest.path().join("vault.db")).expect("destination db");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE name = 'new-source-key'",
            [],
            |row| row.get(0),
        )
        .expect("credential count");
    assert_eq!(
        count, 0,
        "database rows must roll back with sidecar conflict"
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
fn merge_does_not_reenroll_or_revoke_unrelated_destination_identities() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "source-instance",
            "--credential",
            "backup-key",
        ],
    );
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "create",
            "--description",
            "source-token",
        ],
    );
    create_backup(source.path(), &backup);

    run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &backup, "--target", &dest_path,
        ],
    );
    unlock_vault(dest.path());
    run_wispkey_json(
        dest.path(),
        &[
            "--format",
            "json",
            "instance",
            "enroll",
            "destination-instance",
            "--credential",
            "backup-key",
        ],
    );
    run_wispkey_json(
        dest.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "create",
            "--description",
            "destination-token",
        ],
    );

    let merged = run_wispkey_bundle_json(
        dest.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            &backup,
            "--on-conflict",
            "skip",
        ],
    );
    assert_eq!(
        merged["instances_needing_reenrollment"],
        serde_json::json!([])
    );
    assert_eq!(merged["bootstrap_tokens_revoked"], 0);

    let instances = run_wispkey_json(dest.path(), &["--format", "json", "instance", "list"]);
    let destination = instances["instances"]
        .as_array()
        .expect("instances")
        .iter()
        .find(|instance| instance["name"] == "destination-instance")
        .expect("destination instance");
    assert_eq!(destination["status"], "active");
    let tokens = run_wispkey_json(
        dest.path(),
        &["--format", "json", "instance", "bootstrap", "list"],
    );
    let destination_token = tokens["bootstrap_tokens"]
        .as_array()
        .expect("bootstrap tokens")
        .iter()
        .find(|token| token["description"] == "destination-token")
        .expect("destination token");
    assert_eq!(destination_token["status"], "active");
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

#[test]
fn backup_excluding_credentials_omits_dependent_instance_rows() {
    let source = tempfile::tempdir().expect("source");
    let dest = tempfile::tempdir().expect("dest");
    let bundle_dir = tempfile::tempdir().expect("bundle");
    let backup_path = bundle_dir.path().join("vault.wkbackup");
    let backup = backup_path.to_string_lossy().to_string();
    let dest_path = dest.path().to_string_lossy().to_string();

    init_vault(source.path());
    add_named_secret(source.path(), "backup-key", "backup-secret-value");
    run_wispkey_json(
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
            "credentials",
        ],
    );
    assert_eq!(created["scope"]["credentials"], false);
    assert_eq!(created["scope"]["scopes"], false);
    assert_eq!(created["scope"]["access_requests"], false);
    assert_eq!(created["counts"]["scopes"], 0);

    run_wispkey_bundle_json(
        source.path(),
        &[
            "--format", "json", "backup", "restore", &backup, "--target", &dest_path,
        ],
    );
    unlock_vault(dest.path());
    let listed = run_wispkey_json(dest.path(), &["--format", "json", "instance", "list"]);
    assert_eq!(listed["instances"][0]["status"], "needs_reenrollment");
}

#[test]
fn backup_auth_registry_roundtrip_stays_revoked_and_merge_conflicts_fail_closed() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let artifacts = tempfile::tempdir().unwrap();
    let archive = artifacts.path().join("auth.wkbackup");
    init_vault(source.path());
    add_named_secret(source.path(), "auth-backup", "synthetic-auth-backup-secret");
    let registered = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "auth",
            "register",
            "auth-backup",
            "--project",
            "default",
            "--provider",
            "example",
            "--account",
            "production",
            "--origin",
            "https://api.example.com",
            "--provider-expiry",
            "2000-01-01T00:00:00Z",
            "--use-until",
            "2000-01-01T00:00:00Z",
        ],
    );
    let definition = serde_json::json!({
        "name":"production", "project":"default", "partition":"personal", "account":"production",
        "alternatives":[{"name":"api", "members":[{"auth_id":registered["auth"]["id"],
            "revision":registered["auth"]["revision"], "role":"api_key"}]}]
    });
    let definition_path = artifacts.path().join("auth.json");
    std::fs::write(&definition_path, definition.to_string()).unwrap();
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "auth",
            "bundle",
            "set",
            "--file",
            definition_path.to_str().unwrap(),
        ],
    );
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "auth",
            "revoke",
            "auth-backup",
            "--project",
            "default",
        ],
    );
    let source_db = Connection::open(source.path().join("vault.db")).unwrap();
    let expected: (String, String, String) = source_db.query_row(
        "SELECT a.metadata_json,c.encrypted_value,b.bundle_json FROM auth_registry a JOIN credentials c ON c.id=a.credential_id JOIN auth_bundles b ON b.partition_id=c.partition_id", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    drop(source_db);
    assert!(expected.1.starts_with("wka1:"));
    let created = create_backup(source.path(), archive.to_str().unwrap());
    assert_eq!(created["format_version"], 2);
    assert_eq!(created["counts"]["auth_records"], 1);
    assert_eq!(created["counts"]["auth_bundles"], 1);
    let verified = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "verify",
            archive.to_str().unwrap(),
        ],
    );
    assert_eq!(verified["ok"], true);
    run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            archive.to_str().unwrap(),
            "--target",
            target.path().to_str().unwrap(),
        ],
    );
    unlock_vault(target.path());
    let target_db = Connection::open(target.path().join("vault.db")).unwrap();
    let actual: (String, String, String) = target_db.query_row(
        "SELECT a.metadata_json,c.encrypted_value,b.bundle_json FROM auth_registry a JOIN credentials c ON c.id=a.credential_id JOIN auth_bundles b ON b.partition_id=c.partition_id", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(actual, expected);
    let denied = run_wispkey(
        target.path(),
        &[
            "--format",
            "json",
            "auth",
            "bundle",
            "resolve",
            "production",
            "--project",
            "default",
            "--partition",
            "personal",
            "--account",
            "production",
            "--alternative",
            "api",
            "--origin",
            "https://api.example.com",
        ],
    );
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    let input = artifacts.path().join("template.txt");
    std::fs::write(&input, "{{ cred:auth-backup }}").unwrap();
    let denied = run_wispkey(
        target.path(),
        &["inject", "-i", input.to_str().unwrap(), "--stdout"],
    );
    assert!(!denied.status.success());
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("synthetic-auth-backup-secret"));
    let mut changed: Value = serde_json::from_str(&expected.0).unwrap();
    changed["revoked_at"] = Value::Null;
    let changed = changed.to_string();
    target_db
        .execute("UPDATE auth_registry SET metadata_json=?1", [&changed])
        .unwrap();
    drop(target_db);
    let denied = run_wispkey_bundle(
        source.path(),
        &[
            "backup",
            "restore",
            archive.to_str().unwrap(),
            "--target",
            target.path().to_str().unwrap(),
            "--on-conflict",
            "skip",
        ],
    );
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("auth restore conflict"));
    let target_db = Connection::open(target.path().join("vault.db")).unwrap();
    let unchanged: String = target_db
        .query_row("SELECT metadata_json FROM auth_registry", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(unchanged, changed);
}
