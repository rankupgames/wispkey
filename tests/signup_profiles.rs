//! Synthetic end-to-end profile setup, CLI/MCP redaction and backup recovery.
mod common;
use common::*;
use serde_json::{Value, json};
use std::{io::Write, path::Path, process::Stdio};
const EMAIL: &str = "synthetic-profile-email@example.test";
const USERNAME: &str = "synthetic-profile-username";
fn setup(path: &Path) -> Value {
    init_vault(path);
    let input = path.join("synthetic-identity.json");
    std::fs::write(
        &input,
        json!({"email":EMAIL,"username":USERNAME}).to_string(),
    )
    .unwrap();
    let result = run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "signup-profile",
            "create",
            "work",
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            input.to_str().unwrap(),
        ],
    );
    redact(&result.to_string());
    result["profile"].clone()
}
fn redact(text: &str) {
    assert!(!text.contains(EMAIL));
    assert!(!text.contains(USERNAME));
    assert!(!text.contains("encrypted_value"));
}
fn generate(path: &Path, p: &Value, name: &str) -> std::process::Output {
    run_wispkey(
        path,
        &[
            "--format",
            "json",
            "login",
            "generate",
            name,
            "--profile",
            p["id"].as_str().unwrap(),
            "--profile-revision",
            p["revision"].as_str().unwrap(),
            "--url",
            "https://signup.example.test",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    )
}
fn mcp(path: &Path, name: &str, args: Value) -> Value {
    let mut child = wispkey_bin()
        .args(["mcp", "serve"])
        .env("WISPKEY_VAULT_PATH", path)
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_PROTECTOR", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(),"{}",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    redact(&String::from_utf8_lossy(&out.stdout));
    redact(&String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}
#[test]
fn signup_cli_setup_redaction_revision_conflicts_and_mcp_selection() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let p = setup(path);
    let inventory = run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "signup-profile",
            "list",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(inventory["profiles"][0], p);
    redact(&inventory.to_string());
    let out = generate(path, &p, "first");
    assert!(out.status.success());
    redact(&String::from_utf8_lossy(&out.stdout));
    assert!(!generate(path, &p, "first").status.success());
    let list = mcp(
        path,
        "wispkey_signup_profile_list",
        json!({"project":"default","partition":"personal"}),
    );
    assert!(!list["result"]["isError"].as_bool().unwrap_or(false));
    let missing = mcp(
        path,
        "wispkey_signup_profile_list",
        json!({"project":"default"}),
    );
    assert_eq!(missing["result"]["isError"], true);
    let args = json!({"name":"second","profile":p["id"],"profile_revision":p["revision"],"project":"default","partition":"personal","url":"https://signup.example.test"});
    let result = mcp(path, "wispkey_generate_login", args.clone());
    assert!(!result["result"]["isError"].as_bool().unwrap_or(false));
    for change in 0..4 {
        let mut invalid = args.clone();
        invalid["name"] = json!("invalid");
        match change {
            0 => {
                invalid.as_object_mut().unwrap().remove("project");
            }
            1 => invalid["profile_revision"] = json!("stale"),
            2 => invalid["username"] = json!("inline@example.test"),
            _ => invalid["partition"] = json!("other"),
        };
        assert_eq!(
            mcp(path, "wispkey_generate_login", invalid)["result"]["isError"],
            true
        );
    }
    let input = path.join("edit.json");
    std::fs::write(
        &input,
        json!({"email":"edited@example.test","username":null}).to_string(),
    )
    .unwrap();
    let edited = run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "signup-profile",
            "update",
            p["id"].as_str().unwrap(),
            "--revision",
            p["revision"].as_str().unwrap(),
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            input.to_str().unwrap(),
        ],
    );
    assert!(!generate(path, &p, "stale").status.success());
    let new = &edited["profile"];
    assert!(
        run_wispkey(
            path,
            &[
                "signup-profile",
                "remove",
                new["id"].as_str().unwrap(),
                "--revision",
                new["revision"].as_str().unwrap(),
                "--project",
                "default",
                "--partition",
                "personal"
            ]
        )
        .status
        .success()
    );
    assert!(!generate(path, new, "deleted").status.success());
    for args in [
        vec!["--format", "json", "list"],
        vec!["--format", "json", "login", "list"],
        vec!["--format", "json", "log", "--last", "100"],
    ] {
        redact(&run_wispkey_json(path, &args).to_string());
    }
}

#[test]
fn signup_cli_input_stdin_and_invalid_setup_are_secret_safe() {
    let temp = tempfile::tempdir().unwrap();
    init_vault(temp.path());
    let mut child = wispkey_bin()
        .args([
            "--format",
            "json",
            "signup-profile",
            "create",
            "stdin",
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            "-",
        ])
        .env("WISPKEY_VAULT_PATH", temp.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        json!({"email":EMAIL,"username":null})
    )
    .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    redact(&String::from_utf8_lossy(&out.stdout));
    for content in [
        format!("{{malformed {EMAIL}"),
        "x".repeat(4097),
        json!({"email":EMAIL,"username":USERNAME,"unexpected":true}).to_string(),
    ] {
        let path = temp.path().join("invalid.json");
        std::fs::write(&path, content).unwrap();
        let out = run_wispkey(
            temp.path(),
            &[
                "signup-profile",
                "create",
                "bad",
                "--project",
                "default",
                "--partition",
                "personal",
                "--identity-file",
                path.to_str().unwrap(),
            ],
        );
        assert!(!out.status.success());
        redact(&String::from_utf8_lossy(&out.stderr));
    }
    let out = run_wispkey(temp.path(), &["signup-profile", "list"]);
    assert!(!out.status.success());
}

#[test]
fn signup_backup_roundtrip_restores_profiles_and_pending_logins() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    let p = setup(source.path());
    assert!(generate(source.path(), &p, "saved").status.success());
    let path = bundles.path().join("vault.wkbackup");
    let path = path.to_str().unwrap();
    let created = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "create", "--output", path],
    );
    redact(&created.to_string());
    let inspect = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "inspect", path],
    );
    assert_eq!(inspect["format_version"], 3);
    redact(&inspect.to_string());
    let verified = run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "verify", path],
    );
    assert_eq!(verified["ok"], true);
    let restored = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            path,
            "--target",
            dest.path().to_str().unwrap(),
        ],
    );
    assert_eq!(restored["imported"]["signup_profiles"], 1);
    assert!(run_wispkey(dest.path(), &["unlock"]).status.success());
    let profiles = run_wispkey_json(
        dest.path(),
        &[
            "--format",
            "json",
            "signup-profile",
            "list",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(profiles["profiles"][0], p);
    assert!(generate(dest.path(), &p, "after-restore").status.success());
    let original = rusqlite::Connection::open(source.path().join("vault.db")).unwrap();
    let copy = rusqlite::Connection::open(dest.path().join("vault.db")).unwrap();
    let read = |db: &rusqlite::Connection| -> String {
        db.query_row(
            "SELECT encrypted_value FROM credentials WHERE name='saved'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(read(&original), read(&copy));
    for file in [
        std::fs::read(path).unwrap(),
        std::fs::read(source.path().join("vault.db")).unwrap(),
    ] {
        assert!(!file.windows(EMAIL.len()).any(|b| b == EMAIL.as_bytes()));
        assert!(
            !file
                .windows(USERNAME.len())
                .any(|b| b == USERNAME.as_bytes())
        );
    }
}

#[test]
fn signup_backup_exclusion_and_merge_conflict_preserve_owner_state() {
    let source = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    let p = setup(source.path());
    let archive = bundles.path().join("full.wkbackup");
    let archive = archive.to_str().unwrap();
    run_wispkey_bundle_json(
        source.path(),
        &["--format", "json", "backup", "create", "--output", archive],
    );
    let same = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "restore",
            archive,
            "--on-conflict",
            "skip",
        ],
    );
    assert_eq!(same["skipped"]["signup_profiles"], 1);
    let input = source.path().join("edit-merge.json");
    std::fs::write(
        &input,
        json!({"email":"edited@example.test","username":null}).to_string(),
    )
    .unwrap();
    let edited = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "signup-profile",
            "update",
            p["id"].as_str().unwrap(),
            "--revision",
            p["revision"].as_str().unwrap(),
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            input.to_str().unwrap(),
        ],
    );
    let refused = run_wispkey_bundle(
        source.path(),
        &["backup", "restore", archive, "--on-conflict", "skip"],
    );
    assert!(!refused.status.success());
    let inventory = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "signup-profile",
            "list",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(inventory["profiles"][0], edited["profile"]);
    let excluded = bundles.path().join("excluded.wkbackup");
    let created = run_wispkey_bundle_json(
        source.path(),
        &[
            "--format",
            "json",
            "backup",
            "create",
            "--output",
            excluded.to_str().unwrap(),
            "--exclude",
            "credentials",
        ],
    );
    assert_eq!(created["scope"]["credentials"], false);
    assert!(created["counts"]["signup_profiles"].is_null());
}
