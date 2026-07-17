mod common;

use common::*;

#[test]
fn instance_bootstrap_cli_join_consumes_single_use_token() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let created = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "create",
            "--description",
            "test fleet",
            "--tag",
            "company:acme",
            "--uses",
            "1",
            "--ttl",
            "1h",
        ],
    );
    let bootstrap_token = created["token"].as_str().expect("bootstrap token");
    assert_eq!(bootstrap_token.len(), 48);
    assert_eq!(created["bootstrap_token"]["max_uses"], 1);
    let token_file = vault_dir.path().join("bootstrap-token");
    write_private_test_file(&token_file, bootstrap_token);
    let token_file_arg = token_file.to_string_lossy().to_string();

    let joined = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "join",
            "--token-file",
            &token_file_arg,
            "--name",
            "worker-one",
        ],
    );
    assert_eq!(joined["name"], "worker-one");
    assert!(joined["secret"].as_str().expect("instance secret").len() == 48);
    assert!(
        joined["instance"]["scopes"]
            .as_array()
            .expect("scopes")
            .iter()
            .any(|scope| scope["scope_type"] == "tag" && scope["scope_value"] == "company:acme")
    );

    let exhausted = run_wispkey(
        vault_dir.path(),
        &["instance", "join", bootstrap_token, "--name", "worker-two"],
    );
    assert!(
        !exhausted.status.success(),
        "exhausted bootstrap token should fail"
    );
    assert!(
        String::from_utf8_lossy(&exhausted.stderr)
            .contains("invalid, expired, exhausted, or revoked bootstrap token")
    );

    let listed = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "instance", "bootstrap", "list"],
    );
    assert_eq!(listed["bootstrap_tokens"][0]["used_count"], 1);
}

#[test]
fn instance_bootstrap_cli_revoke_fails_future_join() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let created = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "create",
            "--tag",
            "company:acme",
        ],
    );
    let bootstrap_token = created["token"].as_str().expect("bootstrap token");
    let token_id = created["id"].as_str().expect("bootstrap token id");

    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "instance",
            "bootstrap",
            "revoke",
            token_id,
        ],
    );

    let revoked = run_wispkey(
        vault_dir.path(),
        &[
            "instance",
            "join",
            bootstrap_token,
            "--name",
            "worker-revoked",
        ],
    );
    assert!(!revoked.status.success(), "revoked token should fail");
    assert!(
        String::from_utf8_lossy(&revoked.stderr)
            .contains("invalid, expired, exhausted, or revoked bootstrap token")
    );
}
