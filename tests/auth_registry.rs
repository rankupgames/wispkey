mod common;

use std::path::Path;
use std::process::Output;

use chrono::{Duration, Utc};
use common::*;
use serde_json::{Value, json};

const ORIGIN: &str = "https://api.example.com";
const ACCOUNT: &str = "synthetic-account";
const SECRET: &str = "synthetic-auth-registry-secret-never-display";

fn add_secret(dir: &Path, name: &str) -> Value {
    let path = dir.join("synthetic-secret.txt");
    write_private_test_file(&path, SECRET);
    run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "add",
            name,
            "--type",
            "api_key",
            "--value-file",
            path.to_str().unwrap(),
            "--hosts",
            "api.example.com",
            "--project",
            "default",
        ],
    )["credential"]
        .clone()
}

fn register(dir: &Path, name: &str, expiry: &str, until: Option<&str>) -> Value {
    let mut args = vec![
        "--format",
        "json",
        "auth",
        "register",
        name,
        "--project",
        "default",
        "--provider",
        "synthetic-provider",
        "--account",
        ACCOUNT,
        "--origin",
        ORIGIN,
        "--provider-expiry",
        expiry,
    ];
    if let Some(until) = until {
        args.extend(["--use-until", until]);
    }
    run_wispkey_json(dir, &args)["auth"].clone()
}

fn register_bounded(dir: &Path, name: &str) -> Value {
    let deadline = (Utc::now() + Duration::hours(1)).to_rfc3339();
    register(dir, name, "non-expiring", Some(&deadline))
}

fn member(auth: &Value, role: &str) -> Value {
    json!({"auth_id": auth["id"], "revision": auth["revision"], "role": role})
}

fn bundle(alternatives: Value) -> Value {
    json!({
        "name": "synthetic-service", "project": "default", "partition": "personal",
        "account": ACCOUNT, "alternatives": alternatives,
    })
}

fn set_bundle(dir: &Path, bundle: &Value) -> Value {
    let path = dir.join("auth-bundle.json");
    std::fs::write(&path, serde_json::to_vec(bundle).unwrap()).unwrap();
    run_wispkey_json(
        dir,
        &[
            "--format",
            "json",
            "auth",
            "bundle",
            "set",
            "--file",
            path.to_str().unwrap(),
        ],
    )
}

fn resolve(dir: &Path, alternative: &str, account: &str, origin: &str) -> Output {
    run_wispkey(
        dir,
        &[
            "--format",
            "json",
            "auth",
            "bundle",
            "resolve",
            "synthetic-service",
            "--project",
            "default",
            "--partition",
            "personal",
            "--account",
            account,
            "--alternative",
            alternative,
            "--origin",
            origin,
        ],
    )
}

fn assert_denied_without_tokens(output: &Output) {
    assert!(!output.status.success(), "request unexpectedly succeeded");
    assert!(
        output.stdout.is_empty(),
        "denied request emitted partial output"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("wk_"), "error emitted a wisp token");
    assert!(!stderr.contains(SECRET), "error emitted a secret");
}

fn assert_metadata_only(value: &Value, token: &Value) {
    let text = value.to_string();
    assert!(!text.contains(SECRET));
    assert!(!text.contains("wisp_token"));
    assert!(!text.contains(token.as_str().unwrap()));
}

#[test]
fn legacy_inventory_is_opt_in_metadata_only_and_project_scoped() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let credential = add_secret(dir.path(), "legacy-key");
    let token = &credential["wisp_token"];
    let before = run_wispkey_json(dir.path(), &["--format", "json", "auth", "list"]);
    assert_eq!(before["credentials"][0]["name"], "legacy-key");
    assert!(before["credentials"][0]["auth"].is_null());
    assert_metadata_only(&before, token);

    let registered = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "auth",
            "register",
            "legacy-key",
            "--project",
            "default",
            "--provider",
            "synthetic-provider",
            "--account",
            ACCOUNT,
            "--origin",
            ORIGIN,
            "--origin",
            "https://api.example.com:8443",
            "--provider-expiry",
            "non-expiring",
        ],
    );
    assert_metadata_only(&registered, token);
    assert_eq!(
        registered["auth"]["provider_expiry"]["state"],
        "non_expiring"
    );
    assert_eq!(registered["auth"]["origins"].as_array().unwrap().len(), 2);
    assert!(registered["auth"]["use_until"].is_null());

    let after = run_wispkey_json(dir.path(), &["--format", "json", "auth", "list"]);
    assert_eq!(after["credentials"][0]["auth"], registered["auth"]);
    assert_eq!(after["credentials"][0]["project"], "default");
    assert_eq!(after["credentials"][0]["partition"], "personal");
    assert_metadata_only(&after, token);
    let text = run_wispkey(dir.path(), &["auth", "list"]);
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("registered"));
    assert!(!text.contains(token.as_str().unwrap()));
    assert!(!text.contains(SECRET));

    run_wispkey_json(
        dir.path(),
        &["--format", "json", "project", "create", "empty"],
    );
    let other = run_wispkey_json(
        dir.path(),
        &["--format", "json", "auth", "list", "--project", "empty"],
    );
    assert!(other["credentials"].as_array().unwrap().is_empty());
}

#[test]
fn unknown_provider_expiry_requires_a_finite_local_deadline() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let credential = add_secret(dir.path(), "unknown-key");
    let args = [
        "auth",
        "register",
        "unknown-key",
        "--project",
        "default",
        "--provider",
        "synthetic",
        "--account",
        ACCOUNT,
        "--origin",
        ORIGIN,
        "--provider-expiry",
        "unknown",
    ];
    assert_denied_without_tokens(&run_wispkey(dir.path(), &args));
    let inventory = run_wispkey_json(dir.path(), &["--format", "json", "auth", "list"]);
    assert!(inventory["credentials"][0]["auth"].is_null());

    let deadline = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let auth = register(dir.path(), "unknown-key", "unknown", Some(&deadline));
    assert_eq!(auth["provider_expiry"]["state"], "unknown");
    assert!(!auth["use_until"].is_null());
    assert_metadata_only(&auth, &credential["wisp_token"]);
    let mut invalid = args.to_vec();
    invalid.extend(["--use-until", SECRET]);
    assert_denied_without_tokens(&run_wispkey(dir.path(), &invalid));
}

#[test]
fn bundles_require_explicit_choice_exact_account_origin_and_all_members() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let app = add_secret(dir.path(), "app-key");
    let consumer = add_secret(dir.path(), "consumer-key");
    let oauth = add_secret(dir.path(), "oauth-key");
    let app_auth = register_bounded(dir.path(), "app-key");
    let consumer_auth = register_bounded(dir.path(), "consumer-key");
    let oauth_auth = register_bounded(dir.path(), "oauth-key");
    let document = bundle(json!([
        {"name": "keypair", "members": [member(&app_auth, "application_key"), member(&consumer_auth, "consumer_key")]},
        {"name": "oauth", "members": [member(&oauth_auth, "access_token")]},
    ]));
    let stored = set_bundle(dir.path(), &document);
    assert_eq!(stored["bundle"], document);
    for credential in [&app, &consumer, &oauth] {
        assert_metadata_only(&stored, &credential["wisp_token"]);
    }
    let listed = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "auth",
            "bundle",
            "list",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(listed["bundles"], json!([document]));
    assert_metadata_only(&listed, &app["wisp_token"]);

    let output = resolve(dir.path(), "keypair", ACCOUNT, ORIGIN);
    let resolved = output_json(&["auth", "bundle", "resolve"], output);
    assert_eq!(resolved["members"].as_array().unwrap().len(), 2);
    assert_eq!(resolved["members"][0]["wisp_token"], app["wisp_token"]);
    assert_eq!(resolved["members"][1]["wisp_token"], consumer["wisp_token"]);
    assert!(!resolved.to_string().contains(SECRET));

    for (choice, account, origin) in [
        ("keypair", "wrong-account", ORIGIN),
        ("keypair", ACCOUNT, "https://api.example.com:8443"),
        ("keypair", ACCOUNT, "https://other.example.com"),
        ("unknown-choice", ACCOUNT, ORIGIN),
    ] {
        assert_denied_without_tokens(&resolve(dir.path(), choice, account, origin));
    }
    let unspecified = run_wispkey(
        dir.path(),
        &[
            "auth",
            "bundle",
            "resolve",
            "synthetic-service",
            "--project",
            "default",
            "--partition",
            "personal",
            "--account",
            ACCOUNT,
            "--origin",
            ORIGIN,
        ],
    );
    assert_denied_without_tokens(&unspecified);
    assert!(String::from_utf8_lossy(&unspecified.stderr).contains("--alternative"));

    let revoked = run_wispkey_json(
        dir.path(),
        &[
            "--format",
            "json",
            "auth",
            "revoke",
            "consumer-key",
            "--project",
            "default",
        ],
    );
    assert_eq!(revoked["ok"], true);
    assert_denied_without_tokens(&resolve(dir.path(), "keypair", ACCOUNT, ORIGIN));
    let explicit_oauth = output_json(
        &["auth", "bundle", "resolve"],
        resolve(dir.path(), "oauth", ACCOUNT, ORIGIN),
    );
    assert_eq!(explicit_oauth["members"].as_array().unwrap().len(), 1);
    assert_eq!(
        explicit_oauth["members"][0]["wisp_token"],
        oauth["wisp_token"]
    );

    // Re-registering metadata cannot silently undo revocation.
    let still_revoked = register_bounded(dir.path(), "consumer-key");
    assert!(!still_revoked["revoked_at"].is_null());
    assert_denied_without_tokens(&resolve(dir.path(), "keypair", ACCOUNT, ORIGIN));
}

#[test]
fn registration_revision_change_invalidates_existing_bundle_references() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    add_secret(dir.path(), "revision-key");
    let original = register_bounded(dir.path(), "revision-key");
    set_bundle(
        dir.path(),
        &bundle(json!([
            {"name": "token", "members": [member(&original, "access_token")]},
        ])),
    );
    assert!(
        resolve(dir.path(), "token", ACCOUNT, ORIGIN)
            .status
            .success()
    );
    let changed = register_bounded(dir.path(), "revision-key");
    assert_eq!(changed["id"], original["id"]);
    assert_ne!(changed["revision"], original["revision"]);
    assert_denied_without_tokens(&resolve(dir.path(), "token", ACCOUNT, ORIGIN));
    set_bundle(
        dir.path(),
        &bundle(json!([
            {"name": "token", "members": [member(&changed, "access_token")]},
        ])),
    );
    assert!(
        resolve(dir.path(), "token", ACCOUNT, ORIGIN)
            .status
            .success()
    );
}

#[test]
fn expired_or_unbounded_members_deny_the_whole_selected_alternative() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    add_secret(dir.path(), "healthy-key");
    add_secret(dir.path(), "bounded-key");
    let healthy = register_bounded(dir.path(), "healthy-key");
    let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    for (provider_expiry, use_until) in [
        (past.as_str(), Some(future.as_str())),
        ("non-expiring", Some(past.as_str())),
        ("non-expiring", None),
    ] {
        let ineligible = register(dir.path(), "bounded-key", provider_expiry, use_until);
        set_bundle(
            dir.path(),
            &bundle(json!([
                {"name": "together", "members": [member(&healthy, "first"), member(&ineligible, "second")]},
            ])),
        );
        assert_denied_without_tokens(&resolve(dir.path(), "together", ACCOUNT, ORIGIN));
    }
}

#[test]
fn bundle_input_rejects_secret_fields_without_echoing_values() {
    let dir = tempfile::tempdir().unwrap();
    init_vault(dir.path());
    let mut document = bundle(json!([]));
    document["secret"] = json!(SECRET);
    let path = dir.path().join("invalid-bundle.json");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let output = run_wispkey(
        dir.path(),
        &["auth", "bundle", "set", "--file", path.to_str().unwrap()],
    );
    assert_denied_without_tokens(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid auth bundle JSON"));
}
