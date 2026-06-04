mod common;

use common::*;

#[test]
fn cli_project_and_single_credential_bundle_roundtrips_are_real() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let project_dest_dir = tempfile::tempdir().expect("project destination vault dir");
    let credential_dest_dir = tempfile::tempdir().expect("credential destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let project_bundle = bundle_dir.path().join("client-alpha.wkbundle");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "create", "client-alpha"],
    );
    let added = run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "bearer_token",
            "--value",
            "client-secret",
            "--hosts",
            "api.example.com",
            "--tags",
            "client,prod",
            "--project",
            "client-alpha",
        ],
    );
    assert_eq!(added["credential"]["name"], "client-key");

    let project_bundle_path = project_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "export",
            "client-alpha",
            "--output",
            &project_bundle_path,
        ],
    );
    assert!(project_bundle.exists(), "project bundle should be written");

    init_vault(project_dest_dir.path());
    let imported_project = run_wispkey_bundle_json(
        project_dest_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "import",
            &project_bundle_path,
        ],
    );
    assert_eq!(imported_project["imported"], 1);
    let project_list = run_wispkey_json(
        project_dest_dir.path(),
        &["--format", "json", "list", "--project", "client-alpha"],
    );
    assert_eq!(credential_names(&project_list), vec!["client-key"]);
    assert_eq!(
        project_list["credentials"][0]["hosts"],
        serde_json::json!(["api.example.com"])
    );
    assert_eq!(
        project_list["credentials"][0]["tags"],
        serde_json::json!(["client", "prod"])
    );

    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );
    assert!(
        credential_bundle.exists(),
        "single credential bundle should be written"
    );

    init_vault(credential_dest_dir.path());
    let imported_credential = run_wispkey_bundle_json(
        credential_dest_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
            "--project",
            "shared-client",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(imported_credential["imported"], 1);
    let credential_list = run_wispkey_json(
        credential_dest_dir.path(),
        &["--format", "json", "list", "--project", "shared-client"],
    );
    assert_eq!(credential_names(&credential_list), vec!["client-key"]);
}

#[test]
fn cli_partition_bundle_roundtrip_is_real() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let partition_bundle = bundle_dir.path().join("service-tokens.wkbundle");

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "create", "client-alpha"],
    );
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "use", "client-alpha"],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "create",
            "service-tokens",
            "--description",
            "Service tokens",
        ],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "service-key",
            "--type",
            "api_key",
            "--value",
            "service-secret",
            "--hosts",
            "api.service.test",
            "--tags",
            "service,prod",
            "--partition",
            "service-tokens",
        ],
    );

    let partition_bundle_path = partition_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "export",
            "service-tokens",
            "--output",
            &partition_bundle_path,
        ],
    );
    assert!(
        partition_bundle.exists(),
        "partition bundle should be written"
    );

    init_vault(destination_dir.path());
    let imported = run_wispkey_bundle_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "import",
            &partition_bundle_path,
        ],
    );
    assert_eq!(imported["imported"], 1);

    let imported_list = run_wispkey_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "list",
            "--project",
            "client-alpha",
            "--partition",
            "service-tokens",
        ],
    );
    assert_eq!(credential_names(&imported_list), vec!["service-key"]);
    assert_eq!(
        imported_list["credentials"][0]["hosts"],
        serde_json::json!(["api.service.test"])
    );
    assert_eq!(
        imported_list["credentials"][0]["tags"],
        serde_json::json!(["service", "prod"])
    );
}

#[test]
fn bundle_passphrase_is_not_vault_password_fallback() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );

    let output = run_wispkey(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );
    assert!(
        !output.status.success(),
        "export should fail without a bundle passphrase"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WISPKEY_BUNDLE_PASSPHRASE") && stderr.contains("WISPKEY_PASSWORD"),
        "expected separate passphrase guidance, got:\n{stderr}"
    );
    assert!(
        !credential_bundle.exists(),
        "failed export must not write a bundle"
    );
}

#[test]
fn bundle_export_rejects_short_passphrase() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );

    let output = run_wispkey_with_bundle_passphrase(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
        "too-short",
    );
    assert!(!output.status.success(), "short passphrase should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least 12"),
        "expected length validation, got:\n{stderr}"
    );
}

#[test]
fn bundle_import_rejects_wrong_passphrase() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );

    init_vault(destination_dir.path());
    let output = run_wispkey_with_bundle_passphrase(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
        ],
        "wrong-passphrase-value",
    );
    assert!(!output.status.success(), "wrong passphrase should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("wrong password") || stderr.contains("invalid bundle"),
        "expected decryption failure, got:\n{stderr}"
    );
}
