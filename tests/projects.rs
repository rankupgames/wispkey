mod common;

use common::*;

#[test]
fn cli_project_scoping_json_contract_is_real() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "create",
            "client-alpha",
            "--description",
            "Client Alpha",
        ],
    );
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "default-key",
            "--type",
            "api_key",
            "--value",
            "default-secret",
        ],
    );
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
            "--project",
            "client-alpha",
        ],
    );

    let default_list = run_wispkey_json(vault_dir.path(), &["--format", "json", "list"]);
    assert_eq!(credential_names(&default_list), vec!["default-key"]);
    assert_eq!(default_list["project"], "default");

    let client_list = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "list", "--project", "client-alpha"],
    );
    assert_eq!(credential_names(&client_list), vec!["client-key"]);
    assert_eq!(client_list["project"], "client-alpha");

    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "project", "use", "client-alpha"],
    );
    let active_list = run_wispkey_json(vault_dir.path(), &["--format", "json", "list"]);
    assert_eq!(credential_names(&active_list), vec!["client-key"]);
    assert_eq!(active_list["project"], "client-alpha");

    let projects = run_wispkey_json(vault_dir.path(), &["--format", "json", "project", "list"]);
    let client_project = projects["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .find(|project| project["name"] == "client-alpha")
        .expect("client-alpha project");
    assert_eq!(client_project["active"], true);
    assert_eq!(client_project["partition_count"], 1);
}
