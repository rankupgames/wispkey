mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Stdio;

use common::*;

#[test]
fn env_list_discovers_attachable_files_without_generated_or_dependency_files() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    fs::create_dir_all(workspace.path().join("apps/api")).expect("create app directory");
    fs::create_dir_all(workspace.path().join("node_modules/package"))
        .expect("create dependency directory");
    fs::write(workspace.path().join(".env"), "ROOT_SECRET=value\n").expect("write root env");
    fs::write(
        workspace.path().join("apps/api/.env.production"),
        "API_SECRET=value\n",
    )
    .expect("write nested env");
    fs::write(workspace.path().join(".env.example"), "EXAMPLE=value\n").expect("write example env");
    fs::write(
        workspace.path().join("apps/api/.env.production.template"),
        "TEMPLATE=value\n",
    )
    .expect("write nested template env");
    fs::write(workspace.path().join(".env.wispkey"), "TOKEN=wk_example\n")
        .expect("write generated env");
    fs::write(
        workspace.path().join("node_modules/package/.env"),
        "DEPENDENCY_SECRET=value\n",
    )
    .expect("write dependency env");

    let directory = workspace.path().to_str().expect("utf-8 workspace path");
    let output = wispkey_bin()
        .args(["env", "list", directory, "--format", "json"])
        .output()
        .expect("run env list");
    let value = output_json(&["env", "list"], output);
    let files: Vec<PathBuf> = value["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|path| PathBuf::from(path.as_str().expect("file path")))
        .collect();

    assert_eq!(files.len(), 2);
    assert!(files.contains(&fs::canonicalize(workspace.path().join(".env")).expect("root env")));
    assert!(
        files.contains(
            &fs::canonicalize(workspace.path().join("apps/api/.env.production"))
                .expect("production env")
        )
    );
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 0);
}

#[test]
fn env_attach_creates_project_environment_and_only_tokenizes_selected_keys() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env.production");
    let openai_secret = "test-openai-secret";
    let database_secret = "postgres://user:pass@localhost/app";
    fs::write(
        &env_path,
        format!(
            "PORT=3000\nOPENAI_API_KEY={openai_secret}\nDATABASE_URL=\"{database_secret}\" # local database\n"
        ),
    )
    .expect("write env");
    let env_path_string = env_path.to_str().expect("utf-8 env path");
    let args = [
        "env",
        "attach",
        env_path_string,
        "--project",
        "weather-app",
        "--key",
        "OPENAI_API_KEY",
        "--key",
        "DATABASE_URL",
        "--hosts",
        "api.example.com",
        "--format",
        "json",
    ];

    let attached = run_wispkey_json(vault_dir.path(), &args);
    assert_eq!(attached["project"], "weather-app");
    assert_eq!(attached["environment"], "production");
    assert_eq!(attached["partition"], "production");
    assert_eq!(attached["imported"], 2);
    assert_eq!(attached["updated"], 2);
    assert_eq!(attached["project_created"], true);
    assert_eq!(attached["environment_created"], true);

    let rewritten = fs::read_to_string(&env_path).expect("read attached env");
    assert!(rewritten.contains("PORT=3000"));
    assert!(rewritten.contains(" # local database"));
    assert!(!rewritten.contains(openai_secret));
    assert!(!rewritten.contains(database_secret));
    for credential in attached["credentials"]
        .as_array()
        .expect("attached credentials")
    {
        let token = credential["wisp_token"].as_str().expect("wisp token");
        assert!(rewritten.contains(token));
    }

    let audit_log = run_wispkey_json(vault_dir.path(), &["log", "--format", "json"]);
    let serialized_audit = serde_json::to_string(&audit_log).expect("serialize audit log");
    assert!(!serialized_audit.contains(openai_secret));
    assert!(!serialized_audit.contains(database_secret));
    for credential in attached["credentials"]
        .as_array()
        .expect("attached credentials")
    {
        let token = credential["wisp_token"].as_str().expect("wisp token");
        assert!(!serialized_audit.contains(token));
    }
    let credential_additions: Vec<_> = audit_log["entries"]
        .as_array()
        .expect("audit entries")
        .iter()
        .filter(|entry| entry["event_type"] == "CredentialAdded")
        .collect();
    assert_eq!(credential_additions.len(), 2);
    assert!(
        credential_additions
            .iter()
            .all(|entry| entry["token_fingerprint"].as_str().is_some())
    );

    let listed = run_wispkey_json(
        vault_dir.path(),
        &[
            "list",
            "--project",
            "weather-app",
            "--partition",
            "production",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        credential_names(&listed),
        vec![
            "production-database-url".to_string(),
            "production-openai-api-key".to_string(),
        ]
    );
    assert!(
        listed["credentials"]
            .as_array()
            .expect("credentials")
            .iter()
            .all(|credential| credential["hosts"] == serde_json::json!(["api.example.com"]))
    );

    let attached_again = run_wispkey_json(vault_dir.path(), &args);
    assert_eq!(attached_again["imported"], 0);
    assert_eq!(attached_again["already_attached"], 2);
    assert_eq!(attached_again["updated"], 0);

    #[cfg(unix)]
    assert_eq!(file_mode(&env_path), 0o600);
}

#[test]
fn env_attach_requires_hosts_before_mutating_vault_or_file() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    let secret = "not-a-host-scoped-secret";
    let original = format!("API_TOKEN={secret}\n");
    fs::write(&env_path, &original).expect("write env");
    let output = run_wispkey(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "missing-hosts-app",
            "--key",
            "API_TOKEN",
            "--format",
            "json",
        ],
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(&env_path).expect("read env"), original);
    let projects = run_wispkey_json(vault_dir.path(), &["project", "list", "--format", "json"]);
    assert!(
        projects["projects"]
            .as_array()
            .expect("projects")
            .iter()
            .all(|project| project["name"] != "missing-hosts-app")
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires --hosts"), "stderr: {stderr}");
    assert!(!stderr.contains(secret));
}

#[test]
fn env_attach_rejects_wildcard_only_hosts_before_mutating_vault_or_file() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    let secret = "wildcard-host-secret";
    let original = format!("API_TOKEN={secret}\n");
    fs::write(&env_path, &original).expect("write env");
    let output = run_wispkey(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "wildcard-hosts-app",
            "--key",
            "API_TOKEN",
            "--hosts",
            "*",
            "--format",
            "json",
        ],
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(&env_path).expect("read env"), original);
    let projects = run_wispkey_json(vault_dir.path(), &["project", "list", "--format", "json"]);
    assert!(
        projects["projects"]
            .as_array()
            .expect("projects")
            .iter()
            .all(|project| project["name"] != "wildcard-hosts-app")
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("meaningful host restriction"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains(secret));
}

#[test]
fn env_attach_reuses_restricted_credentials_without_broadening_hosts() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    fs::write(&env_path, "API_TOKEN=stored-secret\n").expect("write env");
    let first_args = [
        "env",
        "attach",
        env_path.to_str().expect("utf-8 env path"),
        "--project",
        "restricted-app",
        "--key",
        "API_TOKEN",
        "--hosts",
        "api.example.com",
        "--format",
        "json",
    ];
    let initial = run_wispkey_json(vault_dir.path(), &first_args);
    let token = initial["credentials"][0]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    fs::write(&env_path, "API_TOKEN=stored-secret\n").expect("restore plaintext env");
    let reused = run_wispkey_json(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "restricted-app",
            "--key",
            "API_TOKEN",
            "--hosts",
            "evil.example.com",
            "--format",
            "json",
        ],
    );

    assert_eq!(reused["imported"], 0);
    assert_eq!(reused["reused"], 1);
    assert_eq!(reused["updated"], 1);
    assert!(
        fs::read_to_string(&env_path)
            .expect("read attached env")
            .contains(&token)
    );

    let listed = run_wispkey_json(
        vault_dir.path(),
        &[
            "list",
            "--project",
            "restricted-app",
            "--partition",
            "default",
            "--format",
            "json",
        ],
    );
    assert_eq!(listed["credentials"][0]["wisp_token"], token);
    assert_eq!(
        listed["credentials"][0]["hosts"],
        serde_json::json!(["api.example.com"])
    );
}

#[test]
fn env_attach_rejects_unrestricted_or_wildcard_provisioned_credentials() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    for (environment, hosts) in [("unrestricted", None), ("wildcard", Some("*"))] {
        let project = format!("{environment}-app");
        let credential_name = format!("{environment}-api-token");
        assert!(
            run_wispkey(vault_dir.path(), &["project", "create", &project])
                .status
                .success()
        );
        assert!(
            run_wispkey(
                vault_dir.path(),
                &["partition", "create", environment, "--project", &project,],
            )
            .status
            .success()
        );

        let mut add_args = vec![
            "add",
            &credential_name,
            "--value",
            "stored-secret",
            "--project",
            &project,
            "--partition",
            environment,
        ];
        if let Some(hosts) = hosts {
            add_args.extend(["--hosts", hosts]);
        }
        assert!(run_wispkey(vault_dir.path(), &add_args).status.success());

        let env_path = workspace.path().join(format!(".env.{environment}"));
        let original = "API_TOKEN=stored-secret\n";
        fs::write(&env_path, original).expect("write env");
        let output = run_wispkey(
            vault_dir.path(),
            &[
                "env",
                "attach",
                env_path.to_str().expect("utf-8 env path"),
                "--project",
                &project,
                "--key",
                "API_TOKEN",
                "--format",
                "json",
            ],
        );

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_to_string(&env_path).expect("read env"), original);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("meaningful host restriction"),
            "stderr: {stderr}"
        );
        assert!(!stderr.contains("stored-secret"));
    }
}

#[test]
fn env_attach_conflict_leaves_file_unchanged() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env.local");
    fs::write(&env_path, "API_TOKEN=first-secret\n").expect("write first env");
    let env_path_string = env_path.to_str().expect("utf-8 env path");
    let args = [
        "env",
        "attach",
        env_path_string,
        "--project",
        "conflict-app",
        "--key",
        "API_TOKEN",
        "--hosts",
        "api.example.com",
        "--format",
        "json",
    ];
    run_wispkey_json(vault_dir.path(), &args);

    let conflicting = "API_TOKEN=different-secret\n";
    fs::write(&env_path, conflicting).expect("replace with conflicting env");
    let output = run_wispkey(vault_dir.path(), &args);
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&env_path).expect("read conflicting env"),
        conflicting
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("different value"), "stderr: {stderr}");
    assert!(!stderr.contains("different-secret"));
}

#[test]
fn env_attach_scopes_the_same_key_to_separate_environment_partitions() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let development_path = workspace.path().join(".env.development");
    let production_path = workspace.path().join(".env.production");
    fs::write(&development_path, "API_TOKEN=development-secret\n").expect("write development");
    fs::write(&production_path, "API_TOKEN=production-secret\n").expect("write production");

    for (path, environment) in [
        (&development_path, "development"),
        (&production_path, "production"),
    ] {
        let attached = run_wispkey_json(
            vault_dir.path(),
            &[
                "env",
                "attach",
                path.to_str().expect("utf-8 env path"),
                "--project",
                "multi-env-app",
                "--key",
                "API_TOKEN",
                "--hosts",
                "api.example.com",
                "--format",
                "json",
            ],
        );
        assert_eq!(attached["environment"], environment);

        let listed = run_wispkey_json(
            vault_dir.path(),
            &[
                "list",
                "--project",
                "multi-env-app",
                "--partition",
                environment,
                "--format",
                "json",
            ],
        );
        assert_eq!(
            credential_names(&listed),
            vec![format!("{environment}-api-token")]
        );
    }
}

#[test]
fn env_attach_missing_key_does_not_create_project_or_modify_file() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    let original = "PORT=3000\n";
    fs::write(&env_path, original).expect("write env");
    let output = run_wispkey(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "missing-key-app",
            "--key",
            "API_TOKEN",
            "--format",
            "json",
        ],
    );

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&env_path).expect("read env"), original);
    let projects = run_wispkey_json(vault_dir.path(), &["project", "list", "--format", "json"]);
    assert!(
        projects["projects"]
            .as_array()
            .expect("projects")
            .iter()
            .all(|project| project["name"] != "missing-key-app")
    );
}

#[test]
fn env_attach_rejects_non_env_file_even_with_environment_override() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let config_path = workspace.path().join("config.txt");
    let original = "API_TOKEN=secret\n";
    fs::write(&config_path, original).expect("write config");
    let output = run_wispkey(
        vault_dir.path(),
        &[
            "env",
            "attach",
            config_path.to_str().expect("utf-8 config path"),
            "--project",
            "invalid-target",
            "--environment",
            "production",
            "--key",
            "API_TOKEN",
        ],
    );

    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&config_path).expect("read config"),
        original
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an attachable .env file"));
}

#[test]
fn env_attach_accepts_plaintext_that_only_starts_with_wk_prefix() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    fs::write(&env_path, "API_TOKEN=wk_customer-secret\n").expect("write env");
    let attached = run_wispkey_json(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "wk-prefix-app",
            "--key",
            "API_TOKEN",
            "--hosts",
            "api.example.com",
            "--format",
            "json",
        ],
    );

    assert_eq!(attached["imported"], 1);
    let rewritten = fs::read_to_string(&env_path).expect("read attached env");
    assert!(!rewritten.contains("wk_customer-secret"));
    assert!(rewritten.contains("wk_default_api_token_"));
}

#[cfg(unix)]
#[test]
fn env_attach_rehardens_an_unchanged_attached_file() {
    use std::os::unix::fs::PermissionsExt;

    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    fs::write(&env_path, "API_TOKEN=secret\n").expect("write env");
    let args = [
        "env",
        "attach",
        env_path.to_str().expect("utf-8 env path"),
        "--project",
        "permissions-app",
        "--key",
        "API_TOKEN",
        "--hosts",
        "api.example.com",
        "--format",
        "json",
    ];
    run_wispkey_json(vault_dir.path(), &args);
    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o644)).expect("broaden mode");

    let attached_again = run_wispkey_json(vault_dir.path(), &args);
    assert_eq!(attached_again["updated"], 0);
    assert_eq!(file_mode(&env_path), 0o600);
}

#[test]
fn concurrent_env_attachments_preserve_both_tokens() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    fs::write(
        &env_path,
        "FIRST_TOKEN=first-secret\nSECOND_TOKEN=second-secret\n",
    )
    .expect("write env");
    let env_path = env_path.to_str().expect("utf-8 env path");
    let spawn_attach = |key: &str| {
        wispkey_bin()
            .args([
                "env",
                "attach",
                env_path,
                "--project",
                "concurrent-app",
                "--key",
                key,
                "--hosts",
                "api.example.com",
                "--format",
                "json",
            ])
            .env("WISPKEY_VAULT_PATH", vault_dir.path())
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn env attach")
    };

    let first = spawn_attach("FIRST_TOKEN");
    let second = spawn_attach("SECOND_TOKEN");
    for output in [
        first.wait_with_output().expect("wait for first attach"),
        second.wait_with_output().expect("wait for second attach"),
    ] {
        assert!(
            output.status.success(),
            "concurrent attach failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let rewritten = fs::read_to_string(env_path).expect("read concurrently attached env");
    assert!(!rewritten.contains("first-secret"));
    assert!(!rewritten.contains("second-secret"));
    assert!(rewritten.contains("FIRST_TOKEN=wk_default_first_token_"));
    assert!(rewritten.contains("SECOND_TOKEN=wk_default_second_token_"));
}

#[test]
fn env_attach_text_output_does_not_repeat_token_capabilities() {
    let vault_dir = tempfile::tempdir().expect("temp vault");
    let workspace = tempfile::tempdir().expect("temp workspace");
    init_vault(vault_dir.path());

    let env_path = workspace.path().join(".env");
    fs::write(&env_path, "API_TOKEN=secret\n").expect("write env");
    let output = run_wispkey(
        vault_dir.path(),
        &[
            "env",
            "attach",
            env_path.to_str().expect("utf-8 env path"),
            "--project",
            "text-output-app",
            "--key",
            "API_TOKEN",
            "--hosts",
            "api.example.com",
        ],
    );
    assert!(output.status.success());

    let rewritten = fs::read_to_string(&env_path).expect("read attached env");
    let token = rewritten
        .trim()
        .strip_prefix("API_TOKEN=")
        .expect("attached token");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(token));
    assert!(stdout.contains("API_TOKEN -> default-api-token"));
    assert!(stdout.contains("wispkey project use text-output-app"));
}
