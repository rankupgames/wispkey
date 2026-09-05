mod common;

use common::*;
use serde_json::Value;

fn integrate_print(vault_dir: &std::path::Path, client: &str) -> std::process::Output {
    run_wispkey(
        vault_dir,
        &["--format", "json", "integrate", client, "--print"],
    )
}

fn assert_path_command(config: &Value) {
    let command = config
        .pointer("/mcpServers/wispkey/command")
        .or_else(|| config.pointer("/mcp_servers/wispkey/command"))
        .and_then(Value::as_str)
        .expect("command");
    assert_eq!(command, "wispkey");
    assert!(!command.contains('/'));
    assert!(!command.contains('\\'));
}

#[test]
fn integrate_print_covers_each_documented_client() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    for client in ["cursor", "codex", "claude-code", "generic-mcp"] {
        let output = integrate_print(vault_dir.path(), client);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let report = output_json(
            &["--format", "json", "integrate", client, "--print"],
            output,
        );
        assert_eq!(report["client"], client);
        assert_eq!(report["written"], false);
        assert_path_command(&report["config"]);
        let serialized = report.to_string();
        assert!(
            !serialized.contains("sk-") && !serialized.contains("WISPKEY_PASSWORD"),
            "generated config leaked a secret for {client}: {serialized}"
        );
        if client == "codex" {
            assert_eq!(report["format"], "toml");
            assert!(report["plaintext_env_warning"].is_null());
            assert!(
                !stderr.contains("plaintext"),
                "codex should not warn about plaintext env blocks: {stderr}"
            );
        } else {
            assert_eq!(report["format"], "json");
            assert!(
                report["plaintext_env_warning"]
                    .as_str()
                    .expect("warning")
                    .contains("env")
            );
            assert!(
                stderr.contains("Warning"),
                "JSON client {client} should warn before plaintext env blocks: {stderr}"
            );
        }
    }
}

#[test]
fn integrate_write_is_idempotent_and_preserves_other_servers() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let config_path = vault_dir.path().join("project-mcp.json");
    std::fs::write(
        &config_path,
        r#"{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  },
  "theme": "dark"
}
"#,
    )
    .expect("write existing config");
    let path = config_path.to_string_lossy().to_string();

    let first = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "integrate",
            "generic-mcp",
            "--path",
            &path,
        ],
    );
    assert_eq!(first["written"], true);
    assert_eq!(first["changed"], true);

    let second = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "integrate",
            "generic-mcp",
            "--path",
            &path,
        ],
    );
    assert_eq!(second["written"], true);
    assert_eq!(second["changed"], false);

    let parsed: Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
            .expect("parse written config");
    assert_eq!(parsed["theme"], "dark");
    assert_eq!(parsed["mcpServers"]["github"]["command"], "npx");
    assert_eq!(parsed["mcpServers"]["wispkey"]["command"], "wispkey");
    assert_eq!(
        parsed["mcpServers"]["wispkey"]["args"],
        serde_json::json!(["mcp", "serve"])
    );
}

#[test]
fn integrate_replaces_user_specific_command_path() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let config_path = vault_dir.path().join("cursor-mcp.json");
    std::fs::write(
        &config_path,
        r#"{
  "mcpServers": {
    "wispkey": {
      "command": "/Users/demo/.cargo/bin/wispkey",
      "args": ["mcp", "serve"],
      "disabled": false
    }
  }
}
"#,
    )
    .expect("write existing config");
    let path = config_path.to_string_lossy().to_string();

    let result = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "integrate", "cursor", "--path", &path],
    );
    assert_eq!(result["changed"], true);

    let parsed: Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
            .expect("parse written config");
    assert_eq!(parsed["mcpServers"]["wispkey"]["command"], "wispkey");
    assert_eq!(parsed["mcpServers"]["wispkey"]["disabled"], false);
}

#[test]
fn integrate_rejects_non_object_mcp_servers_without_overwriting() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let config_path = vault_dir.path().join("invalid-shape.json");
    let secret = "json-config-secret";
    let original = format!(r#"{{"mcpServers": "keep", "secret": "{secret}"}}"#);
    std::fs::write(&config_path, &original).expect("write existing config");
    let path = config_path.to_string_lossy().to_string();

    let output = run_wispkey(
        vault_dir.path(),
        &["integrate", "generic-mcp", "--path", &path],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mcpServers must be a JSON object"));
    assert!(!stderr.contains(secret));
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config"),
        original
    );
}

#[test]
fn integrate_does_not_echo_malformed_toml_values() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let config_path = vault_dir.path().join("invalid.toml");
    let secret = "integrate-toml-secret";
    let original = format!("credential = \"{secret}\n");
    std::fs::write(&config_path, &original).expect("write malformed config");
    let path = config_path.to_string_lossy().to_string();

    let output = run_wispkey(vault_dir.path(), &["integrate", "codex", "--path", &path]);

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config"),
        original
    );
}

#[test]
fn integrate_json_output_does_not_expose_existing_config_secrets() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let config_path = vault_dir.path().join("mcp.json");
    let secret = "existing-client-secret";
    let existing = serde_json::json!({
        "mcpServers": {
            "other": {"command": "other", "env": {"API_KEY": secret}},
            "wispkey": {"env": {"WISPKEY_SIDELOAD_TEST": secret}}
        }
    });
    std::fs::write(&config_path, existing.to_string()).expect("write config");
    for _ in 0..2 {
        let output = run_wispkey(
            vault_dir.path(),
            &[
                "integrate",
                "generic-mcp",
                "--path",
                config_path.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .unwrap();
        assert_eq!(
            saved["mcpServers"]["other"],
            existing["mcpServers"]["other"]
        );
        assert_eq!(
            saved["mcpServers"]["wispkey"]["env"],
            existing["mcpServers"]["wispkey"]["env"]
        );
    }
}

#[test]
fn integrate_codex_appends_without_dropping_unrelated_keys() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());
    let config_path = vault_dir.path().join("config.toml");
    std::fs::write(&config_path, "model = \"gpt-5\"\npreferred = true\n").expect("write toml");
    let path = config_path.to_string_lossy().to_string();

    let first = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "integrate", "codex", "--path", &path],
    );
    assert_eq!(first["changed"], true);
    let second = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "integrate", "codex", "--path", &path],
    );
    assert_eq!(second["changed"], false);

    let contents = std::fs::read_to_string(&config_path).expect("read toml");
    assert!(contents.contains("model = \"gpt-5\""));
    assert!(contents.contains("preferred = true"));
    assert!(contents.contains("[mcp_servers.wispkey]"));
    assert!(contents.contains("command = \"wispkey\""));
    assert!(!contents.contains("WISPKEY_PASSWORD"));
}
