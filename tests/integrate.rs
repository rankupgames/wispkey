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
