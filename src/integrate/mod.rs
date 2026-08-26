/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Idempotent MCP client configuration generators.
 * Created: 2026-08-26
 * Last Modified: 2026-08-26
 */

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};

pub const WISPKEY_COMMAND: &str = "wispkey";
pub const WISPKEY_MCP_ARGS: [&str; 2] = ["mcp", "serve"];
pub const JSON_PLAINTEXT_ENV_WARNING: &str = "JSON MCP configs cannot forward environment variables by name. Do not put secret values in an `env` block; start the client with WISPKEY_SIDELOAD_<SLUG> in the process environment, or use Codex `env_vars`.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrateClient {
    Cursor,
    Codex,
    ClaudeCode,
    GenericMcp,
}

impl IntegrateClient {
    pub const ALL: [Self; 4] = [
        Self::Cursor,
        Self::Codex,
        Self::ClaudeCode,
        Self::GenericMcp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::GenericMcp => "generic-mcp",
        }
    }

    pub fn config_kind(self) -> ConfigKind {
        match self {
            Self::Codex => ConfigKind::Toml,
            Self::Cursor | Self::ClaudeCode | Self::GenericMcp => ConfigKind::Json,
        }
    }

    pub fn requires_plaintext_env_warning(self) -> bool {
        matches!(self.config_kind(), ConfigKind::Json)
    }

    pub fn default_path(self) -> PathBuf {
        match self {
            Self::Cursor => PathBuf::from(".cursor").join("mcp.json"),
            Self::ClaudeCode => PathBuf::from(".mcp.json"),
            Self::GenericMcp => PathBuf::from("mcp.json"),
            Self::Codex => dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".codex")
                .join("config.toml"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigKind {
    Json,
    Toml,
}

#[derive(Debug, Clone)]
pub struct ExistingClientConfig {
    pub has_wispkey: bool,
    pub uses_path_command: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegratePlan {
    pub client: IntegrateClient,
    pub format: ConfigKind,
    pub path: PathBuf,
    pub written: bool,
    pub changed: bool,
    pub plaintext_env_warning: Option<String>,
    pub config: Value,
}

pub fn generate_config_value(client: IntegrateClient) -> Value {
    match client.config_kind() {
        ConfigKind::Json => json_snippet(),
        ConfigKind::Toml => toml_snippet_value(),
    }
}

pub fn generate_config_text(client: IntegrateClient) -> Result<String, String> {
    match client.config_kind() {
        ConfigKind::Json => serde_json::to_string_pretty(&json_snippet())
            .map(|text| format!("{text}\n"))
            .map_err(|error| format!("serializing MCP JSON: {error}")),
        ConfigKind::Toml => Ok(toml_snippet()),
    }
}

pub fn inspect_existing(
    client: &IntegrateClient,
    path: &Path,
) -> Result<ExistingClientConfig, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    match client.config_kind() {
        ConfigKind::Json => inspect_json(&content),
        ConfigKind::Toml => inspect_toml(&content),
    }
}

pub fn apply_to_path(client: IntegrateClient, path: &Path) -> Result<(bool, Value), String> {
    let desired = generate_config_value(client);
    if path.exists() {
        let content = fs::read_to_string(path)
            .map_err(|error| format!("reading {}: {error}", path.display()))?;
        match client.config_kind() {
            ConfigKind::Json => {
                let (merged, changed) = merge_json_file(&content)?;
                if changed {
                    write_text(path, &pretty_json(&merged)?)?;
                }
                Ok((changed, merged))
            }
            ConfigKind::Toml => {
                let (merged, changed) = merge_toml_file(&content)?;
                if changed {
                    write_text(path, &merged)?;
                }
                Ok((changed, desired))
            }
        }
    } else {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("creating {}: {error}", parent.display()))?;
        }
        write_text(path, &generate_config_text(client)?)?;
        Ok((true, desired))
    }
}

pub fn plan_print(client: IntegrateClient, path: PathBuf) -> Result<IntegratePlan, String> {
    Ok(IntegratePlan {
        client,
        format: client.config_kind(),
        path,
        written: false,
        changed: false,
        plaintext_env_warning: plaintext_warning(client),
        config: generate_config_value(client),
    })
}

pub fn plan_write(client: IntegrateClient, path: PathBuf) -> Result<IntegratePlan, String> {
    let (changed, config) = apply_to_path(client, &path)?;
    Ok(IntegratePlan {
        client,
        format: client.config_kind(),
        path,
        written: true,
        changed,
        plaintext_env_warning: plaintext_warning(client),
        config,
    })
}

fn plaintext_warning(client: IntegrateClient) -> Option<String> {
    client
        .requires_plaintext_env_warning()
        .then(|| JSON_PLAINTEXT_ENV_WARNING.to_string())
}

fn json_snippet() -> Value {
    json!({
        "mcpServers": {
            "wispkey": {
                "command": WISPKEY_COMMAND,
                "args": WISPKEY_MCP_ARGS,
            }
        }
    })
}

fn toml_snippet() -> String {
    format!("[mcp_servers.wispkey]\ncommand = \"{WISPKEY_COMMAND}\"\nargs = [\"mcp\", \"serve\"]\n")
}

fn toml_snippet_value() -> Value {
    json!({
        "mcp_servers": {
            "wispkey": {
                "command": WISPKEY_COMMAND,
                "args": WISPKEY_MCP_ARGS,
            }
        }
    })
}

fn inspect_json(content: &str) -> Result<ExistingClientConfig, String> {
    let value: Value =
        serde_json::from_str(content).map_err(|error| format!("invalid JSON: {error}"))?;
    let server = value
        .get("mcpServers")
        .and_then(Value::as_object)
        .and_then(|servers| servers.get("wispkey"));
    Ok(config_from_server(server.and_then(Value::as_object)))
}

fn inspect_toml(content: &str) -> Result<ExistingClientConfig, String> {
    let value: toml::Value =
        toml::from_str(content).map_err(|error| format!("invalid TOML: {error}"))?;
    let server = value
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .and_then(|servers| servers.get("wispkey"))
        .and_then(toml::Value::as_table);
    let command = server.and_then(|table| table.get("command").and_then(toml::Value::as_str));
    Ok(ExistingClientConfig {
        has_wispkey: server.is_some(),
        uses_path_command: command.is_some_and(command_is_user_path),
    })
}

fn config_from_server(server: Option<&serde_json::Map<String, Value>>) -> ExistingClientConfig {
    let command = server.and_then(|object| object.get("command").and_then(Value::as_str));
    ExistingClientConfig {
        has_wispkey: server.is_some(),
        uses_path_command: command.is_some_and(command_is_user_path),
    }
}

fn command_is_user_path(command: &str) -> bool {
    command != WISPKEY_COMMAND
        && (command.contains('/') || command.contains('\\') || Path::new(command).is_absolute())
}

fn merge_json_file(content: &str) -> Result<(Value, bool), String> {
    let mut root: Value = if content.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(content).map_err(|error| format!("invalid JSON: {error}"))?
    };
    let object = root
        .as_object_mut()
        .ok_or_else(|| "MCP JSON must be an object".to_string())?;
    let servers = object.entry("mcpServers").or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    let changed = upsert_json_server(
        servers
            .as_object_mut()
            .expect("mcpServers object after normalization"),
    );
    Ok((root, changed))
}

fn upsert_json_server(servers: &mut serde_json::Map<String, Value>) -> bool {
    match servers.get_mut("wispkey") {
        Some(Value::Object(existing)) => {
            let mut changed = false;
            if existing.get("command").and_then(Value::as_str) != Some(WISPKEY_COMMAND) {
                existing.insert("command".to_string(), json!(WISPKEY_COMMAND));
                changed = true;
            }
            let desired_args = json!(WISPKEY_MCP_ARGS);
            if existing.get("args") != Some(&desired_args) {
                existing.insert("args".to_string(), desired_args);
                changed = true;
            }
            changed
        }
        Some(_) | None => {
            servers.insert(
                "wispkey".to_string(),
                json!({
                    "command": WISPKEY_COMMAND,
                    "args": WISPKEY_MCP_ARGS,
                }),
            );
            true
        }
    }
}

fn merge_toml_file(content: &str) -> Result<(String, bool), String> {
    if content.trim().is_empty() {
        return Ok((toml_snippet(), true));
    }

    let mut value: toml::Value =
        toml::from_str(content).map_err(|error| format!("invalid TOML: {error}"))?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| "Codex config must be a TOML table".to_string())?;
    let servers = table
        .entry("mcp_servers")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let servers = servers
        .as_table_mut()
        .ok_or_else(|| "mcp_servers must be a TOML table".to_string())?;

    match servers.get("wispkey") {
        Some(toml::Value::Table(existing)) => {
            let command_ok =
                existing.get("command").and_then(toml::Value::as_str) == Some(WISPKEY_COMMAND);
            let args_ok = existing
                .get("args")
                .and_then(toml::Value::as_array)
                .is_some_and(|args| {
                    args.iter()
                        .filter_map(toml::Value::as_str)
                        .eq(WISPKEY_MCP_ARGS)
                });
            if command_ok && args_ok {
                return Ok((content.to_string(), false));
            }
        }
        None => {
            let mut appended = content.to_string();
            if !appended.ends_with('\n') {
                appended.push('\n');
            }
            if !appended.ends_with("\n\n") {
                appended.push('\n');
            }
            appended.push_str(&toml_snippet());
            return Ok((appended, true));
        }
        Some(_) => {}
    }

    let mut wispkey = toml::map::Map::new();
    if let Some(toml::Value::Table(existing)) = servers.get("wispkey") {
        wispkey = existing.clone();
    }
    wispkey.insert(
        "command".to_string(),
        toml::Value::String(WISPKEY_COMMAND.to_string()),
    );
    wispkey.insert(
        "args".to_string(),
        toml::Value::Array(
            WISPKEY_MCP_ARGS
                .iter()
                .map(|arg| toml::Value::String((*arg).to_string()))
                .collect(),
        ),
    );
    servers.insert("wispkey".to_string(), toml::Value::Table(wispkey));
    toml::to_string_pretty(&value)
        .map(|text| (text, true))
        .map_err(|error| format!("serializing Codex TOML: {error}"))
}

fn pretty_json(value: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|text| format!("{text}\n"))
        .map_err(|error| format!("serializing MCP JSON: {error}"))
}

fn write_text(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|error| format!("writing {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_snippet_uses_path_command_and_no_secrets() {
        let value = json_snippet();
        let serialized = serde_json::to_string(&value).expect("json");
        assert_eq!(value["mcpServers"]["wispkey"]["command"], "wispkey");
        assert_eq!(
            value["mcpServers"]["wispkey"]["args"],
            json!(["mcp", "serve"])
        );
        assert!(value["mcpServers"]["wispkey"].get("env").is_none());
        assert!(!serialized.contains("WISPKEY_PASSWORD"));
        assert!(!serialized.contains('/'));
        assert!(!serialized.contains('\\'));
    }

    #[test]
    fn json_merge_is_idempotent_and_preserves_other_servers() {
        let existing = r#"{
            "mcpServers": {
                "other": { "command": "other" },
                "wispkey": { "command": "wispkey", "args": ["mcp", "serve"], "env_vars": ["KEEP"] }
            },
            "theme": "dark"
        }"#;
        let (first, changed) = merge_json_file(existing).expect("merge");
        assert!(!changed);
        assert_eq!(first["theme"], "dark");
        assert_eq!(first["mcpServers"]["other"]["command"], "other");
        assert_eq!(first["mcpServers"]["wispkey"]["env_vars"], json!(["KEEP"]));

        let serialized = serde_json::to_string(&first).expect("json");
        let (second, changed_again) = merge_json_file(&serialized).expect("second merge");
        assert!(!changed_again);
        assert_eq!(first, second);
    }

    #[test]
    fn json_merge_replaces_user_specific_command() {
        let existing = r#"{
            "mcpServers": {
                "wispkey": { "command": "/Users/me/.local/bin/wispkey", "args": ["mcp", "serve"] }
            }
        }"#;
        let (merged, changed) = merge_json_file(existing).expect("merge");
        assert!(changed);
        assert_eq!(merged["mcpServers"]["wispkey"]["command"], "wispkey");
    }

    #[test]
    fn toml_merge_appends_and_then_is_idempotent() {
        let existing = "model = \"gpt-5\"\n";
        let (first, changed) = merge_toml_file(existing).expect("merge");
        assert!(changed);
        assert!(first.contains("model = \"gpt-5\""));
        assert!(first.contains("[mcp_servers.wispkey]"));
        assert!(first.contains("command = \"wispkey\""));
        let (second, changed_again) = merge_toml_file(&first).expect("second merge");
        assert!(!changed_again);
        assert_eq!(first, second);
    }

    #[test]
    fn json_clients_warn_about_plaintext_env() {
        assert!(IntegrateClient::Cursor.requires_plaintext_env_warning());
        assert!(IntegrateClient::ClaudeCode.requires_plaintext_env_warning());
        assert!(IntegrateClient::GenericMcp.requires_plaintext_env_warning());
        assert!(!IntegrateClient::Codex.requires_plaintext_env_warning());
    }
}
