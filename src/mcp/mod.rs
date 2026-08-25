/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: MCP (Model Context Protocol) server over stdio. Exposes read tools
 *              (wispkey_list, wispkey_get_token, wispkey_proxy_status, wispkey_project_list)
 *              and write tools (wispkey_set, wispkey_delete) via JSON-RPC 2.0.
 *              Handles full MCP lifecycle (initialize, ping, tools).
 * Created: 2026-04-07
 * Last Modified: 2026-08-25
 */

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use crate::audit;
use crate::core::{
    self, AddCredentialRequest, CredentialType, UpdateCredentialRequest, Vault, VaultError,
};
use crate::env_sideload::EnvSideloadCredential;
use crate::proxy::lifecycle;

/// Runs the WispKey MCP server over stdio transport (JSON-RPC 2.0).
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    tracing::info!("MCP server started (stdio transport)");

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let error_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("parse error: {}", e) }
                });
                writeln!(stdout, "{}", serde_json::to_string(&error_resp)?)?;
                stdout.flush()?;
                continue;
            }
        };

        if let Some(response) = handle_jsonrpc(&request).await {
            let response_str = serde_json::to_string(&response)?;
            writeln!(stdout, "{}", response_str)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

async fn handle_jsonrpc(request: &Value) -> Option<Value> {
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method.starts_with("notifications/")
        || (request.get("id").is_none() && method != "initialize")
    {
        return None;
    }

    let id = request.get("id").cloned().unwrap_or(Value::Null);

    let response = match method {
        "initialize" => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "wispkey",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            })
        }
        "ping" => {
            json!({ "jsonrpc": "2.0", "id": id, "result": {} })
        }
        "resources/list" => {
            json!({ "jsonrpc": "2.0", "id": id, "result": { "resources": [] } })
        }
        "prompts/list" => {
            json!({ "jsonrpc": "2.0", "id": id, "result": { "prompts": [] } })
        }
        "tools/list" => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "wispkey_list",
                            "description": "List available credentials by name and type. Scoped to the active project by default. Pass project: \"*\" to list all.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "tag": { "type": "string", "description": "Filter by tag" },
                                    "project": { "type": "string", "description": "Filter by project name (default: active project, \"*\" for all)" }
                                }
                            }
                        },
                        {
                            "name": "wispkey_get_token",
                            "description": "Get the wisp token for a named credential. Use this token in API calls through the WispKey proxy which will swap it for the real credential. For HTTPS targets, add the X-Target-Url header.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string", "description": "Credential name" }
                                },
                                "required": ["name"]
                            }
                        },
                        {
                            "name": "wispkey_proxy_status",
                            "description": "Check if the WispKey proxy is running and accepting connections. Returns vault state, session state, proxy address, and port.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "wispkey_project_list",
                            "description": "List all projects. Shows project name, partition count, and whether it is the active project.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "wispkey_set",
                            "description": "Create or update a named credential in the vault. On create, a new wisp token is generated. On update (overwrite: true), the secret value and metadata are replaced but the wisp token is preserved. Refuses to silently overwrite; set overwrite to true to replace an existing credential.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string", "description": "Credential name (lowercase, hyphen-separated)" },
                                    "value": { "type": "string", "description": "The secret value to store" },
                                    "type": { "type": "string", "description": "Credential type: bearer_token (default), api_key, basic_auth, custom_header, query_param", "default": "bearer_token" },
                                    "description": { "type": "string", "description": "Short human-readable description" },
                                    "hosts": { "type": "string", "description": "Allowed target hosts (comma-separated, glob patterns)" },
                                    "tags": { "type": "string", "description": "Tags (comma-separated)" },
                                    "project": { "type": "string", "description": "Project to scope to (default: active project)" },
                                    "header_name": { "type": "string", "description": "Custom header name (required when type is custom_header)" },
                                    "param_name": { "type": "string", "description": "Query parameter name (required when type is query_param)" },
                                    "overwrite": { "type": "boolean", "description": "If true, update an existing credential in place. If false (default), refuse if the name already exists.", "default": false }
                                },
                                "required": ["name", "value"]
                            }
                        },
                        {
                            "name": "wispkey_delete",
                            "description": "Delete a credential from the vault by name. Returns confirmation on success or an error if the credential does not exist.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string", "description": "Credential name to delete" },
                                    "project": { "type": "string", "description": "Project to scope to (default: active project)" }
                                },
                                "required": ["name"]
                            }
                        }
                    ]
                }
            })
        }
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            let result = match tool_name {
                "wispkey_list" => handle_tool_list(&arguments),
                "wispkey_get_token" => handle_tool_get_token(&arguments),
                "wispkey_proxy_status" => handle_tool_proxy_status().await,
                "wispkey_project_list" => handle_tool_project_list(),
                "wispkey_set" => handle_tool_set(&arguments),
                "wispkey_delete" => handle_tool_delete(&arguments),
                _ => tool_error(&format!("unknown tool: {}", tool_name)),
            };

            json!({ "jsonrpc": "2.0", "id": id, "result": result })
        }
        "" => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32600, "message": "invalid request: missing method" }
            })
        }
        _ => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method not found: {}", method) }
            })
        }
    };

    Some(response)
}

fn handle_tool_list(arguments: &Value) -> Value {
    let tag_filter = arguments.get("tag").and_then(|t| t.as_str());
    let project_filter = arguments.get("project").and_then(|p| p.as_str());
    let active = core::resolve_active_project();
    let mut list: Vec<Value> = Vec::new();

    let vault_state = match Vault::open_with_session() {
        Ok(vault) => {
            let creds_result = match project_filter {
                Some("*") => vault.list_credentials(),
                Some(name) => vault.list_credentials_in_project(name),
                None => vault.list_credentials_in_project(&active),
            };

            match creds_result {
                Ok(creds) => {
                    list.extend(creds.iter().filter_map(|c| {
                        if let Some(tag) = tag_filter
                            && !c.tags.iter().any(|t| t == tag)
                        {
                            return None;
                        }

                        Some(json!({
                            "name": c.name,
                            "description": c.description,
                            "type": c.credential_type.display_name(),
                            "tags": c.tags,
                            "hosts": c.hosts,
                            "partition_id": c.partition_id,
                            "source": "vault",
                        }))
                    }));
                    "active"
                }
                Err(e) => return tool_error(&format!("failed to list: {}", e)),
            }
        }
        Err(VaultError::NotFound) => "not_initialized",
        Err(_) => "locked",
    };

    if tag_filter.is_none() {
        let existing_names: std::collections::HashSet<String> = list
            .iter()
            .filter_map(|credential| {
                credential
                    .get("name")
                    .and_then(|name| name.as_str())
                    .map(String::from)
            })
            .collect();

        list.extend(
            crate::env_sideload::list_available()
                .into_iter()
                .filter(|credential| !existing_names.contains(&credential.name))
                .map(|credential| sideload_credential_json(&credential)),
        );
    }

    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&json!({
                "credentials": list,
                "count": list.len(),
                "project": project_filter.unwrap_or(&active),
                "vault_state": vault_state,
            })).expect("json serialization of credential list")
        }]
    })
}

fn handle_tool_project_list() -> Value {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => return tool_error(&format!("vault error: {}", e)),
    };

    let active = core::resolve_active_project();

    match vault.list_projects() {
        Ok(projects) => {
            let list: Vec<Value> = projects
                .iter()
                .map(|p| {
                    let count = vault.project_partition_count(&p.id).unwrap_or(0);
                    json!({
                        "name": p.name,
                        "description": p.description,
                        "partition_count": count,
                        "active": p.name == active,
                    })
                })
                .collect();

            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({"projects": list, "count": list.len(), "active_project": active})).expect("json serialization of project list")
                }]
            })
        }
        Err(e) => tool_error(&format!("failed to list projects: {}", e)),
    }
}

fn handle_tool_get_token(arguments: &Value) -> Value {
    let name = match arguments.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return tool_error("missing required argument: name"),
    };

    let proxy_address = read_proxy_address();

    match Vault::open_with_session() {
        Ok(vault) => match vault.get_credential(name) {
            Ok(cred) => {
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Wisp token for '{}': {}\n\nUse this token in API requests through the WispKey proxy ({}).\nFor HTTP targets: set HTTP_PROXY={}\nFor HTTPS targets: add header X-Target-Url: <url> to your request.",
                            name, cred.wisp_token, proxy_address, proxy_address
                        )
                    }]
                })
            }
            Err(e) => match crate::env_sideload::credential_for_name(name) {
                Some(credential) => sideload_token_response(name, &credential, &proxy_address),
                None => tool_error(&credential_not_found_message(&vault, name, &e.to_string())),
            },
        },
        Err(e) => match crate::env_sideload::credential_for_name(name) {
            Some(credential) => sideload_token_response(name, &credential, &proxy_address),
            None => {
                let hint = crate::env_sideload::env_key_for_name(name)
                    .map(|env_key| format!(" Set {} to sideload this credential.", env_key))
                    .unwrap_or_default();
                tool_error(&format!("vault error: {}.{}", e, hint))
            }
        },
    }
}

fn sideload_credential_json(credential: &EnvSideloadCredential) -> Value {
    json!({
        "name": credential.name,
        "description": "Environment sideload credential",
        "type": "bearer_token",
        "tags": ["env-sideload"],
        "hosts": [],
        "partition_id": Value::Null,
        "source": "env_sideload",
        "env_key": credential.env_key,
    })
}

fn sideload_token_response(
    requested_name: &str,
    credential: &EnvSideloadCredential,
    proxy_address: &str,
) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "Wisp token for sideloaded env credential '{}': {}\n\nSource: {} (value not exposed). Use this token through the WispKey proxy ({}). Start the proxy with the same env var so it can substitute the token. No vault master password is required for this sideload path.",
                requested_name, credential.token, credential.env_key, proxy_address
            )
        }]
    })
}

async fn handle_tool_proxy_status() -> Value {
    let proxy_status = lifecycle::read_status().await;
    let vault_exists = Vault::exists();
    let session_active = Vault::open_with_session().is_ok();
    let sideload_count = crate::env_sideload::list_available().len();

    let status_json = json!({
        "vault": if vault_exists { "initialized" } else { "not_initialized" },
        "session": if session_active { "active" } else { "locked" },
        "proxy": proxy_status.public_json(),
        "proxy_address": proxy_status.address_or_default(),
        "env_sideloads": sideload_count,
        "https": "supported via X-Target-Url header",
    });

    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&status_json).expect("proxy status json")
        }]
    })
}

fn read_proxy_address() -> String {
    lifecycle::proxy_address_or_default()
}

fn credential_not_found_message(vault: &Vault, requested: &str, error: &str) -> String {
    let suggestions = suggest_credential_names(vault, requested);
    if suggestions.is_empty() {
        return format!("credential '{requested}' not found: {error}");
    }

    format!(
        "credential '{requested}' not found: {error}. Did you mean: {}?",
        suggestions.join(", ")
    )
}

fn suggest_credential_names(vault: &Vault, requested: &str) -> Vec<String> {
    let active = core::resolve_active_project();
    let mut candidates = vault
        .list_credentials_in_project(&active)
        .unwrap_or_default()
        .into_iter()
        .map(|credential| credential.name)
        .collect::<Vec<_>>();

    let active_count = candidates.len();
    for name in vault
        .list_credentials()
        .unwrap_or_default()
        .into_iter()
        .map(|credential| credential.name)
    {
        if !candidates.iter().any(|existing| existing == &name) {
            candidates.push(name);
        }
    }

    let requested_key = normalize_lookup_name(requested);
    let mut scored = candidates
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let key = normalize_lookup_name(&name);
            let project_rank = usize::from(index >= active_count);
            if key == requested_key {
                return Some((0usize, project_rank, name));
            }
            let distance = edit_distance(&key, &requested_key);
            (distance <= 3).then_some((distance, project_rank, name))
        })
        .collect::<Vec<_>>();

    scored.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    scored
        .into_iter()
        .take(3)
        .map(|(_, _, name)| name)
        .collect()
}

fn normalize_lookup_name(name: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !normalized.is_empty() && !last_was_separator {
            normalized.push('-');
            last_was_separator = true;
        }
    }
    while normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut current = vec![left_index + 1];
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insert = current[right_index] + 1;
            let delete = previous[right_index + 1] + 1;
            let replace = previous[right_index] + usize::from(left_char != *right_char);
            current.push(insert.min(delete).min(replace));
        }
        previous = current;
    }

    previous[right_chars.len()]
}

fn handle_tool_set(arguments: &Value) -> Value {
    let name = match arguments.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return tool_error("missing required argument: name"),
    };
    let value = match arguments.get("value").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return tool_error("missing required argument: value"),
    };
    let type_str = arguments
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("bearer_token");
    let header_name = arguments.get("header_name").and_then(|h| h.as_str());
    let param_name = arguments.get("param_name").and_then(|p| p.as_str());
    let description = arguments.get("description").and_then(|d| d.as_str());
    let hosts = arguments.get("hosts").and_then(|h| h.as_str());
    let tags = arguments.get("tags").and_then(|t| t.as_str());
    let project = arguments.get("project").and_then(|p| p.as_str());
    let overwrite = arguments
        .get("overwrite")
        .and_then(|o| o.as_bool())
        .unwrap_or(false);

    let credential_type =
        match CredentialType::from_str_with_params(type_str, header_name, param_name) {
            Ok(t) => t,
            Err(e) => return tool_error(&format!("invalid credential type: {}", e)),
        };

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => return tool_error(&format!("vault error: {}", e)),
    };

    let active = project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);

    let existing = vault.get_credential_in_project(&active, name).ok();

    if existing.is_some() && !overwrite {
        return tool_error(&format!(
            "credential '{}' already exists. Set overwrite: true to replace it.",
            name
        ));
    }

    if existing.is_some() {
        match vault.update_credential(UpdateCredentialRequest {
            name,
            credential_type,
            value,
            description,
            hosts,
            tags,
            project: Some(&active),
        }) {
            Ok(cred) => {
                audit::log_event(
                    vault.db(),
                    "CredentialUpdated",
                    Some(name),
                    Some(&cred.wisp_token),
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    Some(&active),
                );
                json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&json!({
                            "action": "updated",
                            "name": cred.name,
                            "type": cred.credential_type.display_name(),
                            "wisp_token": cred.wisp_token,
                            "hosts": cred.hosts,
                            "tags": cred.tags,
                            "project": active,
                        })).expect("json serialize")
                    }]
                })
            }
            Err(e) => tool_error(&format!("failed to update credential: {}", e)),
        }
    } else {
        match vault.add_credential(AddCredentialRequest {
            name,
            credential_type,
            value,
            description,
            hosts,
            tags,
            partition: None,
            project: Some(&active),
        }) {
            Ok(cred) => {
                audit::log_event(
                    vault.db(),
                    "CredentialAdded",
                    Some(name),
                    Some(&cred.wisp_token),
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    Some(&active),
                );
                json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&json!({
                            "action": "created",
                            "name": cred.name,
                            "type": cred.credential_type.display_name(),
                            "wisp_token": cred.wisp_token,
                            "hosts": cred.hosts,
                            "tags": cred.tags,
                            "project": active,
                        })).expect("json serialize")
                    }]
                })
            }
            Err(e) => tool_error(&format!("failed to add credential: {}", e)),
        }
    }
}

fn handle_tool_delete(arguments: &Value) -> Value {
    let name = match arguments.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return tool_error("missing required argument: name"),
    };
    let project = arguments.get("project").and_then(|p| p.as_str());

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => return tool_error(&format!("vault error: {}", e)),
    };

    let active = project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);

    match vault.remove_credential_in_project(&active, name) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "CredentialRemoved",
                Some(name),
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(&active),
            );
            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({
                        "action": "deleted",
                        "name": name,
                        "project": active,
                    })).expect("json serialize")
                }]
            })
        }
        Err(e) => tool_error(&format!("failed to delete credential '{}': {}", name, e)),
    }
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!("Error: {}", message)
        }],
        "isError": true
    })
}
