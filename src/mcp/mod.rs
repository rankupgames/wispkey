/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: MCP (Model Context Protocol) server over stdio. Exposes wispkey_list,
 *              wispkey_get_token, and wispkey_proxy_status tools via JSON-RPC 2.0.
 * Created: 2026-04-07
 * Last Modified: 2026-04-12
 */

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use crate::core::{self, Vault};

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
            Err(_) => continue,
        };

        if let Some(response) = handle_jsonrpc(&request) {
            let response_str = serde_json::to_string(&response)?;
            writeln!(stdout, "{}", response_str)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

/// Returns None for notifications (no `id` field or known notification methods).
fn handle_jsonrpc(request: &Value) -> Option<Value> {
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method == "notifications/initialized" || request.get("id").is_none() {
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
                                    "tag": {
                                        "type": "string",
                                        "description": "Filter by tag"
                                    },
                                    "project": {
                                        "type": "string",
                                        "description": "Filter by project name (default: active project, \"*\" for all)"
                                    }
                                }
                            }
                        },
                        {
                            "name": "wispkey_get_token",
                            "description": "Get the wisp token for a named credential. Use this token in API calls through the WispKey proxy (HTTP_PROXY=http://localhost:7700) which will swap it for the real credential.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Credential name"
                                    }
                                },
                                "required": ["name"]
                            }
                        },
                        {
                            "name": "wispkey_proxy_status",
                            "description": "Check if the WispKey proxy is running and accepting connections.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "wispkey_project_list",
                            "description": "List all projects. Shows project name, partition count, and whether it is the active project.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
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
                "wispkey_proxy_status" => handle_tool_proxy_status(),
                "wispkey_project_list" => handle_tool_project_list(),
                _ => tool_error(&format!("unknown tool: {}", tool_name)),
            };

            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        }
        _ => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("method not found: {}", method)
                }
            })
        }
    };

    Some(response)
}

fn handle_tool_list(arguments: &Value) -> Value {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => return tool_error(&format!("vault error: {}", e)),
    };

    let tag_filter = arguments.get("tag").and_then(|t| t.as_str());
    let project_filter = arguments.get("project").and_then(|p| p.as_str());

    let creds_result = match project_filter {
        Some("*") => vault.list_credentials(),
        Some(name) => vault.list_credentials_in_project(name),
        None => {
            let active = core::resolve_active_project();
            vault.list_credentials_in_project(&active)
        }
    };

    match creds_result {
        Ok(creds) => {
            let filtered: Vec<_> = creds
                .iter()
                .filter(|c| {
                    if let Some(tag) = tag_filter {
                        c.tags.iter().any(|t| t == tag)
                    } else {
                        true
                    }
                })
                .collect();

            let active = core::resolve_active_project();
            let list: Vec<Value> = filtered
                .iter()
                .map(|c| {
                    json!({
                        "name": c.name,
                        "type": c.credential_type.display_name(),
                        "tags": c.tags,
                        "hosts": c.hosts,
                        "partition_id": c.partition_id,
                    })
                })
                .collect();

            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({
                        "credentials": list,
                        "count": list.len(),
                        "project": project_filter.unwrap_or(&active),
                    })).unwrap()
                }]
            })
        }
        Err(e) => tool_error(&format!("failed to list: {}", e)),
    }
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
                    "text": serde_json::to_string_pretty(&json!({"projects": list, "count": list.len(), "active_project": active})).unwrap()
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

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => return tool_error(&format!("vault error: {}", e)),
    };

    match vault.get_credential(name) {
        Ok(cred) => {
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("Wisp token for '{}': {}\n\nUse this token in API requests through the WispKey proxy (HTTP_PROXY=http://localhost:7700). The proxy will swap it for the real credential.", name, cred.wisp_token)
                }]
            })
        }
        Err(e) => tool_error(&format!("credential '{}' not found: {}", name, e)),
    }
}

fn handle_tool_proxy_status() -> Value {
    let pid_path = Vault::vault_dir().join("proxy.pid");
    let proxy_running = pid_path.exists();

    let vault_exists = Vault::exists();
    let session_active = Vault::open_with_session().is_ok();

    let status_text = format!(
        "Vault: {}\nSession: {}\nProxy: {}\nProxy address: http://localhost:7700",
        if vault_exists {
            "initialized"
        } else {
            "not initialized"
        },
        if session_active { "active" } else { "locked" },
        if proxy_running { "running" } else { "stopped" },
    );

    json!({
        "content": [{
            "type": "text",
            "text": status_text
        }]
    })
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
