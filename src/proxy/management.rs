use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode, Uri};

use crate::audit;
use crate::core::{self, Vault, VaultError};

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let mut split = pair.splitn(2, '=');
        let param_key = split.next()?;
        let param_value = split.next().unwrap_or("");
        if param_key == key {
            Some(
                urlencoding::decode(param_value)
                    .map(|value| value.into_owned())
                    .unwrap_or_else(|_| param_value.to_string()),
            )
        } else {
            None
        }
    })
}

fn requested_project(uri: &Uri) -> String {
    query_param(uri, "project").unwrap_or_else(core::resolve_active_project)
}

pub(super) async fn handle_management_api(
    method: &hyper::Method,
    uri: &Uri,
    _headers: &hyper::HeaderMap,
) -> Response<Full<Bytes>> {
    let path = uri.path();

    if method.as_str() == "GET" && path == "/api/logs" {
        return logs_response(uri);
    }

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(_) => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &serde_json::json!({"error": "vault locked"}),
            );
        }
    };

    match (method.as_str(), path) {
        ("GET", "/api/status") => {
            let active_project = core::resolve_active_project();
            let requested = requested_project(uri);
            let count = if requested == "*" {
                vault.credential_count().unwrap_or(0)
            } else {
                vault
                    .list_credentials_in_project(&requested)
                    .map(|credentials| credentials.len())
                    .unwrap_or(0)
            };
            let created = vault
                .vault_created_at()
                .unwrap_or_else(|_| "unknown".to_string());

            let proxy_info = Vault::vault_dir().join("proxy.json");
            let proxy_port: Option<u64> = std::fs::read_to_string(&proxy_info)
                .ok()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                .and_then(|v| v.get("port").and_then(|p| p.as_u64()));

            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "vault_path": Vault::vault_dir().to_string_lossy(),
                    "created_at": created,
                    "credential_count": count,
                    "session_active": true,
                    "active_project": active_project,
                    "project": requested,
                    "proxy_running": true,
                    "proxy_port": proxy_port,
                }),
            )
        }
        ("GET", "/api/credentials") => match if requested_project(uri) == "*" {
            vault.list_credentials()
        } else {
            vault.list_credentials_in_project(&requested_project(uri))
        } {
            Ok(creds) => {
                let list: Vec<serde_json::Value> = creds.iter().map(credential_to_json).collect();
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "project": requested_project(uri),
                        "credentials": list
                    }),
                )
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": e.to_string()}),
            ),
        },
        ("GET", path) if path.starts_with("/api/credentials/") => {
            let name = &path["/api/credentials/".len()..];
            let project = requested_project(uri);
            match if project == "*" {
                vault.get_credential(name)
            } else {
                vault.get_credential_in_project(&project, name)
            } {
                Ok(cred) => json_response(StatusCode::OK, &credential_to_json(&cred)),
                Err(_) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": "credential not found"}),
                ),
            }
        }
        ("GET", "/api/partitions") => match if requested_project(uri) == "*" {
            vault.list_partitions()
        } else {
            vault.list_partitions_in_project(&requested_project(uri))
        } {
            Ok(partitions) => {
                let list: Vec<serde_json::Value> = partitions
                    .iter()
                    .map(|p| {
                        let count = vault.partition_credential_count(&p.id).unwrap_or(0);
                        serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "project_id": p.project_id,
                            "credential_count": count,
                            "created_at": p.created_at.to_rfc3339(),
                            "updated_at": p.updated_at.to_rfc3339(),
                        })
                    })
                    .collect();
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "project": requested_project(uri),
                        "partitions": list
                    }),
                )
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": e.to_string()}),
            ),
        },
        ("GET", path) if path.starts_with("/api/partitions/") && path.ends_with("/credentials") => {
            let segment = &path["/api/partitions/".len()..path.len() - "/credentials".len()];
            let project = requested_project(uri);
            match vault.list_credentials_in_partition_for_project(&project, segment) {
                Ok(creds) => {
                    let list: Vec<serde_json::Value> =
                        creds.iter().map(credential_to_json).collect();
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "project": project,
                            "partition": segment,
                            "credentials": list
                        }),
                    )
                }
                Err(e) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": e.to_string()}),
                ),
            }
        }
        ("GET", path) if path.starts_with("/api/partitions/") => {
            let name = &path["/api/partitions/".len()..];
            let project = requested_project(uri);
            match vault.get_partition_in_project(&project, name) {
                Ok(p) => {
                    let count = vault.partition_credential_count(&p.id).unwrap_or(0);
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "project_id": p.project_id,
                            "credential_count": count,
                            "created_at": p.created_at.to_rfc3339(),
                            "updated_at": p.updated_at.to_rfc3339(),
                        }),
                    )
                }
                Err(_) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": "partition not found"}),
                ),
            }
        }
        ("DELETE", path) if path.starts_with("/api/partitions/") => {
            let name = &path["/api/partitions/".len()..];
            let project = requested_project(uri);
            match vault.delete_partition_in_project(&project, name) {
                Ok(()) => {
                    audit::log_event(
                        vault.db(),
                        "PartitionDeleted",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                    );
                    json_response(StatusCode::OK, &serde_json::json!({"deleted": name}))
                }
                Err(e) => json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error": e.to_string()}),
                ),
            }
        }
        ("DELETE", path) if path.starts_with("/api/credentials/") => {
            let name = &path["/api/credentials/".len()..];
            let project = requested_project(uri);
            match if project == "*" {
                vault.remove_credential(name)
            } else {
                vault.remove_credential_in_project(&project, name)
            } {
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
                        None,
                    );
                    json_response(StatusCode::OK, &serde_json::json!({"deleted": name}))
                }
                Err(e) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": e.to_string()}),
                ),
            }
        }
        ("GET", "/api/projects") => match vault.list_projects() {
            Ok(projects) => {
                let active = core::resolve_active_project();
                let list: Vec<serde_json::Value> = projects
                    .iter()
                    .map(|p| {
                        let count = vault.project_partition_count(&p.id).unwrap_or(0);
                        serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "partition_count": count,
                            "active": p.name == active,
                            "created_at": p.created_at.to_rfc3339(),
                            "updated_at": p.updated_at.to_rfc3339(),
                        })
                    })
                    .collect();
                json_response(StatusCode::OK, &serde_json::json!({"projects": list}))
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": e.to_string()}),
            ),
        },
        ("GET", path) if path.starts_with("/api/projects/") => {
            let name = &path["/api/projects/".len()..];
            match vault.get_project(name) {
                Ok(p) => {
                    let count = vault.project_partition_count(&p.id).unwrap_or(0);
                    let active = core::resolve_active_project();
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "partition_count": count,
                            "active": p.name == active,
                            "created_at": p.created_at.to_rfc3339(),
                            "updated_at": p.updated_at.to_rfc3339(),
                        }),
                    )
                }
                Err(_) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": "project not found"}),
                ),
            }
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "not found"}),
        ),
    }
}

fn logs_response(uri: &Uri) -> Response<Full<Bytes>> {
    let query = uri.query().unwrap_or("");
    let params: Vec<(&str, &str)> = query
        .split('&')
        .filter_map(|p| {
            let mut split = p.splitn(2, '=');
            Some((split.next()?, split.next().unwrap_or("")))
        })
        .collect();

    let last: usize = params
        .iter()
        .find(|(k, _)| *k == "last")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(50);
    let credential = params
        .iter()
        .find(|(k, _)| *k == "credential")
        .map(|(_, v)| *v);
    let since = params.iter().find(|(k, _)| *k == "since").map(|(_, v)| *v);

    let vault = match Vault::open() {
        Ok(vault) => Some(vault),
        Err(VaultError::NotFound) => None,
        Err(error) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": error.to_string()}),
            );
        }
    };

    let entries = audit::query_combined_log(vault.as_ref().map(Vault::db), last, credential, since);
    let list: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "credential_name": e.credential_name,
                "wisp_token": e.wisp_token,
                "target_host": e.target_host,
                "target_path": e.target_path,
                "http_method": e.http_method,
                "response_status": e.response_status,
                "denied": e.denied,
                "deny_reason": e.deny_reason,
                "project_name": e.project_name,
                "source": e.source,
            })
        })
        .collect();
    json_response(StatusCode::OK, &serde_json::json!({"entries": list}))
}

fn credential_to_json(c: &crate::core::Credential) -> serde_json::Value {
    serde_json::json!({
        "name": c.name,
        "type": c.credential_type.display_name(),
        "wisp_token": c.wisp_token,
        "hosts": c.hosts,
        "tags": c.tags,
        "partition_id": c.partition_id,
        "created_at": c.created_at.to_rfc3339(),
        "updated_at": c.updated_at.to_rfc3339(),
        "last_used_at": c.last_used_at.map(|d| d.to_rfc3339()),
    })
}

pub(super) fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "http://localhost")
        .header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
        .header(
            "access-control-allow-headers",
            "content-type, authorization, x-wispkey-management-token",
        )
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("json response must build")
}
