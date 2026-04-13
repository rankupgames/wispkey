/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: HTTP forward proxy -- intercepts requests containing wk_* wisp tokens,
 *              swaps them for real credentials, enforces host restrictions, logs audit events.
 *              Also serves the management API at /api/ endpoints for the desktop app.
 * Created: 2026-04-07
 * Last Modified: 2026-04-08
 */

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use regex::Regex;
use tokio::net::TcpListener;

use crate::audit;
use crate::core::{CredentialType, Vault};

pub async fn start_proxy(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("WispKey proxy listening on http://{}", addr);

    let pid_path = crate::core::Vault::vault_dir().join("proxy.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let pid_path_cleanup = pid_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = std::fs::remove_file(&pid_path_cleanup);
        std::process::exit(0);
    });

    let wisp_pattern = Arc::new(Regex::new(r"wk_[a-z0-9_]+").unwrap());

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let pattern = wisp_pattern.clone();

        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let pattern = pattern.clone();
                handle_request(req, remote_addr, pattern)
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!("Connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    _remote_addr: SocketAddr,
    wisp_pattern: Arc<Regex>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    if uri.path().starts_with("/api/") {
        return Ok(handle_management_api(&method, &uri, &headers).await);
    }

    let target_host = extract_target_host(&uri, &headers);

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(_) => {
            return Ok(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Vault is locked. Run `wispkey unlock` first.",
            ));
        }
    };

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };

    let mut new_headers = parts.headers.clone();
    let mut new_body = body_bytes.to_vec();
    let mut used_credentials: Vec<(String, String)> = Vec::new();

    for (header_name, header_value) in parts.headers.iter() {
        if let Ok(value_str) = header_value.to_str() {
            for token_match in wisp_pattern.find_iter(value_str) {
                let token = token_match.as_str();
                match vault.lookup_by_wisp_token(token) {
                    Ok((cred, real_value)) => {
                        if !check_host_restriction(&cred.hosts, &target_host) {
                            let reason = format!(
                                "host '{}' not allowed for credential '{}'",
                                target_host, cred.name
                            );
                            audit::log_event(
                                vault.db(),
                                "CredentialDenied",
                                Some(&cred.name),
                                Some(token),
                                Some(&target_host),
                                Some(parts.uri.path()),
                                Some(parts.method.as_str()),
                                None,
                                true,
                                Some(&reason),
                            );
                            return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                        }

                        let injected =
                            inject_credential(&cred.credential_type, &real_value, value_str, token);
                        if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                            new_headers.insert(header_name.clone(), new_value);
                        }
                        used_credentials.push((cred.name.clone(), token.to_string()));
                    }
                    Err(e) => {
                        tracing::debug!("Token '{}' not found in vault: {}", token, e);
                    }
                }
            }
        }
    }

    let body_str = String::from_utf8_lossy(&new_body);
    if wisp_pattern.is_match(&body_str) {
        let mut replaced = body_str.to_string();
        for token_match in wisp_pattern.find_iter(body_str.as_ref()) {
            let token = token_match.as_str();
            match vault.lookup_by_wisp_token(token) {
                Ok((cred, real_value)) => {
                    if !check_host_restriction(&cred.hosts, &target_host) {
                        let reason = format!(
                            "host '{}' not allowed for credential '{}'",
                            target_host, cred.name
                        );
                        audit::log_event(
                            vault.db(),
                            "CredentialDenied",
                            Some(&cred.name),
                            Some(token),
                            Some(&target_host),
                            Some(parts.uri.path()),
                            Some(parts.method.as_str()),
                            None,
                            true,
                            Some(&reason),
                        );
                        return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                    }
                    replaced = replaced.replace(token, &real_value);
                    used_credentials.push((cred.name.clone(), token.to_string()));
                }
                Err(e) => {
                    tracing::debug!("Body token '{}' not found in vault: {}", token, e);
                }
            }
        }
        new_body = replaced.into_bytes();
    }

    let target_uri = build_target_uri(&parts.uri);
    let mut forward_req = Request::builder()
        .method(parts.method.clone())
        .uri(&target_uri);

    for (name, value) in new_headers.iter() {
        if name != "host" {
            forward_req = forward_req.header(name, value);
        }
    }

    let forward_req = match forward_req.body(Full::new(Bytes::from(new_body))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to build forward request: {}", e);
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build request",
            ));
        }
    };

    let client = Client::builder(TokioExecutor::new()).build_http();

    match client.request(forward_req).await {
        Ok(resp) => {
            let response_status = resp.status().as_u16();
            let (resp_parts, resp_body) = resp.into_parts();

            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };

            for (cred_name, token) in &used_credentials {
                audit::log_event(
                    vault.db(),
                    "CredentialUsed",
                    Some(cred_name),
                    Some(token),
                    Some(&target_host),
                    Some(parts.uri.path()),
                    Some(parts.method.as_str()),
                    Some(response_status),
                    false,
                    None,
                );
            }

            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                response = response.header(name, value);
            }

            Ok(response.body(Full::new(resp_bytes)).unwrap())
        }
        Err(e) => {
            for (cred_name, token) in &used_credentials {
                audit::log_event(
                    vault.db(),
                    "CredentialUsed",
                    Some(cred_name),
                    Some(token),
                    Some(&target_host),
                    Some(parts.uri.path()),
                    Some(parts.method.as_str()),
                    None,
                    false,
                    Some(&e.to_string()),
                );
            }

            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream error: {}", e),
            ))
        }
    }
}

fn inject_credential(
    credential_type: &CredentialType,
    real_value: &str,
    original_header_value: &str,
    token: &str,
) -> String {
    match credential_type {
        CredentialType::BearerToken
        | CredentialType::ApiKey
        | CredentialType::CustomHeader { .. }
        | CredentialType::QueryParam { .. } => original_header_value.replace(token, real_value),
        CredentialType::BasicAuth => {
            let encoded = BASE64.encode(real_value.as_bytes());
            original_header_value.replace(token, &format!("Basic {}", encoded))
        }
    }
}

fn check_host_restriction(allowed_hosts: &[String], target_host: &str) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    for pattern in allowed_hosts {
        if glob_match::glob_match(pattern, target_host) {
            return true;
        }
    }
    false
}

fn extract_target_host(uri: &Uri, headers: &hyper::HeaderMap) -> String {
    if let Some(host) = uri.host() {
        return host.to_string();
    }
    if let Some(host_header) = headers.get("host")
        && let Ok(host_str) = host_header.to_str()
    {
        return host_str.split(':').next().unwrap_or(host_str).to_string();
    }
    "unknown".to_string()
}

fn build_target_uri(uri: &Uri) -> String {
    if uri.scheme().is_some() {
        return uri.to_string();
    }
    format!("http://{}", uri)
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

async fn handle_management_api(
    method: &hyper::Method,
    uri: &Uri,
    _headers: &hyper::HeaderMap,
) -> Response<Full<Bytes>> {
    let path = uri.path();

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
            let count = vault.credential_count().unwrap_or(0);
            let created = vault
                .vault_created_at()
                .unwrap_or_else(|_| "unknown".to_string());
            let pid_running = Vault::vault_dir().join("proxy.pid").exists();
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "vault_path": Vault::vault_dir().to_string_lossy(),
                    "created_at": created,
                    "credential_count": count,
                    "session_active": true,
                    "proxy_running": pid_running
                }),
            )
        }
        ("GET", "/api/credentials") => match vault.list_credentials() {
            Ok(creds) => {
                let list: Vec<serde_json::Value> = creds.iter().map(credential_to_json).collect();
                json_response(StatusCode::OK, &serde_json::json!({"credentials": list}))
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": e.to_string()}),
            ),
        },
        ("GET", path) if path.starts_with("/api/credentials/") => {
            let name = &path["/api/credentials/".len()..];
            match vault.get_credential(name) {
                Ok(cred) => json_response(StatusCode::OK, &credential_to_json(&cred)),
                Err(_) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": "credential not found"}),
                ),
            }
        }
        ("GET", "/api/partitions") => match vault.list_partitions() {
            Ok(partitions) => {
                let list: Vec<serde_json::Value> = partitions
                    .iter()
                    .map(|p| {
                        let count = vault.partition_credential_count(&p.id).unwrap_or(0);
                        serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
                            "credential_count": count,
                            "created_at": p.created_at.to_rfc3339(),
                            "updated_at": p.updated_at.to_rfc3339(),
                        })
                    })
                    .collect();
                json_response(StatusCode::OK, &serde_json::json!({"partitions": list}))
            }
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": e.to_string()}),
            ),
        },
        ("GET", path) if path.starts_with("/api/partitions/") && path.ends_with("/credentials") => {
            let segment = &path["/api/partitions/".len()..path.len() - "/credentials".len()];
            match vault.list_credentials_in_partition(segment) {
                Ok(creds) => {
                    let list: Vec<serde_json::Value> =
                        creds.iter().map(credential_to_json).collect();
                    json_response(StatusCode::OK, &serde_json::json!({"credentials": list}))
                }
                Err(e) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": e.to_string()}),
                ),
            }
        }
        ("GET", path) if path.starts_with("/api/partitions/") => {
            let name = &path["/api/partitions/".len()..];
            match vault.get_partition(name) {
                Ok(p) => {
                    let count = vault.partition_credential_count(&p.id).unwrap_or(0);
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "description": p.description,
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
            match vault.delete_partition(name) {
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
            match vault.remove_credential(name) {
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
                    );
                    json_response(StatusCode::OK, &serde_json::json!({"deleted": name}))
                }
                Err(e) => json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": e.to_string()}),
                ),
            }
        }
        ("GET", "/api/logs") => {
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

            let entries = audit::query_log(vault.db(), last, credential, since);
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
                    })
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::json!({"entries": list}))
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "not found"}),
        ),
    }
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

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
        .header(
            "access-control-allow-headers",
            "content-type, authorization",
        )
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_bearer_replaces_token() {
        let result = inject_credential(
            &CredentialType::BearerToken,
            "real-secret",
            "Bearer wk_test_abc123",
            "wk_test_abc123",
        );
        assert_eq!(result, "Bearer real-secret");
    }

    #[test]
    fn inject_api_key_replaces_token() {
        let result = inject_credential(
            &CredentialType::ApiKey,
            "real-key",
            "wk_api_xyz",
            "wk_api_xyz",
        );
        assert_eq!(result, "real-key");
    }

    #[test]
    fn inject_basic_auth_base64_encodes() {
        let result = inject_credential(
            &CredentialType::BasicAuth,
            "user:pass",
            "wk_basic_abc",
            "wk_basic_abc",
        );
        let expected = format!("Basic {}", BASE64.encode("user:pass".as_bytes()));
        assert_eq!(result, expected);
    }

    #[test]
    fn inject_custom_header_replaces() {
        let cred_type = CredentialType::CustomHeader {
            header_name: "X-Custom".to_string(),
        };
        let result = inject_credential(&cred_type, "secret", "wk_custom_abc", "wk_custom_abc");
        assert_eq!(result, "secret");
    }

    #[test]
    fn host_restriction_empty_allows_all() {
        assert!(check_host_restriction(&[], "anything.com"));
    }

    #[test]
    fn host_restriction_exact_match() {
        let hosts = vec!["api.example.com".to_string()];
        assert!(check_host_restriction(&hosts, "api.example.com"));
        assert!(!check_host_restriction(&hosts, "evil.com"));
    }

    #[test]
    fn host_restriction_glob_match() {
        let hosts = vec!["*.example.com".to_string()];
        assert!(check_host_restriction(&hosts, "api.example.com"));
        assert!(!check_host_restriction(&hosts, "example.com"));
    }

    #[test]
    fn build_target_uri_with_scheme() {
        let uri: Uri = "http://example.com/path".parse().unwrap();
        assert_eq!(build_target_uri(&uri), "http://example.com/path");
    }

    #[test]
    fn build_target_uri_without_scheme() {
        let uri: Uri = "/path".parse().unwrap();
        assert_eq!(build_target_uri(&uri), "http:///path");
    }

    #[test]
    fn error_response_has_json_body() {
        let resp = error_response(StatusCode::FORBIDDEN, "denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/json");
    }
}
