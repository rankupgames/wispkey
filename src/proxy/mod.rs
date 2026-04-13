/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: HTTP/HTTPS forward proxy -- intercepts requests containing wk_* wisp tokens,
 *              swaps them for real credentials, enforces host restrictions, logs audit events.
 *              Also serves the management API at /api/ endpoints for the desktop app.
 *              Supports three modes for HTTPS: forward proxy (auto-detects https:// in target),
 *              reverse proxy (X-Target-Url header), and CONNECT tunneling (blind tunnel).
 *
 * Created: 2026-04-07
 * Last Modified: 2026-04-13
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
use hyper::{Method, Request, Response, StatusCode, Uri, upgrade};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use regex::Regex;
use tokio::net::TcpListener;

use crate::audit;
use crate::core::{self, CredentialType, Vault};
use crate::policy::PolicyEngine;

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>;
type HttpsClient = Client<hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>;

/// Starts the HTTP proxy on the given port. Pass `0` for an OS-assigned random port.
/// Returns the actual port the proxy bound to (useful when `port == 0`).
/// Writes `proxy.json` to the vault directory for agent/tool discovery.
pub async fn start_proxy(port: u16, all_projects: bool) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    let actual_port = actual_addr.port();

    tracing::info!("WispKey proxy listening on http://{}", actual_addr);

    let vault_dir = crate::core::Vault::vault_dir();
    let pid_path = vault_dir.join("proxy.pid");
    let info_path = vault_dir.join("proxy.json");

    std::fs::write(&pid_path, std::process::id().to_string())?;

    let proxy_info = serde_json::json!({
        "pid": std::process::id(),
        "port": actual_port,
        "address": format!("http://{}", actual_addr),
    });
    std::fs::write(&info_path, serde_json::to_string_pretty(&proxy_info)?)?;

    let pid_cleanup = pid_path.clone();
    let info_cleanup = info_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = std::fs::remove_file(&pid_cleanup);
        let _ = std::fs::remove_file(&info_cleanup);
        std::process::exit(0);
    });

    let wisp_pattern = Arc::new(Regex::new(r"wk_[a-z0-9_]+").expect("static regex must compile"));
    let project_scope: Arc<Option<String>> = if all_projects {
        Arc::new(None)
    } else {
        Arc::new(Some(core::resolve_active_project()))
    };

    let policy_engine = Arc::new(PolicyEngine::load());
    let policy_count = policy_engine.policies().len();
    if policy_count > 0 {
        tracing::info!("{} policies loaded from {}", policy_count, crate::policy::policies_path().display());
    }

    let shared_http: Arc<HttpClient> = Arc::new(Client::builder(TokioExecutor::new()).build_http());

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new().with_native_roots().expect("native TLS roots").https_or_http().enable_http1().enable_http2().build();
    let shared_https: Arc<HttpsClient> = Arc::new(Client::builder(TokioExecutor::new()).build(https_connector));

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let pattern = wisp_pattern.clone();
        let scope = project_scope.clone();
        let http_client = shared_http.clone();
        let https_client = shared_https.clone();
        let policies = policy_engine.clone();

        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let pattern = pattern.clone();
                let scope = scope.clone();
                let http_client = http_client.clone();
                let https_client = https_client.clone();
                let policies = policies.clone();
                handle_request(req, remote_addr, pattern, scope, http_client, https_client, policies)
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).with_upgrades().await {
                tracing::error!("Connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    _remote_addr: SocketAddr,
    wisp_pattern: Arc<Regex>,
    project_scope: Arc<Option<String>>,
    http_client: Arc<HttpClient>,
    https_client: Arc<HttpsClient>,
    policy_engine: Arc<PolicyEngine>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    if uri.path().starts_with("/api/") {
        if method == Method::OPTIONS {
            return Ok(cors_preflight());
        }
        return Ok(handle_management_api(&method, &uri, &headers).await);
    }

    if method == Method::CONNECT {
        return handle_connect(req).await;
    }

    if let Some(target_url) = headers.get("x-target-url").and_then(|v| v.to_str().ok()) {
        return Ok(handle_reverse_proxy(req, target_url, wisp_pattern, project_scope, https_client).await);
    }

    let target_host = extract_target_host(&uri, &headers);

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(_) => {
            return Ok(error_response(StatusCode::SERVICE_UNAVAILABLE, "Vault is locked. Run `wispkey unlock` first."));
        }
    };

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(error_response(StatusCode::BAD_REQUEST, "Failed to read request body"));
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
                        if let Some(reason) = check_project_scope(&vault, &cred, &project_scope) {
                            let active = project_scope.as_deref().unwrap_or("unknown");
                            audit::log_event(vault.db(), "CredentialDenied", Some(&cred.name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, true, Some(&reason), Some(active));
                            return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                        }
                        if !check_host_restriction(&cred.hosts, &target_host) {
                            let reason = format!("host '{}' not allowed for credential '{}'", target_host, cred.name);
                            audit::log_event(vault.db(), "CredentialDenied", Some(&cred.name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, true, Some(&reason), None);
                            return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                        }
                        if let Some(denial) = policy_engine.evaluate(&cred.name, None, &target_host, parts.uri.path(), parts.method.as_str()) {
                            audit::log_event(vault.db(), "PolicyDenied", Some(&cred.name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, true, Some(&denial.reason), None);
                            return Ok(error_response(StatusCode::FORBIDDEN, &denial.reason));
                        }

                        let injected = inject_credential(&cred.credential_type, &real_value, value_str, token);
                        if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                            new_headers.insert(header_name.clone(), new_value);
                        }
                        used_credentials.push((cred.name.clone(), token.to_string()));
                    }
                    Err(_) => {
                        if let Some(fallback) = try_env_fallback(token) {
                            let injected = inject_credential(&core::CredentialType::BearerToken, &fallback.value, value_str, token);
                            if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                                new_headers.insert(header_name.clone(), new_value);
                            }
                            used_credentials.push((fallback.env_key.clone(), token.to_string()));
                            audit::log_event(vault.db(), "FallbackUsed", Some(&fallback.env_key), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, false, Some("vault lookup failed, used env fallback"), None);
                            record_auto_fix_note(token, &fallback.env_key);
                        } else {
                            tracing::debug!("Token '{}' not found in vault or env fallback", token);
                        }
                    }
                }
            }
        }
    }

    let content_type = parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    let is_text_body = content_type.is_empty() || content_type.contains("json") || content_type.contains("text") || content_type.contains("form-urlencoded") || content_type.contains("xml");

    if is_text_body
        && let Ok(body_str) = std::str::from_utf8(&new_body)
        && wisp_pattern.is_match(body_str)
    {
        let mut replaced = body_str.to_string();
        for token_match in wisp_pattern.find_iter(body_str) {
            let token = token_match.as_str();
            match vault.lookup_by_wisp_token(token) {
                Ok((cred, real_value)) => {
                    if let Some(reason) = check_project_scope(&vault, &cred, &project_scope) {
                        let active = project_scope.as_deref().unwrap_or("unknown");
                        audit::log_event(vault.db(), "CredentialDenied", Some(&cred.name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, true, Some(&reason), Some(active));
                        return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                    }
                    if !check_host_restriction(&cred.hosts, &target_host) {
                        let reason = format!("host '{}' not allowed for credential '{}'", target_host, cred.name);
                        audit::log_event(vault.db(), "CredentialDenied", Some(&cred.name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, true, Some(&reason), None);
                        return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                    }
                    let injected = inject_credential(&cred.credential_type, &real_value, &replaced, token);
                    replaced = injected;
                    used_credentials.push((cred.name.clone(), token.to_string()));
                }
                Err(_) => {
                    if let Some(fallback) = try_env_fallback(token) {
                        replaced = replaced.replace(token, &fallback.value);
                        used_credentials.push((fallback.env_key.clone(), token.to_string()));
                        audit::log_event(vault.db(), "FallbackUsed", Some(&fallback.env_key), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, false, Some("vault lookup failed, used env fallback (body)"), None);
                        record_auto_fix_note(token, &fallback.env_key);
                    } else {
                        tracing::debug!("Body token '{}' not found in vault or env fallback", token);
                    }
                }
            }
        }
        new_body = replaced.into_bytes();
    }

    let mut target_uri = build_target_uri(&parts.uri, &headers);
    target_uri = replace_tokens_in_uri(&target_uri, &vault, &wisp_pattern, &project_scope, &target_host, &mut used_credentials);
    let mut forward_req = Request::builder().method(parts.method.clone()).uri(&target_uri);

    for (name, value) in new_headers.iter() {
        if name != "host" {
            forward_req = forward_req.header(name, value);
        }
    }

    let forward_req = match forward_req.body(Full::new(Bytes::from(new_body))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to build forward request: {}", e);
            return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build request"));
        }
    };

    let response = if target_uri.starts_with("https://") {
        https_client.request(forward_req).await
    } else {
        http_client.request(forward_req).await
    };

    match response {
        Ok(resp) => {
            let response_status = resp.status().as_u16();
            let (resp_parts, resp_body) = resp.into_parts();

            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };

            for (cred_name, token) in &used_credentials {
                audit::log_event(vault.db(), "CredentialUsed", Some(cred_name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), Some(response_status), false, None, None);
            }

            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                response = response.header(name, value);
            }

            Ok(response.body(Full::new(resp_bytes)).expect("response builder with valid parts"))
        }
        Err(e) => {
            for (cred_name, token) in &used_credentials {
                audit::log_event(vault.db(), "CredentialUsed", Some(cred_name), Some(token), Some(&target_host), Some(parts.uri.path()), Some(parts.method.as_str()), None, false, Some(&e.to_string()), None);
            }

            Ok(error_response(StatusCode::BAD_GATEWAY, &format!("Upstream error: {}", e)))
        }
    }
}

/// Reverse proxy mode for HTTPS targets. Agent sends to the proxy with `X-Target-Url` header
/// pointing to the real HTTPS endpoint. The proxy swaps wisp tokens and forwards over TLS.
async fn handle_reverse_proxy(
    req: Request<Incoming>,
    target_url: &str,
    wisp_pattern: Arc<Regex>,
    project_scope: Arc<Option<String>>,
    https_client: Arc<HttpsClient>,
) -> Response<Full<Bytes>> {
    let target_uri: Uri = match target_url.parse() {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid X-Target-Url"),
    };

    let target_host = target_uri.host().unwrap_or("unknown").to_string();

    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Vault is locked. Run `wispkey unlock` first."),
    };

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };

    let mut new_headers = parts.headers.clone();
    new_headers.remove("x-target-url");
    let mut new_body = body_bytes.to_vec();
    let mut used_credentials: Vec<(String, String)> = Vec::new();

    for (header_name, header_value) in parts.headers.iter() {
        if header_name == "x-target-url" || header_name == "host" {
            continue;
        }
        if let Ok(value_str) = header_value.to_str() {
            for token_match in wisp_pattern.find_iter(value_str) {
                let token = token_match.as_str();
                if let Ok((cred, real_value)) = vault.lookup_by_wisp_token(token) {
                    if check_project_scope(&vault, &cred, &project_scope).is_some() || !check_host_restriction(&cred.hosts, &target_host) {
                        continue;
                    }
                    let injected = inject_credential(&cred.credential_type, &real_value, value_str, token);
                    if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                        new_headers.insert(header_name.clone(), new_value);
                    }
                    used_credentials.push((cred.name.clone(), token.to_string()));
                }
            }
        }
    }

    let content_type = parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    let is_text_body = content_type.is_empty() || content_type.contains("json") || content_type.contains("text") || content_type.contains("form-urlencoded") || content_type.contains("xml");

    if is_text_body
        && let Ok(body_str) = std::str::from_utf8(&new_body)
        && wisp_pattern.is_match(body_str)
    {
        let mut replaced = body_str.to_string();
        for token_match in wisp_pattern.find_iter(body_str) {
            let token = token_match.as_str();
            if let Ok((cred, real_value)) = vault.lookup_by_wisp_token(token) {
                if check_project_scope(&vault, &cred, &project_scope).is_some() || !check_host_restriction(&cred.hosts, &target_host) {
                    continue;
                }
                let injected = inject_credential(&cred.credential_type, &real_value, &replaced, token);
                replaced = injected;
                used_credentials.push((cred.name.clone(), token.to_string()));
            }
        }
        new_body = replaced.into_bytes();
    }

    let mut forward_req = Request::builder().method(parts.method.clone()).uri(target_url);
    for (name, value) in new_headers.iter() {
        if name != "host" && name != "x-target-url" {
            forward_req = forward_req.header(name, value);
        }
    }

    let forward_req = match forward_req.body(Full::new(Bytes::from(new_body))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to build HTTPS forward request: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build request");
        }
    };

    match https_client.request(forward_req).await {
        Ok(resp) => {
            let response_status = resp.status().as_u16();
            let (resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };

            for (cred_name, token) in &used_credentials {
                audit::log_event(vault.db(), "CredentialUsed", Some(cred_name), Some(token), Some(&target_host), Some(target_uri.path()), Some(parts.method.as_str()), Some(response_status), false, None, None);
            }

            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                response = response.header(name, value);
            }
            response.body(Full::new(resp_bytes)).expect("response builder with valid parts")
        }
        Err(e) => {
            for (cred_name, token) in &used_credentials {
                audit::log_event(vault.db(), "CredentialUsed", Some(cred_name), Some(token), Some(&target_host), Some(target_uri.path()), Some(parts.method.as_str()), None, false, Some(&e.to_string()), None);
            }
            error_response(StatusCode::BAD_GATEWAY, &format!("HTTPS upstream error: {}", e))
        }
    }
}

/// Handles CONNECT tunneling for HTTPS forward proxy. Establishes a TCP connection
/// to the upstream host and bidirectionally copies bytes between client and upstream.
/// This is a blind tunnel -- wisp token replacement is not possible inside the encrypted
/// stream. For wisp token support over HTTPS, use the reverse proxy mode (X-Target-Url)
/// or configure the agent to send requests as plain HTTP to the proxy which forwards via HTTPS.
async fn handle_connect(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_else(|| {
        req.uri().host().map(|h| {
            let port = req.uri().port_u16().unwrap_or(443);
            format!("{h}:{port}")
        }).unwrap_or_default()
    });

    if authority.is_empty() {
        return Ok(error_response(StatusCode::BAD_REQUEST, "CONNECT: missing target authority"));
    }

    let host_port = if authority.contains(':') {
        authority.clone()
    } else {
        format!("{authority}:443")
    };

    tracing::debug!("CONNECT tunnel to {}", host_port);

    tokio::task::spawn(async move {
        match upgrade::on(req).await {
            Ok(upgraded) => {
                match tokio::net::TcpStream::connect(&host_port).await {
                    Ok(upstream) => {
                        let (mut client_read, mut client_write) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
                        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

                        let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                        let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

                        let _ = tokio::try_join!(client_to_upstream, upstream_to_client);
                    }
                    Err(e) => {
                        tracing::error!("CONNECT: failed to reach {}: {}", host_port, e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("CONNECT: upgrade failed: {}", e);
            }
        }
    });

    Ok(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).expect("static response"))
}

fn replace_tokens_in_uri(uri: &str, vault: &Vault, wisp_pattern: &Regex, project_scope: &Option<String>, target_host: &str, used_credentials: &mut Vec<(String, String)>) -> String {
    if !wisp_pattern.is_match(uri) {
        return uri.to_string();
    }
    let mut result = uri.to_string();
    for token_match in wisp_pattern.find_iter(uri) {
        let token = token_match.as_str();
        if let Ok((cred, real_value)) = vault.lookup_by_wisp_token(token) {
            if check_project_scope(vault, &cred, project_scope).is_some() || !check_host_restriction(&cred.hosts, target_host) {
                continue;
            }
            result = result.replace(token, &real_value);
            used_credentials.push((cred.name.clone(), token.to_string()));
        }
    }
    result
}

/// Checks if a credential's project matches the active project scope.
/// Returns `Some(reason)` with the denial reason if the credential is out of scope,
/// or `None` if access is allowed.
fn check_project_scope(vault: &Vault, cred: &crate::core::Credential, project_scope: &Option<String>) -> Option<String> {
    let active_project = project_scope.as_ref()?;
    let partition_id = cred.partition_id.as_ref()?;
    let cred_project = vault.get_partition_project_name(partition_id).ok().flatten()?;
    if cred_project != *active_project {
        Some(format!("credential '{}' belongs to project '{}', not active project '{}'", cred.name, cred_project, active_project))
    } else {
        None
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
    allowed_hosts.is_empty()
        || allowed_hosts.iter().any(|pattern| glob_match::glob_match(pattern, target_host))
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

fn build_target_uri(uri: &Uri, headers: &hyper::HeaderMap) -> String {
    if uri.scheme().is_some() {
        return uri.to_string();
    }
    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("localhost");
    format!("http://{}{}", host, uri)
}

fn cors_preflight() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("access-control-allow-headers", "content-type, authorization")
        .header("access-control-max-age", "86400")
        .body(Full::new(Bytes::new()))
        .expect("empty cors response must build")
}

struct EnvFallback {
    env_key: String,
    value: String,
}

/// Attempts to find a credential value from environment variables when the vault
/// lookup fails. Looks for `WISPKEY_FALLBACK_{TOKEN_SLUG}` where the slug is
/// extracted from the wisp token (e.g. `wk_openai_abc123` -> `WISPKEY_FALLBACK_OPENAI`).
fn try_env_fallback(token: &str) -> Option<EnvFallback> {
    let parts: Vec<&str> = token.splitn(3, '_').collect();
    if parts.len() < 2 {
        return None;
    }
    let slug = parts[1].to_uppercase();
    let env_key = format!("WISPKEY_FALLBACK_{slug}");
    std::env::var(&env_key).ok().map(|value| EnvFallback { env_key, value })
}

/// Appends a fallback event to `.wispkey/auto-fix-notes.json` for later investigation.
fn record_auto_fix_note(token: &str, env_key: &str) {
    let vault_dir = crate::core::Vault::vault_dir();
    let notes_path = vault_dir.join("auto-fix-notes.json");

    let note = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event": "credential_fallback",
        "wisp_token": token,
        "fallback_env": env_key,
        "action_needed": "Add this credential to the WispKey vault to stop relying on env fallback",
    });

    let mut notes: Vec<serde_json::Value> = if notes_path.exists() {
        std::fs::read_to_string(&notes_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    notes.push(note);

    if let Ok(data) = serde_json::to_string_pretty(&notes) {
        let _ = std::fs::write(&notes_path, data);
    }

    tracing::warn!("(Proxy - handleRequest) Wisp token {} not found in vault, fell back to env var {}. See .wispkey/auto-fix-notes.json", token, env_key);
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("error response must build")
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

            let proxy_info = Vault::vault_dir().join("proxy.json");
            let proxy_port: Option<u64> = std::fs::read_to_string(&proxy_info).ok().and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok()).and_then(|v| v.get("port").and_then(|p| p.as_u64()));

            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "vault_path": Vault::vault_dir().to_string_lossy(),
                    "created_at": created,
                    "credential_count": count,
                    "session_active": true,
                    "proxy_running": true,
                    "proxy_port": proxy_port,
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
                            "project_id": p.project_id,
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
        .expect("json response must build")
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
        let headers = hyper::HeaderMap::new();
        let uri: Uri = "http://example.com/path".parse().unwrap();
        assert_eq!(build_target_uri(&uri, &headers), "http://example.com/path");
    }

    #[test]
    fn build_target_uri_without_scheme() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", hyper::header::HeaderValue::from_static("example.com"));
        let uri: Uri = "/path".parse().unwrap();
        assert_eq!(build_target_uri(&uri, &headers), "http://example.com/path");
    }

    #[test]
    fn build_target_uri_without_scheme_no_host() {
        let headers = hyper::HeaderMap::new();
        let uri: Uri = "/path".parse().unwrap();
        assert_eq!(build_target_uri(&uri, &headers), "http://localhost/path");
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
