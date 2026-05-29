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
use http_body_util::{BodyExt, Full, Limited};
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
type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;
type ProxyActionResult<T> = Result<T, Box<Response<Full<Bytes>>>>;

const MAX_PROXY_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone)]
struct ProxyRuntime {
    wisp_pattern: Arc<Regex>,
    project_scope: Arc<Option<String>>,
    http_client: Arc<HttpClient>,
    https_client: Arc<HttpsClient>,
    policy_engine: Arc<PolicyEngine>,
    management_token: Arc<String>,
}

/// Starts the HTTP proxy on the given port. Pass `0` for an OS-assigned random port.
/// Returns the actual port the proxy bound to (useful when `port == 0`).
/// Writes `proxy.json` to the vault directory for agent/tool discovery.
pub async fn start_proxy(
    port: u16,
    all_projects: bool,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    let actual_port = actual_addr.port();

    tracing::info!("WispKey proxy listening on http://{}", actual_addr);

    let vault_dir = crate::core::Vault::vault_dir();
    crate::secure_files::ensure_private_directory(&vault_dir)?;
    let pid_path = vault_dir.join("proxy.pid");
    let info_path = vault_dir.join("proxy.json");
    let management_token = Arc::new(crate::random::alphanumeric(48, false)?);

    std::fs::write(&pid_path, std::process::id().to_string())?;

    let proxy_info = serde_json::json!({
        "pid": std::process::id(),
        "port": actual_port,
        "address": format!("http://{}", actual_addr),
        "management_token": management_token.as_ref(),
    });
    crate::secure_files::write_private(
        &info_path,
        serde_json::to_string_pretty(&proxy_info)?.as_bytes(),
    )?;

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
        tracing::info!(
            "{} policies loaded from {}",
            policy_count,
            crate::policy::policies_path().display()
        );
    }

    let shared_http: Arc<HttpClient> = Arc::new(Client::builder(TokioExecutor::new()).build_http());

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native TLS roots")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let shared_https: Arc<HttpsClient> =
        Arc::new(Client::builder(TokioExecutor::new()).build(https_connector));
    let runtime = ProxyRuntime {
        wisp_pattern,
        project_scope,
        http_client: shared_http,
        https_client: shared_https,
        policy_engine,
        management_token,
    };

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let runtime = runtime.clone();

        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let runtime = runtime.clone();
                handle_request(req, remote_addr, runtime)
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::error!("Connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    _remote_addr: SocketAddr,
    runtime: ProxyRuntime,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    if uri.path().starts_with("/api/") {
        if method == Method::OPTIONS {
            return Ok(cors_preflight());
        }
        if !management_request_authorized(&headers, runtime.management_token.as_ref()) {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({"error": "missing or invalid management token"}),
            ));
        }
        return Ok(handle_management_api(&method, &uri, &headers).await);
    }

    if method == Method::CONNECT {
        return handle_connect(req).await;
    }

    if let Some(target_url) = headers.get("x-target-url").and_then(|v| v.to_str().ok()) {
        return Ok(handle_reverse_proxy(
            req,
            target_url,
            runtime.wisp_pattern,
            runtime.project_scope,
            runtime.policy_engine,
            runtime.https_client,
        )
        .await);
    }

    let target_host = extract_target_host(&uri, &headers);

    let vault = Vault::open_with_session().ok();

    let (parts, body) = req.into_parts();
    let body_bytes = match collect_limited_body(body).await {
        Ok(bytes) => bytes,
        Err(response) => return Ok(*response),
    };

    let mut new_headers = parts.headers.clone();
    let mut new_body = body_bytes.to_vec();
    let mut used_credentials: Vec<(String, String)> = Vec::new();
    let context = TokenRequestContext {
        target_host: &target_host,
        target_path: parts.uri.path(),
        http_method: parts.method.as_str(),
        project_scope: runtime.project_scope.as_ref(),
        policy_engine: runtime.policy_engine.as_ref(),
    };

    for (header_name, header_value) in parts.headers.iter() {
        if let Ok(value_str) = header_value.to_str()
            && runtime.wisp_pattern.is_match(value_str)
        {
            let injected = match inject_tokens_in_value(
                value_str,
                vault.as_ref(),
                &runtime.wisp_pattern,
                &context,
                &mut used_credentials,
            ) {
                Ok(value) => value,
                Err(response) => return Ok(*response),
            };
            if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                new_headers.insert(header_name.clone(), new_value);
            }
        }
    }

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_text_body = content_type.is_empty()
        || content_type.contains("json")
        || content_type.contains("text")
        || content_type.contains("form-urlencoded")
        || content_type.contains("xml");

    if is_text_body
        && let Ok(body_str) = std::str::from_utf8(&new_body)
        && runtime.wisp_pattern.is_match(body_str)
    {
        let replaced = match inject_tokens_in_value(
            body_str,
            vault.as_ref(),
            &runtime.wisp_pattern,
            &context,
            &mut used_credentials,
        ) {
            Ok(value) => value,
            Err(response) => return Ok(*response),
        };
        new_body = replaced.into_bytes();
    }
    set_content_length(&mut new_headers, new_body.len());

    let mut target_uri = build_target_uri(&parts.uri, &headers);
    target_uri = match replace_tokens_in_uri(
        &target_uri,
        vault.as_ref(),
        &runtime.wisp_pattern,
        &context,
        &mut used_credentials,
    ) {
        Ok(uri) => uri,
        Err(response) => return Ok(*response),
    };
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

    let response = if target_uri.starts_with("https://") {
        runtime.https_client.request(forward_req).await
    } else {
        runtime.http_client.request(forward_req).await
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
                if let Some(vault) = &vault {
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
                        None,
                    );
                }
            }

            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                response = response.header(name, value);
            }

            Ok(response
                .body(Full::new(resp_bytes))
                .expect("response builder with valid parts"))
        }
        Err(e) => {
            for (cred_name, token) in &used_credentials {
                if let Some(vault) = &vault {
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
                        None,
                    );
                }
            }

            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream error: {}", e),
            ))
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
    policy_engine: Arc<PolicyEngine>,
    https_client: Arc<HttpsClient>,
) -> Response<Full<Bytes>> {
    let target_uri: Uri = match target_url.parse() {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid X-Target-Url"),
    };

    let target_host = target_uri.host().unwrap_or("unknown").to_string();

    let vault = Vault::open_with_session().ok();

    let (parts, body) = req.into_parts();
    let body_bytes = match collect_limited_body(body).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };

    let mut new_headers = parts.headers.clone();
    new_headers.remove("x-target-url");
    let mut new_body = body_bytes.to_vec();
    let mut used_credentials: Vec<(String, String)> = Vec::new();
    let context = TokenRequestContext {
        target_host: &target_host,
        target_path: target_uri.path(),
        http_method: parts.method.as_str(),
        project_scope: project_scope.as_ref(),
        policy_engine: policy_engine.as_ref(),
    };

    for (header_name, header_value) in parts.headers.iter() {
        if header_name == "x-target-url" || header_name == "host" {
            continue;
        }
        if let Ok(value_str) = header_value.to_str()
            && wisp_pattern.is_match(value_str)
        {
            let injected = match inject_tokens_in_value(
                value_str,
                vault.as_ref(),
                &wisp_pattern,
                &context,
                &mut used_credentials,
            ) {
                Ok(value) => value,
                Err(response) => return *response,
            };
            if let Ok(new_value) = hyper::header::HeaderValue::from_str(&injected) {
                new_headers.insert(header_name.clone(), new_value);
            }
        }
    }

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_text_body = content_type.is_empty()
        || content_type.contains("json")
        || content_type.contains("text")
        || content_type.contains("form-urlencoded")
        || content_type.contains("xml");

    if is_text_body
        && let Ok(body_str) = std::str::from_utf8(&new_body)
        && wisp_pattern.is_match(body_str)
    {
        let replaced = match inject_tokens_in_value(
            body_str,
            vault.as_ref(),
            &wisp_pattern,
            &context,
            &mut used_credentials,
        ) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        new_body = replaced.into_bytes();
    }
    set_content_length(&mut new_headers, new_body.len());

    let mut forward_req = Request::builder()
        .method(parts.method.clone())
        .uri(target_url);
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
                if let Some(vault) = &vault {
                    audit::log_event(
                        vault.db(),
                        "CredentialUsed",
                        Some(cred_name),
                        Some(token),
                        Some(&target_host),
                        Some(target_uri.path()),
                        Some(parts.method.as_str()),
                        Some(response_status),
                        false,
                        None,
                        None,
                    );
                }
            }

            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in resp_parts.headers.iter() {
                response = response.header(name, value);
            }
            response
                .body(Full::new(resp_bytes))
                .expect("response builder with valid parts")
        }
        Err(e) => {
            for (cred_name, token) in &used_credentials {
                if let Some(vault) = &vault {
                    audit::log_event(
                        vault.db(),
                        "CredentialUsed",
                        Some(cred_name),
                        Some(token),
                        Some(&target_host),
                        Some(target_uri.path()),
                        Some(parts.method.as_str()),
                        None,
                        false,
                        Some(&e.to_string()),
                        None,
                    );
                }
            }
            error_response(
                StatusCode::BAD_GATEWAY,
                &format!("HTTPS upstream error: {}", e),
            )
        }
    }
}

/// Handles CONNECT tunneling for HTTPS forward proxy. Establishes a TCP connection
/// to the upstream host and bidirectionally copies bytes between client and upstream.
/// This is a blind tunnel -- wisp token replacement is not possible inside the encrypted
/// stream. For wisp token support over HTTPS, use the reverse proxy mode (X-Target-Url)
/// or configure the agent to send requests as plain HTTP to the proxy which forwards via HTTPS.
async fn handle_connect(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| {
            req.uri()
                .host()
                .map(|h| {
                    let port = req.uri().port_u16().unwrap_or(443);
                    format!("{h}:{port}")
                })
                .unwrap_or_default()
        });

    if authority.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "CONNECT: missing target authority",
        ));
    }

    let host_port = if authority.contains(':') {
        authority.clone()
    } else {
        format!("{authority}:443")
    };

    tracing::debug!("CONNECT tunnel to {}", host_port);

    tokio::task::spawn(async move {
        match upgrade::on(req).await {
            Ok(upgraded) => match tokio::net::TcpStream::connect(&host_port).await {
                Ok(upstream) => {
                    let (mut client_read, mut client_write) =
                        tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
                    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

                    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

                    let _ = tokio::try_join!(client_to_upstream, upstream_to_client);
                }
                Err(e) => {
                    tracing::error!("CONNECT: failed to reach {}: {}", host_port, e);
                }
            },
            Err(e) => {
                tracing::error!("CONNECT: upgrade failed: {}", e);
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .expect("static response"))
}

fn replace_tokens_in_uri(
    uri: &str,
    vault: Option<&Vault>,
    wisp_pattern: &Regex,
    context: &TokenRequestContext<'_>,
    used_credentials: &mut Vec<(String, String)>,
) -> ProxyActionResult<String> {
    if !wisp_pattern.is_match(uri) {
        return Ok(uri.to_string());
    }
    inject_tokens_in_value(uri, vault, wisp_pattern, context, used_credentials)
}

/// Checks if a credential's project matches the active project scope.
/// Returns `Some(reason)` with the denial reason if the credential is out of scope,
/// or `None` if access is allowed.
fn check_project_scope(
    vault: &Vault,
    cred: &crate::core::Credential,
    project_scope: &Option<String>,
) -> Option<String> {
    let active_project = project_scope.as_ref()?;
    let partition_id = cred.partition_id.as_ref()?;
    let cred_project = vault
        .get_partition_project_name(partition_id)
        .ok()
        .flatten()?;
    if cred_project != *active_project {
        Some(format!(
            "credential '{}' belongs to project '{}', not active project '{}'",
            cred.name, cred_project, active_project
        ))
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
        || allowed_hosts
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, target_host))
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
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{}{}", host, uri)
}

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

fn cors_preflight() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", "http://localhost")
        .header(
            "access-control-allow-methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .header(
            "access-control-allow-headers",
            "content-type, authorization",
        )
        .header("access-control-max-age", "86400")
        .body(Full::new(Bytes::new()))
        .expect("empty cors response must build")
}

fn management_request_authorized(headers: &hyper::HeaderMap, expected_token: &str) -> bool {
    let header_token = headers
        .get("x-wispkey-management-token")
        .and_then(|value| value.to_str().ok());
    if header_token == Some(expected_token) {
        return true;
    }

    headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        == Some(expected_token)
}

struct EnvCredentialResolution {
    name: String,
    env_key: String,
    value: String,
}

struct TokenRequestContext<'a> {
    target_host: &'a str,
    target_path: &'a str,
    http_method: &'a str,
    project_scope: &'a Option<String>,
    policy_engine: &'a PolicyEngine,
}

struct ResolvedToken {
    credential_name: String,
    token: String,
    credential_type: CredentialType,
    value: String,
}

fn inject_tokens_in_value(
    value: &str,
    vault: Option<&Vault>,
    wisp_pattern: &Regex,
    context: &TokenRequestContext<'_>,
    used_credentials: &mut Vec<(String, String)>,
) -> ProxyActionResult<String> {
    if !wisp_pattern.is_match(value) {
        return Ok(value.to_string());
    }

    let tokens: Vec<String> = wisp_pattern
        .find_iter(value)
        .map(|token_match| token_match.as_str().to_string())
        .collect();
    let mut replaced = value.to_string();

    for token in tokens {
        let resolved = resolve_token_for_request(vault, &token, context)?;
        replaced = inject_credential(
            &resolved.credential_type,
            &resolved.value,
            &replaced,
            &resolved.token,
        );
        used_credentials.push((resolved.credential_name, resolved.token));
    }

    Ok(replaced)
}

fn resolve_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> ProxyActionResult<ResolvedToken> {
    let Some(vault) = vault else {
        return resolve_env_token_for_request(None, token, context);
    };

    match vault.lookup_by_wisp_token(token) {
        Ok((cred, real_value)) => {
            if let Some(reason) = check_project_scope(vault, &cred, context.project_scope) {
                audit_denial(
                    vault,
                    "CredentialDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &reason,
                );
                return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
            }

            if !check_host_restriction(&cred.hosts, context.target_host) {
                let reason = format!(
                    "host '{}' not allowed for credential '{}'",
                    context.target_host, cred.name
                );
                audit_denial(
                    vault,
                    "CredentialDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &reason,
                );
                return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
            }

            if let Some(denial) = context.policy_engine.evaluate(
                &cred.name,
                None,
                context.target_host,
                context.target_path,
                context.http_method,
            ) {
                audit_denial(
                    vault,
                    "PolicyDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &denial.reason,
                );
                return Err(Box::new(error_response(
                    StatusCode::FORBIDDEN,
                    &denial.reason,
                )));
            }

            Ok(ResolvedToken {
                credential_name: cred.name,
                token: token.to_string(),
                credential_type: cred.credential_type,
                value: real_value,
            })
        }
        Err(_) => {
            if let Ok(resolved) = resolve_env_token_for_request(Some(vault), token, context) {
                return Ok(resolved);
            }

            let reason = format!("wisp token '{}' was not found in the active vault", token);
            audit_denial(vault, "CredentialDenied", None, token, context, &reason);
            Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)))
        }
    }
}

fn resolve_env_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> ProxyActionResult<ResolvedToken> {
    let Some(env_credential) = try_env_sideload(token) else {
        let reason = if vault.is_some() {
            format!("wisp token '{}' was not found in the active vault", token)
        } else {
            format!(
                "wisp token '{}' requires an unlocked vault or matching WISPKEY_SIDELOAD_* env var",
                token
            )
        };
        return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
    };

    if let Some(denial) = context.policy_engine.evaluate(
        &env_credential.name,
        None,
        context.target_host,
        context.target_path,
        context.http_method,
    ) {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            &denial.reason,
        )));
    }

    if let Some(vault) = vault {
        audit::log_event(
            vault.db(),
            "SideloadUsed",
            Some(&env_credential.env_key),
            Some(token),
            Some(context.target_host),
            Some(context.target_path),
            Some(context.http_method),
            None,
            false,
            Some("used env sideload credential"),
            context.project_scope.as_deref(),
        );
    }

    Ok(ResolvedToken {
        credential_name: env_credential.env_key,
        token: token.to_string(),
        credential_type: CredentialType::BearerToken,
        value: env_credential.value,
    })
}

fn audit_denial(
    vault: &Vault,
    event_type: &str,
    credential_name: Option<&str>,
    token: &str,
    context: &TokenRequestContext<'_>,
    reason: &str,
) {
    audit::log_event(
        vault.db(),
        event_type,
        credential_name,
        Some(token),
        Some(context.target_host),
        Some(context.target_path),
        Some(context.http_method),
        None,
        true,
        Some(reason),
        context.project_scope.as_deref(),
    );
}

/// Attempts to find a sideloaded credential value from environment variables.
/// Supports deterministic MCP sideload tokens (`wk_env_<slug>`).
fn try_env_sideload(token: &str) -> Option<EnvCredentialResolution> {
    crate::env_sideload::value_for_token(token).map(|(credential, value)| EnvCredentialResolution {
        name: credential.name,
        env_key: credential.env_key,
        value,
    })
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("error response must build")
}

async fn collect_limited_body(body: Incoming) -> ProxyActionResult<Bytes> {
    match Limited::new(body, MAX_PROXY_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err(Box::new(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds WispKey proxy size limit",
        ))),
    }
}

fn set_content_length(headers: &mut hyper::HeaderMap, body_len: usize) {
    headers.remove(hyper::header::CONTENT_LENGTH);
    if body_len == 0 {
        return;
    }
    let value = hyper::header::HeaderValue::from_str(&body_len.to_string())
        .expect("usize content length must be a valid header value");
    headers.insert(hyper::header::CONTENT_LENGTH, value);
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
            match vault.get_credential(name) {
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
        .header("access-control-allow-origin", "http://localhost")
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
        headers.insert(
            "host",
            hyper::header::HeaderValue::from_static("example.com"),
        );
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
