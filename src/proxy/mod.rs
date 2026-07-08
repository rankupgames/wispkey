/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: HTTP/HTTPS forward proxy -- listener, request routing, and forwarding.
 * Created: 2026-04-07
 * Last Modified: 2026-04-13
 */

use std::net::SocketAddr;
use std::sync::Arc;

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
use tokio::sync::broadcast;

use crate::audit;
use crate::core::{self, Vault};
use crate::policy::PolicyEngine;

pub mod lifecycle;
mod management;
mod target;
#[cfg(test)]
mod tests;
mod tokens;

use lifecycle::{ProxyMetadata, ProxyState, StartDecision};
use management::{handle_management_api, json_response};
use target::{authority_points_to_proxy, target_points_to_proxy};
use tokens::{TokenRequestContext, inject_tokens_in_value, replace_tokens_in_uri};

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>;
type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;
type ProxyActionResult<T> = Result<T, Box<Response<Full<Bytes>>>>;

const MAX_PROXY_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum StartProxyOutcome {
    AlreadyRunning(ProxyMetadata),
    Stopped { port: u16 },
}

#[derive(Clone)]
struct ProxyRuntime {
    wisp_pattern: Arc<Regex>,
    project_scope: Arc<Option<String>>,
    http_client: Arc<HttpClient>,
    https_client: Arc<HttpsClient>,
    policy_engine: Arc<PolicyEngine>,
    management_token: Arc<String>,
    shutdown_tx: broadcast::Sender<String>,
    proxy_port: u16,
    metadata: Arc<ProxyMetadata>,
}

/// Starts the HTTP proxy on the given port. Pass `0` for an OS-assigned random port.
/// Returns the actual port the proxy bound to (useful when `port == 0`).
/// Writes `proxy.json` to the vault directory for agent/tool discovery.
pub async fn start_proxy(
    port: u16,
    all_projects: bool,
) -> Result<StartProxyOutcome, Box<dyn std::error::Error + Send + Sync>> {
    match lifecycle::prepare_for_start(port).await {
        Ok(StartDecision::Start) => {}
        Ok(StartDecision::AlreadyRunning(metadata)) => {
            return Ok(StartProxyOutcome::AlreadyRunning(metadata));
        }
        Err(e) => return Err(e.into()),
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        format!(
            "failed to bind {addr}: {e}. If another process owns this port, WispKey will not terminate it without owned proxy metadata."
        )
    })?;
    let actual_addr = listener.local_addr()?;
    let actual_port = actual_addr.port();

    tracing::info!("WispKey proxy listening on http://{}", actual_addr);

    let wisp_pattern = Arc::new(Regex::new(r"wk_[a-z0-9_]+").expect("static regex must compile"));
    let project_scope: Arc<Option<String>> = if all_projects {
        Arc::new(None)
    } else {
        Arc::new(Some(core::resolve_active_project()))
    };
    let management_token = Arc::new(crate::random::alphanumeric(48, false)?);
    let metadata = Arc::new(ProxyMetadata::new(
        actual_port,
        format!("http://{}", actual_addr),
        project_scope.as_ref().clone(),
        management_token.as_ref().clone(),
    ));
    lifecycle::write_metadata(&metadata)?;

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
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<String>(4);
    let runtime = ProxyRuntime {
        wisp_pattern,
        project_scope,
        http_client: shared_http,
        https_client: shared_https,
        policy_engine,
        management_token,
        shutdown_tx,
        proxy_port: actual_port,
        metadata: metadata.clone(),
    };

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = tokio::signal::ctrl_c() => {
                lifecycle::cleanup_metadata(&metadata.instance_id, "ctrl-c signal")?;
                return Ok(StartProxyOutcome::Stopped { port: actual_port });
            }
            reason = shutdown_rx.recv() => {
                let reason = reason.unwrap_or_else(|_| "shutdown requested".to_string());
                lifecycle::cleanup_metadata(&metadata.instance_id, &reason)?;
                return Ok(StartProxyOutcome::Stopped { port: actual_port });
            }
        };

        let (stream, remote_addr) = accepted;
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
        if method == Method::POST && uri.path() == "/api/shutdown" {
            lifecycle::record_event(
                "shutdown_requested",
                "management API requested shutdown",
                Some(&runtime.metadata),
                ProxyState::Running,
            );
            let _ = runtime
                .shutdown_tx
                .send("management API shutdown".to_string());
            return Ok(json_response(
                StatusCode::OK,
                &serde_json::json!({"stopping": true}),
            ));
        }
        return Ok(handle_management_api(&method, &uri, &headers).await);
    }

    if method == Method::CONNECT {
        return handle_connect(req, runtime.proxy_port, &runtime).await;
    }

    if let Some(target_url) = headers.get("x-target-url").and_then(|v| v.to_str().ok()) {
        if target_points_to_proxy(target_url, runtime.proxy_port) {
            return Ok(reject_self_target(
                "reverse proxy target",
                target_url,
                &runtime,
            ));
        }
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
    if target_points_to_proxy(&target_uri, runtime.proxy_port) {
        return Ok(reject_self_target(
            "forward proxy target",
            &target_uri,
            &runtime,
        ));
    }
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

    let target_url = match replace_tokens_in_uri(
        target_url,
        vault.as_ref(),
        &wisp_pattern,
        &context,
        &mut used_credentials,
    ) {
        Ok(uri) => uri,
        Err(response) => return *response,
    };

    let mut forward_req = Request::builder()
        .method(parts.method.clone())
        .uri(&target_url);
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
async fn handle_connect(
    req: Request<Incoming>,
    proxy_port: u16,
    runtime: &ProxyRuntime,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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

    if authority_points_to_proxy(&authority, Some(443), proxy_port) {
        return Ok(reject_self_target("CONNECT target", &authority, runtime));
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
            "content-type, authorization, x-wispkey-management-token",
        )
        .header("access-control-max-age", "86400")
        .body(Full::new(Bytes::new()))
        .expect("empty cors response must build")
}

fn management_request_authorized(headers: &hyper::HeaderMap, expected_token: &str) -> bool {
    let header_token = headers
        .get(lifecycle::MANAGEMENT_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok());
    if token_matches(header_token, expected_token) {
        return true;
    }

    let bearer_token = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    token_matches(bearer_token, expected_token)
}

#[allow(deprecated)]
fn token_matches(actual: Option<&str>, expected: &str) -> bool {
    actual
        .map(|token| {
            ring::constant_time::verify_slices_are_equal(token.as_bytes(), expected.as_bytes())
                .is_ok()
        })
        .unwrap_or(false)
}

fn reject_self_target(kind: &str, target: &str, runtime: &ProxyRuntime) -> Response<Full<Bytes>> {
    let reason = format!("blocked self-targeted proxy request ({kind}: {target})");
    lifecycle::record_event(
        "self_target_blocked",
        &reason,
        Some(&runtime.metadata),
        ProxyState::Running,
    );
    error_response(
        StatusCode::from_u16(508).expect("508 is a valid status"),
        &reason,
    )
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
    headers.remove(hyper::header::TRANSFER_ENCODING);
    if body_len == 0 {
        return;
    }
    let value = hyper::header::HeaderValue::from_str(&body_len.to_string())
        .expect("usize content length must be a valid header value");
    headers.insert(hyper::header::CONTENT_LENGTH, value);
}
