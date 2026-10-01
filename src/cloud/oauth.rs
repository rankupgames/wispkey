//! Public-client OAuth authorization code + S256 PKCE. No bearer crosses the browser callback.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::future::Future;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::{Zeroize, Zeroizing};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);
const CALLBACK_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CALLBACK_BYTES: usize = 8192;
const MAX_TOKEN_BYTES: usize = 16384;
const MAX_TOKEN_LIFETIME: i64 = 86400;
const SCOPE: &str = "wispkey:sync";

fn invalid(message: &str) -> CloudError {
    CloudError::ApiError(message.to_owned())
}

/// Non-secret context binding the stored bearer to its verified account and destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthSession {
    pub issuer: String,
    pub client_id: String,
    pub api_origin: String,
    pub resource: String,
    pub account_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub token_format: String,
    pub binding_sha256: String,
}

/// Logout distinguishes local deletion from confirmed provider revocation.
#[derive(Debug, Serialize)]
pub struct LogoutReport {
    pub ok: bool,
    pub authenticated: bool,
    pub remote_revocation: &'static str,
    pub may_remain_valid_until: Option<i64>,
    pub warning: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Deployment {
    issuer: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    token_format: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    data: T,
}

#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedBinding {
    issuer: String,
    client_id: String,
    resource: String,
    issued_at: i64,
    expires_at: i64,
    token_format: String,
}

struct LoginSecrets {
    verifier: Zeroizing<String>,
    challenge: String,
    state: Zeroizing<String>,
}
impl LoginSecrets {
    fn generate() -> CloudResult<Self> {
        let mut bytes = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| invalid("secure_random_unavailable"))?;
        let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| invalid("secure_random_unavailable"))?;
        let state = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        bytes.zeroize();
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        Ok(Self {
            verifier,
            challenge,
            state,
        })
    }
}

fn binding_digest(session: &OAuthSession, token: &str) -> String {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"wispkey-cloud-oauth-v1");
    for value in [
        token,
        &session.issuer,
        &session.client_id,
        &session.api_origin,
        &session.resource,
        &session.account_id,
        &session.token_format,
    ] {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(&session.issued_at.to_be_bytes());
    hash.update(&session.expires_at.to_be_bytes());
    URL_SAFE_NO_PAD.encode(hash.finish())
}

/// Require a canonical HTTPS origin. In particular, paths and query strings cannot change routing.
fn https_origin(value: &str) -> CloudResult<String> {
    let url = reqwest::Url::parse(value).map_err(|_| invalid("invalid_https_origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || value.chars().any(char::is_whitespace)
    {
        return Err(invalid(
            "cloud_login_requires_https_origin_without_path_or_credentials",
        ));
    }
    Ok(url.origin().ascii_serialization())
}

fn endpoint(issuer: &str, value: &str, path: &str) -> CloudResult<String> {
    let expected = format!("{issuer}{path}");
    // Do not permit redirects, credentials, arbitrary same-host endpoints, or alternate encodings.
    if value != expected {
        return Err(invalid("untrusted_oauth_endpoint"));
    }
    Ok(expected)
}

impl Deployment {
    fn validate(&self, api_origin: &str, previous: Option<&OAuthSession>) -> CloudResult<()> {
        if https_origin(&self.issuer)? != self.issuer
            || self.resource != format!("{api_origin}/api/v1")
            || self.scopes != [SCOPE]
            || self.token_format != "opaque"
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || !self.client_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid("invalid_cli_oauth_configuration"));
        }
        if previous.is_some_and(|old| {
            old.api_origin != api_origin
                || old.issuer != self.issuer
                || old.client_id != self.client_id
                || old.resource != self.resource
        }) {
            return Err(invalid(
                "oauth_deployment_changed; log out before changing Cloud deployments",
            ));
        }
        Ok(())
    }
}
impl Metadata {
    fn validate(&self, deployment: &Deployment) -> CloudResult<()> {
        if self.issuer != deployment.issuer
            || !self.response_types_supported.iter().any(|s| s == "code")
            || !self
                .grant_types_supported
                .iter()
                .any(|s| s == "authorization_code")
            || !self
                .token_endpoint_auth_methods_supported
                .iter()
                .any(|s| s == "none")
            || !self
                .code_challenge_methods_supported
                .iter()
                .any(|s| s == "S256")
        {
            return Err(invalid(
                "issuer_does_not_advertise_public_s256_authorization_code",
            ));
        }
        endpoint(
            &self.issuer,
            &self.authorization_endpoint,
            "/oauth/authorize",
        )?;
        endpoint(&self.issuer, &self.token_endpoint, "/oauth/token")?;
        Ok(())
    }
}

pub(super) fn ensure_session(config: &CloudConfig) -> CloudResult<()> {
    let token = config
        .clerk_session_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(CloudError::NotAuthenticated)?;
    let session = config
        .oauth_session
        .as_ref()
        .ok_or_else(|| invalid("legacy_cloud_session; run `wispkey cloud login` again"))?;
    if session.expires_at <= chrono::Utc::now().timestamp() {
        return Err(invalid(
            "cloud_session_expired; run `wispkey cloud login` again",
        ));
    }
    if session.api_origin != config.api_url.trim_end_matches('/')
        || session.resource != format!("{}/api/v1", session.api_origin)
        || config.user_id.as_deref() != Some(&session.account_id)
        || config.org_id.is_some()
        || session.binding_sha256 != binding_digest(session, token)
        || session.client_id.is_empty()
        || session.token_format != "opaque"
        || !token.starts_with("oat_")
        || token.len() <= 4
        || token.len() > MAX_TOKEN_BYTES
        || !token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'~' | b'+' | b'/' | b'=')
        })
        || session.issued_at < 0
        || session.expires_at <= session.issued_at
        || session.expires_at.saturating_sub(session.issued_at) > MAX_TOKEN_LIFETIME
        || https_origin(&session.issuer)? != session.issuer
    {
        return Err(invalid(
            "cloud_session_binding_changed; run `wispkey cloud login` again",
        ));
    }
    Ok(())
}

fn authorize_url(
    deployment: &Deployment,
    metadata: &Metadata,
    redirect: &str,
    secrets: &LoginSecrets,
) -> CloudResult<reqwest::Url> {
    let mut url = reqwest::Url::parse(&metadata.authorization_endpoint)
        .map_err(|_| invalid("invalid_authorization_endpoint"))?;
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("response_mode", "query"),
        ("client_id", deployment.client_id.as_str()),
        ("redirect_uri", redirect),
        ("scope", SCOPE),
        ("resource", deployment.resource.as_str()),
        ("state", secrets.state.as_str()),
        ("code_challenge", secrets.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    Ok(url)
}

fn validate_token_response(response: &TokenResponse) -> CloudResult<()> {
    if !response.token_type.eq_ignore_ascii_case("bearer")
        || response.expires_in == 0
        || response.expires_in > MAX_TOKEN_LIFETIME as u64
        || response.access_token.len() > MAX_TOKEN_BYTES
        || response.access_token.len() <= 4
        || !response.access_token.starts_with("oat_")
        || !response.access_token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'~' | b'+' | b'/' | b'=')
        })
        || response
            .scope
            .as_deref()
            .is_some_and(|scope| scope != SCOPE)
    {
        return Err(invalid(
            "invalid_oauth_token_response; expected a short-lived opaque access token",
        ));
    }
    Ok(())
}

// Opaque access tokens contain no trusted local identity. Only the pinned API's
// successful provider verification establishes this context, including entitlement.
fn verified_session(
    response: &TokenResponse,
    deployment: &Deployment,
    api_origin: &str,
    account: &serde_json::Value,
    exchanged_at: i64,
    now: i64,
) -> CloudResult<OAuthSession> {
    let binding: VerifiedBinding = serde_json::from_value(account["oauth"].clone())
        .map_err(|_| invalid("invalid_verified_oauth_binding"))?;
    let account_id = account["clerkUserId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| invalid("invalid_verified_oauth_account"))?;
    if binding.issuer != deployment.issuer
        || binding.client_id != deployment.client_id
        || binding.resource != deployment.resource
        || binding.token_format != "opaque"
        || binding.issued_at < 0
        || binding.issued_at > now.saturating_add(60)
        || binding.expires_at <= now.saturating_add(30)
        || binding.expires_at <= binding.issued_at
        || binding.expires_at.saturating_sub(binding.issued_at) > MAX_TOKEN_LIFETIME
        || binding
            .expires_at
            .abs_diff(exchanged_at.saturating_add(response.expires_in as i64))
            > 60
        || account["sessionClaims"]["sub"].as_str() != Some(account_id)
        || !account["sessionClaims"]["org_id"].is_null()
    {
        return Err(invalid("oauth_account_binding_or_lifetime_mismatch"));
    }
    let mut session = OAuthSession {
        issuer: binding.issuer,
        client_id: binding.client_id,
        api_origin: api_origin.to_owned(),
        resource: binding.resource,
        account_id: account_id.to_owned(),
        issued_at: binding.issued_at,
        expires_at: binding.expires_at,
        token_format: binding.token_format,
        binding_sha256: String::new(),
    };
    session.binding_sha256 = binding_digest(&session, &response.access_token);
    Ok(session)
}

/// Reject unknown, repeated, malformed, or token-bearing parameters. No callback value is logged.
fn callback_code(
    request: &[u8],
    authority: &str,
    state: &str,
    issuer: &str,
) -> CloudResult<Zeroizing<String>> {
    let text = std::str::from_utf8(request).map_err(|_| invalid("invalid_callback"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| invalid("invalid_callback"))?;
    let fields: Vec<_> = request_line.split(' ').collect();
    if fields.len() != 3
        || fields[0] != "GET"
        || fields[2] != "HTTP/1.1"
        || !fields[1].starts_with("/callback?")
        || fields[1].contains('#')
        || fields[1].contains(['\r', '\n'])
    {
        return Err(invalid("invalid_callback"));
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid_callback"))?;
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim()).is_some() {
                return Err(invalid("invalid_callback"));
            }
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(invalid("invalid_callback"));
        }
    }
    if host != Some(authority) {
        return Err(invalid("invalid_callback"));
    }
    let query = fields[1]
        .strip_prefix("/callback?")
        .ok_or_else(|| invalid("invalid_callback"))?;
    let mut params = std::collections::BTreeMap::new();
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| invalid("invalid_callback"))?;
        // Decode strictly (url's form decoder replaces malformed UTF-8 and escapes).
        let decode = |s: &str| -> CloudResult<String> {
            let bytes = s.as_bytes();
            for (i, b) in bytes.iter().enumerate() {
                if *b == b'%'
                    && (i + 2 >= bytes.len()
                        || !bytes[i + 1].is_ascii_hexdigit()
                        || !bytes[i + 2].is_ascii_hexdigit())
                {
                    return Err(invalid("invalid_callback"));
                }
            }
            urlencoding::decode(&s.replace('+', " "))
                .map(|s| s.into_owned())
                .map_err(|_| invalid("invalid_callback"))
        };
        let key = decode(key)?;
        let value = Zeroizing::new(decode(value)?);
        if !matches!(
            key.as_str(),
            "code" | "state" | "iss" | "error" | "error_description" | "error_uri"
        ) || params.insert(key, value).is_some()
        {
            return Err(invalid("invalid_callback"));
        }
    }
    if params.get("state").map(|s| s.as_str()) != Some(state)
        || params.get("iss").is_some_and(|s| s.as_str() != issuer)
    {
        return Err(invalid("invalid_callback"));
    }
    if params.contains_key("error") {
        if params.contains_key("code") {
            return Err(invalid("invalid_callback"));
        }
        return Err(invalid(
            "cloud_login_denied; run `wispkey cloud login` to retry",
        ));
    }
    if params.contains_key("error_description") || params.contains_key("error_uri") {
        return Err(invalid("invalid_callback"));
    }
    params
        .remove("code")
        .filter(|s| !s.is_empty() && s.len() <= 2048 && s.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| invalid("invalid_callback"))
}

async fn read_callback(stream: &mut TcpStream) -> CloudResult<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let mut chunk = [0_u8; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| invalid("callback_read_failed"))?;
        if n == 0 {
            return Err(invalid("invalid_callback"));
        }
        if bytes.len() + n > MAX_CALLBACK_BYTES {
            return Err(invalid("callback_too_large"));
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            if end + 4 != bytes.len() {
                return Err(invalid("invalid_callback"));
            }
            return Ok(bytes);
        }
    }
}

async fn receive_code(
    listener: TcpListener,
    secrets: &LoginSecrets,
    issuer: &str,
    timeout: Duration,
) -> CloudResult<Zeroizing<String>> {
    let authority = listener
        .local_addr()
        .map_err(|_| invalid("callback_address_failed"))?
        .to_string();
    let outcome = tokio::time::timeout(timeout, async {
        loop {
            let (mut stream, peer) = listener.accept().await.map_err(|_| invalid("callback_accept_failed"))?;
            if !peer.ip().is_loopback() { continue; }
            let parsed = match tokio::time::timeout(CALLBACK_REQUEST_TIMEOUT, read_callback(&mut stream)).await {
                Ok(Ok(request)) => callback_code(&request, &authority, &secrets.state, issuer),
                _ => Err(invalid("invalid_callback")),
            };
            let denied = parsed.as_ref().err().is_some_and(|e| e.to_string().contains("cloud_login_denied"));
            let (status, message) = if parsed.is_ok() {
                ("200 OK", "WispKey received the sign-in response. Return to the terminal to check account verification.")
            } else if denied { ("400 Bad Request", "Sign-in was cancelled. Return to the terminal.") }
            else { ("400 Bad Request", "Invalid sign-in callback. Return to the original sign-in window.") };
            let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{message}", message.len());
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await
            }).await;
            if parsed.is_ok() || denied { return parsed; }
        }
    }).await;
    // Close the owned socket after the response attempt and before returning a
    // code, so any pending TCP handshake cannot lead to another callback exchange.
    drop(listener);
    outcome.map_err(|_| invalid("cloud_login_timed_out; run `wispkey cloud login` to retry"))?
}

async fn cancellable<T>(
    work: impl Future<Output = CloudResult<T>>,
    cancel: impl Future<Output = ()>,
) -> CloudResult<T> {
    tokio::select! { result = work => result, _ = cancel => Err(invalid("cloud_login_cancelled")) }
}

impl CloudClient {
    async fn oauth_json<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> CloudResult<T> {
        let response = request
            .send()
            .await
            .map_err(|_| CloudError::Network("oauth_request_failed".into()))?;
        if response.status() != 200 {
            return Err(invalid(
                "oauth_request_rejected; check Cloud OAuth deployment configuration or retry login",
            ));
        }
        let bytes = Zeroizing::new(Self::response_bytes(response, 65536).await?);
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid_oauth_response"))
    }

    async fn login_inner(
        &self,
        open_browser: impl FnOnce(&reqwest::Url) -> CloudResult<()>,
    ) -> CloudResult<CloudConfig> {
        let api_origin = https_origin(&self.config.api_url)?;
        let envelope: Envelope<Deployment> = self
            .oauth_json(
                self.http_client
                    .get(format!("{api_origin}/api/v1/auth/cli-config")),
            )
            .await?;
        if !envelope.success {
            return Err(invalid("cloud_cli_login_not_enabled"));
        }
        let deployment = envelope.data;
        deployment.validate(&api_origin, self.config.oauth_session.as_ref())?;
        let metadata: Metadata = self
            .oauth_json(self.http_client.get(format!(
                "{}/.well-known/oauth-authorization-server",
                deployment.issuer
            )))
            .await?;
        metadata.validate(&deployment)?;
        let secrets = LoginSecrets::generate()?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| invalid("callback_bind_failed"))?;
        let redirect = format!(
            "http://{}/callback",
            listener
                .local_addr()
                .map_err(|_| invalid("callback_address_failed"))?
        );
        let url = authorize_url(&deployment, &metadata, &redirect, &secrets)?;
        open_browser(&url)?;
        let code = receive_code(listener, &secrets, &deployment.issuer, LOGIN_TIMEOUT).await?;
        let exchanged_at = chrono::Utc::now().timestamp();
        let mut response: TokenResponse = self
            .oauth_json(self.http_client.post(&metadata.token_endpoint).form(&[
                ("grant_type", "authorization_code"),
                ("client_id", deployment.client_id.as_str()),
                ("code", code.as_str()),
                ("code_verifier", secrets.verifier.as_str()),
                ("redirect_uri", redirect.as_str()),
                ("resource", deployment.resource.as_str()),
            ]))
            .await?;
        // Clerk may include a refresh token without an explicit offline_access
        // request. It is never persisted, logged, sent elsewhere, or used.
        if let Some(mut refresh) = response.refresh_token.take() {
            refresh.zeroize();
        }
        validate_token_response(&response)?;
        let verified: Envelope<serde_json::Value> = self
            .oauth_json(
                self.http_client
                    .get(format!("{api_origin}/api/v1/billing/status"))
                    .bearer_auth(&response.access_token),
            )
            .await?;
        if !verified.success {
            return Err(invalid("cloud_account_verification_failed"));
        }
        let session = verified_session(
            &response,
            &deployment,
            &api_origin,
            &verified.data,
            exchanged_at,
            chrono::Utc::now().timestamp(),
        )?;
        if self
            .config
            .user_id
            .as_ref()
            .is_some_and(|id| id != &session.account_id)
        {
            return Err(invalid(
                "cloud_account_changed; log out before signing in to a different account",
            ));
        }
        let mut candidate = Self {
            config: self.config.clone(),
            http_client: self.http_client.clone(),
        };
        candidate.config.api_url = api_origin;
        candidate.config.clerk_session_token = Some(std::mem::take(&mut response.access_token));
        candidate.config.user_id = Some(session.account_id.clone());
        candidate.config.org_id = None;
        candidate.config.oauth_session = Some(session);
        candidate.config.auth_generation = Some(uuid::Uuid::new_v4().to_string());
        candidate.apply_verified_account(&verified.data)?;
        Ok(candidate.config)
    }

    /// Browser public OAuth code+S256 login. No credentials are saved until the API verifies identity.
    pub async fn login(&mut self) -> CloudResult<CloudConfig> {
        let candidate = cancellable(
            self.login_inner(|url| {
                eprintln!(
                    "Opening your system browser for WispKey Cloud sign-in. Press Ctrl-C to cancel."
                );
                // Do not print a live authorization URL: even state/challenge belong
                // only to this attempt, not shell logs or copied diagnostics.
                open::that_detached(url.as_str()).map_err(|_| {
                    invalid("system_browser_unavailable; run login on a computer with a browser")
                })
            }),
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await?;
        self.persist_login(candidate)
    }

    fn persist_login(&mut self, candidate: CloudConfig) -> CloudResult<CloudConfig> {
        let _lock = ConfigLock::acquire()?;
        if load_config()? != self.config {
            return Err(invalid("cloud_config_changed_during_login; retry login"));
        }
        save_config_unlocked(&candidate)?;
        self.config = candidate;
        Ok(self.config.clone())
    }

    /// Clear local credentials before trying remote revocation; network failure never restores them.
    pub async fn logout(&mut self) -> CloudResult<LogoutReport> {
        let previous = {
            let _lock = ConfigLock::acquire()?;
            // Logout wins over an already-completed concurrent login. A pending
            // login will see this new generation and cannot restore credentials.
            let previous = load_config()?;
            let cleared = CloudConfig {
                api_url: previous.api_url.clone(),
                auth_generation: Some(uuid::Uuid::new_v4().to_string()),
                ..CloudConfig::default()
            };
            save_config_unlocked(&cleared)?;
            self.config = cleared;
            previous
        };
        let mut outcome = "not_attempted";
        let mut until = None;
        if let (Some(session), Some(token)) =
            (&previous.oauth_session, &previous.clerk_session_token)
        {
            until = Some(session.expires_at);
            // Expiry does not prevent a best-effort revocation request, but every
            // destination/identity pin must still match before disclosing the bearer.
            if https_origin(&session.api_origin).is_ok_and(|origin| origin == session.api_origin)
                && session.api_origin == previous.api_url.trim_end_matches('/')
                && session.resource == format!("{}/api/v1", session.api_origin)
                && session.token_format == "opaque"
                && session.binding_sha256 == binding_digest(session, token)
                && previous.user_id.as_deref() == Some(session.account_id.as_str())
            {
                let response: CloudResult<Envelope<serde_json::Value>> = self
                    .oauth_json(
                        self.http_client
                            .post(format!("{}/api/v1/auth/cli-logout", session.api_origin))
                            .bearer_auth(token),
                    )
                    .await;
                outcome = if response.is_ok_and(|r| r.success && r.data["revoked"] == true) {
                    "revoked"
                } else {
                    "unconfirmed"
                };
            }
        }
        Ok(LogoutReport {
            ok: true,
            authenticated: false,
            remote_revocation: outcome,
            may_remain_valid_until: if outcome == "revoked" { None } else { until },
            warning: if outcome == "revoked" {
                "Local credentials cleared and the associated Cloud authorization grant revoked. Your browser session is separate."
            } else {
                "Local credentials cleared. Remote revocation was not confirmed; a copied token may remain valid until expiry. Your browser session is separate."
            },
        })
    }
}

pub(super) struct ConfigLock(std::fs::File);
impl ConfigLock {
    pub(super) fn acquire() -> CloudResult<Self> {
        let path = Vault::vault_dir().join("cloud-auth.lock");
        secure_files::create_private(&path, b"")?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| invalid("unsafe_cloud_auth_lock"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("unsafe_cloud_auth_lock"));
        }
        secure_files::harden_existing_file(&path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| invalid("cloud_auth_lock_unavailable"))?;
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| invalid("cloud_auth_change_in_progress"))?;
        Ok(Self(file))
    }
}
impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(test)]
mod tests;
