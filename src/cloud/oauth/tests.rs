use super::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

fn deployment() -> Deployment {
    Deployment {
        issuer: "https://issuer.example".into(),
        client_id: "fixture-client".into(),
        resource: "https://api.example/api/v1".into(),
        scopes: vec![SCOPE.into()],
        token_format: "opaque".into(),
    }
}
fn metadata(d: &Deployment) -> Metadata {
    Metadata {
        issuer: d.issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", d.issuer),
        token_endpoint: format!("{}/oauth/token", d.issuer),
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into()],
        token_endpoint_auth_methods_supported: vec!["none".into()],
        code_challenge_methods_supported: vec!["S256".into()],
    }
}
const OPAQUE: &str = "oat_synthetic_access_canary";
const REFRESH_CANARY: &str = "synthetic_refresh_never_saved_or_sent";
fn account(d: &Deployment, now: i64) -> Value {
    json!({"clerkUserId":"user_fixture","sessionClaims":{"sub":"user_fixture","plan":"cloud","features":["cloud_sync"]},
        "oauth":{"issuer":d.issuer,"clientId":d.client_id,"resource":d.resource,"issuedAt":now,"expiresAt":now+3600,"tokenFormat":"opaque"}})
}
fn response() -> TokenResponse {
    TokenResponse {
        access_token: OPAQUE.into(),
        token_type: "Bearer".into(),
        expires_in: 3600,
        scope: Some(SCOPE.into()),
        refresh_token: None,
    }
}
fn request(query: &str) -> Vec<u8> {
    format!("GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n").into_bytes()
}

#[test]
fn pkce_matches_rfc7636_and_uses_independent_random_state() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes())),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let a = LoginSecrets::generate().unwrap();
    let b = LoginSecrets::generate().unwrap();
    assert_eq!(a.verifier.len(), 43);
    assert_eq!(a.state.len(), 43);
    assert_ne!(a.state.as_str(), a.verifier.as_str());
    assert_ne!(a.state.as_str(), b.state.as_str());
    let d = deployment();
    let url = authorize_url(&d, &metadata(&d), "http://127.0.0.1:3456/callback", &a).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["response_mode"], "query");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], SCOPE);
    assert_eq!(query["resource"], d.resource);
    assert!(!url.as_str().contains(a.verifier.as_str()));
    assert!(!query.contains_key("client_secret"));
    assert!(!url.as_str().contains("offline_access"));
}

#[test]
fn configuration_and_discovery_are_https_origin_pinned() {
    for value in [
        "http://issuer.example",
        "http://127.0.0.1",
        "https://user@issuer.example",
        "https://issuer.example/path",
        "https://issuer.example?x=y",
        "https://issuer.example#fragment",
        " https://issuer.example",
    ] {
        assert!(https_origin(value).is_err(), "{value}");
    }
    let d = deployment();
    d.validate("https://api.example", None).unwrap();
    metadata(&d).validate(&d).unwrap();
    let mut m = metadata(&d);
    m.token_endpoint = "https://other.example/oauth/token".into();
    assert!(m.validate(&d).is_err());
    let mut m = metadata(&d);
    m.token_endpoint = format!("{}/oauth/token?target=bad", d.issuer);
    assert!(m.validate(&d).is_err());
    let mut m = metadata(&d);
    m.issuer = "https://other.example".into();
    assert!(m.validate(&d).is_err());
    let mut m = metadata(&d);
    m.code_challenge_methods_supported = vec!["plain".into()];
    assert!(m.validate(&d).is_err());
    let mut wrong_format = deployment();
    wrong_format.token_format = "jwt".into();
    assert!(wrong_format.validate("https://api.example", None).is_err());
    let mut d = deployment();
    d.scopes.push("offline_access".into());
    assert!(d.validate("https://api.example", None).is_err());
    let mut d = deployment();
    d.resource = "https://other.example/api/v1".into();
    assert!(d.validate("https://api.example", None).is_err());
}

#[test]
fn callbacks_reject_raw_tokens_duplicates_wrong_state_and_wrong_issuer() {
    let good = request("code=synthetic-code&state=expected");
    assert_eq!(
        callback_code(
            &good,
            "127.0.0.1:1234",
            "expected",
            "https://issuer.example"
        )
        .unwrap()
        .as_str(),
        "synthetic-code"
    );
    for query in [
        "token=bearer&state=expected",
        "access_token=bearer&state=expected",
        "id_token=bearer&state=expected",
        "code=good&state=wrong",
        "code=good",
        "code=&state=expected",
        "code=good&state=expected&state=expected",
        "code=good&%73tate=expected&state=expected",
        "code=good&code=other&state=expected",
        "code=good&state=expected&iss=https%3A%2F%2Fevil.example",
        "code=good&state=expected&unexpected=x",
        "code=%GG&state=expected",
        "code=%FF&state=expected",
        "code=good&state=expected#fragment",
        "code=good&state=expected&error=access_denied",
    ] {
        assert!(
            callback_code(
                &request(query),
                "127.0.0.1:1234",
                "expected",
                "https://issuer.example"
            )
            .is_err(),
            "{query}"
        );
    }
    let error = callback_code(
        &request("error=access_denied&error_description=secret-canary&state=expected"),
        "127.0.0.1:1234",
        "expected",
        "https://issuer.example",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("cloud_login_denied"));
    assert!(!error.contains("secret-canary"));
}

#[test]
fn callbacks_require_exact_method_path_and_host_without_bodies() {
    let good = String::from_utf8(request("code=good&state=expected")).unwrap();
    for bad in [
        good.replace("GET ", "POST "),
        good.replace("/callback?", "/evil?"),
        good.replace("/callback?", "http://127.0.0.1:1234/callback?"),
        good.replace("Host: 127.0.0.1:1234", "Host: localhost:1234"),
        good.replace(
            "Host: 127.0.0.1:1234",
            "Host: 127.0.0.1:1234\r\nHost: 127.0.0.1:1234",
        ),
        good.replace("HTTP/1.1", "HTTP/1.0"),
        good.replace("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n"),
    ] {
        assert!(
            callback_code(
                bad.as_bytes(),
                "127.0.0.1:1234",
                "expected",
                "https://issuer.example"
            )
            .is_err()
        );
    }
}

#[test]
fn opaque_tokens_and_verified_context_fail_closed_without_secret_errors() {
    let d = deployment();
    let now = 1_800_000_000;
    let data = account(&d, now);
    let r = response();
    validate_token_response(&r).unwrap();
    let session = verified_session(&r, &d, "https://api.example", &data, now, now).unwrap();
    assert_eq!(session.account_id, "user_fixture");
    assert_eq!(session.expires_at, now + 3600);
    for (key, value) in [
        ("issuer", json!("https://evil.example")),
        ("resource", json!("wrong")),
        ("clientId", json!("other")),
        ("tokenFormat", json!("jwt")),
        ("expiresAt", json!(now - 1)),
        ("expiresAt", json!(now + 86401)),
        ("issuedAt", json!(now + 120)),
        ("issuedAt", json!(now - 86400)),
    ] {
        let mut bad = data.clone();
        bad["oauth"][key] = value;
        assert!(
            verified_session(&r, &d, "https://api.example", &bad, now, now).is_err(),
            "{key}"
        );
    }
    for value in [
        "",
        "not-opaque",
        "oauth_wrong-prefix",
        "eyJh.e30.signature",
        "oat_has.dot",
        "oat_",
        "oat_ newline\n",
    ] {
        let mut bad = response();
        bad.access_token = value.into();
        let error = validate_token_response(&bad).unwrap_err().to_string();
        assert!(!error.contains(OPAQUE));
    }
    let mut bad = response();
    bad.refresh_token = Some(REFRESH_CANARY.into());
    validate_token_response(&bad).unwrap();
    let mut bad = response();
    bad.scope = Some("openid wispkey:sync".into());
    assert!(validate_token_response(&bad).is_err());
    let mut bad = response();
    bad.token_type = "MAC".into();
    assert!(validate_token_response(&bad).is_err());
    let mut bad = response();
    bad.expires_in = 86401;
    assert!(validate_token_response(&bad).is_err());
    let mut bad = data.clone();
    bad["clerkUserId"] = json!("other");
    assert!(verified_session(&r, &d, "https://api.example", &bad, now, now).is_err());
    let mut bad = data.clone();
    bad["sessionClaims"]["org_id"] = json!("org_123");
    assert!(verified_session(&r, &d, "https://api.example", &bad, now, now).is_err());
}

#[test]
fn persisted_bearer_is_pinned_and_debug_is_redacted() {
    let d = deployment();
    let now = chrono::Utc::now().timestamp();
    let data = account(&d, now);
    let r = response();
    let session = verified_session(&r, &d, "https://api.example", &data, now, now).unwrap();
    let config = CloudConfig {
        api_url: "https://api.example".into(),
        clerk_session_token: Some(r.access_token.clone()),
        user_id: Some("user_fixture".into()),
        oauth_session: Some(session),
        ..CloudConfig::default()
    };
    ensure_session(&config).unwrap();
    assert!(!format!("{config:?}").contains(OPAQUE));
    for mutation in 0..8 {
        let mut bad = config.clone();
        match mutation {
            0 => bad.api_url = "https://evil.example".into(),
            1 => bad.user_id = Some("other".into()),
            2 => bad.clerk_session_token = Some("other-token".into()),
            3 => bad.org_id = Some("org".into()),
            4 => bad.oauth_session.as_mut().unwrap().expires_at = 0,
            5 => bad.oauth_session.as_mut().unwrap().issuer = "https://other.example".into(),
            6 => bad.oauth_session.as_mut().unwrap().client_id = "other-client".into(),
            _ => bad.oauth_session = None,
        };
        assert!(ensure_session(&bad).is_err());
    }
    let mut changed = deployment();
    changed.client_id = "new-client".into();
    assert!(
        changed
            .validate("https://api.example", config.oauth_session.as_ref())
            .is_err()
    );
}

async fn send_callback(address: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

async fn assert_replay_not_acknowledged(address: std::net::SocketAddr, state: &str) {
    // A completed TCP handshake can race kernel teardown (especially on macOS).
    // Check the auth boundary: the consumed listener must never acknowledge another code.
    let response = tokio::time::timeout(Duration::from_secs(1), async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(format!("GET /callback?code=synthetic-replay&state={state} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await?;
        let mut bytes = Vec::new();
        stream.take(MAX_CALLBACK_BYTES as u64).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    }).await;
    if let Ok(Ok(bytes)) = response {
        assert!(
            !String::from_utf8_lossy(&bytes).contains("WispKey received the sign-in response"),
            "consumed callback acknowledged a replay"
        );
    }
}

#[tokio::test]
async fn listener_rejects_injection_then_accepts_once_and_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    assert_eq!(
        address.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    let secrets = LoginSecrets::generate().unwrap();
    let state = secrets.state.to_string();
    let task = tokio::spawn(async move {
        receive_code(
            listener,
            &secrets,
            "https://issuer.example",
            Duration::from_secs(5),
        )
        .await
    });
    assert!(
        send_callback(address, "/callback?token=synthetic-bearer&state=wrong")
            .await
            .starts_with("HTTP/1.1 400")
    );
    assert!(
        send_callback(
            address,
            &format!("/callback?code=synthetic-code&state={state}")
        )
        .await
        .contains("no-store")
    );
    assert_eq!(task.await.unwrap().unwrap().as_str(), "synthetic-code");
    assert_replay_not_acknowledged(address, &state).await;
}

#[tokio::test]
async fn timeout_cancellation_slow_requests_and_oversize_are_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secrets = LoginSecrets::generate().unwrap();
    let state = secrets.state.to_string();
    let task = tokio::spawn(async move {
        receive_code(
            listener,
            &secrets,
            "https://issuer.example",
            Duration::from_millis(80),
        )
        .await
    });
    let _idle = TcpStream::connect(address).await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("timed_out")
    );
    assert_replay_not_acknowledged(address, &state).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secrets = LoginSecrets::generate().unwrap();
    let state = secrets.state.to_string();
    let result = cancellable(
        receive_code(
            listener,
            &secrets,
            "https://issuer.example",
            Duration::from_secs(60),
        ),
        async {},
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert_replay_not_acknowledged(address, &state).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_callback(&mut stream).await
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    let _ = stream
        .write_all(&vec![b'x'; MAX_CALLBACK_BYTES + 1024])
        .await;
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("too_large")
    );
}

struct Fixture {
    api: String,
    issuer: String,
    client: reqwest::Client,
    requests: Arc<Mutex<Vec<String>>>,
    challenge: Arc<Mutex<String>>,
    callback: Arc<Mutex<Option<(std::net::SocketAddr, String)>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(mode: &'static str) -> Self {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::io::{Read, Write};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert =
            rcgen::generate_simple_self_signed(vec!["api.example".into(), "issuer.example".into()])
                .unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
                )
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let api = format!("https://api.example:{}", address.port());
        let issuer = format!("https://issuer.example:{}", address.port());
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_der(cert.cert.der()).unwrap())
            .resolve("api.example", address)
            .resolve("issuer.example", address)
            .build()
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let challenge = Arc::new(Mutex::new(String::new()));
        let (done, seen, proof, api_clone, issuer_clone) = (
            stop.clone(),
            requests.clone(),
            challenge.clone(),
            api.clone(),
            issuer.clone(),
        );
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                // BSD/macOS can inherit O_NONBLOCK from the listening socket.
                // StreamOwned below is deliberately synchronous on this fixture thread.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(tls.clone()).unwrap(),
                    stream,
                );
                let mut bytes = Vec::new();
                let mut header_end = None;
                let mut length = 0;
                loop {
                    let mut chunk = [0; 4096];
                    let n = match stream.read(&mut chunk) {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    bytes.extend_from_slice(&chunk[..n]);
                    if header_end.is_none()
                        && let Some(i) = bytes.windows(4).position(|b| b == b"\r\n\r\n")
                    {
                        header_end = Some(i + 4);
                        let header = String::from_utf8_lossy(&bytes[..i]);
                        length = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|s| s.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                    }
                    if header_end.is_some_and(|i| bytes.len() >= i + length) {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&bytes).to_string();
                seen.lock().unwrap().push(request.clone());
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let d = Deployment {
                    issuer: issuer_clone.clone(),
                    client_id: "fixture-client".into(),
                    resource: format!("{api_clone}/api/v1"),
                    scopes: vec![SCOPE.into()],
                    token_format: "opaque".into(),
                };
                let now = chrono::Utc::now().timestamp();
                let data = account(&d, now);
                let mut status = "200 OK";
                let mut location = String::new();
                let body = match path {
                    "/api/v1/auth/cli-config" => {
                        json!({"success":true,"data":{"issuer":d.issuer,"clientId":d.client_id,"resource":d.resource,"scopes":[SCOPE],"tokenFormat":"opaque"}})
                    }
                    "/.well-known/oauth-authorization-server" => {
                        json!({"issuer":d.issuer,"authorization_endpoint":format!("{}/oauth/authorize",d.issuer),"token_endpoint":if mode=="cross_origin"{format!("{api_clone}/oauth/token")}else{format!("{}/oauth/token",d.issuer)},"response_types_supported":["code"],"grant_types_supported":["authorization_code"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"]})
                    }
                    "/oauth/token" => {
                        let form: BTreeMap<_, _> =
                            url::form_urlencoded::parse(&bytes[header_end.unwrap()..])
                                .into_owned()
                                .collect();
                        assert_eq!(form["grant_type"], "authorization_code");
                        assert_eq!(form["client_id"], "fixture-client");
                        assert_eq!(form["code"], "synthetic-code");
                        assert_eq!(form["resource"], d.resource);
                        assert_eq!(
                            URL_SAFE_NO_PAD.encode(digest::digest(
                                &digest::SHA256,
                                form["code_verifier"].as_bytes()
                            )),
                            *proof.lock().unwrap()
                        );
                        assert!(!form.contains_key("client_secret"));
                        assert!(form["redirect_uri"].starts_with("http://127.0.0.1:"));
                        if mode == "redirect" {
                            status = "307 Temporary Redirect";
                            location = format!("Location: {api_clone}/stolen\r\n");
                        }
                        let mut tokens = json!({"access_token":OPAQUE,"token_type":"Bearer","expires_in":3600,"scope":SCOPE});
                        if mode == "refresh" {
                            tokens["refresh_token"] = json!(REFRESH_CANARY);
                        }
                        tokens
                    }
                    "/api/v1/billing/status" => {
                        let bearer = request
                            .lines()
                            .find_map(|l| l.strip_prefix("authorization: Bearer "))
                            .unwrap();
                        assert_eq!(bearer, OPAQUE);
                        let mut data = data;
                        if mode == "wrong_account" {
                            data["clerkUserId"] = json!("user_other");
                        }
                        if mode == "wrong_client" {
                            data["oauth"]["clientId"] = json!("other");
                        }
                        json!({"success":true,"data":data})
                    }
                    "/api/v1/auth/cli-logout" => {
                        assert_eq!(&bytes[header_end.unwrap()..], b"");
                        assert!(request.contains(&format!("authorization: Bearer {OPAQUE}")));
                        assert!(
                            load_config().unwrap().clerk_session_token.is_none(),
                            "local logout precedes remote request"
                        );
                        if mode == "revoke_fail" {
                            status = "503 Service Unavailable";
                        }
                        json!({"success":true,"data":{"revoked":true}})
                    }
                    _ => {
                        status = "404 Not Found";
                        json!({})
                    }
                };
                let text = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            api,
            issuer,
            client,
            requests,
            challenge,
            callback: Arc::new(Mutex::new(None)),
            stop,
            worker: Some(worker),
        }
    }
    async fn login(&self) -> CloudResult<CloudConfig> {
        let client = CloudClient {
            config: CloudConfig {
                api_url: self.api.clone(),
                ..CloudConfig::default()
            },
            http_client: self.client.clone(),
        };
        let proof = self.challenge.clone();
        let callback = self.callback.clone();
        client
            .login_inner(|url| {
                let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
                *proof.lock().unwrap() = params["code_challenge"].clone();
                let redirect = reqwest::Url::parse(&params["redirect_uri"]).unwrap();
                let address = format!("127.0.0.1:{}", redirect.port().unwrap())
                    .parse()
                    .unwrap();
                let state = params["state"].clone();
                *callback.lock().unwrap() = Some((address, state.clone()));
                tokio::spawn(async move {
                    send_callback(
                        address,
                        &format!("/callback?code=synthetic-code&state={state}"),
                    )
                    .await;
                });
                Ok(())
            })
            .await
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn synthetic_https_oauth_flow_verifies_before_returning_candidate() {
    let fixture = Fixture::new("ok");
    let config = fixture.login().await.unwrap();
    assert_eq!(config.user_id.as_deref(), Some("user_fixture"));
    assert_eq!(config.tier, CloudTier::Cloud);
    assert_eq!(
        config.oauth_session.as_ref().unwrap().issuer,
        fixture.issuer
    );
    ensure_session(&config).unwrap();
    let (address, state) = fixture.callback.lock().unwrap().clone().unwrap();
    assert_replay_not_acknowledged(address, &state).await;
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST /oauth/token"))
            .count(),
        1,
        "a replay caused another code exchange"
    );
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /api/v1/auth/cli-config"));
    assert!(!requests[0].to_lowercase().contains("authorization:"));
    assert!(requests[2].starts_with("POST /oauth/token"));
    assert!(requests[3].starts_with("GET /api/v1/billing/status"));
}

#[tokio::test]
async fn cross_origin_discovery_redirects_and_wrong_verified_bindings_fail() {
    for mode in ["cross_origin", "redirect", "wrong_account", "wrong_client"] {
        let fixture = Fixture::new(mode);
        let error = fixture.login().await.unwrap_err().to_string();
        assert!(!error.contains("synthetic-code"));
        assert!(!error.contains(OPAQUE));
        let requests = fixture.requests.lock().unwrap();
        assert!(!requests.iter().any(|r| r.starts_with("POST /stolen")));
        if mode == "cross_origin" {
            assert_eq!(requests.len(), 2);
        }
    }
}

#[tokio::test]
async fn valid_provider_denial_ends_attempt_and_closes_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secrets = LoginSecrets::generate().unwrap();
    let state = secrets.state.to_string();
    let task = tokio::spawn(async move {
        receive_code(
            listener,
            &secrets,
            "https://issuer.example",
            Duration::from_secs(10),
        )
        .await
    });
    assert!(
        send_callback(
            address,
            &format!("/callback?state={state}&error=access_denied")
        )
        .await
        .contains("cancelled")
    );
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cloud_login_denied")
    );
    assert_replay_not_acknowledged(address, &state).await;
}

#[tokio::test]
async fn persistence_logout_and_concurrent_changes_use_isolated_storage() {
    const CHILD: &str = "WISPKEY_OAUTH_PERSISTENCE_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().unwrap();
        let output=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","cloud::oauth::tests::persistence_logout_and_concurrent_changes_use_isolated_storage","--nocapture"])
            .env(CHILD,"1").env("WISPKEY_VAULT_PATH",directory.path()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(REFRESH_CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(REFRESH_CANARY));
        return;
    }
    for mode in ["ok", "revoke_fail", "refresh"] {
        let fixture = Fixture::new(mode);
        let candidate = fixture.login().await.unwrap();
        let mut stale = CloudClient {
            config: load_config().unwrap(),
            http_client: fixture.client.clone(),
        };
        let mut client = CloudClient {
            config: load_config().unwrap(),
            http_client: fixture.client.clone(),
        };
        client.persist_login(candidate.clone()).unwrap();
        let loaded = load_config().unwrap();
        assert_eq!(loaded, candidate);
        assert!(
            !fs::read_to_string(config_path())
                .unwrap()
                .contains(REFRESH_CANARY)
        );
        assert!(
            !serde_json::to_string(&loaded)
                .unwrap()
                .contains("refresh_token")
        );
        assert!(
            !fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.contains(REFRESH_CANARY))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(config_path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let report = client.logout().await.unwrap();
        assert_eq!(
            report.remote_revocation,
            if mode != "revoke_fail" {
                "revoked"
            } else {
                "unconfirmed"
            }
        );
        assert_eq!(
            report.may_remain_valid_until,
            if mode != "revoke_fail" {
                None
            } else {
                candidate.oauth_session.as_ref().map(|s| s.expires_at)
            }
        );
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains(OPAQUE));
        assert!(report.warning.contains(if mode != "revoke_fail" {
            "authorization grant revoked"
        } else {
            "may remain valid"
        }));
        let stored = load_config().unwrap();
        assert!(stored.clerk_session_token.is_none());
        assert!(stored.oauth_session.is_none());
        assert!(stored.user_id.is_none());
        assert_eq!(stored.api_url, fixture.api);
        assert!(
            stale
                .persist_login(candidate)
                .unwrap_err()
                .to_string()
                .contains("config_changed")
        );
        assert!(load_config().unwrap().clerk_session_token.is_none());
    }
    let legacy = CloudConfig {
        clerk_session_token: Some("synthetic-legacy".into()),
        ..CloudConfig::default()
    };
    save_config(&legacy).unwrap();
    let report = CloudClient::new(legacy).logout().await.unwrap();
    assert_eq!(report.remote_revocation, "not_attempted");
    assert!(load_config().unwrap().clerk_session_token.is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(config_path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_config().is_err());
        fs::remove_file(config_path()).unwrap();
        let target = Vault::vault_dir().join("symlink-target");
        fs::write(&target, "{}").unwrap();
        symlink(target, config_path()).unwrap();
        assert!(load_config().is_err());
    }
}
