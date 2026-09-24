//! Bounded Kubernetes Secret delivery for one owner-reviewed environment.
//! The caller reserves and audits a grant before invoking this transport.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use reqwest::{Certificate, Client, StatusCode};
use ring::{digest, signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::identity;

type Result<T> = std::result::Result<T, &'static str>;
const INVALID_TARGET: &str = "environment target is invalid";
const INVALID_POSTURE: &str = "environment posture is unverified";
const PROVIDER_UNAVAILABLE: &str = "environment provider is unavailable";
const TARGET_MISMATCH: &str = "environment target identity mismatch";
const MAX_RESPONSE: usize = 256 * 1024;
const MAX_SELECTED_SECRET: usize = 64 * 1024;
const MAX_PROVIDER_TOKEN: usize = 8 * 1024;
const IDEMPOTENCY_ANNOTATION: &str = "wispkey.dev/credential-revision";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KubernetesAction {
    Deliver,
    Revoke,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KubernetesTarget {
    pub endpoint: String,
    pub cluster_id: String,
    pub context: String,
    pub environment_id: String,
    pub environment_owner: String,
    pub consumer_id: String,
    pub issuer_id: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub secret_name: String,
    pub secret_uid: String,
    pub data_key: String,
    pub ca_file: PathBuf,
    pub provider_credential_id: String,
    pub posture_file: PathBuf,
    pub posture_public_key: String,
    pub encryption_config_revision: String,
    pub action: KubernetesAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KubernetesOutcome {
    DeliveryAcknowledged,
    RevocationUnverified,
    OutcomeUnknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPosture {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PosturePayload {
    endpoint: String,
    ca_sha256: String,
    cluster_id: String,
    context: String,
    environment_id: String,
    namespace_uid: String,
    secret_uid: String,
    environment_owner: String,
    consumer_id: String,
    issuer_id: String,
    encryption_config_revision: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct VerifiedInputs {
    ca_pem: String,
    posture_raw: String,
    expires_at: DateTime<Utc>,
}

impl KubernetesTarget {
    pub(crate) fn validate(&self) -> Result<()> {
        self.verified_inputs().map(|_| ())
    }

    /// Stable grant binding for both owner-reviewed metadata and exact private
    /// CA/posture bytes. A replacement invalidates an outstanding grant.
    pub(crate) fn snapshot_revision(&self) -> Result<(String, DateTime<Utc>)> {
        let inputs = self.verified_inputs()?;
        let encoded = serde_json::to_vec(self).map_err(|_| INVALID_TARGET)?;
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(b"wispkey-kubernetes-target-v1\0");
        context.update(&encoded);
        context.update(inputs.ca_pem.as_bytes());
        context.update(inputs.posture_raw.as_bytes());
        Ok((
            STANDARD_NO_PAD.encode(context.finish().as_ref()),
            inputs.expires_at,
        ))
    }

    fn verified_inputs(&self) -> Result<VerifiedInputs> {
        self.validate_syntax()?;
        let ca_pem = identity::read_private_catalog(&self.ca_file).map_err(|_| INVALID_TARGET)?;
        Certificate::from_pem(ca_pem.as_bytes()).map_err(|_| INVALID_TARGET)?;
        let posture_raw =
            identity::read_private_catalog(&self.posture_file).map_err(|_| INVALID_POSTURE)?;
        let envelope: SignedPosture =
            serde_json::from_str(&posture_raw).map_err(|_| INVALID_POSTURE)?;
        let payload_bytes =
            decode_canonical(&envelope.payload, 16 * 1024).ok_or(INVALID_POSTURE)?;
        let signature_bytes = decode_canonical(&envelope.signature, 64)
            .filter(|bytes| bytes.len() == 64)
            .ok_or(INVALID_POSTURE)?;
        let public_key = decode_canonical(&self.posture_public_key, 32)
            .filter(|bytes| bytes.len() == 32)
            .ok_or(INVALID_POSTURE)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&payload_bytes, &signature_bytes)
            .map_err(|_| INVALID_POSTURE)?;
        let posture: PosturePayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| INVALID_POSTURE)?;
        let ca_digest =
            STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256, ca_pem.as_bytes()).as_ref());
        let now = Utc::now();
        let duration = posture.expires_at.signed_duration_since(posture.issued_at);
        if posture.endpoint != self.endpoint
            || posture.ca_sha256 != ca_digest
            || posture.cluster_id != self.cluster_id
            || posture.context != self.context
            || posture.environment_id != self.environment_id
            || posture.namespace_uid != self.namespace_uid
            || posture.secret_uid != self.secret_uid
            || posture.environment_owner != self.environment_owner
            || posture.consumer_id != self.consumer_id
            || posture.issuer_id != self.issuer_id
            || posture.encryption_config_revision != self.encryption_config_revision
            || duration <= chrono::Duration::zero()
            || duration > chrono::Duration::hours(1)
            || posture.issued_at > now
            || posture.expires_at <= now
        {
            return Err(INVALID_POSTURE);
        }
        Ok(VerifiedInputs {
            ca_pem,
            posture_raw,
            expires_at: posture.expires_at,
        })
    }

    fn validate_syntax(&self) -> Result<()> {
        let parsed = url::Url::parse(&self.endpoint).map_err(|_| INVALID_TARGET)?;
        if parsed.scheme() != "https"
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
            || parsed.origin().ascii_serialization() != self.endpoint
            || !slug(&self.cluster_id)
            || !slug(&self.context)
            || !slug(&self.environment_id)
            || !slug(&self.environment_owner)
            || !slug(&self.consumer_id)
            || !slug(&self.issuer_id)
            || !slug(&self.namespace)
            || !slug(&self.secret_name)
            || !data_key(&self.data_key)
            || !canonical_uuid(&self.namespace_uid)
            || !canonical_uuid(&self.secret_uid)
            || !canonical_uuid(&self.provider_credential_id)
            || !slug(&self.encryption_config_revision)
            || !self.ca_file.is_absolute()
            || !self.posture_file.is_absolute()
        {
            return Err(INVALID_TARGET);
        }
        Ok(())
    }
}

fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn decode_canonical(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    if value.len() > max_bytes.saturating_mul(4).div_ceil(3) + 4 {
        return None;
    }
    let bytes = STANDARD_NO_PAD.decode(value).ok()?;
    (bytes.len() <= max_bytes && STANDARD_NO_PAD.encode(&bytes) == value).then_some(bytes)
}

/// Uses one provider token to inspect exactly two named objects, then releases
/// the selected secret only after the live namespace and Secret UIDs match.
/// `idempotency_key` is supplied by the trusted runtime from the immutable
/// destination scope and selected credential revision; it remains stable
/// across separately authorized grants for that same revision.
pub(crate) async fn execute<Provider, Selected>(
    target: &KubernetesTarget,
    idempotency_key: &str,
    deadline: Instant,
    connect_timeout: Duration,
    mut cancellation: watch::Receiver<bool>,
    provider_token: Provider,
    release_selected: Selected,
) -> Result<KubernetesOutcome>
where
    Provider: FnOnce() -> Result<Vec<u8>>,
    Selected: FnOnce() -> Result<Vec<u8>>,
{
    if connect_timeout.is_zero()
        || idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(INVALID_TARGET);
    }
    let write_started = Arc::new(AtomicBool::new(false));
    let operation = execute_inner(
        target,
        idempotency_key,
        deadline,
        connect_timeout,
        provider_token,
        release_selected,
        &write_started,
    );
    tokio::select! {
        result = timeout_at(deadline, operation) => match result {
            Ok(result) => result,
            Err(_) if write_started.load(Ordering::SeqCst) => Ok(KubernetesOutcome::OutcomeUnknown),
            Err(_) => Err(PROVIDER_UNAVAILABLE),
        },
        _ = async {
            if cancellation.wait_for(|cancelled| *cancelled).await.is_err() {
                std::future::pending::<()>().await;
            }
        } => {
            if write_started.load(Ordering::SeqCst) {
                Ok(KubernetesOutcome::OutcomeUnknown)
            } else {
                Err(PROVIDER_UNAVAILABLE)
            }
        }
    }
}

async fn execute_inner<Provider, Selected>(
    target: &KubernetesTarget,
    idempotency_key: &str,
    deadline: Instant,
    connect_timeout: Duration,
    provider_token: Provider,
    release_selected: Selected,
    write_started: &AtomicBool,
) -> Result<KubernetesOutcome>
where
    Provider: FnOnce() -> Result<Vec<u8>>,
    Selected: FnOnce() -> Result<Vec<u8>>,
{
    let inputs = target.verified_inputs()?;
    if Utc::now() >= inputs.expires_at {
        return Err(INVALID_POSTURE);
    }
    let ca = Certificate::from_pem(inputs.ca_pem.as_bytes()).map_err(|_| INVALID_TARGET)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(PROVIDER_UNAVAILABLE);
    }
    let client = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .connect_timeout(remaining.min(connect_timeout))
        .timeout(remaining)
        .build()
        .map_err(|_| PROVIDER_UNAVAILABLE)?;
    let provider = Zeroizing::new(provider_token()?);
    if provider.is_empty()
        || provider.len() > MAX_PROVIDER_TOKEN
        || !provider.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(PROVIDER_UNAVAILABLE);
    }
    let token = std::str::from_utf8(&provider).map_err(|_| PROVIDER_UNAVAILABLE)?;
    let namespace_url = format!("{}/api/v1/namespaces/{}", target.endpoint, target.namespace);
    let secret_url = format!(
        "{}/api/v1/namespaces/{}/secrets/{}",
        target.endpoint, target.namespace, target.secret_name
    );
    let namespace = read_json(
        client
            .get(&namespace_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| PROVIDER_UNAVAILABLE)?,
    )
    .await?;
    if namespace.get("apiVersion").and_then(Value::as_str) != Some("v1")
        || namespace.get("kind").and_then(Value::as_str) != Some("Namespace")
        || metadata_str(&namespace, "name") != Some(target.namespace.as_str())
        || metadata_str(&namespace, "uid") != Some(target.namespace_uid.as_str())
    {
        return Err(TARGET_MISMATCH);
    }
    let mut secret = read_json(
        client
            .get(&secret_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| PROVIDER_UNAVAILABLE)?,
    )
    .await?;
    verify_secret_metadata(&secret, target)?;
    let resource_version = metadata_str(&secret, "resourceVersion")
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(TARGET_MISMATCH)?
        .to_owned();

    let existing_marker = secret
        .get("metadata")
        .and_then(|metadata| metadata.get("annotations"))
        .and_then(|annotations| annotations.get(IDEMPOTENCY_ANNOTATION))
        .and_then(Value::as_str);
    let existing_value = secret
        .get("data")
        .and_then(|data| data.get(&target.data_key))
        .and_then(Value::as_str);
    let encoded_selected = match target.action {
        KubernetesAction::Deliver => {
            if Utc::now() >= inputs.expires_at || Instant::now() >= deadline {
                return Err(INVALID_POSTURE);
            }
            let selected = Zeroizing::new(release_selected()?);
            if selected.is_empty() || selected.len() > MAX_SELECTED_SECRET {
                return Err("selected credential is unavailable");
            }
            Some(Zeroizing::new(STANDARD.encode(&*selected)))
        }
        KubernetesAction::Revoke => None,
    };
    if existing_marker == Some(idempotency_key)
        && match &encoded_selected {
            Some(encoded) => existing_value == Some(encoded.as_str()),
            None => existing_value.is_none(),
        }
    {
        return Ok(match target.action {
            KubernetesAction::Deliver => KubernetesOutcome::DeliveryAcknowledged,
            KubernetesAction::Revoke => KubernetesOutcome::RevocationUnverified,
        });
    }

    let metadata = secret
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(TARGET_MISMATCH)?;
    let annotations = metadata.entry("annotations").or_insert_with(|| json!({}));
    let annotations = annotations.as_object_mut().ok_or(TARGET_MISMATCH)?;
    annotations.insert(
        IDEMPOTENCY_ANNOTATION.to_owned(),
        Value::String(idempotency_key.to_owned()),
    );
    metadata.insert(
        "resourceVersion".to_owned(),
        Value::String(resource_version.clone()),
    );
    let object = secret.as_object_mut().ok_or(TARGET_MISMATCH)?;
    let data = object.entry("data").or_insert_with(|| json!({}));
    let data = data.as_object_mut().ok_or(TARGET_MISMATCH)?;
    match encoded_selected {
        Some(encoded) => {
            data.insert(target.data_key.clone(), Value::String((*encoded).clone()));
        }
        None => {
            data.remove(&target.data_key);
        }
    }
    let body = Zeroizing::new(serde_json::to_vec(&secret).map_err(|_| PROVIDER_UNAVAILABLE)?);
    if body.len() > MAX_RESPONSE {
        return Err(PROVIDER_UNAVAILABLE);
    }
    write_started.store(true, Ordering::SeqCst);
    let response = client
        .put(&secret_url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body((*body).clone())
        .send()
        .await;
    let Ok(response) = response else {
        return Ok(KubernetesOutcome::OutcomeUnknown);
    };
    let response = match read_json(response).await {
        Ok(value) => value,
        Err(_) => return Ok(KubernetesOutcome::OutcomeUnknown),
    };
    if verify_secret_metadata(&response, target).is_err()
        || metadata_str(&response, "resourceVersion")
            .is_none_or(|version| version.is_empty() || version == resource_version)
        || response
            .get("metadata")
            .and_then(|metadata| metadata.get("annotations"))
            .and_then(|annotations| annotations.get(IDEMPOTENCY_ANNOTATION))
            .and_then(Value::as_str)
            != Some(idempotency_key)
        || match target.action {
            KubernetesAction::Deliver => {
                response
                    .get("data")
                    .and_then(|data| data.get(&target.data_key))
                    .and_then(Value::as_str)
                    != secret
                        .get("data")
                        .and_then(|data| data.get(&target.data_key))
                        .and_then(Value::as_str)
            }
            KubernetesAction::Revoke => response
                .get("data")
                .and_then(|data| data.get(&target.data_key))
                .is_some(),
        }
    {
        return Ok(KubernetesOutcome::OutcomeUnknown);
    }
    Ok(match target.action {
        KubernetesAction::Deliver => KubernetesOutcome::DeliveryAcknowledged,
        KubernetesAction::Revoke => KubernetesOutcome::RevocationUnverified,
    })
}

async fn read_json(mut response: reqwest::Response) -> Result<Value> {
    if response.status() != StatusCode::OK {
        return Err(PROVIDER_UNAVAILABLE);
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE as u64)
    {
        return Err(PROVIDER_UNAVAILABLE);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| PROVIDER_UNAVAILABLE)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(PROVIDER_UNAVAILABLE);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| PROVIDER_UNAVAILABLE)
}

fn metadata_str<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get("metadata")?.get(key)?.as_str()
}

fn verify_secret_metadata(secret: &Value, target: &KubernetesTarget) -> Result<()> {
    if secret.get("apiVersion").and_then(Value::as_str) != Some("v1")
        || secret.get("kind").and_then(Value::as_str) != Some("Secret")
        || metadata_str(secret, "name") != Some(target.secret_name.as_str())
        || metadata_str(secret, "namespace") != Some(target.namespace.as_str())
        || metadata_str(secret, "uid") != Some(target.secret_uid.as_str())
    {
        return Err(TARGET_MISMATCH);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    fn private_file(path: &std::path::Path, bytes: &[u8]) {
        crate::secure_files::write_private(path, bytes).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use std::ptr::null_mut;
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            };
            use windows_sys::Win32::Security::{
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
            };
            let principal = identity::current_principal().unwrap();
            let sid = principal.strip_prefix("windows-sid:").unwrap();
            let sddl: Vec<u16> = format!("O:{sid}").encode_utf16().chain(Some(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        null_mut(),
                    )
                },
                0
            );
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let applied =
                unsafe { SetFileSecurityW(wide.as_ptr(), OWNER_SECURITY_INFORMATION, descriptor) };
            unsafe { LocalFree(descriptor.cast()) };
            assert_ne!(applied, 0);
        }
    }

    fn certificates() -> (String, Arc<ServerConfig>) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        (ca_pem, Arc::new(config))
    }

    fn serve_response(stream: &mut StreamOwned<ServerConnection, TcpStream>, value: &Value) {
        let body = serde_json::to_vec(value).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
    }

    #[derive(Clone, Copy)]
    enum FakeMode {
        OneWrite,
        RepeatSameRevision,
        ChangedRevision,
    }

    fn run_fake_api(
        listener: TcpListener,
        config: Arc<ServerConfig>,
        target: KubernetesTarget,
        tamper_put: Option<&'static str>,
        revision_key: &'static str,
        mode: FakeMode,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let namespace_path = format!("/api/v1/namespaces/{}", target.namespace);
            let secret_path = format!(
                "/api/v1/namespaces/{}/secrets/{}",
                target.namespace, target.secret_name
            );
            let steps = if matches!(mode, FakeMode::RepeatSameRevision) {
                5
            } else {
                3
            };
            for step in 0..steps {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut received = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0 && received.len() + count < MAX_RESPONSE);
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(index) =
                        received.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8(received[..header_end].to_vec()).unwrap();
                assert!(
                    headers.contains("authorization: Bearer test-provider-token")
                        || headers.contains("Authorization: Bearer test-provider-token")
                );
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let lower = line.to_ascii_lowercase();
                        lower
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while received.len() < header_end + content_length {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0 && received.len() + count < MAX_RESPONSE);
                    received.extend_from_slice(&chunk[..count]);
                }
                let body: Value = if content_length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&received[header_end..header_end + content_length])
                        .unwrap()
                };
                let response = match step {
                    0 | 3 => {
                        assert!(headers.starts_with(&format!("GET {namespace_path} ")));
                        json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":target.namespace,"uid":target.namespace_uid}})
                    }
                    1 | 4 => {
                        assert!(headers.starts_with(&format!("GET {secret_path} ")));
                        let version = if step == 4 { "8" } else { "7" };
                        let mut value = json!({"apiVersion":"v1","kind":"Secret","type":"Opaque","metadata":{"name":target.secret_name,"namespace":target.namespace,"uid":target.secret_uid,"resourceVersion":version,"annotations":{"owner":"unchanged"}},"data":{"other":"b3RoZXI="}});
                        if step == 4 || matches!(mode, FakeMode::ChangedRevision) {
                            let marker = if step == 4 {
                                revision_key
                            } else {
                                "prior-revision"
                            };
                            value["metadata"]["annotations"][IDEMPOTENCY_ANNOTATION] =
                                json!(marker);
                            value["data"][&target.data_key] = if step == 4 {
                                json!(STANDARD.encode(b"synthetic-user-password"))
                            } else {
                                json!(STANDARD.encode(b"prior-password"))
                            };
                        }
                        value
                    }
                    _ => {
                        assert!(headers.starts_with(&format!("PUT {secret_path} ")));
                        assert_eq!(body["metadata"]["uid"], target.secret_uid);
                        assert_eq!(body["metadata"]["resourceVersion"], "7");
                        assert_eq!(body["metadata"]["annotations"]["owner"], "unchanged");
                        assert_eq!(body["data"]["other"], "b3RoZXI=");
                        assert_eq!(
                            body["data"][&target.data_key],
                            STANDARD.encode(b"synthetic-user-password")
                        );
                        let mut response = body;
                        response["metadata"]["resourceVersion"] = json!("8");
                        match tamper_put {
                            Some("missing") => {
                                response["data"]
                                    .as_object_mut()
                                    .unwrap()
                                    .remove(&target.data_key);
                            }
                            Some("changed") => {
                                response["data"][&target.data_key] = json!("Y2hhbmdlZA==");
                            }
                            _ => {}
                        }
                        response
                    }
                };
                serve_response(&mut stream, &response);
            }
        })
    }

    fn fixture(
        root: &std::path::Path,
        environment: &str,
    ) -> (KubernetesTarget, TcpListener, Arc<ServerConfig>) {
        let (ca_pem, config) = certificates();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let suffix = if environment == "env-a" { "1" } else { "2" };
        let ca_file = root.join(format!("{environment}-ca.pem"));
        let posture_file = root.join(format!("{environment}-posture.json"));
        private_file(&ca_file, ca_pem.as_bytes());
        let mut target = KubernetesTarget {
            endpoint,
            cluster_id: format!("cluster-{suffix}"),
            context: format!("context-{suffix}"),
            environment_id: environment.to_owned(),
            environment_owner: format!("owner-{suffix}"),
            consumer_id: format!("consumer-{suffix}"),
            issuer_id: format!("issuer-{suffix}"),
            namespace: format!("space-{suffix}"),
            namespace_uid: format!("10000000-0000-4000-8000-00000000000{suffix}"),
            secret_name: format!("secret-{suffix}"),
            secret_uid: format!("20000000-0000-4000-8000-00000000000{suffix}"),
            data_key: "database-password".to_owned(),
            ca_file,
            provider_credential_id: format!("30000000-0000-4000-8000-00000000000{suffix}"),
            posture_file,
            posture_public_key: String::new(),
            encryption_config_revision: format!("revision-{suffix}"),
            action: KubernetesAction::Deliver,
        };
        let rng = SystemRandom::new();
        let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).unwrap();
        target.posture_public_key = STANDARD_NO_PAD.encode(key.public_key().as_ref());
        let ca_hash =
            STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256, ca_pem.as_bytes()).as_ref());
        let now = Utc::now();
        let payload = serde_json::to_vec(&json!({
            "endpoint":target.endpoint,"ca_sha256":ca_hash,"cluster_id":target.cluster_id,
            "context":target.context,"environment_id":target.environment_id,
            "namespace_uid":target.namespace_uid,"secret_uid":target.secret_uid,
            "environment_owner":target.environment_owner,"consumer_id":target.consumer_id,
            "issuer_id":target.issuer_id,"encryption_config_revision":target.encryption_config_revision,
            "issued_at":now-chrono::Duration::minutes(1),"expires_at":now+chrono::Duration::minutes(30)
        })).unwrap();
        let envelope = json!({"payload":STANDARD_NO_PAD.encode(&payload),"signature":STANDARD_NO_PAD.encode(key.sign(&payload).as_ref())});
        private_file(
            &target.posture_file,
            serde_json::to_vec(&envelope).unwrap().as_slice(),
        );
        (target, listener, config)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn two_environment_https_delivery_is_scoped_and_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for environment in ["env-a", "env-b"] {
            let (target, listener, config) = fixture(&root, environment);
            let (revision, expiry) = target.snapshot_revision().unwrap();
            assert!(!revision.is_empty() && expiry > Utc::now());
            let mut wrong = target.clone();
            wrong.environment_id = "wrong-environment".into();
            assert_eq!(wrong.validate(), Err(INVALID_POSTURE));
            let server = run_fake_api(
                listener,
                config,
                target.clone(),
                None,
                "operation-credential-revision",
                FakeMode::OneWrite,
            );
            let (_, cancellation) = watch::channel(false);
            let outcome = execute(
                &target,
                "operation-credential-revision",
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(3),
                cancellation,
                || Ok(b"test-provider-token".to_vec()),
                || Ok(b"synthetic-user-password".to_vec()),
            )
            .await
            .unwrap();
            assert_eq!(outcome, KubernetesOutcome::DeliveryAcknowledged);
            server.join().unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_ack_requires_exact_selected_data() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for tamper in ["missing", "changed"] {
            let (target, listener, config) = fixture(&root, "env-a");
            let server = run_fake_api(
                listener,
                config,
                target.clone(),
                Some(tamper),
                "fixed-attempt-id",
                FakeMode::OneWrite,
            );
            let (_, cancellation) = watch::channel(false);
            let outcome = execute(
                &target,
                "fixed-attempt-id",
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(3),
                cancellation,
                || Ok(b"test-provider-token".to_vec()),
                || Ok(b"synthetic-user-password".to_vec()),
            )
            .await
            .unwrap();
            assert_eq!(outcome, KubernetesOutcome::OutcomeUnknown);
            server.join().unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_revision_skips_second_write_after_readback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (target, listener, config) = fixture(&root, "env-a");
        let server = run_fake_api(
            listener,
            config,
            target.clone(),
            None,
            "stable-credential-revision",
            FakeMode::RepeatSameRevision,
        );
        for _ in 0..2 {
            let (_, cancellation) = watch::channel(false);
            let outcome = execute(
                &target,
                "stable-credential-revision",
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(3),
                cancellation,
                || Ok(b"test-provider-token".to_vec()),
                || Ok(b"synthetic-user-password".to_vec()),
            )
            .await
            .unwrap();
            assert_eq!(outcome, KubernetesOutcome::DeliveryAcknowledged);
        }
        server.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn changed_revision_writes_again() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (target, listener, config) = fixture(&root, "env-a");
        let server = run_fake_api(
            listener,
            config,
            target.clone(),
            None,
            "new-credential-revision",
            FakeMode::ChangedRevision,
        );
        let (_, cancellation) = watch::channel(false);
        let outcome = execute(
            &target,
            "new-credential-revision",
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(3),
            cancellation,
            || Ok(b"test-provider-token".to_vec()),
            || Ok(b"synthetic-user-password".to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(outcome, KubernetesOutcome::DeliveryAcknowledged);
        server.join().unwrap();
    }
}
