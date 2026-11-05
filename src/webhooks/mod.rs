/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Standard Webhooks v1 verification for instance-authenticated callers.
 * Created: 2026-11-03
 * Last Modified: 2026-11-03
 */

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use ring::hmac;
use zeroize::Zeroizing;

use crate::core::Vault;
use crate::proxy::{INSTANCE_ID_HEADER, INSTANCE_SECRET_HEADER};

pub(crate) const VERIFY_PATH: &str = "/api/webhooks/verify";
const CREDENTIAL_ID_HEADER: &str = "x-wispkey-credential-id";
const WEBHOOK_ID_HEADER: &str = "webhook-id";
const WEBHOOK_TIMESTAMP_HEADER: &str = "webhook-timestamp";
const WEBHOOK_SIGNATURE_HEADER: &str = "webhook-signature";

const MAX_BODY_BYTES: usize = 1024 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WEBHOOK_ID_BYTES: usize = 256;
const MAX_SIGNATURE_HEADER_BYTES: usize = 4096;
const MAX_SIGNATURE_CANDIDATES: usize = 16;
/// 9999-12-31T23:59:59Z; keeps timestamp arithmetic far from `i64` limits.
const MAX_TIMESTAMP_SECONDS: i64 = 253_402_300_799;
const MAX_TIMESTAMP_DIGITS: usize = 12;
const TOLERANCE_SECONDS: i64 = 300;
const SIGNING_SECRET_PREFIX: &[u8] = b"whsec_";
const SIGNATURE_VERSION: &str = "v1";
const HMAC_SHA256_BYTES: usize = 32;

/// Semantic verification result. Only these values produce `200 OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookResult {
    Valid,
    Invalid,
    Stale,
}

impl WebhookResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Stale => "stale",
        }
    }
}

/// Fail-closed denials after the request passes boundary validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookDenial {
    /// Vault locked, session expired, storage or audit failure.
    Unavailable,
    /// Unknown, revoked or wrong instance identity.
    Unauthenticated,
    /// Credential absent, out of scope, wrong kind, or auth revoked or expired.
    Forbidden,
}

impl WebhookDenial {
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
        }
    }

    pub(crate) fn audit_reason(self) -> &'static str {
        match self {
            Self::Unavailable => "verifier_unavailable",
            Self::Unauthenticated => "instance_authentication_failed",
            Self::Forbidden => "credential_not_permitted",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "verifier unavailable",
            Self::Unauthenticated => "instance authentication failed",
            Self::Forbidden => "credential not permitted",
        }
    }
}

/// The stored credential value is not a `whsec_` + base64 signing secret.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidSigningSecret;

/// Boundary rejection of malformed webhook metadata.
#[derive(Debug, PartialEq, Eq)]
struct MalformedWebhook;

/// Validated Standard Webhooks metadata.
#[derive(Debug)]
struct WebhookHeaders {
    id: String,
    timestamp: String,
    timestamp_seconds: i64,
    signatures: Vec<[u8; HMAC_SHA256_BYTES]>,
}

impl WebhookHeaders {
    fn parse(id: &str, timestamp: &str, signature: &str) -> Result<Self, MalformedWebhook> {
        Ok(Self {
            id: parse_webhook_id(id)?.to_owned(),
            timestamp: timestamp.to_owned(),
            timestamp_seconds: parse_timestamp(timestamp)?,
            signatures: parse_signatures(signature)?,
        })
    }
}

/// One webhook delivery: validated metadata plus the exact raw body bytes.
pub(crate) struct SignedWebhook {
    headers: WebhookHeaders,
    body: Bytes,
}

impl SignedWebhook {
    /// True when the signed timestamp is within the tolerance of the trusted current time.
    pub(crate) fn is_fresh_at(&self, now_unix_seconds: i64) -> bool {
        now_unix_seconds
            .checked_sub(self.headers.timestamp_seconds)
            .is_some_and(|age| (-TOLERANCE_SECONDS..=TOLERANCE_SECONDS).contains(&age))
    }

    /// Uses constant-time HMAC comparison for each candidate until one matches.
    pub(crate) fn matches_signing_secret(
        &self,
        signing_secret: &[u8],
    ) -> Result<bool, InvalidSigningSecret> {
        let encoded_key = signing_secret
            .strip_prefix(SIGNING_SECRET_PREFIX)
            .ok_or(InvalidSigningSecret)?;
        let key_bytes = Zeroizing::new(
            BASE64
                .decode(encoded_key)
                .map_err(|_| InvalidSigningSecret)?,
        );
        if key_bytes.is_empty() {
            return Err(InvalidSigningSecret);
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let message = self.signed_content();
        Ok(self
            .headers
            .signatures
            .iter()
            .any(|signature| hmac::verify(&key, &message, signature).is_ok()))
    }

    /// `id + "." + timestamp + "." + body` over raw bytes; the body is never decoded.
    fn signed_content(&self) -> Vec<u8> {
        let headers = &self.headers;
        let mut message =
            Vec::with_capacity(headers.id.len() + headers.timestamp.len() + self.body.len() + 2);
        message.extend_from_slice(headers.id.as_bytes());
        message.push(b'.');
        message.extend_from_slice(headers.timestamp.as_bytes());
        message.push(b'.');
        message.extend_from_slice(&self.body);
        message
    }
}

fn parse_webhook_id(id: &str) -> Result<&str, MalformedWebhook> {
    let printable_ascii = id.bytes().all(|byte| (b' '..=b'~').contains(&byte));
    if id.is_empty() || id.len() > MAX_WEBHOOK_ID_BYTES || !printable_ascii {
        return Err(MalformedWebhook);
    }
    Ok(id)
}

/// Strict canonical non-negative Unix seconds: digits only, no sign, no leading zero.
fn parse_timestamp(timestamp: &str) -> Result<i64, MalformedWebhook> {
    let canonical_digits = !timestamp.is_empty()
        && timestamp.len() <= MAX_TIMESTAMP_DIGITS
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && (timestamp == "0" || !timestamp.starts_with('0'));
    if !canonical_digits {
        return Err(MalformedWebhook);
    }
    timestamp
        .parse::<i64>()
        .ok()
        .filter(|seconds| *seconds <= MAX_TIMESTAMP_SECONDS)
        .ok_or(MalformedWebhook)
}

/// Space-separated `v1,<base64 HMAC-SHA256>` candidates. Any unsupported or
/// malformed candidate rejects the whole header.
fn parse_signatures(header: &str) -> Result<Vec<[u8; HMAC_SHA256_BYTES]>, MalformedWebhook> {
    if header.is_empty() || header.len() > MAX_SIGNATURE_HEADER_BYTES {
        return Err(MalformedWebhook);
    }
    let candidates: Vec<&str> = header.split(' ').collect();
    if candidates.len() > MAX_SIGNATURE_CANDIDATES {
        return Err(MalformedWebhook);
    }
    candidates
        .into_iter()
        .map(|candidate| {
            let (version, encoded) = candidate.split_once(',').ok_or(MalformedWebhook)?;
            if version != SIGNATURE_VERSION {
                return Err(MalformedWebhook);
            }
            let decoded = BASE64.decode(encoded).map_err(|_| MalformedWebhook)?;
            <[u8; HMAC_SHA256_BYTES]>::try_from(decoded.as_slice()).map_err(|_| MalformedWebhook)
        })
        .collect()
}

/// Exactly one non-empty, visible-ASCII value for the header.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok().filter(|value| !value.is_empty())
}

/// Canonical lowercase hyphenated non-nil UUID, as WispKey stores credential IDs.
fn parse_credential_id(value: &str) -> Option<&str> {
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.hyphenated().to_string() == value).then_some(value)
}

fn response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");
    if status == StatusCode::METHOD_NOT_ALLOWED {
        builder = builder.header("allow", "POST");
    }
    builder
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("webhook response must build")
}

fn error(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    response(status, serde_json::json!({ "error": message }))
}

fn denial(denial: WebhookDenial) -> Response<Full<Bytes>> {
    error(denial.status(), denial.message())
}

/// Handles `POST /api/webhooks/verify`. Never returns the signing key, the body
/// or the signatures. No CORS headers: this is not a browser API.
pub(crate) async fn handle_verify_request(
    request: Request<Incoming>,
    project_scope: Option<String>,
) -> Response<Full<Bytes>> {
    if request.method() != Method::POST {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let headers = request.headers();
    if request.uri().query().is_some()
        || request.uri().authority().is_some()
        || headers.contains_key("origin")
    {
        return error(StatusCode::BAD_REQUEST, "malformed verification request");
    }
    let (Some(instance_id), Some(instance_secret)) = (
        single_header(headers, INSTANCE_ID_HEADER),
        single_header(headers, INSTANCE_SECRET_HEADER),
    ) else {
        if let Ok(vault) = Vault::open_with_session() {
            vault.audit_webhook_denial(WebhookDenial::Unauthenticated, None);
        }
        return denial(WebhookDenial::Unauthenticated);
    };
    let Some(credential_id) =
        single_header(headers, CREDENTIAL_ID_HEADER).and_then(parse_credential_id)
    else {
        return error(StatusCode::BAD_REQUEST, "malformed verification request");
    };
    let parsed_headers = match (
        single_header(headers, WEBHOOK_ID_HEADER),
        single_header(headers, WEBHOOK_TIMESTAMP_HEADER),
        single_header(headers, WEBHOOK_SIGNATURE_HEADER),
    ) {
        (Some(id), Some(timestamp), Some(signature)) => {
            WebhookHeaders::parse(id, timestamp, signature)
        }
        _ => Err(MalformedWebhook),
    };
    let Ok(webhook_headers) = parsed_headers else {
        return error(StatusCode::BAD_REQUEST, "malformed verification request");
    };
    let declared_length = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared_length.is_some_and(|length| length > MAX_BODY_BYTES as u64) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "webhook body too large");
    }
    let credential_id = credential_id.to_owned();
    let instance_id = instance_id.to_owned();
    let instance_secret = Zeroizing::new(instance_secret.to_owned());

    {
        let Ok(vault) = Vault::open_with_session() else {
            return denial(WebhookDenial::Unavailable);
        };
        if let Err(rejection) = vault.authenticate_webhook_instance(&instance_id, &instance_secret)
        {
            return denial(rejection);
        }
    }

    let body = match tokio::time::timeout(
        BODY_READ_TIMEOUT,
        Limited::new(request.into_body(), MAX_BODY_BYTES).collect(),
    )
    .await
    {
        Err(_elapsed) => return error(StatusCode::REQUEST_TIMEOUT, "webhook body timed out"),
        Ok(Err(read_error)) if read_error.downcast_ref::<LengthLimitError>().is_some() => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "webhook body too large");
        }
        Ok(Err(_)) => return error(StatusCode::BAD_REQUEST, "malformed verification request"),
        Ok(Ok(collected)) => collected.to_bytes(),
    };

    let webhook = SignedWebhook {
        headers: webhook_headers,
        body,
    };
    // Body collection yields. Reopen the session and authenticate again so lock,
    // expiry and instance-secret changes during upload cannot retain authority.
    let Ok(mut vault) = Vault::open_with_session() else {
        return denial(WebhookDenial::Unavailable);
    };
    let instance = match vault.authenticate_webhook_instance(&instance_id, &instance_secret) {
        Ok(instance) => instance,
        Err(rejection) => return denial(rejection),
    };
    // Authentication performs password hashing. Revalidate the session after
    // that work as well; this reload does not extend its deadline.
    if vault.restore_or_refresh_session(None).is_err() {
        return denial(WebhookDenial::Unavailable);
    }
    match vault.verify_webhook(
        &instance,
        &credential_id,
        project_scope.as_deref(),
        &webhook,
    ) {
        Ok(result) => response(
            StatusCode::OK,
            serde_json::json!({ "result": result.as_str() }),
        ),
        Err(rejection) => denial(rejection),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published Standard Webhooks reference vector.
    const VECTOR_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const VECTOR_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const VECTOR_TIMESTAMP: &str = "1614265330";
    const VECTOR_BODY: &[u8] = br#"{"test": 2432232314}"#;
    const VECTOR_SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    const OTHER_SIGNATURE: &str = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn webhook(id: &str, timestamp: &str, signature: &str, body: &'static [u8]) -> SignedWebhook {
        SignedWebhook {
            headers: WebhookHeaders::parse(id, timestamp, signature).expect("valid headers"),
            body: Bytes::from_static(body),
        }
    }

    #[test]
    fn reference_vector_matches_only_exact_signed_content() {
        let second_candidate = format!("{OTHER_SIGNATURE} {VECTOR_SIGNATURE}");
        let (id, ts, sig, body) = (VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_SIGNATURE, VECTOR_BODY);
        let cases: [(&str, &str, &str, &'static [u8], bool); 6] = [
            (id, ts, sig, body, true),
            (id, ts, &second_candidate, body, true),
            ("msg_other", ts, sig, body, false),
            (id, "1614265331", sig, body, false),
            (id, ts, sig, br#"{"test":2432232314}"#, false),
            (id, ts, OTHER_SIGNATURE, body, false),
        ];
        for (id, timestamp, signature, body, expected) in cases {
            let delivery = webhook(id, timestamp, signature, body);
            assert_eq!(
                delivery.matches_signing_secret(VECTOR_SECRET),
                Ok(expected),
                "id={id} timestamp={timestamp}"
            );
        }
    }

    #[test]
    fn signing_secret_requires_whsec_base64() {
        let delivery = webhook(VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_SIGNATURE, VECTOR_BODY);
        for secret in [
            &b"MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"[..],
            b"whsec_",
            b"whsec_not base64!",
            b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\n",
        ] {
            assert_eq!(
                delivery.matches_signing_secret(secret),
                Err(InvalidSigningSecret)
            );
        }
    }

    #[test]
    fn freshness_boundaries_are_inclusive_at_tolerance() {
        let delivery = webhook(VECTOR_ID, VECTOR_TIMESTAMP, VECTOR_SIGNATURE, VECTOR_BODY);
        let signed_at = 1_614_265_330_i64;
        for (offset, fresh) in [
            (0, true),
            (300, true),
            (-300, true),
            (301, false),
            (-301, false),
        ] {
            let now = signed_at + offset;
            assert_eq!(delivery.is_fresh_at(now), fresh, "offset={offset}");
        }
        assert!(!delivery.is_fresh_at(i64::MIN));
    }

    #[test]
    fn timestamp_parser_accepts_only_canonical_bounded_seconds() {
        assert_eq!(parse_timestamp("0"), Ok(0));
        assert_eq!(parse_timestamp("253402300799"), Ok(MAX_TIMESTAMP_SECONDS));
        for rejected in [
            "",
            "-1",
            "+1",
            "01",
            " 1",
            "1.5",
            "1e9",
            "253402300800",
            "9999999999999",
            "99999999999999999999",
        ] {
            assert_eq!(
                parse_timestamp(rejected),
                Err(MalformedWebhook),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn signature_parser_rejects_unsupported_and_oversized_headers() {
        let sixteen = vec![OTHER_SIGNATURE; MAX_SIGNATURE_CANDIDATES].join(" ");
        assert_eq!(parse_signatures(&sixteen).map(|list| list.len()), Ok(16));
        let seventeen = vec![OTHER_SIGNATURE; MAX_SIGNATURE_CANDIDATES + 1].join(" ");
        let oversized = format!("v1,{}", "A".repeat(MAX_SIGNATURE_HEADER_BYTES));
        for rejected in [
            "",
            "v1",
            "v1,",
            "v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            "v1a,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            "v1,not-base64!",
            "v1,AAAA",
            "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE= ",
            &seventeen,
            &oversized,
        ] {
            assert_eq!(
                parse_signatures(rejected),
                Err(MalformedWebhook),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn webhook_id_parser_bounds_length_and_bytes() {
        let longest = "m".repeat(MAX_WEBHOOK_ID_BYTES);
        assert_eq!(parse_webhook_id(&longest), Ok(longest.as_str()));
        let too_long = "m".repeat(MAX_WEBHOOK_ID_BYTES + 1);
        for rejected in ["", too_long.as_str(), "msg\tid", "msg\u{e9}"] {
            assert_eq!(
                parse_webhook_id(rejected),
                Err(MalformedWebhook),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn credential_id_must_be_canonical_non_nil_uuid() {
        let canonical = "0f8fad5b-d9cb-469f-a165-70867728950e";
        assert_eq!(parse_credential_id(canonical), Some(canonical));
        for rejected in [
            "00000000-0000-0000-0000-000000000000",
            "0F8FAD5B-D9CB-469F-A165-70867728950E",
            "0f8fad5bd9cb469fa16570867728950e",
            "{0f8fad5b-d9cb-469f-a165-70867728950e}",
            "openai-key",
        ] {
            assert_eq!(parse_credential_id(rejected), None, "{rejected:?}");
        }
    }
}
