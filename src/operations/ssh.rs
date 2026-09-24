//! In-process, pinned SSH transport for one restricted helper invocation.
//! The caller must reserve the one-use grant and persist `started` before calling this module.
//! No SSH config, agent, proxy, shell argument, forwarding, or terminal is consulted.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use russh::ChannelMsg;
use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;

use super::catalog::SshTarget;

const MAX_LINE: usize = 1024;
const MAX_OUTPUT: usize = 2048;
const MAX_SECRET: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SshOutcome {
    Succeeded,
    FailedChild,
    TimedOut,
    Canceled,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SshResult {
    pub outcome: SshOutcome,
    pub exit_code: Option<i32>,
}

impl SshResult {
    fn new(outcome: SshOutcome) -> Self {
        Self {
            outcome,
            exit_code: None,
        }
    }
}

#[derive(Clone)]
struct PinnedHost(String);

impl client::Handler for PinnedHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Certificates are a different trust model and cannot satisfy a raw-key pin.
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            return Ok(false);
        };
        Ok(key.algorithm().as_str() == "ssh-ed25519"
            && key.fingerprint(HashAlg::Sha256).to_string() == self.0)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Hello<'a> {
    version: u8,
    attempt_id: &'a str,
    phase: &'static str,
    remaining_ms: u64,
    deadline_unix_ms: i64,
}

#[derive(Serialize)]
struct Delivery<'a> {
    version: u8,
    attempt_id: &'a str,
    phase: &'static str,
    credential_b64: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    attempt_id: String,
    phase: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u8,
    attempt_id: String,
    outcome: String,
    count: u32,
    exit_code: RequiredExitCode,
}

// A protocol v1 completion must explicitly carry null when no child exit code
// exists. An older helper omitting the field is not a valid acknowledgement.
struct RequiredExitCode(Option<i32>);

impl<'de> Deserialize<'de> for RequiredExitCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Null => Ok(Self(None)),
            serde_json::Value::Number(number) => number
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .map(|code| Self(Some(code)))
                .ok_or_else(|| serde::de::Error::custom("invalid child exit code")),
            _ => Err(serde::de::Error::custom("invalid child exit code")),
        }
    }
}

#[derive(Default)]
struct Output {
    line: Vec<u8>,
    total: usize,
}

impl Output {
    fn append(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.total = self.total.checked_add(data.len()).ok_or(())?;
        if self.total > MAX_OUTPUT {
            return Err(());
        }
        for (index, byte) in data.iter().enumerate() {
            if *byte == b'\n' {
                if index + 1 != data.len() || self.line.len() > MAX_LINE {
                    return Err(());
                }
                return Ok(Some(std::mem::take(&mut self.line)));
            }
            if !byte.is_ascii() || *byte == b'\r' || *byte < b' ' {
                return Err(());
            }
            self.line.push(*byte);
            if self.line.len() > MAX_LINE {
                return Err(());
            }
        }
        Ok(None)
    }
}

enum Stop {
    Timeout,
    Cancel,
}

async fn guarded<T>(
    future: impl Future<Output = T>,
    deadline: Instant,
    cancel: &mut watch::Receiver<bool>,
) -> Result<T, Stop> {
    if *cancel.borrow() {
        return Err(Stop::Cancel);
    }
    tokio::select! {
        biased;
        _ = cancel.changed() => Err(Stop::Cancel),
        _ = tokio::time::sleep_until(deadline) => Err(Stop::Timeout),
        value = future => Ok(value),
    }
}

fn stopped(stop: Stop, released: bool) -> SshResult {
    if released {
        SshResult::new(SshOutcome::OutcomeUnknown)
    } else {
        SshResult::new(match stop {
            Stop::Timeout => SshOutcome::TimedOut,
            Stop::Cancel => SshOutcome::Canceled,
        })
    }
}

/// Run one already-authorized attempt. `load_secret` is invoked only after the
/// pinned host, fixed account, and versioned helper-ready message are verified.
/// Its error must be a fixed code; neither it nor SSH diagnostics are returned.
pub(crate) async fn execute<F>(
    target: &SshTarget,
    attempt_id: &str,
    deadline: Instant,
    connect_timeout: Duration,
    mut cancel: watch::Receiver<bool>,
    load_secret: F,
) -> SshResult
where
    F: FnOnce() -> Result<Vec<u8>, &'static str>,
{
    if uuid::Uuid::parse_str(attempt_id).is_err()
        || target.host_key_algorithm != "ssh-ed25519"
        || !target.host_key_sha256.starts_with("SHA256:")
        || connect_timeout.is_zero()
        || Instant::now() >= deadline
    {
        return SshResult::new(SshOutcome::FailedChild);
    }
    // A caller cannot accidentally extend execution past the contract's maximum.
    let deadline = deadline.min(Instant::now() + Duration::from_secs(60));
    let connect_deadline = deadline.min(Instant::now() + connect_timeout);
    let address = SocketAddr::new(target.address, target.port);
    let config = Arc::new(client::Config::default());
    let host = PinnedHost(target.host_key_sha256.clone());
    let mut session = match guarded(
        client::connect(config, address, host),
        connect_deadline,
        &mut cancel,
    )
    .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(_)) => return SshResult::new(SshOutcome::FailedChild),
        Err(stop) => return stopped(stop, false),
    };
    // Only the catalog's dedicated identity is read. No SSH agent or password fallback.
    let pem =
        match super::identity::read_private_catalog(std::path::Path::new(&target.identity_file)) {
            Ok(pem) => Zeroizing::new(pem),
            Err(_) => return SshResult::new(SshOutcome::FailedChild),
        };
    let key = match russh::keys::decode_secret_key(&pem, None) {
        Ok(key) => Arc::new(key),
        Err(_) => return SshResult::new(SshOutcome::FailedChild),
    };
    let auth = guarded(
        session.authenticate_publickey(&target.account, PrivateKeyWithHashAlg::new(key, None)),
        connect_deadline,
        &mut cancel,
    )
    .await;
    match auth {
        Ok(Ok(result)) if result.success() => {}
        Ok(_) => return SshResult::new(SshOutcome::FailedChild),
        Err(stop) => return stopped(stop, false),
    }
    let mut channel = match guarded(
        session.channel_open_session(),
        connect_deadline,
        &mut cancel,
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        Ok(_) => return SshResult::new(SshOutcome::FailedChild),
        Err(stop) => return stopped(stop, false),
    };
    // SSH exec sends exactly one catalog path. POSIX SSH servers usually pass
    // this to a shell; its restricted ASCII path grammar makes it one token.
    match guarded(
        channel.exec(true, target.helper_path.as_bytes()),
        connect_deadline,
        &mut cancel,
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(_) => return SshResult::new(SshOutcome::FailedChild),
        Err(stop) => return stopped(stop, false),
    }
    let remaining_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(60_000) as u64;
    if remaining_ms == 0 {
        return SshResult::new(SshOutcome::TimedOut);
    }
    let deadline_unix_ms = chrono::Utc::now()
        .timestamp_millis()
        .saturating_add(remaining_ms as i64);
    let mut hello = match serde_json::to_vec(&Hello {
        version: 1,
        attempt_id,
        phase: "hello",
        remaining_ms,
        deadline_unix_ms,
    }) {
        Ok(line) => line,
        Err(_) => return SshResult::new(SshOutcome::FailedChild),
    };
    hello.push(b'\n');
    match guarded(channel.data_bytes(hello), connect_deadline, &mut cancel).await {
        Ok(Ok(())) => {}
        Ok(_) => return SshResult::new(SshOutcome::FailedChild),
        Err(stop) => return stopped(stop, false),
    }
    let mut output = Output::default();
    let ready = loop {
        let event = guarded(channel.wait(), connect_deadline, &mut cancel).await;
        match event {
            Ok(Some(ChannelMsg::Data { data })) => match output.append(&data) {
                Ok(Some(line)) => {
                    if serde_json::from_slice::<Completion>(&line).is_ok_and(|reply| {
                        reply.version == 1
                            && reply.attempt_id == attempt_id
                            && reply.outcome == "outcome_unknown"
                            && reply.count == 0
                            && reply.exit_code.0.is_none()
                    }) {
                        return SshResult::new(SshOutcome::OutcomeUnknown);
                    }
                    break serde_json::from_slice::<Ready>(&line).ok();
                }
                Ok(None) => {}
                Err(_) => return SshResult::new(SshOutcome::FailedChild),
            },
            Ok(Some(ChannelMsg::ExtendedData { .. }))
            | Ok(Some(ChannelMsg::Failure))
            | Ok(Some(ChannelMsg::Close))
            | Ok(None) => return SshResult::new(SshOutcome::FailedChild),
            Ok(Some(ChannelMsg::Success)) => {}
            Ok(Some(_)) => return SshResult::new(SshOutcome::FailedChild),
            Err(stop) => return stopped(stop, false),
        }
    };
    if !matches!(ready, Some(Ready { version: 1, attempt_id: ref ready_attempt_id, ref phase }) if ready_attempt_id == attempt_id && phase == "ready")
    {
        return SshResult::new(SshOutcome::FailedChild);
    }
    if *cancel.borrow() {
        return SshResult::new(SshOutcome::Canceled);
    }
    if Instant::now() >= deadline {
        return SshResult::new(SshOutcome::TimedOut);
    }
    let mut secret = match load_secret() {
        Ok(secret) if !secret.is_empty() && secret.len() <= MAX_SECRET => Zeroizing::new(secret),
        _ => return SshResult::new(SshOutcome::FailedChild),
    };
    if *cancel.borrow() {
        return SshResult::new(SshOutcome::Canceled);
    }
    if Instant::now() >= deadline {
        return SshResult::new(SshOutcome::TimedOut);
    }
    let encoded = Zeroizing::new(STANDARD.encode(&secret));
    let mut delivery = match serde_json::to_vec(&Delivery {
        version: 1,
        attempt_id,
        phase: "deliver",
        credential_b64: &encoded,
    }) {
        Ok(line) => Zeroizing::new(line),
        Err(_) => return SshResult::new(SshOutcome::FailedChild),
    };
    secret.fill(0);
    delivery.push(b'\n');
    // Once this write starts, an absent acknowledgement leaves a remote outcome unknown.
    let send = guarded(
        channel.data(std::io::Cursor::new(delivery.as_slice())),
        deadline,
        &mut cancel,
    )
    .await;
    match send {
        Ok(Ok(())) => {}
        Ok(_) => return SshResult::new(SshOutcome::OutcomeUnknown),
        Err(stop) => {
            best_effort_cancel(&channel, attempt_id, deadline).await;
            return stopped(stop, true);
        }
    }
    let mut completion: Option<Completion> = None;
    let mut helper_exit_code: Option<i32> = None;
    loop {
        let event = guarded(channel.wait(), deadline, &mut cancel).await;
        match event {
            Ok(Some(ChannelMsg::Data { data })) if completion.is_none() => {
                match output.append(&data) {
                    Ok(Some(line)) => {
                        let parsed = serde_json::from_slice::<Completion>(&line).ok();
                        if !matches!(&parsed, Some(c) if c.version == 1 && c.attempt_id == attempt_id && matches!(c.outcome.as_str(), "succeeded" | "failed_child" | "outcome_unknown") && match c.outcome.as_str() {
                            "succeeded" => c.count == 1 && c.exit_code.0 == Some(0),
                            "failed_child" => c.count == 0 && c.exit_code.0.is_none_or(|code| (1..=255).contains(&code)),
                            "outcome_unknown" => c.count == 0 && c.exit_code.0.is_none(),
                            _ => false,
                        }) {
                            return SshResult::new(SshOutcome::OutcomeUnknown);
                        }
                        completion = parsed;
                    }
                    Ok(None) => {}
                    Err(_) => return SshResult::new(SshOutcome::OutcomeUnknown),
                }
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status }))
                if helper_exit_code.is_none() && exit_status <= i32::MAX as u32 =>
            {
                helper_exit_code = Some(exit_status as i32)
            }
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(ChannelMsg::ExtendedData { .. }))
            | Ok(Some(ChannelMsg::Data { .. }))
            | Ok(Some(ChannelMsg::ExitSignal { .. }))
            | Ok(Some(ChannelMsg::Failure)) => return SshResult::new(SshOutcome::OutcomeUnknown),
            Ok(Some(_)) => {}
            Err(stop) => {
                best_effort_cancel(&channel, attempt_id, deadline).await;
                return stopped(stop, true);
            }
        }
    }
    if !output.line.is_empty() {
        return SshResult::new(SshOutcome::OutcomeUnknown);
    }
    match (completion, helper_exit_code) {
        (Some(c), Some(0)) if c.outcome == "succeeded" => SshResult {
            outcome: SshOutcome::Succeeded,
            exit_code: c.exit_code.0,
        },
        (Some(c), Some(1)) if c.outcome == "failed_child" => SshResult {
            outcome: SshOutcome::FailedChild,
            exit_code: c.exit_code.0,
        },
        (Some(c), Some(1)) if c.outcome == "outcome_unknown" => {
            SshResult::new(SshOutcome::OutcomeUnknown)
        }
        _ => SshResult::new(SshOutcome::OutcomeUnknown),
    }
}

async fn best_effort_cancel(
    channel: &russh::Channel<client::Msg>,
    attempt_id: &str,
    deadline: Instant,
) {
    let line = serde_json::to_vec(
        &serde_json::json!({"version":1,"attempt_id":attempt_id,"phase":"cancel"}),
    )
    .unwrap_or_default();
    let mut line = line;
    line.push(b'\n');
    let until = deadline.min(Instant::now() + Duration::from_millis(100));
    let _ = timeout_at(until, channel.data_bytes(line)).await;
    let _ = timeout_at(until, channel.eof()).await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use russh::{Channel, ChannelId, server};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FixtureServer {
        received: Arc<AtomicUsize>,
        helper_ready: bool,
        pending: Vec<u8>,
        saw_secret: Arc<AtomicBool>,
        emit_canary: bool,
        expected_secret: Vec<u8>,
        child_outcome: &'static str,
        child_exit_code: Option<i32>,
    }

    #[test]
    fn completion_requires_explicit_exit_code_field() {
        let missing = br#"{"version":1,"attempt_id":"5af05c13-1c0a-4394-a7a3-7f457ff74a40","outcome":"outcome_unknown","count":0}"#;
        assert!(serde_json::from_slice::<Completion>(missing).is_err());
        let unknown = br#"{"version":1,"attempt_id":"5af05c13-1c0a-4394-a7a3-7f457ff74a40","outcome":"outcome_unknown","count":0,"exit_code":null}"#;
        assert!(
            serde_json::from_slice::<Completion>(unknown)
                .unwrap()
                .exit_code
                .0
                .is_none()
        );
    }

    pub(crate) struct SuccessFixture {
        pub target: SshTarget,
        pub received: Arc<AtomicUsize>,
        pub saw_secret: Arc<AtomicBool>,
        pub server_task: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }

    pub(crate) async fn spawn_success_fixture(expected_secret: Vec<u8>) -> SuccessFixture {
        spawn_fixture(expected_secret, "succeeded", Some(0)).await
    }

    async fn spawn_fixture(
        expected_secret: Vec<u8>,
        child_outcome: &'static str,
        child_exit_code: Option<i32>,
    ) -> SuccessFixture {
        let host_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let client_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let directory = tempfile::tempdir().unwrap();
        // macOS temp paths can contain /var -> /private/var; the production
        // private-file reader correctly refuses any linked path component.
        let identity = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("restricted_key");
        std::fs::write(
            &identity,
            client_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        private_test_file(&identity);
        let mut server_config = server::Config::default();
        server_config.keys.push(host_key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let saw_secret = Arc::new(AtomicBool::new(false));
        let received_server = received.clone();
        let saw_secret_server = saw_secret.clone();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                Arc::new(server_config),
                socket,
                FixtureServer {
                    received: received_server,
                    helper_ready: false,
                    pending: Vec::new(),
                    saw_secret: saw_secret_server,
                    emit_canary: false,
                    expected_secret,
                    child_outcome,
                    child_exit_code,
                },
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        let target = SshTarget {
            address: address.ip(),
            port: address.port(),
            account: "restricted".into(),
            host_key_algorithm: "ssh-ed25519".into(),
            host_key_sha256: fingerprint,
            helper_path: "/usr/local/libexec/wispkey-helper".into(),
            identity_file: identity.to_string_lossy().into_owned(),
        };
        SuccessFixture {
            target,
            received,
            saw_secret,
            server_task,
            _directory: directory,
        }
    }

    impl server::Handler for FixtureServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            account: &str,
            _: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            Ok(if account == "restricted" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            _: Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if command == b"/usr/local/libexec/wispkey-helper" {
                session.channel_success(channel)?;
            } else {
                session.channel_failure(channel)?;
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.received.fetch_add(data.len(), Ordering::SeqCst);
            self.pending.extend_from_slice(data);
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: serde_json::Value = serde_json::from_slice(&self.pending[..end]).unwrap();
                self.pending.drain(..=end);
                if !self.helper_ready {
                    assert_eq!(line["phase"], "hello");
                    self.helper_ready = true;
                    let ready = format!(
                        "{{\"version\":1,\"attempt_id\":\"{}\",\"phase\":\"ready\"}}\n",
                        line["attempt_id"].as_str().unwrap()
                    );
                    session.data(channel, ready.into_bytes())?;
                } else {
                    assert_eq!(line["phase"], "deliver");
                    let secret = STANDARD
                        .decode(line["credential_b64"].as_str().unwrap())
                        .unwrap();
                    self.saw_secret
                        .store(secret == self.expected_secret, Ordering::SeqCst);
                    if self.emit_canary {
                        session.extended_data(channel, 1, b"synthetic-stderr-canary".to_vec())?;
                    } else {
                        let completion = format!(
                            "{{\"version\":1,\"attempt_id\":\"{}\",\"outcome\":\"{}\",\"count\":{},\"exit_code\":{}}}\n",
                            line["attempt_id"].as_str().unwrap(),
                            self.child_outcome,
                            if self.child_outcome == "succeeded" {
                                1
                            } else {
                                0
                            },
                            serde_json::to_string(&self.child_exit_code).unwrap(),
                        );
                        session.data(channel, completion.into_bytes())?;
                    }
                    session.exit_status_request(
                        channel,
                        if self.child_outcome == "succeeded" {
                            0
                        } else {
                            1
                        },
                    )?;
                    session.close(channel)?;
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn mismatched_live_host_key_never_invokes_secret_callback() {
        let host_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let wrong_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let mut server_config = server::Config::default();
        server_config.keys.push(host_key);
        let server_config = Arc::new(server_config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let received_server = received.clone();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                server_config,
                socket,
                FixtureServer {
                    received: received_server,
                    helper_ready: false,
                    pending: Vec::new(),
                    saw_secret: Arc::new(AtomicBool::new(false)),
                    emit_canary: false,
                    expected_secret: b"synthetic-secret-canary".to_vec(),
                    child_outcome: "succeeded",
                    child_exit_code: Some(0),
                },
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        let target = SshTarget {
            address: address.ip(),
            port: address.port(),
            account: "restricted".into(),
            host_key_algorithm: "ssh-ed25519".into(),
            host_key_sha256: wrong_key
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            helper_path: "/usr/local/libexec/wispkey-helper".into(),
            identity_file: "/not/read/when/host/rejected".into(),
        };
        let called = AtomicBool::new(false);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let result = execute(
            &target,
            "5af05c13-1c0a-4394-a7a3-7f457ff74a40",
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(3),
            cancel_rx,
            || {
                called.store(true, Ordering::SeqCst);
                Ok(b"synthetic-secret-canary".to_vec())
            },
        )
        .await;
        assert_eq!(result.outcome, SshOutcome::FailedChild);
        assert!(!called.load(Ordering::SeqCst));
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
        assert_eq!(received.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pinned_host_and_ready_helper_receive_only_stdin_credential() {
        let host_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let client_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let directory = tempfile::tempdir().unwrap();
        let identity = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("restricted_key");
        std::fs::write(
            &identity,
            client_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        private_test_file(&identity);
        let mut server_config = server::Config::default();
        server_config.keys.push(host_key);
        let server_config = Arc::new(server_config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let saw_secret = Arc::new(AtomicBool::new(false));
        let received_server = received.clone();
        let saw_secret_server = saw_secret.clone();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                server_config,
                socket,
                FixtureServer {
                    received: received_server,
                    helper_ready: false,
                    pending: Vec::new(),
                    saw_secret: saw_secret_server,
                    emit_canary: false,
                    expected_secret: b"synthetic-secret-canary".to_vec(),
                    child_outcome: "succeeded",
                    child_exit_code: Some(0),
                },
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        let target = SshTarget {
            address: address.ip(),
            port: address.port(),
            account: "restricted".into(),
            host_key_algorithm: "ssh-ed25519".into(),
            host_key_sha256: fingerprint,
            helper_path: "/usr/local/libexec/wispkey-helper".into(),
            identity_file: identity.to_string_lossy().into_owned(),
        };
        let called = AtomicBool::new(false);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let result = execute(
            &target,
            "5af05c13-1c0a-4394-a7a3-7f457ff74a40",
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(5),
            cancel_rx,
            || {
                called.store(true, Ordering::SeqCst);
                Ok(b"synthetic-secret-canary".to_vec())
            },
        )
        .await;
        assert_eq!(
            result,
            SshResult {
                outcome: SshOutcome::Succeeded,
                exit_code: Some(0)
            }
        );
        assert!(called.load(Ordering::SeqCst));
        assert!(saw_secret.load(Ordering::SeqCst));
        assert!(received.load(Ordering::SeqCst) > 0);
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
    }

    #[tokio::test]
    async fn child_exit_code_comes_from_completion_not_helper_status() {
        for (outcome, child_code, expected) in [
            (
                "failed_child",
                Some(42),
                SshResult {
                    outcome: SshOutcome::FailedChild,
                    exit_code: Some(42),
                },
            ),
            (
                "outcome_unknown",
                None,
                SshResult {
                    outcome: SshOutcome::OutcomeUnknown,
                    exit_code: None,
                },
            ),
        ] {
            let fixture =
                spawn_fixture(b"synthetic-secret-canary".to_vec(), outcome, child_code).await;
            let (_cancel_tx, cancel_rx) = watch::channel(false);
            let result = execute(
                &fixture.target,
                "5af05c13-1c0a-4394-a7a3-7f457ff74a40",
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(5),
                cancel_rx,
                || Ok(b"synthetic-secret-canary".to_vec()),
            )
            .await;
            assert_eq!(result, expected);
            assert!(fixture.saw_secret.load(Ordering::SeqCst));
            fixture.server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn remote_stderr_canary_is_suppressed() {
        let host_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let client_key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let directory = tempfile::tempdir().unwrap();
        let identity = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("restricted_key");
        std::fs::write(
            &identity,
            client_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        private_test_file(&identity);
        let mut server_config = server::Config::default();
        server_config.keys.push(host_key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                Arc::new(server_config),
                socket,
                FixtureServer {
                    received: Arc::new(AtomicUsize::new(0)),
                    helper_ready: false,
                    pending: Vec::new(),
                    saw_secret: Arc::new(AtomicBool::new(false)),
                    emit_canary: true,
                    expected_secret: b"synthetic-secret-canary".to_vec(),
                    child_outcome: "succeeded",
                    child_exit_code: Some(0),
                },
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        let target = SshTarget {
            address: address.ip(),
            port: address.port(),
            account: "restricted".into(),
            host_key_algorithm: "ssh-ed25519".into(),
            host_key_sha256: fingerprint,
            helper_path: "/usr/local/libexec/wispkey-helper".into(),
            identity_file: identity.to_string_lossy().into_owned(),
        };
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let result = execute(
            &target,
            "5af05c13-1c0a-4394-a7a3-7f457ff74a40",
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(5),
            cancel_rx,
            || Ok(b"synthetic-secret-canary".to_vec()),
        )
        .await;
        assert_eq!(result.outcome, SshOutcome::OutcomeUnknown);
        assert!(!format!("{result:?}").contains("canary"));
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
    }

    #[cfg(unix)]
    fn private_test_file(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(windows)]
    fn private_test_file(path: &std::path::Path) {
        let principal = super::super::identity::current_principal().unwrap();
        let sid = principal.strip_prefix("windows-sid:").unwrap();
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("*{sid}:F")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn line_parser_rejects_noise_and_oversize_without_reflecting_it() {
        let mut output = Output::default();
        assert!(output.append(b"{\"version\":1,").unwrap().is_none());
        assert!(output.append(b"\"phase\":\"ready\"}\n").unwrap().is_some());
        assert!(
            Output::default()
                .append(b"synthetic-secret-canary\nnoise")
                .is_err()
        );
        assert!(
            Output::default()
                .append(&vec![b'a'; MAX_OUTPUT + 1])
                .is_err()
        );
    }
}
