/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Authenticated current-user owner IPC for tray and desktop clients.
 * Created: 2026-08-25
 * Last Modified: 2026-11-05
 */

use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use crate::core::{Vault, VaultError};
use crate::secure_files;

mod dispatch;
mod imports;
mod protocol;
mod settings;

#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod diagnostics;

use protocol::{PROTOCOL_VERSION, clear_request_values};
const OWNER_SOCK_NAME: &str = "owner.sock";
const OWNER_META_NAME: &str = "owner.json";
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const SECRET_FIELD_NAMES: &[&str] = &[
    "value",
    "password",
    "application_key",
    "application_secret",
    "consumer_key",
];

/// Errors from serving or calling the owner IPC endpoint.
#[derive(Debug, thiserror::Error)]
pub enum OwnerIpcError {
    #[error("owner IPC server is already running")]
    AlreadyRunning,
    #[error("owner IPC is unauthorized")]
    Unauthorized,
    #[error("owner IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("owner IPC protocol error: {0}")]
    Protocol(String),
    #[error("{0}")]
    Vault(#[from] VaultError),
}

/// Discovery metadata for the owner IPC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerEndpoint {
    pub schema_version: u8,
    pub pid: u32,
    pub endpoint: String,
}

/// Returns the owner socket path for the current vault directory.
#[must_use]
pub fn socket_path() -> PathBuf {
    Vault::vault_dir().join(OWNER_SOCK_NAME)
}

/// Returns the owner discovery file path.
#[must_use]
pub fn metadata_path() -> PathBuf {
    Vault::vault_dir().join(OWNER_META_NAME)
}

/// Returns true when the connecting peer UID matches the server UID.
#[must_use]
pub fn authorize_peer_uid(peer_uid: Option<u32>, expected_uid: u32) -> bool {
    peer_uid == Some(expected_uid)
}

/// Public redaction utility retained for external callers. Owner IPC transport
/// does not log request payloads and does not rely on this helper for protection.
#[must_use]
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, child) in map {
                if SECRET_FIELD_NAMES.contains(&key.as_str()) {
                    redacted.insert(key.clone(), Value::String("[redacted]".to_string()));
                } else {
                    redacted.insert(key.clone(), redact_json(child));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

/// Serves owner IPC until shutdown or a fatal listener error.
pub async fn serve() -> Result<(), OwnerIpcError> {
    serve_at(&socket_path()).await
}

/// Serves owner IPC on an explicit socket path until shutdown or listener failure.
pub async fn serve_at(path: &Path) -> Result<(), OwnerIpcError> {
    let _lease = acquire_server_lease(path)?;
    cleanup_endpoint(path);
    let expiry = async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            imports::expire_imports();
        }
    };
    let result = tokio::select! {
        result = serve_platform(path) => result,
        () = expiry => unreachable!("import expiry runs until the server stops"),
    };
    cleanup_endpoint(path);
    result
}

async fn serve_platform(path: &Path) -> Result<(), OwnerIpcError> {
    #[cfg(unix)]
    {
        unix::serve(path).await
    }
    #[cfg(windows)]
    {
        windows::serve(path).await
    }
}

/// Verifies that discovery metadata identifies the server that answers the live endpoint.
pub async fn is_live() -> bool {
    is_live_at(&socket_path(), &metadata_path()).await
}

/// Verifies an explicit endpoint and metadata path (used by isolated clients and tests).
pub async fn is_live_at(path: &Path, metadata_path: &Path) -> bool {
    let metadata = match std::fs::read(metadata_path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<OwnerEndpoint>(&raw).ok())
    {
        Some(metadata) => metadata,
        None => return false,
    };
    if metadata.schema_version != PROTOCOL_VERSION || metadata.endpoint != endpoint_label(path) {
        return false;
    }
    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        call(path, json!({ "id": "liveness", "method": "status" })),
    )
    .await
    {
        Ok(Ok(response)) => response,
        _ => return false,
    };
    response["ok"] == true
        && response["result"]["owner_pid"].as_u64() == Some(u64::from(metadata.pid))
        && response["result"]["protocol_version"].as_u64() == Some(u64::from(PROTOCOL_VERSION))
}

/// Sends one JSON request to the owner endpoint and returns the response object.
pub async fn call(path: &Path, mut request: Value) -> Result<Value, OwnerIpcError> {
    #[cfg(unix)]
    {
        let result = unix::call(path, &request).await;
        clear_request_values(&mut request);
        result
    }
    #[cfg(windows)]
    {
        let result = windows::call(path, &request).await;
        clear_request_values(&mut request);
        result
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

fn write_metadata(path: &Path) -> Result<(), OwnerIpcError> {
    let endpoint = OwnerEndpoint {
        schema_version: PROTOCOL_VERSION,
        pid: std::process::id(),
        endpoint: endpoint_label(path),
    };
    let encoded = serde_json::to_vec_pretty(&endpoint)
        .map_err(|error| OwnerIpcError::Protocol(error.to_string()))?;
    secure_files::write_private(&metadata_path(), &encoded)?;
    Ok(())
}

fn endpoint_label(path: &Path) -> String {
    #[cfg(unix)]
    {
        format!("unix:{}", path.display())
    }
    #[cfg(windows)]
    {
        windows::pipe_name(path)
    }
}

fn acquire_server_lease(path: &Path) -> Result<std::fs::File, OwnerIpcError> {
    if let Some(parent) = path.parent() {
        secure_files::ensure_private_directory(parent)?;
    }
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))?;
    match FileExt::try_lock_exclusive(&lease) {
        Ok(()) => Ok(lease),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(OwnerIpcError::AlreadyRunning)
        }
        Err(error) => Err(error.into()),
    }
}

fn cleanup_endpoint(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(metadata_path());
}

async fn write_line<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &Value,
) -> Result<(), OwnerIpcError> {
    let mut encoded = zeroize::Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|_| OwnerIpcError::Protocol("could not encode owner request".into()))?,
    );
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

// A client that stops receiving must not take down the listener after a handler
// has already completed. Shutdown is handled independently by the caller.
async fn write_response<W: AsyncWriteExt + Unpin>(writer: &mut W, response: &Value) -> bool {
    if write_line(writer, response).await.is_err() {
        tracing::warn!("owner ipc response delivery failed");
        return false;
    }
    true
}

async fn read_request_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    let mut bounded = reader.take(MAX_REQUEST_BYTES as u64 + 1);
    let read = tokio::time::timeout(
        REQUEST_READ_TIMEOUT,
        bounded.read_until(b'\n', &mut encoded),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "owner request read timed out")
    })??;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "owner request exceeds the size limit",
        ));
    }
    Ok((read != 0).then_some(encoded))
}

struct ProcessedLine {
    response: Value,
    shutdown: bool,
    #[cfg(windows)]
    method: diagnostics::Method,
}

fn process_line(line: &[u8], #[cfg(windows)] phases: &diagnostics::Phases) -> ProcessedLine {
    let request = match serde_json::from_slice::<Value>(line) {
        Ok(request) => request,
        Err(_) => {
            #[cfg(windows)]
            phases.record(
                diagnostics::Method::Unknown,
                diagnostics::Phase::InvalidRequest,
            );
            return ProcessedLine {
                response: json!({"ok":false,"error":{"code":"invalid_input","message":"owner request is invalid"}}),
                shutdown: false,
                #[cfg(windows)]
                method: diagnostics::Method::Unknown,
            };
        }
    };
    let shutdown = request.get("method").and_then(Value::as_str) == Some("shutdown");
    #[cfg(windows)]
    let method = diagnostics::Method::from_request(&request);
    #[cfg(windows)]
    phases.record(method, diagnostics::Phase::HandlerStart);
    let response = dispatch::handle_request(request);
    #[cfg(windows)]
    phases.record(method, diagnostics::Phase::HandlerComplete);
    ProcessedLine {
        response,
        shutdown,
        #[cfg(windows)]
        method,
    }
}

// Only the byte-stream exchange is transport-independent. Connection setup and
// peer authorization stay in the platform-specific implementations below.
#[cfg(any(unix, test))]
async fn call_connected<S>(stream: S, request: &Value) -> Result<Value, OwnerIpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (reader, mut writer) = tokio::io::split(stream);
    write_line(&mut writer, request).await?;
    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| OwnerIpcError::Protocol("empty owner IPC response".into()))?;
    serde_json::from_str(&line).map_err(|error| OwnerIpcError::Protocol(error.to_string()))
}

#[cfg(test)]
mod simulated_transport;

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use serde_json::Value;
    use tokio::io::BufReader;
    use tokio::net::{UnixListener, UnixStream};

    use super::{
        OwnerIpcError, authorize_peer_uid, current_uid, process_line, read_request_line,
        write_metadata, write_response,
    };

    pub(super) async fn serve(path: &Path) -> Result<(), OwnerIpcError> {
        if let Some(parent) = path.parent() {
            crate::secure_files::ensure_private_directory(parent)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        write_metadata(path)?;
        tracing::info!(path = %path.display(), "owner ipc listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let peer_uid = stream.peer_cred().ok().map(|cred| cred.uid());
            if !authorize_peer_uid(peer_uid, current_uid()) {
                tracing::warn!(error = %OwnerIpcError::Unauthorized, "owner ipc rejected unauthorized peer");
                continue;
            }
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            loop {
                let line = match read_request_line(&mut reader).await {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                    Err(_) => {
                        write_response(&mut writer, &serde_json::json!({"ok":false,"error":{"code":"invalid_input","message":"owner request is invalid or exceeds the size limit"}})).await;
                        break;
                    }
                };
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let processed = process_line(&line);
                let delivered = write_response(&mut writer, &processed.response).await;
                if processed.shutdown {
                    return Ok(());
                }
                if !delivered {
                    break;
                }
            }
        }
    }

    pub(super) async fn call(path: &Path, request: &Value) -> Result<Value, OwnerIpcError> {
        let stream = UnixStream::connect(path).await?;
        super::call_connected(stream, request).await
    }
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::Duration;

    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    use super::diagnostics::{Method, Phase, Phases};
    use super::{
        OwnerIpcError, process_line, read_request_line, write_line, write_metadata, write_response,
    };

    pub(super) fn pipe_name(path: &Path) -> String {
        let raw = path.to_string_lossy().replace(['\\', '/', ':', ' '], "_");
        format!(r"\\.\pipe\wispkey-owner-{raw}")
    }

    fn create_server(
        name: &str,
        first: bool,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, OwnerIpcError> {
        let descriptor = crate::secure_files::windows_acl::current_user_only_security_descriptor()?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: attributes and its owned security descriptor remain valid for the create call.
        // Tokio takes a raw *mut c_void, matching CreateNamedPipeW's lpSecurityAttributes.
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .create_with_security_attributes_raw(
                    name,
                    std::ptr::from_mut(&mut attributes).cast(),
                )
        }?;
        Ok(server)
    }

    fn replace_instance(
        name: &str,
        current: BufReader<tokio::net::windows::named_pipe::NamedPipeServer>,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, OwnerIpcError> {
        // Retain the current instance until its replacement owns the pipe name.
        let next = create_server(name, false)?;
        drop(current);
        Ok(next)
    }

    fn authorize_server(
        client: &tokio::net::windows::named_pipe::NamedPipeClient,
    ) -> Result<(), OwnerIpcError> {
        let mut process_id = 0;
        // SAFETY: client owns the connected pipe handle and process_id is writable.
        if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut process_id) } == 0 {
            return Err(OwnerIpcError::Unauthorized);
        }
        crate::secure_files::windows_private::verify_process_owner(process_id)
            .map_err(|_| OwnerIpcError::Unauthorized)
    }

    pub(super) async fn serve(path: &Path) -> Result<(), OwnerIpcError> {
        let name = pipe_name(path);
        let mut server = create_server(&name, true)?;
        write_metadata(path)?;
        tracing::info!(pipe = %name, "owner ipc listening");
        let mut phases = Phases::new();
        loop {
            phases.next_connection();
            phases.record(Method::Pending, Phase::ConnectWait);
            server.connect().await?;
            phases.record(Method::Pending, Phase::Connected);
            let mut reader = BufReader::new(server);
            phases.record(Method::Pending, Phase::ReadWait);
            let line = match read_request_line(&mut reader).await {
                Ok(line) => line,
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    server = replace_instance(&name, reader)?;
                    phases.record(Method::Pending, Phase::InstanceReady);
                    continue;
                }
                Err(_) => {
                    phases.record(Method::Unknown, Phase::InvalidRequest);
                    write_response(reader.get_mut(), &serde_json::json!({"ok":false,"error":{"code":"invalid_input","message":"owner request is invalid or exceeds the size limit"}})).await;
                    server = replace_instance(&name, reader)?;
                    phases.record(Method::Pending, Phase::InstanceReady);
                    continue;
                }
            };
            phases.record(Method::Pending, Phase::ReadComplete);
            let Some(line) = line else {
                phases.record(Method::Pending, Phase::ReadEmpty);
                server = replace_instance(&name, reader)?;
                phases.record(Method::Pending, Phase::InstanceReady);
                continue;
            };
            let processed = process_line(&line, &phases);
            phases.record(processed.method, Phase::WriteStart);
            if write_response(reader.get_mut(), &processed.response).await {
                phases.record(processed.method, Phase::WriteAccepted);
            }
            if processed.shutdown {
                return Ok(());
            }
            server = replace_instance(&name, reader)?;
            phases.record(Method::Pending, Phase::InstanceReady);
        }
    }

    pub(super) async fn call(path: &Path, request: &Value) -> Result<Value, OwnerIpcError> {
        let method = Method::from_request(request).label();
        let name = pipe_name(path);
        let started = tokio::time::Instant::now();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        // The server replaces its one-shot pipe instance after each response.
        let mut client = loop {
            match ClientOptions::new().open(&name) {
                Ok(client) => break client,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) =>
                {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(OwnerIpcError::Protocol(format!(
                            "connection phase timed out after 5000 ms (method={method})"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        authorize_server(&client)?;
        let connected_ms = started.elapsed().as_millis();
        tokio::time::timeout(Duration::from_secs(5), write_line(&mut client, request))
            .await
            .map_err(|_| {
                OwnerIpcError::Protocol(format!(
                    "request_write phase timed out after 5000 ms (method={method}; connection: {connected_ms} ms)"
                ))
            })??;
        let written_ms = started.elapsed().as_millis();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        // Password hashing and import commits can outlast connection setup.
        // Match the GUI operation allowance; timing out does not cancel work
        // already admitted by the owner and must never trigger an auto-retry.
        let response_timeout = Duration::from_secs(30);
        tokio::time::timeout(response_timeout, reader.read_line(&mut line))
            .await
            .map_err(|_| OwnerIpcError::Protocol(format!("response_read phase timed out after {} ms (method={method}; connection: {connected_ms} ms; request write: {} ms)", response_timeout.as_millis(), written_ms - connected_ms)))??;
        serde_json::from_str(line.trim())
            .map_err(|error| OwnerIpcError::Protocol(error.to_string()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn completed_owner_work_can_reply_after_the_old_five_second_deadline() {
            for method in ["unlock", "import_commit"] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("owner.sock");
                let server = create_server(&pipe_name(&path), true).unwrap();
                let client =
                    super::super::call(&path, serde_json::json!({"id":"held", "method":method}));
                let serve = async {
                    server.connect().await.unwrap();
                    let mut reader = BufReader::new(server);
                    let mut request = String::new();
                    reader.read_line(&mut request).await.unwrap();
                    // This is the response deadline boundary under test. Hold
                    // completion until beyond the old budget, observing EOF if
                    // the real client abandons its pending result too early.
                    assert!(
                        tokio::time::timeout(Duration::from_secs(6), reader.fill_buf())
                            .await
                            .is_err(),
                        "client abandoned completed {method} work before its owner-operation budget"
                    );
                    write_line(
                        reader.get_mut(),
                        &serde_json::json!({"id":"held", "ok":true, "result":{"completed":true}}),
                    )
                    .await
                    .unwrap();
                };
                let (response, ()) = tokio::join!(client, serve);
                assert_eq!(response.unwrap()["result"]["completed"], true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{authorize_peer_uid, redact_json};
    use serde_json::json;

    #[tokio::test]
    async fn request_framing_is_bounded_and_keeps_the_next_line() {
        let mut reader = tokio::io::BufReader::new(b"first\nsecond\n".as_slice());
        assert_eq!(
            &**super::read_request_line(&mut reader)
                .await
                .unwrap()
                .unwrap(),
            b"first\n"
        );
        assert_eq!(
            &**super::read_request_line(&mut reader)
                .await
                .unwrap()
                .unwrap(),
            b"second\n"
        );
        assert!(
            super::read_request_line(&mut reader)
                .await
                .unwrap()
                .is_none()
        );
        let boundary = vec![b'x'; super::MAX_REQUEST_BYTES];
        let mut reader = tokio::io::BufReader::new(boundary.as_slice());
        assert_eq!(
            super::read_request_line(&mut reader)
                .await
                .unwrap()
                .unwrap()
                .len(),
            super::MAX_REQUEST_BYTES
        );
        let oversized = vec![b'x'; super::MAX_REQUEST_BYTES + 1];
        let mut reader = tokio::io::BufReader::new(oversized.as_slice());
        assert_eq!(
            super::read_request_line(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn peer_uid_mismatch_is_unauthorized() {
        assert!(!authorize_peer_uid(Some(1), 1000));
        assert!(!authorize_peer_uid(None, 1000));
        assert!(authorize_peer_uid(Some(1000), 1000));
    }

    #[test]
    fn redact_json_strips_secret_fields() {
        let redacted = redact_json(&json!({
            "method": "add_credential",
            "params": {
                "name": "openai-key",
                "value": "sk-live-secret",
                "application_secret": "ovh-secret"
            }
        }));
        let encoded = redacted.to_string();
        assert!(!encoded.contains("sk-live-secret"));
        assert!(!encoded.contains("ovh-secret"));
        assert_eq!(redacted["params"]["value"], "[redacted]");
        assert_eq!(redacted["params"]["name"], "openai-key");
    }
}
