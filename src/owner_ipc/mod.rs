/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Authenticated current-user owner IPC for tray and desktop clients.
 * Created: 2026-08-25
 * Last Modified: 2026-08-25
 */

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use crate::audit;
use crate::core::{
    self, AddCredentialRequest, CredentialType, OvhApiTemplate, Vault, VaultError,
    expand_credential_template,
};
use crate::secure_files;

const PROTOCOL_VERSION: u8 = 1;
const OWNER_SOCK_NAME: &str = "owner.sock";
const OWNER_META_NAME: &str = "owner.json";
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

/// Redacts known secret fields from JSON values before logging.
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

/// Serves owner IPC on an explicit socket path (used by tests).
pub async fn serve_at(path: &Path) -> Result<(), OwnerIpcError> {
    #[cfg(unix)]
    {
        unix::serve(path).await
    }
    #[cfg(windows)]
    {
        windows::serve(path).await
    }
}

/// Sends one JSON request to the owner endpoint and returns the response object.
pub async fn call(path: &Path, request: Value) -> Result<Value, OwnerIpcError> {
    #[cfg(unix)]
    {
        unix::call(path, request).await
    }
    #[cfg(windows)]
    {
        windows::call(path, request).await
    }
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }
    #[cfg(windows)]
    {
        0
    }
}

fn write_metadata(path: &Path) -> Result<(), OwnerIpcError> {
    let endpoint = OwnerEndpoint {
        schema_version: PROTOCOL_VERSION,
        pid: std::process::id(),
        endpoint: format!("unix:{}", path.display()),
    };
    let encoded = serde_json::to_vec_pretty(&endpoint)
        .map_err(|error| OwnerIpcError::Protocol(error.to_string()))?;
    secure_files::write_private(&metadata_path(), &encoded)?;
    Ok(())
}

fn cleanup_endpoint(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(metadata_path());
}

fn handle_request(request: Value) -> Value {
    let id = request
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    tracing::info!(
        method = method.as_str(),
        request = %redact_json(&request),
        "owner ipc request"
    );

    let result = match method.as_str() {
        "status" => status_response(),
        "unlock" => unlock_response(&params),
        "lock" => lock_response(),
        "list_credentials" => list_credentials_response(&params),
        "list_projects" => list_projects_response(),
        "list_partitions" => list_partitions_response(&params),
        "add_credential" => add_credential_response(&params),
        "add_template" => add_template_response(&params),
        "get_settings" => Ok(json!({ "start_at_login": read_start_at_login() })),
        "set_settings" => set_settings_response(&params),
        "shutdown" => Ok(json!({ "ok": true, "shutdown": true })),
        "" => Err(error_body("invalid_input", "method is required")),
        other => Err(error_body(
            "invalid_input",
            &format!("unknown method '{other}'"),
        )),
    };

    match result {
        Ok(value) => json!({ "id": id, "ok": true, "result": value }),
        Err(error) => json!({ "id": id, "ok": false, "error": error }),
    }
}

fn status_response() -> Result<Value, Value> {
    if !Vault::exists() {
        return Ok(json!({
            "initialized": false,
            "session_active": false,
            "session_protection": Vault::session_protection_label(),
            "vault_path": Vault::vault_dir().to_string_lossy(),
            "active_project": core::resolve_active_project(),
            "credential_count": 0,
        }));
    }
    let vault = Vault::open().map_err(vault_error)?;
    let session_active = Vault::open_with_session().is_ok();
    Ok(json!({
        "initialized": true,
        "session_active": session_active,
        "session_protection": Vault::session_protection_label(),
        "vault_path": Vault::vault_dir().to_string_lossy(),
        "active_project": core::resolve_active_project(),
        "credential_count": vault.credential_count().unwrap_or(0),
        "created_at": vault.vault_created_at().ok(),
    }))
}

fn unlock_response(params: &Value) -> Result<Value, Value> {
    let password = required_string(params, "password")?;
    let mut vault = Vault::open().map_err(vault_error)?;
    vault
        .unlock_with_timeout(&password, None)
        .map_err(vault_error)?;
    audit::log_event(
        vault.db(),
        "VaultUnlocked",
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
    Ok(json!({ "session_active": true }))
}

fn lock_response() -> Result<Value, Value> {
    let mut vault = Vault::open().map_err(vault_error)?;
    vault.lock().map_err(vault_error)?;
    Ok(json!({ "session_active": false }))
}

fn list_credentials_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let all_projects = params
        .get("all_projects")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let project = params
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    let credentials = if all_projects {
        vault.list_credentials().map_err(vault_error)?
    } else {
        vault
            .list_credentials_in_project(&project)
            .map_err(vault_error)?
    };
    Ok(json!({
        "project": if all_projects { "*".to_string() } else { project },
        "credentials": credentials.iter().map(credential_metadata).collect::<Vec<_>>(),
    }))
}

fn list_projects_response() -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let active = core::resolve_active_project();
    let projects = vault.list_projects().map_err(vault_error)?;
    Ok(json!({
        "projects": projects.iter().map(|project| {
            json!({
                "name": project.name,
                "description": project.description,
                "active": project.name == active,
                "partition_count": vault.project_partition_count(&project.id).unwrap_or(0),
            })
        }).collect::<Vec<_>>(),
    }))
}

fn list_partitions_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let project = params
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    let partitions = vault
        .list_partitions_in_project(&project)
        .map_err(vault_error)?;
    Ok(json!({
        "project": project,
        "partitions": partitions.iter().map(|partition| {
            json!({
                "name": partition.name,
                "description": partition.description,
                "credential_count": vault.partition_credential_count(&partition.id).unwrap_or(0),
            })
        }).collect::<Vec<_>>(),
    }))
}

fn add_credential_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let name = required_string(params, "name")?;
    let type_str = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("api_key");
    let value = required_string(params, "value")?;
    let credential_type = CredentialType::from_str_with_params(
        type_str,
        params.get("header_name").and_then(Value::as_str),
        params.get("param_name").and_then(Value::as_str),
    )
    .map_err(vault_error)?;
    let description = optional_string(params, "description");
    let hosts = optional_string(params, "hosts");
    let tags = optional_string(params, "tags");
    let partition = optional_string(params, "partition");
    let project = optional_string(params, "project");
    let project_name = project
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    let created = vault
        .add_credential(AddCredentialRequest {
            name: &name,
            credential_type,
            value: &value,
            description: description.as_deref(),
            hosts: hosts.as_deref(),
            tags: tags.as_deref(),
            partition: partition.as_deref(),
            project: project.as_deref(),
        })
        .map_err(vault_error)?;
    audit::log_event(
        vault.db(),
        "CredentialAdded",
        Some(&name),
        Some(&created.wisp_token),
        None,
        None,
        None,
        None,
        false,
        None,
        Some(&project_name),
    );
    Ok(json!({
        "credentials": [credential_metadata(&created)],
        "project": project_name,
    }))
}

fn add_template_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let template = required_string(params, "template")?;
    let name_prefix = required_string(params, "name_prefix")?;
    let application_key = required_string(params, "application_key")?;
    let application_secret = required_string(params, "application_secret")?;
    let consumer_key = required_string(params, "consumer_key")?;
    let description = optional_string(params, "description");
    let hosts = optional_string(params, "hosts");
    let tags = optional_string(params, "tags");
    let partition = optional_string(params, "partition");
    let project = optional_string(params, "project");
    let owned = expand_credential_template(
        &template,
        OvhApiTemplate {
            name_prefix: &name_prefix,
            application_key: &application_key,
            application_secret: &application_secret,
            consumer_key: &consumer_key,
            description: description.as_deref(),
            hosts: hosts.as_deref(),
            tags: tags.as_deref(),
            partition: partition.as_deref(),
            project: project.as_deref(),
        },
    )
    .map_err(vault_error)?;
    let requests: Vec<_> = owned.iter().map(|item| item.as_request()).collect();
    let created = vault
        .add_credentials_atomic(&requests)
        .map_err(vault_error)?;
    let project_name = project.unwrap_or_else(core::resolve_active_project);
    for credential in &created {
        audit::log_event(
            vault.db(),
            "CredentialAdded",
            Some(&credential.name),
            Some(&credential.wisp_token),
            None,
            None,
            None,
            None,
            false,
            None,
            Some(&project_name),
        );
    }
    Ok(json!({
        "credentials": created.iter().map(credential_metadata).collect::<Vec<_>>(),
        "project": project_name,
    }))
}

fn set_settings_response(params: &Value) -> Result<Value, Value> {
    let start_at_login = params
        .get("start_at_login")
        .and_then(Value::as_bool)
        .ok_or_else(|| error_body("invalid_input", "start_at_login is required"))?;
    write_start_at_login(start_at_login).map_err(|error| {
        error_body("unavailable", &format!("failed to write settings: {error}"))
    })?;
    Ok(json!({ "start_at_login": start_at_login }))
}

fn credential_metadata(credential: &core::Credential) -> Value {
    json!({
        "name": credential.name,
        "description": credential.description,
        "type": credential.credential_type.display_name(),
        "wisp_token": credential.wisp_token,
        "hosts": credential.hosts,
        "tags": credential.tags,
        "partition_id": credential.partition_id,
        "created_at": credential.created_at.to_rfc3339(),
        "updated_at": credential.updated_at.to_rfc3339(),
    })
}

fn required_string(params: &Value, key: &str) -> Result<String, Value> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| error_body("invalid_input", &format!("{key} is required")))
}

fn optional_string(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn vault_error(error: VaultError) -> Value {
    let code = match error {
        VaultError::NotFound => "not_initialized",
        VaultError::Locked | VaultError::SessionInvalid => "locked",
        VaultError::InvalidPassword => "unauthorized",
        VaultError::DuplicateCredential(_) => "duplicate",
        VaultError::EmptyCredentialName | VaultError::EmptyCredentialValue => "invalid_input",
        VaultError::InvalidCredentialType(_) | VaultError::InvalidCredentialTemplate(_) => {
            "invalid_input"
        }
        VaultError::ProjectNotFound(_) | VaultError::PartitionNotFound(_) => "invalid_input",
        _ => "unavailable",
    };
    error_body(code, &error.to_string())
}

fn error_body(code: &str, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

fn autostart_exec_line() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wispkey"));
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wispkey");
    if name.starts_with("wispkey-tray") {
        format!("\"{}\"", exe.display())
    } else {
        format!("\"{}\" tray", exe.display())
    }
}

fn settings_path() -> PathBuf {
    Vault::vault_dir().join("tray.json")
}

fn read_start_at_login() -> bool {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| value.get("start_at_login")?.as_bool())
        .unwrap_or(false)
}

fn write_start_at_login(enabled: bool) -> Result<(), VaultError> {
    let encoded = serde_json::to_vec_pretty(&json!({ "start_at_login": enabled }))
        .map_err(|error| VaultError::InvalidBundle(error.to_string()))?;
    secure_files::write_private(&settings_path(), &encoded)?;
    #[cfg(target_os = "linux")]
    write_linux_autostart(enabled)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_linux_autostart(enabled: bool) -> Result<(), VaultError> {
    let autostart_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autostart");
    let desktop_path = autostart_dir.join("wispkey-tray.desktop");
    if enabled {
        std::fs::create_dir_all(&autostart_dir)?;
        let desktop = format!(
            "[Desktop Entry]\nType=Application\nName=WispKey Tray\nExec={}\nX-GNOME-Autostart-enabled=true\n",
            autostart_exec_line()
        );
        std::fs::write(&desktop_path, desktop)?;
    } else if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)?;
    }
    Ok(())
}

async fn write_line<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &Value,
) -> Result<(), OwnerIpcError> {
    let mut encoded =
        serde_json::to_vec(value).map_err(|error| OwnerIpcError::Protocol(error.to_string()))?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::{
        OwnerIpcError, authorize_peer_uid, cleanup_endpoint, current_uid, handle_request,
        write_line, write_metadata,
    };

    pub(super) async fn serve(path: &Path) -> Result<(), OwnerIpcError> {
        if let Some(parent) = path.parent() {
            crate::secure_files::ensure_private_directory(parent)?;
        }
        let _ = std::fs::remove_file(path);
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
            let mut lines = BufReader::new(reader).lines();
            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                let request = match serde_json::from_str::<Value>(&line) {
                    Ok(request) => request,
                    Err(error) => {
                        write_line(
                            &mut writer,
                            &serde_json::json!({
                                "ok": false,
                                "error": { "code": "invalid_input", "message": error.to_string() }
                            }),
                        )
                        .await?;
                        continue;
                    }
                };
                let shutdown = request.get("method").and_then(Value::as_str) == Some("shutdown");
                let response = handle_request(request);
                write_line(&mut writer, &response).await?;
                if shutdown {
                    cleanup_endpoint(path);
                    return Ok(());
                }
            }
        }
    }

    pub(super) async fn call(path: &Path, request: Value) -> Result<Value, OwnerIpcError> {
        let stream = UnixStream::connect(path).await?;
        let (reader, mut writer) = stream.into_split();
        write_line(&mut writer, &request).await?;
        let mut lines = BufReader::new(reader).lines();
        let line = lines
            .next_line()
            .await?
            .ok_or_else(|| OwnerIpcError::Protocol("empty owner IPC response".into()))?;
        serde_json::from_str(&line).map_err(|error| OwnerIpcError::Protocol(error.to_string()))
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;
    use std::time::Duration;

    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    use super::{OwnerIpcError, cleanup_endpoint, handle_request, write_line, write_metadata};

    fn pipe_name(path: &Path) -> String {
        let raw = path.to_string_lossy().replace(['\\', '/', ':', ' '], "_");
        format!(r"\\.\pipe\wispkey-owner-{raw}")
    }

    pub(super) async fn serve(path: &Path) -> Result<(), OwnerIpcError> {
        let name = pipe_name(path);
        write_metadata(path)?;
        tracing::info!(pipe = %name, "owner ipc listening");
        let mut first = true;
        loop {
            let mut server = ServerOptions::new()
                .first_pipe_instance(first)
                .create(&name)?;
            first = false;
            server.connect().await?;
            let mut reader = BufReader::new(server);
            let mut line = String::new();
            line.clear();
            let read = reader.read_line(&mut line).await?;
            if read == 0 {
                continue;
            }
            let request = match serde_json::from_str::<Value>(line.trim()) {
                Ok(request) => request,
                Err(error) => {
                    write_line(
                        reader.get_mut(),
                        &serde_json::json!({
                            "ok": false,
                            "error": { "code": "invalid_input", "message": error.to_string() }
                        }),
                    )
                    .await?;
                    continue;
                }
            };
            let shutdown = request.get("method").and_then(Value::as_str) == Some("shutdown");
            let response = handle_request(request);
            write_line(reader.get_mut(), &response).await?;
            if shutdown {
                cleanup_endpoint(path);
                return Ok(());
            }
        }
    }

    pub(super) async fn call(path: &Path, request: Value) -> Result<Value, OwnerIpcError> {
        let name = pipe_name(path);
        let mut client = ClientOptions::new().open(&name)?;
        write_line(&mut client, &request).await?;
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| OwnerIpcError::Protocol("timed out waiting for owner IPC".into()))??;
        serde_json::from_str(line.trim())
            .map_err(|error| OwnerIpcError::Protocol(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{authorize_peer_uid, redact_json};
    use serde_json::json;

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
