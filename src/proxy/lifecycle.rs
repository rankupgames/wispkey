use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::Vault;

pub const MANAGEMENT_TOKEN_HEADER: &str = "x-wispkey-management-token";
pub const DEFAULT_PROXY_ADDRESS: &str = "http://localhost:7700";

const SCHEMA_VERSION: u8 = 1;
const STATUS_TIMEOUT_MS: u64 = 750;
const SHUTDOWN_WAIT_ATTEMPTS: usize = 20;
const SHUTDOWN_WAIT_MS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyMetadata {
    pub schema_version: u8,
    pub instance_id: String,
    pub pid: u32,
    pub port: u16,
    pub address: String,
    pub mode: String,
    pub project_scope: Option<String>,
    pub started_at: String,
    pub parent_pid: Option<u32>,
    pub management_token: String,
}

impl ProxyMetadata {
    pub fn new(port: u16, address: String, project_scope: Option<String>, token: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            instance_id: crate::random::alphanumeric(24, true)
                .expect("proxy instance id generation should not fail"),
            pid: std::process::id(),
            port,
            address,
            mode: "standalone".to_string(),
            project_scope,
            started_at: Utc::now().to_rfc3339(),
            parent_pid: current_parent_pid(),
            management_token: token,
        }
    }

    pub fn public_json(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "instance_id": self.instance_id,
            "pid": self.pid,
            "port": self.port,
            "address": self.address,
            "mode": self.mode,
            "project_scope": self.project_scope,
            "started_at": self.started_at,
            "parent_pid": self.parent_pid,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyState {
    Stopped,
    Running,
    Stale,
    Unhealthy,
    UnknownOwner,
}

impl ProxyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Stale => "stale",
            Self::Unhealthy => "unhealthy",
            Self::UnknownOwner => "unknown_owner",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyStatus {
    pub state: ProxyState,
    pub running: bool,
    pub healthy: bool,
    pub metadata: Option<ProxyMetadata>,
    pub check_error: Option<String>,
}

impl ProxyStatus {
    pub fn stopped() -> Self {
        Self {
            state: ProxyState::Stopped,
            running: false,
            healthy: false,
            metadata: None,
            check_error: None,
        }
    }

    pub fn address_or_default(&self) -> String {
        self.metadata
            .as_ref()
            .map(|metadata| metadata.address.clone())
            .unwrap_or_else(|| DEFAULT_PROXY_ADDRESS.to_string())
    }

    pub fn public_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "running": self.running,
            "healthy": self.healthy,
            "proxy": self.metadata.as_ref().map(ProxyMetadata::public_json),
            "check_error": self.check_error,
        })
    }
}

#[derive(Debug, Clone)]
pub enum StartDecision {
    Start,
    AlreadyRunning(ProxyMetadata),
}

#[derive(Debug, Clone)]
pub struct StopResult {
    pub state: ProxyState,
    pub stopped: bool,
    pub message: String,
}

pub async fn prepare_for_start(requested_port: u16) -> Result<StartDecision, String> {
    let status = read_status().await;
    let Some(metadata) = status.metadata.clone() else {
        return Ok(StartDecision::Start);
    };

    match status.state {
        ProxyState::Stopped => Ok(StartDecision::Start),
        ProxyState::Running if requested_port == 0 || metadata.port == requested_port => {
            Ok(StartDecision::AlreadyRunning(metadata))
        }
        ProxyState::Running => Err(format!(
            "WispKey proxy is already running on port {}. Stop it before starting port {}.",
            metadata.port, requested_port
        )),
        ProxyState::Stale => {
            cleanup_metadata(&metadata.instance_id, "stale metadata before start")?;
            Ok(StartDecision::Start)
        }
        ProxyState::Unhealthy => {
            stop_metadata_proxy(&metadata, "unhealthy proxy before start").await?;
            Ok(StartDecision::Start)
        }
        ProxyState::UnknownOwner => Err(format!(
            "proxy discovery points at {}, but that endpoint is not owned by this WispKey instance: {}",
            metadata.address,
            status
                .check_error
                .unwrap_or_else(|| "ownership check failed".to_string())
        )),
    }
}

pub async fn read_status() -> ProxyStatus {
    let Some(metadata) = read_metadata() else {
        return ProxyStatus::stopped();
    };

    let pid_alive = process_is_alive(metadata.pid);
    match probe_proxy(&metadata).await {
        ProbeOutcome::Healthy => ProxyStatus {
            state: ProxyState::Running,
            running: true,
            healthy: true,
            metadata: Some(metadata),
            check_error: None,
        },
        ProbeOutcome::Unauthorized => ProxyStatus {
            state: ProxyState::UnknownOwner,
            running: false,
            healthy: false,
            metadata: Some(metadata),
            check_error: Some("management token was rejected".to_string()),
        },
        ProbeOutcome::Unhealthy(message) if pid_alive => ProxyStatus {
            state: ProxyState::Unhealthy,
            running: false,
            healthy: false,
            metadata: Some(metadata),
            check_error: Some(message),
        },
        ProbeOutcome::Unhealthy(message) => ProxyStatus {
            state: ProxyState::Stale,
            running: false,
            healthy: false,
            metadata: Some(metadata),
            check_error: Some(message),
        },
    }
}

pub fn proxy_address_or_default() -> String {
    read_metadata()
        .map(|metadata| metadata.address)
        .unwrap_or_else(|| DEFAULT_PROXY_ADDRESS.to_string())
}

pub fn write_metadata(metadata: &ProxyMetadata) -> Result<(), String> {
    let paths = ProxyPaths::new();
    crate::secure_files::ensure_private_directory(&paths.vault_dir).map_err(|e| e.to_string())?;
    crate::secure_files::write_private(&paths.pid, metadata.pid.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    crate::secure_files::write_private(
        &paths.info,
        serde_json::to_string_pretty(metadata)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    record_event(
        "started",
        "proxy metadata written",
        Some(metadata),
        ProxyState::Running,
    );
    Ok(())
}

pub fn cleanup_metadata(instance_id: &str, reason: &str) -> Result<(), String> {
    let current = read_metadata();
    if current
        .as_ref()
        .is_some_and(|metadata| metadata.instance_id != instance_id)
    {
        return Ok(());
    }

    remove_discovery_files()?;
    record_event("cleanup", reason, current.as_ref(), ProxyState::Stopped);
    Ok(())
}

pub async fn stop_owned_proxy(reason: &str) -> Result<StopResult, String> {
    let status = read_status().await;
    let Some(metadata) = status.metadata else {
        return Ok(StopResult {
            state: ProxyState::Stopped,
            stopped: false,
            message: "proxy is already stopped".to_string(),
        });
    };

    match status.state {
        ProxyState::Running | ProxyState::Unhealthy => {
            stop_metadata_proxy(&metadata, reason).await?;
            Ok(StopResult {
                state: ProxyState::Stopped,
                stopped: true,
                message: format!("proxy stopped: {reason}"),
            })
        }
        ProxyState::Stale => {
            cleanup_metadata(&metadata.instance_id, reason)?;
            Ok(StopResult {
                state: ProxyState::Stale,
                stopped: false,
                message: "removed stale proxy metadata".to_string(),
            })
        }
        ProxyState::UnknownOwner => Err(status
            .check_error
            .unwrap_or_else(|| "refusing to stop unknown proxy owner".to_string())),
        ProxyState::Stopped => Ok(StopResult {
            state: ProxyState::Stopped,
            stopped: false,
            message: "proxy is already stopped".to_string(),
        }),
    }
}

pub async fn cleanup_stale_proxy(reason: &str) -> Result<StopResult, String> {
    let status = read_status().await;
    let Some(metadata) = status.metadata else {
        return Ok(StopResult {
            state: ProxyState::Stopped,
            stopped: false,
            message: "no proxy metadata to clean".to_string(),
        });
    };

    match status.state {
        ProxyState::Stale => {
            cleanup_metadata(&metadata.instance_id, reason)?;
            Ok(StopResult {
                state: ProxyState::Stale,
                stopped: false,
                message: "removed stale proxy metadata".to_string(),
            })
        }
        ProxyState::Running | ProxyState::Unhealthy | ProxyState::UnknownOwner => Err(format!(
            "proxy is {}; use `wispkey proxy stop`",
            status.state.as_str()
        )),
        ProxyState::Stopped => Ok(StopResult {
            state: ProxyState::Stopped,
            stopped: false,
            message: "no proxy metadata to clean".to_string(),
        }),
    }
}

pub fn record_event(
    event: &str,
    reason: &str,
    metadata: Option<&ProxyMetadata>,
    state: ProxyState,
) {
    let paths = ProxyPaths::new();
    if crate::secure_files::ensure_private_directory(&paths.vault_dir).is_err() {
        return;
    }

    let line = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "event": event,
        "reason": reason,
        "state": state.as_str(),
        "pid": metadata.map(|metadata| metadata.pid),
        "port": metadata.map(|metadata| metadata.port),
        "instance_id": metadata.map(|metadata| metadata.instance_id.clone()),
        "address": metadata.map(|metadata| metadata.address.clone()),
    });

    let Ok(mut file) = open_event_log(&paths.events) else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

fn read_metadata() -> Option<ProxyMetadata> {
    let raw = fs::read_to_string(ProxyPaths::new().info).ok()?;
    let value = serde_json::from_str::<Value>(&raw).ok()?;
    metadata_from_value(value)
}

fn metadata_from_value(value: Value) -> Option<ProxyMetadata> {
    let pid = u32::try_from(value.get("pid")?.as_u64()?).ok()?;
    let port = u16::try_from(value.get("port")?.as_u64()?).ok()?;
    let address = value
        .get("address")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
    let management_token = value
        .get("management_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let instance_id = value
        .get("instance_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("legacy-{pid}-{port}"));
    let mode = value
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("standalone")
        .to_string();
    let project_scope = value
        .get("project_scope")
        .and_then(Value::as_str)
        .map(str::to_string);
    let started_at = value
        .get("started_at")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let parent_pid = value
        .get("parent_pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok());

    Some(ProxyMetadata {
        schema_version: u8::try_from(
            value
                .get("schema_version")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        )
        .ok()?,
        instance_id,
        pid,
        port,
        address,
        mode,
        project_scope,
        started_at,
        parent_pid,
        management_token,
    })
}

async fn stop_metadata_proxy(metadata: &ProxyMetadata, reason: &str) -> Result<(), String> {
    if matches!(probe_proxy(metadata).await, ProbeOutcome::Healthy) {
        request_shutdown(metadata).await?;
        for _ in 0..SHUTDOWN_WAIT_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(SHUTDOWN_WAIT_MS)).await;
            if read_metadata().is_none() {
                return Ok(());
            }
            if !process_is_alive(metadata.pid) {
                cleanup_metadata(&metadata.instance_id, reason)?;
                return Ok(());
            }
        }
    }

    terminate_owned_process(metadata)?;
    cleanup_metadata(&metadata.instance_id, reason)?;
    Ok(())
}

async fn request_shutdown(metadata: &ProxyMetadata) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(STATUS_TIMEOUT_MS))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/api/shutdown", metadata.address.trim_end_matches('/'));
    let response = client
        .post(url)
        .header(MANAGEMENT_TOKEN_HEADER, &metadata.management_token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        Ok(())
    } else if response.status().as_u16() == 401 {
        Err("management token was rejected".to_string())
    } else {
        Err(format!("shutdown returned HTTP {}", response.status()))
    }
}

async fn probe_proxy(metadata: &ProxyMetadata) -> ProbeOutcome {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(STATUS_TIMEOUT_MS))
        .no_proxy()
        .build()
    {
        Ok(client) => client,
        Err(e) => return ProbeOutcome::Unhealthy(e.to_string()),
    };
    let url = format!("{}/api/status", metadata.address.trim_end_matches('/'));
    let mut request = client.get(url);
    if !metadata.management_token.is_empty() {
        request = request.header(MANAGEMENT_TOKEN_HEADER, &metadata.management_token);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => return ProbeOutcome::Unhealthy(e.to_string()),
    };

    if response.status().is_success() {
        return ProbeOutcome::Healthy;
    }
    if response.status().as_u16() == 503 {
        let body = response.text().await.unwrap_or_default();
        if body.contains("vault locked") {
            return ProbeOutcome::Healthy;
        }
        return ProbeOutcome::Unhealthy("management API returned HTTP 503".to_string());
    }
    if response.status().as_u16() == 401 {
        return ProbeOutcome::Unauthorized;
    }

    ProbeOutcome::Unhealthy(format!(
        "management API returned HTTP {}",
        response.status()
    ))
}

#[derive(Debug)]
enum ProbeOutcome {
    Healthy,
    Unauthorized,
    Unhealthy(String),
}

fn remove_discovery_files() -> Result<(), String> {
    let paths = ProxyPaths::new();
    match fs::remove_file(&paths.pid) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    match fs::remove_file(&paths.info) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

fn terminate_owned_process(metadata: &ProxyMetadata) -> Result<(), String> {
    if metadata.pid == std::process::id() {
        return Err("refusing to terminate the current process".to_string());
    }
    if !process_command_looks_wispkey(metadata.pid) {
        return Err(format!(
            "refusing to terminate PID {} because it does not look like WispKey",
            metadata.pid
        ));
    }

    terminate_process(metadata.pid)?;
    Ok(())
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(all(not(unix), not(windows)))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn process_command_looks_wispkey(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .to_ascii_lowercase()
                .contains("wispkey")
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_command_looks_wispkey(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .to_ascii_lowercase()
                .contains("wispkey")
        })
        .unwrap_or(false)
}

#[cfg(all(not(unix), not(windows)))]
fn process_command_looks_wispkey(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> Result<(), String> {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(300));
    if process_is_alive(pid) {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> Result<(), String> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("taskkill failed for PID {pid}"))
    }
}

#[cfg(all(not(unix), not(windows)))]
fn terminate_process(_pid: u32) -> Result<(), String> {
    Err("process termination is not supported on this platform".to_string())
}

#[cfg(unix)]
fn current_parent_pid() -> Option<u32> {
    let output = Command::new("ps")
        .args(["-o", "ppid=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

#[cfg(not(unix))]
fn current_parent_pid() -> Option<u32> {
    None
}

fn open_event_log(path: &PathBuf) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

struct ProxyPaths {
    vault_dir: PathBuf,
    pid: PathBuf,
    info: PathBuf,
    events: PathBuf,
}

impl ProxyPaths {
    fn new() -> Self {
        let vault_dir = Vault::vault_dir();
        Self {
            pid: vault_dir.join("proxy.pid"),
            info: vault_dir.join("proxy.json"),
            events: vault_dir.join("proxy-events.jsonl"),
            vault_dir,
        }
    }
}
