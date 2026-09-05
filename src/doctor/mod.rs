/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Secret-safe doctor diagnostics with stable check IDs.
 * Created: 2026-08-26
 * Last Modified: 2026-08-26
 */

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use serde_json::{Value, json};

use crate::audit;
use crate::core::Vault;
use crate::integrate::{self, IntegrateClient};
use crate::policy::{self, PolicyConfig};
use crate::proxy::lifecycle::{self, ProxyState};
use crate::proxy::prove_synthetic_token_substitution;
use crate::secure_files;

pub const STABLE_CHECK_IDS: &[&str] = &[
    "binary.version",
    "vault.permissions",
    "session.state",
    "proxy.ownership",
    "proxy.readiness",
    "policy.validity",
    "audit.writability",
    "mcp.initialization",
    "mcp.transport",
    "proxy.substitution",
    "client.discovery",
];

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Check {
    fn pass(id: &'static str, message: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            status: CheckStatus::Pass,
            message: message.into(),
            remediation: None,
        }
    }

    fn fail(id: &'static str, message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            status: CheckStatus::Fail,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    fn warn(id: &'static str, message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            status: CheckStatus::Warn,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    fn skip(id: &'static str, message: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            status: CheckStatus::Skip,
            message: message.into(),
            remediation: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummary {
    pub passed: usize,
    pub failed: usize,
    pub warned: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub version: String,
    pub checks: Vec<Check>,
    pub summary: DoctorSummary,
}

impl DoctorReport {
    fn from_checks(checks: Vec<Check>) -> Self {
        let summary = DoctorSummary {
            passed: count_status(&checks, CheckStatus::Pass),
            failed: count_status(&checks, CheckStatus::Fail),
            warned: count_status(&checks, CheckStatus::Warn),
            skipped: count_status(&checks, CheckStatus::Skip),
        };
        Self {
            ok: summary.failed == 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks,
            summary,
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("doctor report must serialize")
    }
}

fn count_status(checks: &[Check], status: CheckStatus) -> usize {
    checks.iter().filter(|check| check.status == status).count()
}

/// Runs the full doctor suite using only generated or local metadata.
pub async fn run_doctor() -> DoctorReport {
    let mut checks = vec![
        check_binary_version(),
        check_vault_permissions(),
        check_session_state(),
    ];

    let proxy_status = lifecycle::read_status().await;
    checks.push(check_proxy_ownership(&proxy_status));
    checks.push(check_proxy_readiness(&proxy_status));
    checks.push(check_policy_validity());
    checks.push(check_audit_writability());
    checks.push(check_mcp_initialization());
    checks.push(check_mcp_transport());
    checks.push(check_proxy_substitution());
    checks.push(check_client_discovery());

    DoctorReport::from_checks(checks)
}

pub fn render_text(report: &DoctorReport) -> String {
    let mut lines = vec![format!("WispKey doctor {}", report.version), String::new()];
    for check in &report.checks {
        lines.push(format!(
            "[{:<4}] {:<22} {}",
            status_label(check.status),
            check.id,
            check.message
        ));
        if let Some(remediation) = &check.remediation {
            lines.push(format!("       {remediation}"));
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "{} passed, {} warned, {} failed, {} skipped",
        report.summary.passed, report.summary.warned, report.summary.failed, report.summary.skipped
    ));
    lines.join("\n")
}

fn status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Fail => "fail",
        CheckStatus::Warn => "warn",
        CheckStatus::Skip => "skip",
    }
}

fn check_binary_version() -> Check {
    Check::pass(
        "binary.version",
        format!(
            "wispkey {} (clients should invoke `wispkey` from PATH)",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

fn check_vault_permissions() -> Check {
    if !Vault::exists() {
        return Check::fail(
            "vault.permissions",
            format!(
                "vault is not initialized at {}",
                Vault::vault_dir().display()
            ),
            "Run `wispkey init` to create an owner-only vault.",
        );
    }

    if !secure_files::private_metadata_inspection_supported() {
        return Check::skip(
            "vault.permissions",
            "owner-only vault file permissions cannot be inspected on this platform",
        );
    }

    let mut problems = Vec::new();
    let vault_dir = Vault::vault_dir();
    if let Err(error) = secure_files::inspect_private_directory(&vault_dir) {
        problems.push(error);
    }

    for relative in ["vault.db", "session", "session-protector", "proxy.json"] {
        let path = vault_dir.join(relative);
        if path.exists()
            && let Err(error) = secure_files::inspect_private_file(&path)
        {
            problems.push(error);
        }
    }

    if problems.is_empty() {
        Check::pass(
            "vault.permissions",
            format!("vault files under {} are owner-only", vault_dir.display()),
        )
    } else {
        Check::fail(
            "vault.permissions",
            problems.join("; "),
            "Restrict vault files to the current user (Unix 0700/0600) and re-run `wispkey doctor`.",
        )
    }
}

fn check_session_state() -> Check {
    if !Vault::exists() {
        return Check::fail(
            "session.state",
            "no vault is available to unlock",
            "Run `wispkey init`, then `wispkey unlock`. Doctor does not collect a password.",
        );
    }

    if Vault::open_with_session().is_ok() {
        let detail = Vault::session_metadata()
            .ok()
            .and_then(|(issued_at, timeout)| {
                if timeout > 0 {
                    issued_at
                        .checked_add_signed(chrono::Duration::minutes(timeout))
                        .map(|expires| format!("session is active until {}", expires.to_rfc3339()))
                } else {
                    Some("session is active with no expiry".to_string())
                }
            })
            .unwrap_or_else(|| "session is active".to_string());
        Check::pass("session.state", detail)
    } else {
        Check::warn(
            "session.state",
            "vault is locked",
            "Run `wispkey unlock` for vault-backed credentials. Doctor does not collect a password.",
        )
    }
}

fn check_proxy_ownership(status: &lifecycle::ProxyStatus) -> Check {
    match status.state {
        ProxyState::UnknownOwner => Check::fail(
            "proxy.ownership",
            status
                .check_error
                .clone()
                .unwrap_or_else(|| "proxy discovery is not owned by this WispKey instance".into()),
            "Stop the unknown proxy or run `wispkey proxy cleanup` if discovery files are stale.",
        ),
        ProxyState::Stopped => Check::skip(
            "proxy.ownership",
            "no proxy discovery files; ownership check is not applicable",
        ),
        _ => Check::pass(
            "proxy.ownership",
            "proxy discovery files belong to this WispKey instance",
        ),
    }
}

fn check_proxy_readiness(status: &lifecycle::ProxyStatus) -> Check {
    match status.state {
        ProxyState::Running if status.healthy => Check::pass(
            "proxy.readiness",
            status
                .metadata
                .as_ref()
                .map(|metadata| format!("proxy is running on {}", metadata.address))
                .unwrap_or_else(|| "proxy is running".to_string()),
        ),
        ProxyState::Stopped => Check::warn(
            "proxy.readiness",
            "proxy is stopped",
            "Run `wispkey serve` to start the token proxy.",
        ),
        ProxyState::Stale => Check::fail(
            "proxy.readiness",
            status
                .check_error
                .clone()
                .unwrap_or_else(|| "proxy discovery files are stale".into()),
            "Run `wispkey proxy cleanup`, then `wispkey serve`.",
        ),
        ProxyState::Unhealthy => Check::fail(
            "proxy.readiness",
            status
                .check_error
                .clone()
                .unwrap_or_else(|| "proxy is unhealthy".into()),
            "Run `wispkey proxy stop` and start it again with `wispkey serve`.",
        ),
        ProxyState::UnknownOwner => Check::fail(
            "proxy.readiness",
            "proxy endpoint rejected this instance's management token",
            "Stop the unknown proxy or run `wispkey proxy cleanup` if discovery files are leftover.",
        ),
        ProxyState::Running => Check::fail(
            "proxy.readiness",
            "proxy process is running but is not healthy",
            "Run `wispkey proxy stop` and start it again with `wispkey serve`.",
        ),
    }
}

fn check_policy_validity() -> Check {
    let path = policy::policies_path();
    if !path.exists() {
        return Check::pass(
            "policy.validity",
            "no policies.toml; requests are allowed by default",
        );
    }

    match std::fs::read_to_string(&path) {
        Ok(content) => match toml::from_str::<PolicyConfig>(&content) {
            Ok(config) => match policy::validate_policy_config(&config) {
                Ok(()) => Check::pass(
                    "policy.validity",
                    format!(
                        "{} {} parsed from {}",
                        config.policy.len(),
                        if config.policy.len() == 1 {
                            "policy"
                        } else {
                            "policies"
                        },
                        path.display()
                    ),
                ),
                Err(error) => Check::fail(
                    "policy.validity",
                    error,
                    format!("Fix {} or run `wispkey policy check`.", path.display()),
                ),
            },
            Err(_error) => Check::fail(
                "policy.validity",
                format!("could not parse {}", path.display()),
                format!(
                    "Fix the TOML in {} or run `wispkey policy init`.",
                    path.display()
                ),
            ),
        },
        Err(error) => Check::fail(
            "policy.validity",
            format!("could not read {}: {error}", path.display()),
            format!("Restore read access to {}.", path.display()),
        ),
    }
}

fn check_audit_writability() -> Check {
    if !Vault::exists() {
        return Check::fail(
            "audit.writability",
            "no vault database is available for audit events",
            "Run `wispkey init` so doctor can write a diagnostic audit event.",
        );
    }

    if let Ok(vault) = Vault::open_with_session() {
        return match audit::try_log_event(
            vault.db(),
            "DoctorCheck",
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        ) {
            Ok(()) => Check::pass(
                "audit.writability",
                "wrote a DoctorCheck audit event to the vault database",
            ),
            Err(error) => Check::fail(
                "audit.writability",
                format!("could not write a vault audit event: {error}"),
                "Check vault database permissions and re-run `wispkey doctor`.",
            ),
        };
    }

    match audit::try_log_fallback_event(
        "DoctorCheck",
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    ) {
        Ok(()) => Check::warn(
            "audit.writability",
            "vault is locked; wrote a fallback sideload audit event",
            "Run `wispkey unlock` to write vault-backed audit events.",
        ),
        Err(error) => Check::fail(
            "audit.writability",
            format!("could not write a fallback audit event while the vault is locked: {error}"),
            "Check permissions on the vault directory, then run `wispkey unlock`.",
        ),
    }
}

fn check_mcp_initialization() -> Check {
    match handshake_mcp_initialize() {
        Ok(message) => Check::pass("mcp.initialization", message),
        Err(error) => Check::fail(
            "mcp.initialization",
            error,
            "Install `wispkey` on PATH and run `wispkey mcp serve` to confirm stdio MCP startup.",
        ),
    }
}

fn check_mcp_transport() -> Check {
    Check::pass(
        "mcp.transport",
        format!("stdio JSON-RPC 2.0 is the supported MCP transport ({MCP_PROTOCOL_VERSION})"),
    )
}

fn check_proxy_substitution() -> Check {
    match prove_synthetic_token_substitution() {
        Ok(()) => Check::pass(
            "proxy.substitution",
            "synthetic diagnostic replaced a generated test token; no vault credential was used",
        ),
        Err(error) => Check::fail(
            "proxy.substitution",
            error,
            "Reinstall WispKey and re-run `wispkey doctor`. Substitution uses generated test material only.",
        ),
    }
}

fn check_client_discovery() -> Check {
    let mut found = Vec::new();
    let mut issues = Vec::new();

    for client in IntegrateClient::ALL {
        let path = client.default_path();
        if !path.exists() {
            continue;
        }
        match integrate::inspect_existing(&client, &path) {
            Ok(info) => {
                if info.has_wispkey {
                    if info.uses_path_command {
                        issues.push(format!(
                            "{} at {} uses a user-specific command path",
                            client.as_str(),
                            path.display()
                        ));
                    } else {
                        found.push(format!("{} ({})", client.as_str(), path.display()));
                    }
                } else {
                    found.push(format!(
                        "{} config without wispkey ({})",
                        client.as_str(),
                        path.display()
                    ));
                }
            }
            Err(error) => issues.push(format!("{}: {error}", path.display())),
        }
    }

    if !issues.is_empty() {
        return Check::warn(
            "client.discovery",
            issues.join("; "),
            "Run `wispkey integrate <client> --print` and replace absolute paths with `wispkey`.",
        );
    }
    if found.is_empty() {
        Check::pass(
            "client.discovery",
            "no MCP client configs found; generate one with `wispkey integrate <client> --print`",
        )
    } else {
        Check::pass("client.discovery", format!("found {}", found.join(", ")))
    }
}

fn handshake_mcp_initialize() -> Result<String, String> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "wispkey-doctor", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let mut child = mcp_command()
        .args(["mcp", "serve"])
        .env("WISPKEY_VAULT_PATH", Vault::vault_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start MCP server: {error}"))?;

    let write_result = (|| {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "MCP stdin was not piped".to_string())?;
        writeln!(stdin, "{request}").map_err(|error| format!("writing MCP initialize: {error}"))?;
        Ok::<(), String>(())
    })();
    drop(child.stdin.take());
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => return Err(format!("waiting for MCP server: {error}")),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: Value = stdout
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or_else(|| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("MCP initialize did not return JSON-RPC ({stderr})")
        })?;

    let protocol = response
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| "MCP initialize response missing protocolVersion".to_string())?;
    let name = response
        .pointer("/result/serverInfo/name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if name != "wispkey" {
        return Err(format!(
            "MCP server identified as '{name}', expected 'wispkey'"
        ));
    }
    Ok(format!("initialized {name} {protocol} over stdio"))
}

fn mcp_command() -> Command {
    if let Some(exe) = current_wispkey_executable() {
        Command::new(exe)
    } else {
        Command::new("wispkey")
    }
}

fn current_wispkey_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_str()?;
    let stem = Path::new(name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(name);
    if stem == "wispkey" { Some(exe) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_ok_without_failures() {
        let report = DoctorReport::from_checks(vec![
            Check::pass("binary.version", "ok"),
            Check::warn("session.state", "locked", "unlock"),
            Check::skip("proxy.ownership", "stopped"),
        ]);
        assert!(report.ok);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.warned, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.failed, 0);
    }

    #[test]
    fn report_fails_when_any_check_fails() {
        let report = DoctorReport::from_checks(vec![
            Check::pass("binary.version", "ok"),
            Check::fail("policy.validity", "bad toml", "fix it"),
        ]);
        assert!(!report.ok);
        assert_eq!(report.summary.failed, 1);
    }

    #[test]
    fn stable_check_ids_are_unique() {
        let mut ids = STABLE_CHECK_IDS.to_vec();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), STABLE_CHECK_IDS.len());
    }
}
