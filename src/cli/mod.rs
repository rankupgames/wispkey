/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: CLI command handlers -- wires user-facing subcommands to vault operations.
 *              Handles interactive password prompts and env sideload support.
 * Created: 2026-04-07
 * Last Modified: 2026-04-12
 */

use crate::audit;
use crate::cloud::{self, CloudClient, CloudError, CloudTier};
use crate::core::{self, AddCredentialRequest, CredentialType, Vault, VaultError};
use crate::mcp;
use crate::migrate;
use crate::partition;
use crate::proxy;
use crate::secure_files;
use crate::sharing;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
const BUNDLE_PASSPHRASE_ENV: &str = "WISPKEY_BUNDLE_PASSPHRASE";
const MIN_BUNDLE_PASSPHRASE_LEN: usize = 12;
const MAX_BUNDLE_PASSPHRASE_FILE_BYTES: u64 = 16 * 1024;

pub fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, Ordering::Relaxed);
}

fn json_output() -> bool {
    JSON_OUTPUT.load(Ordering::Relaxed)
}

fn public_proxy_info(info: &serde_json::Value) -> serde_json::Value {
    let mut public = info.clone();
    if let Some(object) = public.as_object_mut() {
        object.remove("management_token");
    }
    public
}

#[derive(Debug)]
struct ProxyStatus {
    info: Option<serde_json::Value>,
    running: bool,
    pid: Option<u64>,
    port: Option<u64>,
    check_error: Option<String>,
}

async fn read_proxy_status() -> ProxyStatus {
    let info_path = Vault::vault_dir().join("proxy.json");
    let info = std::fs::read_to_string(&info_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok());

    let Some(info) = info else {
        return ProxyStatus {
            info: None,
            running: false,
            pid: None,
            port: None,
            check_error: None,
        };
    };

    let pid = info.get("pid").and_then(|v| v.as_u64());
    let port = info.get("port").and_then(|v| v.as_u64());
    let public_info = public_proxy_info(&info);
    let address = info
        .get("address")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .or_else(|| port.map(|p| format!("http://127.0.0.1:{}", p)));
    let management_token = info
        .get("management_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let Some(address) = address else {
        return ProxyStatus {
            info: Some(public_info),
            running: false,
            pid,
            port,
            check_error: Some("missing proxy address".to_string()),
        };
    };

    match probe_proxy_status(&address, management_token.as_deref()).await {
        Ok(running) => ProxyStatus {
            info: Some(public_info),
            running,
            pid,
            port,
            check_error: None,
        },
        Err(e) => ProxyStatus {
            info: Some(public_info),
            running: false,
            pid,
            port,
            check_error: Some(e),
        },
    }
}

async fn probe_proxy_status(address: &str, management_token: Option<&str>) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(750))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/api/status", address.trim_end_matches('/'));
    let mut request = client.get(url);
    if let Some(token) = management_token {
        request = request.header("x-wispkey-management-token", token);
    }
    let response = request.send().await.map_err(|e| e.to_string())?;

    if response.status().is_success() {
        return Ok(true);
    }

    if response.status().as_u16() == 503 {
        let body = response.text().await.unwrap_or_default();
        return Ok(body.contains("vault locked"));
    }

    Ok(false)
}

fn print_json(value: serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("json output must serialize")
    );
}

fn credential_json(cred: &core::Credential) -> serde_json::Value {
    serde_json::json!({
        "id": cred.id,
        "name": cred.name,
        "description": cred.description,
        "type": cred.credential_type.display_name(),
        "wisp_token": cred.wisp_token,
        "hosts": cred.hosts,
        "tags": cred.tags,
        "partition_id": cred.partition_id,
        "created_at": cred.created_at.to_rfc3339(),
        "updated_at": cred.updated_at.to_rfc3339(),
        "last_used_at": cred.last_used_at.map(|d| d.to_rfc3339()),
    })
}

fn partition_json(vault: &Vault, partition: &core::Partition) -> serde_json::Value {
    serde_json::json!({
        "id": partition.id,
        "name": partition.name,
        "description": partition.description,
        "project_id": partition.project_id,
        "credential_count": vault.partition_credential_count(&partition.id).unwrap_or(0),
        "created_at": partition.created_at.to_rfc3339(),
        "updated_at": partition.updated_at.to_rfc3339(),
    })
}

fn project_json(vault: &Vault, project: &core::Project, active: &str) -> serde_json::Value {
    serde_json::json!({
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "partition_count": vault.project_partition_count(&project.id).unwrap_or(0),
        "active": project.name == active,
        "created_at": project.created_at.to_rfc3339(),
        "updated_at": project.updated_at.to_rfc3339(),
    })
}

/// Creates a new vault after prompting for and confirming the master password.
pub async fn handle_init() {
    if Vault::exists() {
        eprintln!(
            "Error: vault already exists at {}",
            Vault::vault_dir().display()
        );
        eprintln!("Delete {} to start fresh.", Vault::vault_dir().display());
        std::process::exit(1);
    }

    let password =
        match prompt_password_confirm("Enter master password: ", "Confirm master password: ") {
            Some(p) => p,
            None => {
                eprintln!("Error: passwords did not match");
                std::process::exit(1);
            }
        };

    match Vault::init(&password) {
        Ok(vault) => {
            audit::log_event(
                vault.db(),
                "VaultCreated",
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
            println!("Vault created at {}", Vault::vault_dir().display());
            println!("Vault is unlocked for this session (30 min timeout).");
            println!();
            println!("Next steps:");
            println!("  wispkey add \"my-api-key\" --type bearer_token --value \"sk-...\"");
            println!("  wispkey import .env");
            println!("  wispkey serve");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Unlocks the vault with the master password and optional session timeout.
pub async fn handle_unlock(timeout: Option<i64>) {
    let mut vault = match Vault::open() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let password = prompt_password("Enter master password: ");

    match vault.unlock_with_timeout(&password, timeout) {
        Ok(()) => {
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
            let effective_timeout = timeout.unwrap_or_else(Vault::session_timeout_minutes);
            if effective_timeout > 0 {
                println!("Vault unlocked ({} min session).", effective_timeout);
            } else {
                println!("Vault unlocked (no expiry).");
            }
        }
        Err(VaultError::InvalidPassword) => {
            eprintln!("Error: invalid master password");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Adds a credential to the vault with the given type, value, and optional scope fields.
pub async fn handle_add(
    name: &str,
    type_str: &str,
    description: Option<&str>,
    value: Option<&str>,
    hosts: Option<&str>,
    tags: Option<&str>,
    header_name: Option<&str>,
    param_name: Option<&str>,
    partition: Option<&str>,
    project: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let credential_type =
        match CredentialType::from_str_with_params(type_str, header_name, param_name) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

    let resolved_value = match value {
        Some(v) => v.to_string(),
        None => {
            let entered = prompt_password_confirm("Enter secret value: ", "Confirm secret value: ");
            match entered {
                Some(v) => v,
                None => {
                    eprintln!("Error: values did not match");
                    std::process::exit(1);
                }
            }
        }
    };

    let active_project = project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);

    match vault.add_credential(AddCredentialRequest {
        name,
        credential_type,
        value: &resolved_value,
        description,
        hosts,
        tags,
        partition,
        project,
    }) {
        Ok(cred) => {
            audit::log_event(
                vault.db(),
                "CredentialAdded",
                Some(name),
                Some(&cred.wisp_token),
                None,
                None,
                None,
                None,
                false,
                None,
                Some(&active_project),
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "credential": credential_json(&cred),
                    "project": active_project,
                }));
                return;
            }
            println!("Credential '{}' added.", name);
            println!("Wisp token: {}", cred.wisp_token);
            println!();
            println!(
                "Use this token in API calls. The proxy will swap it for the real credential."
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Lists credentials for a partition, the active or named project, or all projects.
pub async fn handle_list(partition: Option<&str>, project: Option<&str>, all_projects: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let list_result = if let Some(partition_name) = partition {
        let active = project
            .map(String::from)
            .unwrap_or_else(core::resolve_active_project);
        vault.list_credentials_in_partition_for_project(&active, partition_name)
    } else if all_projects {
        vault.list_credentials()
    } else {
        let active = project
            .map(String::from)
            .unwrap_or_else(core::resolve_active_project);
        vault.list_credentials_in_project(&active)
    };

    match list_result {
        Ok(credentials) => {
            if json_output() {
                let active = project
                    .map(String::from)
                    .unwrap_or_else(core::resolve_active_project);
                let list: Vec<serde_json::Value> =
                    credentials.iter().map(credential_json).collect();
                print_json(serde_json::json!({
                    "credentials": list,
                    "project": if all_projects { serde_json::Value::String("*".to_string()) } else { serde_json::Value::String(active) },
                    "all_projects": all_projects,
                    "partition": partition,
                }));
                return;
            }
            if credentials.is_empty() {
                let active = core::resolve_active_project();
                if !all_projects {
                    println!(
                        "No credentials in project '{}'. Use --all-projects to see all.",
                        active
                    );
                } else {
                    println!("No credentials stored.");
                }
                println!(
                    "Add one with: wispkey add \"name\" --type bearer_token --value \"secret\""
                );
                return;
            }

            println!(
                "{:<24} {:<16} {:<30} {:<20} TAGS",
                "NAME", "TYPE", "DESCRIPTION", "CREATED"
            );
            println!("{}", "-".repeat(102));
            for cred in &credentials {
                let tags = if cred.tags.is_empty() {
                    String::new()
                } else {
                    cred.tags.join(", ")
                };
                let desc = if cred.description.len() > 28 {
                    format!("{}..", &cred.description[..28])
                } else {
                    cred.description.clone()
                };
                println!(
                    "{:<24} {:<16} {:<30} {:<20} {}",
                    cred.name,
                    cred.credential_type.display_name(),
                    desc,
                    cred.created_at.format("%Y-%m-%d %H:%M"),
                    tags
                );
            }
            println!();
            println!("{} credential(s)", credentials.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Prints metadata for a credential, optionally including its wisp token.
pub async fn handle_get(name: &str, show_token: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.get_credential(name) {
        Ok(cred) => {
            if json_output() {
                let mut value = credential_json(&cred);
                if !show_token && let Some(object) = value.as_object_mut() {
                    object.remove("wisp_token");
                }
                print_json(serde_json::json!({ "credential": value }));
                return;
            }
            println!("Name:       {}", cred.name);
            if !cred.description.is_empty() {
                println!("Desc:       {}", cred.description);
            }
            println!("Type:       {}", cred.credential_type.display_name());
            if show_token {
                println!("Wisp Token: {}", cred.wisp_token);
            }
            if !cred.hosts.is_empty() {
                println!("Hosts:      {}", cred.hosts.join(", "));
            }
            if !cred.tags.is_empty() {
                println!("Tags:       {}", cred.tags.join(", "));
            }
            println!(
                "Created:    {}",
                cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "Updated:    {}",
                cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if let Some(last_used) = cred.last_used_at {
                println!("Last Used:  {}", last_used.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Removes a credential from the vault by name.
pub async fn handle_remove(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.remove_credential(name) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "CredentialRemoved",
                Some(name),
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "deleted": name,
                }));
                return;
            }
            println!("Credential '{}' removed.", name);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Rotates the wisp token for the named credential.
pub async fn handle_rotate(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.rotate_wisp_token(name) {
        Ok(new_token) => {
            audit::log_event(
                vault.db(),
                "CredentialRotated",
                Some(name),
                Some(&new_token),
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "credential": name,
                    "wisp_token": new_token,
                }));
                return;
            }
            println!("Wisp token rotated for '{}'.", name);
            println!("New token: {}", new_token);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Starts the HTTP proxy in the foreground or as a background daemon.
pub async fn handle_serve(port: u16, daemon: bool, all_projects: bool) {
    let vault = match Vault::open_with_session() {
        Ok(vault) => Some(vault),
        Err(e) if crate::env_sideload::list_available().is_empty() => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Warning: {}. Starting proxy for env sideload credentials only.",
                e
            );
            None
        }
    };

    if daemon {
        spawn_daemon(port, all_projects);
        return;
    }

    let active = core::resolve_active_project();
    if let Some(vault) = &vault {
        audit::log_event(
            vault.db(),
            "ProxyStarted",
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(&active),
        );
    }

    if port == 0 {
        println!("Starting WispKey proxy on a random port...");
    } else {
        println!("Starting WispKey proxy on localhost:{}...", port);
    }
    if all_projects {
        println!("Project scope: ALL (no project filtering)");
    } else {
        println!(
            "Project scope: '{}' (use --all-projects to allow all)",
            active
        );
    }

    match proxy::start_proxy(port, all_projects).await {
        Ok(actual_port) => {
            println!(
                "Set HTTP_PROXY=http://localhost:{} in your agent's environment.",
                actual_port
            );
        }
        Err(e) => {
            if let Some(vault) = &vault {
                audit::log_event(
                    vault.db(),
                    "ProxyStopped",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    Some(&e.to_string()),
                    None,
                );
            }
            eprintln!("Proxy error: {}", e);
            std::process::exit(1);
        }
    }
}

fn spawn_daemon(port: u16, all_projects: bool) {
    let executable = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("Error: cannot find executable path: {}", e);
        std::process::exit(1);
    });

    let log_path = Vault::vault_dir().join("proxy.log");
    if let Some(parent) = log_path.parent()
        && let Err(e) = crate::secure_files::ensure_private_directory(parent)
    {
        eprintln!("Error: cannot prepare vault directory: {}", e);
        std::process::exit(1);
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot open log file {}: {}", log_path.display(), e);
            std::process::exit(1);
        });

    let stderr_file = log_file.try_clone().unwrap_or_else(|e| {
        eprintln!("Error: cannot clone log file handle: {}", e);
        std::process::exit(1);
    });

    let mut args: Vec<String> = vec!["serve".into()];
    if port == 0 {
        args.push("--random-port".into());
    } else {
        args.push("--port".into());
        args.push(port.to_string());
    }
    if all_projects {
        args.push("--all-projects".into());
    }

    match std::process::Command::new(executable)
        .args(&args)
        .stdout(log_file)
        .stderr(stderr_file)
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            println!("WispKey proxy daemonized (PID {}).", child.id());
            println!(
                "Discovery: {}",
                Vault::vault_dir().join("proxy.json").display()
            );
            println!("Logs: {}", log_path.display());
            println!("Stop: kill {}", child.id());
        }
        Err(e) => {
            eprintln!("Error: failed to spawn daemon: {}", e);
            std::process::exit(1);
        }
    }
}

/// Imports entries from a `.env` file into the vault with optional prefix and partition.
pub async fn handle_import(
    path: &str,
    prefix: Option<&str>,
    partition: Option<&str>,
    project: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match migrate::import_env_file(&vault, path, prefix, partition, project) {
        Ok(results) => {
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                    "output_path": results.output_path,
                    "project": project,
                    "partition": partition,
                }));
                return;
            }
            println!("Import complete:");
            println!("  Imported:  {}", results.imported);
            println!("  Skipped:   {}", results.skipped);
            if results.errors > 0 {
                println!("  Errors:    {}", results.errors);
            }
            if !results.output_path.is_empty() {
                println!();
                println!("Wisp token .env written to: {}", results.output_path);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Prints vault initialization, session, credential count, and proxy process status.
pub async fn handle_status() {
    if !Vault::exists() {
        if json_output() {
            print_json(serde_json::json!({
                "initialized": false,
                "vault_path": Vault::vault_dir().to_string_lossy(),
                "session_active": false,
                "proxy_running": false,
                "active_project": core::resolve_active_project(),
                "credential_count": 0,
            }));
            return;
        }
        println!("Vault: not initialized");
        println!("Run `wispkey init` to create a vault.");
        return;
    }

    let vault = Vault::open();
    match vault {
        Ok(v) => {
            let count = v.credential_count().unwrap_or(0);
            let created = v
                .vault_created_at()
                .unwrap_or_else(|_| "unknown".to_string());
            let session_active = Vault::open_with_session().is_ok();
            let proxy_status = read_proxy_status().await;

            if json_output() {
                print_json(serde_json::json!({
                    "vault_path": Vault::vault_dir().to_string_lossy(),
                    "created_at": created,
                    "credential_count": count,
                    "session_active": session_active,
                    "active_project": core::resolve_active_project(),
                    "proxy_running": proxy_status.running,
                    "proxy": proxy_status.info,
                    "proxy_check_error": proxy_status.check_error,
                }));
                return;
            }

            println!("Vault:       {}", Vault::vault_dir().display());
            println!("Created:     {}", created);
            println!("Credentials: {}", count);
            println!(
                "Session:     {}",
                if session_active { "active" } else { "locked" }
            );

            if proxy_status.info.is_some() && proxy_status.running {
                println!(
                    "Proxy:       running (PID {}, port {})",
                    proxy_status.pid.unwrap_or(0),
                    proxy_status.port.unwrap_or(0)
                );
            } else if proxy_status.info.is_some() {
                let detail = proxy_status
                    .check_error
                    .as_deref()
                    .map(|e| format!(": {}", e))
                    .unwrap_or_default();
                println!("Proxy:       stopped (stale proxy.json{})", detail);
            } else {
                println!("Proxy:       stopped");
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}

/// Prints audit log entries with optional credential filter and time window.
pub async fn handle_log(last: usize, credential: Option<&str>, since: Option<&str>) {
    let vault = match Vault::open() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let entries = audit::query_log(vault.db(), last, credential, since);

    if json_output() {
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "event_type": entry.event_type,
                    "credential_name": entry.credential_name,
                    "wisp_token": entry.wisp_token,
                    "target_host": entry.target_host,
                    "target_path": entry.target_path,
                    "http_method": entry.http_method,
                    "response_status": entry.response_status,
                    "denied": entry.denied,
                    "deny_reason": entry.deny_reason,
                    "project_name": entry.project_name,
                })
            })
            .collect();
        print_json(serde_json::json!({ "entries": list }));
        return;
    }

    if entries.is_empty() {
        println!("No audit log entries found.");
        return;
    }

    println!(
        "{:<20} {:<18} {:<20} {:<24} STATUS",
        "TIMESTAMP", "EVENT", "CREDENTIAL", "TARGET"
    );
    println!("{}", "-".repeat(96));
    for entry in &entries {
        let target = match (&entry.target_host, &entry.target_path) {
            (Some(host), Some(path)) => format!("{}{}", host, path),
            (Some(host), None) => host.clone(),
            _ => String::new(),
        };
        let status = if entry.denied {
            format!(
                "DENIED: {}",
                entry.deny_reason.as_deref().unwrap_or("policy")
            )
        } else if let Some(code) = entry.response_status {
            code.to_string()
        } else {
            String::new()
        };

        println!(
            "{:<20} {:<18} {:<20} {:<24} {}",
            &entry.timestamp[..19],
            entry.event_type,
            entry.credential_name.as_deref().unwrap_or("-"),
            target,
            status
        );
    }
    println!();
    println!("{} entries", entries.len());
}

/// Runs the Model Context Protocol server.
/// Uses an unlocked vault session when available, tries `WISPKEY_PASSWORD` for optional
/// auto-unlock, and otherwise stays online for env-sideload credentials.
pub async fn handle_mcp_serve() {
    if Vault::open_with_session().is_err()
        && let Ok(password) = std::env::var("WISPKEY_PASSWORD")
    {
        match Vault::open() {
            Ok(mut vault) => {
                if let Err(e) = vault.unlock(&password) {
                    eprintln!(
                        "Warning: auto-unlock via WISPKEY_PASSWORD failed: {}. Continuing with locked vault and env sideloads only.",
                        e
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: vault unavailable for auto-unlock: {}. Continuing with env sideloads only.",
                    e
                );
            }
        }
    }

    if let Err(e) = mcp::run_mcp_server().await {
        eprintln!("MCP server error: {}", e);
        std::process::exit(1);
    }
}

/// Creates a partition in the active or explicitly named project.
pub async fn handle_partition_create(name: &str, description: &str, project: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.create_partition(name, description, project) {
        Ok(p) => {
            let active = core::resolve_active_project();
            audit::log_event(
                vault.db(),
                "PartitionCreated",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(&active),
            );
            let project_name = project.unwrap_or(&active);
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "project": project_name,
                    "partition": partition_json(&vault, &p),
                }));
                return;
            }
            println!(
                "Partition '{}' created in project '{}'.",
                p.name, project_name
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Lists partitions in the active project or across every project.
pub async fn handle_partition_list(all_projects: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let list_result = if all_projects {
        vault.list_partitions()
    } else {
        let active = core::resolve_active_project();
        vault.list_partitions_in_project(&active)
    };

    match list_result {
        Ok(partitions) => {
            if json_output() {
                let active = core::resolve_active_project();
                let list: Vec<serde_json::Value> = partitions
                    .iter()
                    .map(|p| partition_json(&vault, p))
                    .collect();
                print_json(serde_json::json!({
                    "project": if all_projects { serde_json::Value::String("*".to_string()) } else { serde_json::Value::String(active) },
                    "all_projects": all_projects,
                    "partitions": list,
                }));
                return;
            }
            println!(
                "{:<20} {:<10} {:<30} CREATED",
                "NAME", "CREDS", "DESCRIPTION"
            );
            println!("{}", "-".repeat(72));
            for p in &partitions {
                let count = vault.partition_credential_count(&p.id).unwrap_or(0);
                println!(
                    "{:<20} {:<10} {:<30} {}",
                    p.name,
                    count,
                    p.description,
                    p.created_at.format("%Y-%m-%d %H:%M")
                );
            }
            println!();
            println!("{} partition(s)", partitions.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Deletes a partition and moves its credentials into the personal partition.
pub async fn handle_partition_delete(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.delete_partition(name) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "PartitionDeleted",
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
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "deleted": name,
                }));
                return;
            }
            println!(
                "Partition '{}' deleted. Credentials moved to 'personal'.",
                name
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Assigns a credential to the named partition.
pub async fn handle_partition_assign(credential: &str, partition_name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.assign_credential_to_partition(credential, partition_name) {
        Ok(()) => {
            println!(
                "Credential '{}' assigned to partition '{}'.",
                credential, partition_name
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Exports an encrypted bundle of a partition's credentials to a file path.
pub async fn handle_partition_export(name: &str, output: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_export_bundle_passphrase(passphrase_file);
    match partition::export_partition(&vault, name, &passphrase, output) {
        Ok(count) => {
            audit::log_event(
                vault.db(),
                "PartitionExported",
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
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "partition": name,
                    "output": output,
                    "credential_count": count,
                }));
                return;
            }
            println!(
                "Exported {} credential(s) from partition '{}' to {}",
                count, name, output
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Imports credentials from an encrypted partition bundle file.
pub async fn handle_partition_import(path: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match partition::import_partition(&vault, path, &passphrase) {
        Ok(results) => {
            audit::log_event(
                vault.db(),
                "PartitionImported",
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
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                }));
                return;
            }
            println!("Import complete:");
            println!("  Imported:  {}", results.imported);
            println!("  Skipped:   {}", results.skipped);
            if results.errors > 0 {
                println!("  Errors:    {}", results.errors);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Creates a new project within the vault.
pub async fn handle_project_create(name: &str, description: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.create_project(name, description) {
        Ok(p) => {
            audit::log_event(
                vault.db(),
                "ProjectCreated",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(&p.name),
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "project": project_json(&vault, &p, &core::resolve_active_project()),
                }));
                return;
            }
            println!("Project '{}' created.", p.name);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Lists all projects and highlights the active one.
pub async fn handle_project_list() {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let active = core::resolve_active_project();
    match vault.list_projects() {
        Ok(projects) => {
            if json_output() {
                let list: Vec<serde_json::Value> = projects
                    .iter()
                    .map(|project| project_json(&vault, project, &active))
                    .collect();
                print_json(serde_json::json!({
                    "active_project": active,
                    "projects": list,
                }));
                return;
            }
            println!(
                "{:<3} {:<20} {:<10} {:<30} CREATED",
                "", "NAME", "PARTS", "DESCRIPTION"
            );
            println!("{}", "-".repeat(80));
            for p in &projects {
                let count = vault.project_partition_count(&p.id).unwrap_or(0);
                let marker = if p.name == active { " *" } else { "  " };
                println!(
                    "{:<3} {:<20} {:<10} {:<30} {}",
                    marker,
                    p.name,
                    count,
                    p.description,
                    p.created_at.format("%Y-%m-%d %H:%M")
                );
            }
            println!();
            println!("{} project(s)  (* = active)", projects.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Deletes a project and moves its partitions into the default project.
pub async fn handle_project_delete(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.delete_project(name) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "ProjectDeleted",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(name),
            );
            println!("Project '{}' deleted. Partitions moved to 'default'.", name);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Sets the active project used by default for subsequent CLI commands.
pub async fn handle_project_use(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    match vault.get_project(name) {
        Ok(_) => {
            if let Err(e) = core::set_active_project(name) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "active_project": name,
                }));
                return;
            }
            println!("Active project set to '{}'.", name);
            println!("All commands will now default to this project.");
            println!(
                "Override per-terminal with: export WISPKEY_PROJECT={}",
                name
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Prints the active project and whether it came from env, file, or default.
pub async fn handle_project_current() {
    let active = core::resolve_active_project();
    if json_output() {
        let source = if std::env::var("WISPKEY_PROJECT").is_ok() {
            "env"
        } else if Vault::vault_dir().join("active_project").exists() {
            "file"
        } else {
            "default"
        };
        print_json(serde_json::json!({
            "active_project": active,
            "source": source,
        }));
        return;
    }
    println!("Active project: {}", active);
    if std::env::var("WISPKEY_PROJECT").is_ok() {
        println!("  (set via WISPKEY_PROJECT env var)");
    } else if Vault::vault_dir().join("active_project").exists() {
        println!("  (set via `wispkey project use`)");
    } else {
        println!("  (default)");
    }
}

/// Exports a full project into an encrypted share bundle.
pub async fn handle_project_export(name: &str, output: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_export_bundle_passphrase(passphrase_file);

    match sharing::export_project(&vault, name, &passphrase, output) {
        Ok(count) => {
            audit::log_event(
                vault.db(),
                "ProjectExported",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(name),
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "project": name,
                    "output": output,
                    "credential_count": count,
                }));
                return;
            }
            println!(
                "Exported project '{}' with {} credential(s) to {}",
                name, count, output
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Imports a full project from an encrypted share bundle.
pub async fn handle_project_import(path: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match sharing::import_project(&vault, path, &passphrase) {
        Ok(results) => {
            audit::log_event(
                vault.db(),
                "ProjectImported",
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
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                }));
                return;
            }
            println!("Import complete:");
            println!("  Imported:  {}", results.imported);
            println!("  Skipped:   {}", results.skipped);
            if results.errors > 0 {
                println!("  Errors:    {}", results.errors);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Exports one credential into an encrypted share bundle.
pub async fn handle_credential_export(name: &str, output: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_export_bundle_passphrase(passphrase_file);

    match sharing::export_credential(&vault, name, &passphrase, output) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "CredentialExported",
                Some(name),
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "credential": name,
                    "output": output,
                }));
                return;
            }
            println!("Exported credential '{}' to {}", name, output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Imports one credential from an encrypted share bundle.
pub async fn handle_credential_import(
    path: &str,
    project: Option<&str>,
    partition: Option<&str>,
    passphrase_file: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match sharing::import_credential(&vault, path, &passphrase, project, partition) {
        Ok(results) => {
            audit::log_event(
                vault.db(),
                "CredentialImported",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                project,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                    "project": project,
                    "partition": partition,
                }));
                return;
            }
            println!("Import complete:");
            println!("  Imported:  {}", results.imported);
            println!("  Skipped:   {}", results.skipped);
            if results.errors > 0 {
                println!("  Errors:    {}", results.errors);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Prints WispKey Cloud auth state, tier, and local sync summary.
pub async fn handle_cloud_status() {
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let status = match cloud::summarize_local_cloud_status(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    if !status.authenticated {
        println!("WispKey Cloud: not connected");
        println!("Run `wispkey cloud login` to connect.");
        println!("Pricing: Pro $1.99/mo | Team $9.99/user/mo");
        println!("API: {}", config.api_url);
        return;
    }
    println!("WispKey Cloud: connected (local session)");
    println!("API:          {}", config.api_url);
    println!("Tier:         {}", cloud_tier_label(&status.tier));
    if let Some(user_id) = config.user_id.as_ref() {
        println!("User ID:      {}", user_id);
    }
    if let Some(org_id) = config.org_id.as_ref() {
        println!("Org ID:       {}", org_id);
    }
    if let Some(last) = config.last_sync.as_ref() {
        println!("Last sync:    {}", last);
    }
    println!("Partitions (local manifest): {}", status.synced_partitions);
    println!(
        "Storage:      {} / {} bytes (local estimate until API is live)",
        status.storage_used_bytes, status.storage_limit_bytes
    );
}

/// Opens an interactive WispKey Cloud login and persists the local session.
pub async fn handle_cloud_login() {
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let mut client = CloudClient::new(config);
    match client.login().await {
        Ok(_) => {
            println!("Logged in to WispKey Cloud.");
        }
        Err(e) => {
            print_cloud_error(&e);
            std::process::exit(1);
        }
    }
}

/// Clears the stored WispKey Cloud session from local configuration.
pub async fn handle_cloud_logout() {
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let mut client = CloudClient::new(config);
    match client.logout() {
        Ok(()) => println!("Logged out of WispKey Cloud."),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Uploads the named partition from the vault to WispKey Cloud.
pub async fn handle_cloud_push(partition_name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let client = CloudClient::new(config);
    match client.push_partition(&vault, partition_name).await {
        Ok(manifest) => {
            println!("Push complete for partition '{}'.", manifest.partition_name);
            println!("Last synced at: {}", manifest.last_synced_at);
        }
        Err(e) => {
            print_cloud_error(&e);
            std::process::exit(1);
        }
    }
}

/// Downloads the named partition from WispKey Cloud into the vault.
pub async fn handle_cloud_pull(partition_name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let client = CloudClient::new(config);
    match client.pull_partition(&vault, partition_name).await {
        Ok(manifest) => {
            println!("Pull complete for partition '{}'.", manifest.partition_name);
            println!("Last synced at: {}", manifest.last_synced_at);
        }
        Err(e) => {
            print_cloud_error(&e);
            std::process::exit(1);
        }
    }
}

/// Syncs every cloud-backed partition between the vault and WispKey Cloud.
pub async fn handle_cloud_sync() {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let client = CloudClient::new(config);
    match client.sync_all(&vault).await {
        Ok(manifests) => {
            println!("Sync complete ({} partition(s)).", manifests.len());
            for manifest in &manifests {
                println!(
                    "  - {} @ {}",
                    manifest.partition_name, manifest.last_synced_at
                );
            }
        }
        Err(e) => {
            print_cloud_error(&e);
            std::process::exit(1);
        }
    }
}

fn cloud_tier_label(tier: &CloudTier) -> &'static str {
    match tier {
        CloudTier::Personal => "Personal",
        CloudTier::Cloud => "Cloud",
        CloudTier::Enterprise => "Enterprise",
    }
}

fn print_cloud_error(error: &CloudError) {
    match error {
        CloudError::Vault(vault_error) => eprintln!("Error: {}", vault_error),
        other => eprintln!("Error: {}", other),
    }
}

/// Prints proxy access policies loaded from `policies.toml` on disk.
pub async fn handle_policy_list() {
    let config = crate::policy::load_policies_from_disk();
    if config.policy.is_empty() {
        println!("No policies configured.");
        println!("Run `wispkey policy init` to create a template policies.toml");
        return;
    }
    println!(
        "{} policies loaded from {}",
        config.policy.len(),
        crate::policy::policies_path().display()
    );
    println!();
    for policy in &config.policy {
        println!("  [{}]", policy.name);
        if let Some(ref cred) = policy.credential {
            println!("    credential: {}", cred);
        }
        if let Some(ref agent) = policy.agent {
            println!("    agent: {}", agent);
        }
        if !policy.allowed_methods.is_empty() {
            println!("    allowed_methods: {}", policy.allowed_methods.join(", "));
        }
        if !policy.allowed_hosts.is_empty() {
            println!("    allowed_hosts: {}", policy.allowed_hosts.join(", "));
        }
        if !policy.denied_hosts.is_empty() {
            println!("    denied_hosts: {}", policy.denied_hosts.join(", "));
        }
        if !policy.denied_paths.is_empty() {
            println!("    denied_paths: {}", policy.denied_paths.join(", "));
        }
        if !policy.allowed_paths.is_empty() {
            println!("    allowed_paths: {}", policy.allowed_paths.join(", "));
        }
        if let Some(ref rl) = policy.rate_limit {
            println!("    rate_limit: {}", rl);
        }
        if let Some(ref tw) = policy.time_window {
            println!("    time_window: {}", tw);
        }
        if policy.deny {
            println!("    deny: true");
        }
        println!();
    }
}

/// Writes a commented `policies.toml` template when the file does not exist.
pub async fn handle_policy_init() {
    let path = crate::policy::policies_path();
    if path.exists() {
        println!("Policies file already exists at {}", path.display());
        return;
    }
    let template = r#"# WispKey Policy Configuration
# Each [[policy]] block defines an access rule evaluated on every proxied request.
# Policies are evaluated in order; the first match that denies wins.

# Example: restrict production AWS credentials to GET-only
# [[policy]]
# name = "restrict-aws-prod"
# credential = "aws-prod"
# allowed_methods = ["GET"]
# denied_paths = ["/admin*", "/delete*"]
# rate_limit = "10/minute"

# Example: block all access to a credential
# [[policy]]
# name = "block-deprecated"
# credential = "old-api-key"
# deny = true

# Example: time-windowed access
# [[policy]]
# name = "business-hours-only"
# credential = "billing-api"
# time_window = "09:00-17:00"
"#;
    std::fs::write(&path, template).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
    println!("Created policies template at {}", path.display());
}

/// Parses `policies.toml` and reports success or TOML validation errors.
pub async fn handle_policy_check() {
    let path = crate::policy::policies_path();
    if !path.exists() {
        eprintln!("No policies file at {}", path.display());
        eprintln!("Run `wispkey policy init` to create one.");
        std::process::exit(1);
    }
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });
    match toml::from_str::<crate::policy::PolicyConfig>(&content) {
        Ok(config) => {
            println!(
                "OK -- {} policies parsed from {}",
                config.policy.len(),
                path.display()
            );
            for policy in &config.policy {
                println!("  [{}] ok", policy.name);
            }
        }
        Err(e) => {
            eprintln!("INVALID -- parse error in {}", path.display());
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn prompt_password(prompt: &str) -> String {
    if let Ok(password) = std::env::var("WISPKEY_PASSWORD") {
        return password;
    }
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Error reading password: {}", e);
        eprintln!("Hint: set WISPKEY_PASSWORD env var for non-interactive use.");
        std::process::exit(1);
    })
}

fn prompt_password_confirm(prompt1: &str, prompt2: &str) -> Option<String> {
    if let Ok(password) = std::env::var("WISPKEY_PASSWORD") {
        return Some(password);
    }
    let password1 = prompt_password(prompt1);
    let password2 = rpassword::prompt_password(prompt2).unwrap_or_else(|e| {
        eprintln!("Error reading password: {}", e);
        std::process::exit(1);
    });
    if password1 == password2 {
        Some(password1)
    } else {
        None
    }
}

fn prompt_export_bundle_passphrase(passphrase_file: Option<&str>) -> String {
    let passphrase = read_bundle_passphrase(passphrase_file, true);
    validate_export_bundle_passphrase(&passphrase);
    passphrase
}

fn prompt_import_bundle_passphrase(passphrase_file: Option<&str>) -> String {
    read_bundle_passphrase(passphrase_file, false)
}

fn read_bundle_passphrase(passphrase_file: Option<&str>, confirm_interactive: bool) -> String {
    if let Some(path) = passphrase_file {
        return read_bundle_passphrase_file(path);
    }
    if let Ok(passphrase) = std::env::var(BUNDLE_PASSPHRASE_ENV) {
        return passphrase;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!("Error: bundle passphrase is separate from WISPKEY_PASSWORD.");
        eprintln!(
            "Hint: set {BUNDLE_PASSPHRASE_ENV} or pass --bundle-passphrase-file for encrypted bundle operations."
        );
        std::process::exit(1);
    }

    if confirm_interactive {
        let passphrase1 = prompt_hidden_bundle_passphrase("Enter bundle passphrase: ");
        let passphrase2 = prompt_hidden_bundle_passphrase("Confirm bundle passphrase: ");
        if passphrase1 != passphrase2 {
            eprintln!("Error: bundle passphrases did not match");
            std::process::exit(1);
        }
        return passphrase1;
    }

    prompt_hidden_bundle_passphrase("Enter bundle passphrase: ")
}

fn read_bundle_passphrase_file(path: &str) -> String {
    let passphrase = match secure_files::read_private_string(
        Path::new(path),
        MAX_BUNDLE_PASSPHRASE_FILE_BYTES,
    ) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Error reading bundle passphrase file: {error}");
            std::process::exit(1);
        }
    };
    passphrase.trim_end_matches(['\n', '\r']).to_string()
}

fn prompt_hidden_bundle_passphrase(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|error| {
        eprintln!("Error reading bundle passphrase: {error}");
        eprintln!(
            "Hint: set {BUNDLE_PASSPHRASE_ENV} or pass --bundle-passphrase-file for non-interactive use."
        );
        std::process::exit(1);
    })
}

fn validate_export_bundle_passphrase(passphrase: &str) {
    if passphrase.chars().count() < MIN_BUNDLE_PASSPHRASE_LEN {
        eprintln!(
            "Error: bundle passphrase must be at least {MIN_BUNDLE_PASSPHRASE_LEN} characters."
        );
        eprintln!(
            "Hint: use a dedicated export passphrase; do not reuse WISPKEY_PASSWORD or send it with the bundle."
        );
        std::process::exit(1);
    }
}
