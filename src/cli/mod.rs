/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: CLI command handlers -- wires user-facing subcommands to vault operations.
 *              Handles interactive password prompts with WISPKEY_PASSWORD env var fallback.
 * Created: 2026-04-07
 * Last Modified: 2026-04-12
 */

use crate::audit;
use crate::cloud::{self, CloudClient, CloudError, CloudTier};
use crate::core::{self, CredentialType, Vault, VaultError};
use crate::mcp;
use crate::migrate;
use crate::partition;
use crate::proxy;

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

    match vault.add_credential(
        name,
        credential_type,
        &resolved_value,
        hosts,
        tags,
        partition,
    ) {
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
        vault.list_credentials_in_partition(partition_name)
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

            println!("{:<24} {:<16} {:<20} TAGS", "NAME", "TYPE", "CREATED");
            println!("{}", "-".repeat(72));
            for cred in &credentials {
                let tags = if cred.tags.is_empty() {
                    String::new()
                } else {
                    cred.tags.join(", ")
                };
                println!(
                    "{:<24} {:<16} {:<20} {}",
                    cred.name,
                    cred.credential_type.display_name(),
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
            println!("Name:       {}", cred.name);
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
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if daemon {
        spawn_daemon(port, all_projects);
        return;
    }

    let active = core::resolve_active_project();
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
pub async fn handle_import(path: &str, prefix: Option<&str>, partition: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match migrate::import_env_file(&vault, path, prefix, partition) {
        Ok(results) => {
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

            println!("Vault:       {}", Vault::vault_dir().display());
            println!("Created:     {}", created);
            println!("Credentials: {}", count);
            println!(
                "Session:     {}",
                if session_active { "active" } else { "locked" }
            );

            let info_path = Vault::vault_dir().join("proxy.json");
            if info_path.exists() {
                if let Ok(contents) = std::fs::read_to_string(&info_path)
                    && let Ok(info) = serde_json::from_str::<serde_json::Value>(&contents)
                {
                    let pid = info.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                    let port = info.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!("Proxy:       running (PID {}, port {})", pid, port);
                }
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

/// Runs the Model Context Protocol server backed by an unlocked vault session.
/// Falls back to `WISPKEY_PASSWORD` for non-interactive auto-unlock (e.g. Cursor MCP spawning).
pub async fn handle_mcp_serve() {
    let _vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(_) => match std::env::var("WISPKEY_PASSWORD") {
            Ok(password) => {
                let mut vault = Vault::open().unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                });
                vault.unlock(&password).unwrap_or_else(|e| {
                    eprintln!("Error: auto-unlock via WISPKEY_PASSWORD failed: {}", e);
                    std::process::exit(1);
                });
                vault
            }
            Err(_) => {
                eprintln!("Error: vault is locked and WISPKEY_PASSWORD is not set.");
                eprintln!(
                    "Hint: run `wispkey unlock` or set WISPKEY_PASSWORD for non-interactive use."
                );
                std::process::exit(1);
            }
        },
    };

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
pub async fn handle_partition_export(name: &str, output: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_password_confirm("Enter bundle passphrase: ", "Confirm passphrase: ");
    let passphrase = match passphrase {
        Some(p) => p,
        None => {
            eprintln!("Error: passphrases did not match");
            std::process::exit(1);
        }
    };
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
pub async fn handle_partition_import(path: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_password("Enter bundle passphrase: ");
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
    println!("Active project: {}", active);
    if std::env::var("WISPKEY_PROJECT").is_ok() {
        println!("  (set via WISPKEY_PROJECT env var)");
    } else if Vault::vault_dir().join("active_project").exists() {
        println!("  (set via `wispkey project use`)");
    } else {
        println!("  (default)");
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
