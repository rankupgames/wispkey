use crate::audit;
use crate::core::{self, Vault};
use crate::proxy::lifecycle;
use crate::proxy::{self, StartProxyOutcome};

use super::shared::{json_output, print_json};

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
        Ok(StartProxyOutcome::AlreadyRunning(metadata)) => {
            println!(
                "WispKey proxy is already running (PID {}, port {}).",
                metadata.pid, metadata.port
            );
            println!(
                "Set HTTP_PROXY=http://localhost:{} in your agent's environment.",
                metadata.port
            );
        }
        Ok(StartProxyOutcome::Stopped { port }) => {
            println!("WispKey proxy stopped (port {}).", port);
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

pub async fn handle_proxy_status() {
    let status = lifecycle::read_status().await;
    if json_output() {
        print_json(status.public_json());
        return;
    }
    print_proxy_status(&status);
}

pub async fn handle_proxy_stop() {
    match lifecycle::stop_owned_proxy("manual proxy stop").await {
        Ok(result) => {
            if json_output() {
                print_json(serde_json::json!({
                    "state": result.state.as_str(),
                    "stopped": result.stopped,
                    "message": result.message,
                }));
                return;
            }
            println!("{}", result.message);
        }
        Err(e) => {
            if json_output() {
                print_json(serde_json::json!({"error": e}));
            } else {
                eprintln!("Error: {}", e);
            }
            std::process::exit(1);
        }
    }
}

pub async fn handle_proxy_cleanup() {
    match lifecycle::cleanup_stale_proxy("manual proxy cleanup").await {
        Ok(result) => {
            if json_output() {
                print_json(serde_json::json!({
                    "state": result.state.as_str(),
                    "cleaned": result.state == lifecycle::ProxyState::Stale,
                    "message": result.message,
                }));
                return;
            }
            println!("{}", result.message);
        }
        Err(e) => {
            if json_output() {
                print_json(serde_json::json!({"error": e}));
            } else {
                eprintln!("Error: {}", e);
            }
            std::process::exit(1);
        }
    }
}

fn print_proxy_status(status: &lifecycle::ProxyStatus) {
    match &status.metadata {
        Some(metadata) => {
            println!("Proxy:       {}", status.state.as_str());
            println!("Address:     {}", metadata.address);
            println!("PID:         {}", metadata.pid);
            println!("Port:        {}", metadata.port);
            println!("Mode:        {}", metadata.mode);
            println!(
                "Scope:       {}",
                metadata
                    .project_scope
                    .as_deref()
                    .unwrap_or("ALL (no project filtering)")
            );
            println!("Started:     {}", metadata.started_at);
            if let Some(parent_pid) = metadata.parent_pid {
                println!("Parent PID:  {}", parent_pid);
            }
            if let Some(error) = &status.check_error {
                println!("Check:       {}", error);
            }
        }
        None => {
            println!("Proxy:       stopped");
            println!("Address:     {}", status.address_or_default());
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
            println!("Stop: wispkey proxy stop");
        }
        Err(e) => {
            eprintln!("Error: failed to spawn daemon: {}", e);
            std::process::exit(1);
        }
    }
}
