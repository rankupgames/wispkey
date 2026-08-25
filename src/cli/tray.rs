use std::process::Command;

use crate::core::{Vault, VaultError};
use crate::owner_ipc;

use super::shared::{json_output, print_json};

/// Locks the vault by clearing the session file and in-memory key.
pub async fn handle_lock() {
    let mut vault = match Vault::open() {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        }
    };
    match vault.lock() {
        Ok(()) => {
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "session_active": false,
                }));
                return;
            }
            println!("Vault locked.");
        }
        Err(error) => {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        }
    }
}

/// Starts the owner IPC server, optionally spawning the tray UI binary.
pub async fn handle_tray(ipc_only: bool) {
    if !Vault::exists() {
        eprintln!("Error: {}", VaultError::NotFound);
        std::process::exit(1);
    }
    if !ipc_only {
        spawn_tray_ui();
    }
    if let Err(error) = owner_ipc::serve().await {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }
}

fn spawn_tray_ui() {
    let candidates = tray_binary_candidates();
    for path in candidates {
        match Command::new(&path).spawn() {
            Ok(_) => return,
            Err(error) => {
                tracing::debug!(path = %path, error = %error, "failed to spawn tray UI");
            }
        }
    }
    eprintln!(
        "Note: wispkey-tray GUI was not found. Owner IPC is running; use `wispkey-tray` or `--ipc-only`."
    );
}

fn tray_binary_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join("wispkey-tray").to_string_lossy().into_owned());
        candidates.push(
            parent
                .join("wispkey-tray.exe")
                .to_string_lossy()
                .into_owned(),
        );
    }
    candidates.push("wispkey-tray".to_string());
    candidates
}
