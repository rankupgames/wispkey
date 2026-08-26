use std::process::Command;
use std::time::{Duration, Instant};

use crate::core::{Vault, VaultError};
use crate::owner_ipc;

/// Starts the owner IPC server, optionally spawning the tray UI binary.
pub async fn handle_tray(ipc_only: bool) {
    if !Vault::exists() {
        eprintln!("Error: {}", VaultError::NotFound);
        std::process::exit(1);
    }
    if !ipc_only && owner_ipc::is_live().await {
        spawn_tray_ui();
        return;
    }

    if ipc_only {
        if let Err(error) = owner_ipc::serve().await {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        }
        return;
    }

    let server = tokio::spawn(owner_ipc::serve());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !owner_ipc::is_live().await {
        if server.is_finished() || Instant::now() >= deadline {
            eprintln!("Error: owner IPC did not start");
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    spawn_tray_ui();
    if let Err(error) = server.await.expect("owner IPC task panicked") {
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
