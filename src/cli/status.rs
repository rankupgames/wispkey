use crate::core::{self, Vault};
use crate::proxy::lifecycle;

use super::shared::{json_output, print_json};

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
            let proxy_status = lifecycle::read_status().await;

            if json_output() {
                print_json(serde_json::json!({
                    "vault_path": Vault::vault_dir().to_string_lossy(),
                    "created_at": created,
                    "credential_count": count,
                    "session_active": session_active,
                    "active_project": core::resolve_active_project(),
                    "proxy_running": proxy_status.running,
                    "proxy_status": proxy_status.state.as_str(),
                    "proxy": proxy_status.metadata.as_ref().map(lifecycle::ProxyMetadata::public_json),
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

            if let Some(metadata) = &proxy_status.metadata {
                let detail = proxy_status
                    .check_error
                    .as_deref()
                    .map(|e| format!(": {}", e))
                    .unwrap_or_default();
                println!(
                    "Proxy:       {} (PID {}, port {}{})",
                    proxy_status.state.as_str(),
                    metadata.pid,
                    metadata.port,
                    detail
                );
            } else {
                println!("Proxy:       stopped");
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
