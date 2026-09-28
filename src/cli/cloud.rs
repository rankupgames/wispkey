use super::shared::{json_output, print_json};
use crate::cloud::{self, CloudClient, CloudError, CloudTier};
use crate::core::Vault;

pub async fn handle_cloud_status(remote: bool) {
    let config = match cloud::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    if config.clerk_session_token.is_some() && Vault::exists() {
        let opened = Vault::open_with_session()
            .or_else(|error| if remote { Err(error) } else { Vault::open() });
        match opened {
            Ok(vault) => {
                let client = CloudClient::new(config.clone());
                match client.sync_status(&vault, remote).await {
                    Ok(status) => {
                        if json_output() {
                            print_json(status);
                        } else {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&status).expect("status serializes")
                            );
                        }
                        return;
                    }
                    Err(error) => {
                        print_cloud_error(&error);
                        std::process::exit(1);
                    }
                }
            }
            Err(error) => {
                eprintln!("Error: {error}");
                std::process::exit(1);
            }
        }
    } else if remote {
        eprintln!("Error: remote status requires an authenticated session and an unlocked vault");
        std::process::exit(1);
    }
    let status = match cloud::summarize_local_cloud_status(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    if json_output() {
        let mut output = serde_json::to_value(&status).expect("cloud status is serializable");
        output["source"] = serde_json::json!("local");
        output["remote_verified"] = serde_json::json!(false);
        output["sync_available"] = serde_json::json!(true);
        output["pending_changes"] = serde_json::json!("unknown_until_unlocked");
        output["api_url"] = serde_json::json!(config.api_url);
        output["last_sync"] = serde_json::json!(config.last_sync);
        print_json(output);
        return;
    }
    if !status.authenticated {
        println!("WispKey Cloud: not connected");
        println!("Run `wispkey cloud login` to connect.");
        println!("Pricing: Personal free local-only | Cloud $1.99/mo | Enterprise contact us");
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
            if json_output() {
                print_json(serde_json::json!({"ok":true,"authenticated":true}));
            } else {
                println!("Logged in to WispKey Cloud.");
            }
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
        Ok(()) => {
            if json_output() {
                print_json(serde_json::json!({"ok": true, "authenticated": false}));
            } else {
                println!("Logged out of WispKey Cloud.");
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Synchronizes one partition or all tracked partitions in the active project.
pub async fn handle_cloud_transfer(
    partition: Option<&str>,
    mode: cloud::SyncMode,
    passphrase_file: Option<&str>,
    resolution: Option<(&str, &str)>,
) {
    let vault = Vault::open_with_session().unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1)
    });
    let config = cloud::load_config().unwrap_or_else(|error| {
        print_cloud_error(&error);
        std::process::exit(1)
    });
    let passphrase = super::shared::prompt_export_bundle_passphrase(passphrase_file);
    let client = CloudClient::new(config);
    let result = if let Some(partition) = partition {
        client
            .synchronize_partition(&vault, partition, &passphrase, mode, resolution)
            .await
            .map(|result| vec![result])
    } else {
        client.sync_all(&vault, &passphrase).await
    };
    match result {
        Ok(results) => {
            if json_output() {
                print_json(serde_json::json!({"ok":true,"partitions":results}));
            } else {
                for result in results {
                    println!(
                        "{} / {}: {} (revision {})",
                        result.project,
                        result.partition_name,
                        result.outcome,
                        result.remote_revision.as_deref().unwrap_or("absent")
                    );
                    if result.local_changes_pending {
                        println!("Local changes remain pending; run sync again.");
                    }
                    if let Some(path) = result.recovery_path {
                        println!("Encrypted recovery copy: {path}");
                    }
                }
            }
        }
        Err(error) => {
            if json_output() {
                let status = client.sync_status(&vault, false).await.ok();
                print_json(
                    serde_json::json!({"ok":false,"error":error.to_string(),"status":status}),
                );
            } else {
                print_cloud_error(&error);
            }
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

pub fn handle_cloud_recover(path: &str, passphrase_file: Option<&str>) {
    let vault = Vault::open_with_session().unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1)
    });
    let passphrase = super::shared::prompt_import_bundle_passphrase(passphrase_file);
    match cloud::recover_partition(&vault, std::path::Path::new(path), &passphrase) {
        Ok(result) => {
            if json_output() {
                print_json(result);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("recovery metadata serializes")
                );
            }
        }
        Err(error) => {
            print_cloud_error(&error);
            std::process::exit(1);
        }
    }
}

fn print_cloud_error(error: &CloudError) {
    match error {
        CloudError::Vault(vault_error) => eprintln!("Error: {}", vault_error),
        other => eprintln!("Error: {}", other),
    }
}
