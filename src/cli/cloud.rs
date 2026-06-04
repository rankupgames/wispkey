use crate::cloud::{self, CloudClient, CloudError, CloudTier};
use crate::core::Vault;

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
