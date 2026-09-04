use crate::audit;
use crate::core::{Vault, VaultError};

use super::shared::{json_output, print_json};

pub async fn handle_log(last: usize, credential: Option<&str>, since: Option<&str>) {
    let vault = match Vault::open() {
        Ok(v) => Some(v),
        Err(VaultError::NotFound) => None,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let entries = audit::query_combined_log(vault.as_ref().map(Vault::db), last, credential, since);

    if json_output() {
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "event_type": entry.event_type,
                    "credential_name": entry.credential_name,
                    "token_fingerprint": entry.token_fingerprint,
                    "target_host": entry.target_host,
                    "target_path": entry.target_path,
                    "http_method": entry.http_method,
                    "response_status": entry.response_status,
                    "denied": entry.denied,
                    "deny_reason": entry.deny_reason,
                    "project_name": entry.project_name,
                    "source": entry.source,
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
