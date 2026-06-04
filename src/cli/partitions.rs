use crate::audit;
use crate::core::{self, Vault};
use crate::partition;

use super::shared::{
    json_output, partition_json, print_json, prompt_export_bundle_passphrase,
    prompt_import_bundle_passphrase,
};

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
