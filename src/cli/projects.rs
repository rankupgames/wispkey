use crate::audit;
use crate::core::{self, Vault};
use crate::sharing;

use super::shared::{
    json_output, print_json, project_json, prompt_export_bundle_passphrase,
    prompt_import_bundle_passphrase,
};

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
