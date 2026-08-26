//! `.env` discovery and project/environment attachment handlers.
//!
//! Author: Miguel A. Lopez
//! Created: 2026-07-14

use crate::core::Vault;
use crate::migrate;

use super::shared::{json_output, print_json};

pub async fn handle_env_list(directory: &str) {
    match migrate::discover_env_files(directory) {
        Ok(results) => {
            if json_output() {
                print_json(serde_json::json!({
                    "directory": results.directory,
                    "files": results.files,
                    "warnings": results.warnings,
                }));
                return;
            }

            for path in &results.files {
                println!("{path}");
            }
            println!();
            println!("{} .env file(s) found", results.files.len());
            for warning in results.warnings {
                eprintln!(
                    "Warning: could not scan {}: {}",
                    warning.path, warning.error
                );
            }
        }
        Err(error) => {
            eprintln!("Error scanning {directory}: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn handle_env_attach(
    path: &str,
    keys: &[String],
    project: &str,
    environment: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };

    match migrate::attach_env_file(&vault, path, keys, project, environment) {
        Ok(results) => {
            if json_output() {
                print_json(
                    serde_json::to_value(&results).expect("attachment results must serialize"),
                );
                return;
            }

            println!(
                "Attached {} to project '{}' environment '{}'.",
                results.path, results.project, results.environment
            );
            for credential in &results.credentials {
                println!("  {} -> {}", credential.env_key, credential.credential);
            }
            println!();
            println!("  Imported:         {}", results.imported);
            println!("  Reused:           {}", results.reused);
            println!("  Already attached: {}", results.already_attached);
            println!("  Updated in file:  {}", results.updated);
            println!();
            println!("Next: wispkey project use {}", results.project);
            println!("Warning: attached credentials have no inferred host restrictions.");
        }
        Err(error) => {
            eprintln!("Error attaching {path}: {error}");
            std::process::exit(1);
        }
    }
}
