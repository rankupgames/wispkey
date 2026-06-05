use crate::audit;
use crate::core::Vault;
use crate::sharing;

use super::shared::{
    json_output, print_json, prompt_export_bundle_passphrase, prompt_import_bundle_passphrase,
};

pub async fn handle_credential_export(name: &str, output: &str, passphrase_file: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_export_bundle_passphrase(passphrase_file);

    match sharing::export_credential(&vault, name, &passphrase, output) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "CredentialExported",
                Some(name),
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
                    "credential": name,
                    "output": output,
                }));
                return;
            }
            println!("Exported credential '{}' to {}", name, output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Imports one credential from an encrypted share bundle.
pub async fn handle_credential_import(
    path: &str,
    project: Option<&str>,
    partition: Option<&str>,
    passphrase_file: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match sharing::import_credential(&vault, path, &passphrase, project, partition) {
        Ok(results) => {
            audit::log_event(
                vault.db(),
                "CredentialImported",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                project,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                    "project": project,
                    "partition": partition,
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
