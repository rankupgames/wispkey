use std::path::Path;

use crate::{core::Vault, operations};

use super::shared::{json_output, print_json};

pub fn handle_operation_identity() {
    match operations::current_principal() {
        Ok(principal) => {
            if json_output() {
                print_json(serde_json::json!({
                    "principal": principal,
                    "source": "operating_system",
                    "scope": "local_os_account"
                }));
            } else {
                println!("{principal}");
            }
        }
        Err(error) => fail(error),
    }
}

pub fn handle_operation_check(config: Option<&Path>, operation: Option<&str>) {
    let default_path = Vault::vault_dir().join("operations.toml");
    match operations::check(config.unwrap_or(&default_path), operation) {
        Ok(report) => {
            if json_output() {
                print_json(serde_json::to_value(report).expect("fixed preflight schema"));
            } else {
                println!(
                    "Configuration valid for {} operation(s) and the current OS account.",
                    report.checked_operations
                );
                println!("Catalog revision: {}", report.catalog_revision);
                println!(
                    "Preflight only: credentials and live targets are unverified; execution is unavailable."
                );
            }
        }
        Err(error) => fail(error),
    }
}

fn fail(error: &'static str) -> ! {
    if json_output() {
        print_json(serde_json::json!({
            "configuration_valid": false,
            "error": error,
            "execution_available": false,
        }));
    } else {
        eprintln!("Operation preflight failed: {error}");
    }
    std::process::exit(1)
}
