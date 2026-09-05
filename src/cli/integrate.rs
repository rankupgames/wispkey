use std::path::PathBuf;

use crate::integrate::{self, IntegrateClient};

use super::shared::{json_output, print_json};

pub async fn handle_integrate(client: IntegrateClient, print_only: bool, path: Option<String>) {
    let output_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| client.default_path());

    if let Some(warning) = client
        .requires_plaintext_env_warning()
        .then_some(integrate::JSON_PLAINTEXT_ENV_WARNING)
    {
        eprintln!("Warning: {warning}");
    }

    let plan = if print_only {
        integrate::plan_print(client, output_path)
    } else {
        integrate::plan_write(client, output_path)
    };

    match plan {
        Ok(plan) => {
            if json_output() {
                print_json(serde_json::json!({
                    "client": plan.client,
                    "format": plan.format,
                    "path": plan.path,
                    "written": plan.written,
                    "changed": plan.changed,
                    "plaintext_env_warning": plan.plaintext_env_warning,
                    "config": plan.config,
                }));
                return;
            }

            if print_only {
                println!(
                    "# {} MCP config ({})",
                    client.as_str(),
                    match client.config_kind() {
                        integrate::ConfigKind::Json => "JSON",
                        integrate::ConfigKind::Toml => "TOML",
                    }
                );
                println!("# Default path: {}", plan.path.display());
                println!();
                match integrate::generate_config_text(client) {
                    Ok(text) => print!("{text}"),
                    Err(error) => {
                        eprintln!("Error: {error}");
                        std::process::exit(1);
                    }
                }
                return;
            }

            if plan.changed {
                println!(
                    "Wrote {} MCP config to {}",
                    client.as_str(),
                    plan.path.display()
                );
            } else {
                println!(
                    "WispKey MCP config already present in {} (unchanged)",
                    plan.path.display()
                );
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}
