use std::process::Command;

use crate::audit;
use crate::core::Vault;

use super::exec::{exit_code, open_unlocked_vault};

pub struct RunArgs<'a> {
    pub overrides: &'a [String],
    pub manifest: Option<&'a str>,
    pub project: Option<&'a str>,
    pub command: &'a [String],
}

pub async fn handle_run(args: RunArgs<'_>) {
    if args.command.is_empty() {
        eprintln!("Error: missing child command after --");
        std::process::exit(1);
    }

    // Parse manual config before opening a vault, preserving fail-closed preflight.
    let manual = match super::worktree::manual_manifest(args.manifest, args.overrides) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };
    let vault = open_unlocked_vault();
    let transaction = match vault.db().unchecked_transaction() {
        Ok(transaction) => transaction,
        Err(_) => {
            eprintln!("Error: cannot read a consistent vault snapshot");
            std::process::exit(1);
        }
    };
    let selection = match super::worktree::select(&vault, manual, args.project, args.overrides) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };
    let project = selection.project;
    let (env_vars, credential_names) = resolve_manifest_env(
        &vault,
        &project,
        &selection.manifest,
        selection.partition_id.as_deref(),
    );

    if transaction.commit().is_err() {
        eprintln!("Error: cannot finish vault snapshot");
        std::process::exit(1);
    }

    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    for (name, value) in env_vars {
        command.env(name, value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Error: failed to spawn child command: {}", e);
            std::process::exit(1);
        }
    };

    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            eprintln!("Error: failed to wait for child command: {}", e);
            std::process::exit(1);
        }
    };
    let code = exit_code(status);
    audit_credential_run(
        &vault,
        &credential_names,
        &args.command[0],
        Some(code),
        &project,
    );
    std::process::exit(code);
}

fn resolve_manifest_env(
    vault: &Vault,
    project: &str,
    manifest: &super::worktree::Manifest,
    partition_id: Option<&str>,
) -> (Vec<(String, String)>, Vec<String>) {
    let env = &manifest.env;
    let mut env_vars = Vec::with_capacity(env.len());
    let mut credential_names = Vec::new();
    for (env_name, value) in env {
        let raw_value = value.as_str();
        if let Some(credential_name) = raw_value.strip_prefix("cred:") {
            if credential_name.is_empty() {
                eprintln!(
                    "Error: [env].{} has an empty credential reference",
                    env_name
                );
                std::process::exit(1);
            }
            if let Some(partition) = partition_id {
                let in_scope = vault
                    .get_credential_in_project(project, credential_name)
                    .is_ok_and(|credential| credential.partition_id.as_deref() == Some(partition));
                if !in_scope {
                    eprintln!("Error: credential is outside the bound development environment");
                    std::process::exit(1);
                }
            }
            let secret = match vault.decrypt_credential_value_in_project(project, credential_name) {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("Error: referenced credential is unavailable for use");
                    std::process::exit(1);
                }
            };
            if secret.contains('\0') {
                eprintln!("Error: credential cannot be used as an environment value");
                std::process::exit(1);
            }
            env_vars.push((env_name.clone(), secret));
            credential_names.push(credential_name.to_string());
        } else {
            env_vars.push((env_name.clone(), raw_value.to_string()));
        }
    }

    (env_vars, credential_names)
}

fn audit_credential_run(
    vault: &Vault,
    credential_names: &[String],
    child_program: &str,
    exit_status: Option<i32>,
    project: &str,
) {
    let credentials = credential_names.join(",");
    audit::log_event(
        vault.db(),
        "CredentialRun",
        Some(&credentials),
        None,
        Some(child_program),
        None,
        Some("run"),
        exit_status.and_then(|code| u16::try_from(code).ok()),
        false,
        None,
        Some(project),
    );
}
