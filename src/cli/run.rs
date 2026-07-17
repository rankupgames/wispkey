use std::fs;
use std::process::Command;

use crate::audit;
use crate::core::{self, Vault};

use super::exec::{exit_code, open_unlocked_vault};

pub struct RunArgs<'a> {
    pub manifest: Option<&'a str>,
    pub project: Option<&'a str>,
    pub command: &'a [String],
}

pub async fn handle_run(args: RunArgs<'_>) {
    if args.command.is_empty() {
        eprintln!("Error: missing child command after --");
        std::process::exit(1);
    }

    let manifest_path = args.manifest.unwrap_or("wispkey.toml");
    let manifest = read_manifest(manifest_path);
    let project = args
        .project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);
    let vault = open_unlocked_vault();
    let (env_vars, credential_names) = resolve_manifest_env(&vault, &project, &manifest);

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

fn read_manifest(path: &str) -> toml::Value {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("Error: failed to read manifest {}: {}", path, e);
            std::process::exit(1);
        }
    };
    match toml::from_str(&raw) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Error: failed to parse manifest {}: {}", path, e);
            std::process::exit(1);
        }
    }
}

fn resolve_manifest_env(
    vault: &Vault,
    project: &str,
    manifest: &toml::Value,
) -> (Vec<(String, String)>, Vec<String>) {
    let Some(env) = manifest.get("env").and_then(toml::Value::as_table) else {
        eprintln!("Error: manifest must contain a non-empty [env] table");
        std::process::exit(1);
    };
    if env.is_empty() {
        eprintln!("Error: manifest must contain a non-empty [env] table");
        std::process::exit(1);
    }

    let mut env_vars = Vec::with_capacity(env.len());
    let mut credential_names = Vec::new();
    for (env_name, value) in env {
        let Some(raw_value) = value.as_str() else {
            eprintln!("Error: [env].{} must be a string", env_name);
            std::process::exit(1);
        };

        if let Some(credential_name) = raw_value.strip_prefix("cred:") {
            if credential_name.is_empty() {
                eprintln!(
                    "Error: [env].{} has an empty credential reference",
                    env_name
                );
                std::process::exit(1);
            }
            let secret = match vault.decrypt_credential_value_in_project(project, credential_name) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
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
