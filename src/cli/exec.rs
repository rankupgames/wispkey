use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::audit;
use crate::core::{self, Vault};
use crate::secure_files;

use serde::{Deserialize, Serialize};

const ASKPASS_HANDOFF_ENV: &str = "WISPKEY_ASKPASS_HANDOFF";
const ASKPASS_HANDOFF_MAX_BYTES: u64 = 4096;

#[derive(Deserialize, Serialize)]
struct AskpassHandoff {
    capability: String,
    credential: String,
    project: String,
}

pub struct ExecArgs<'a> {
    pub credential: &'a str,
    pub project: Option<&'a str>,
    pub stdin: bool,
    pub env: &'a [String],
    pub askpass: bool,
    pub command: &'a [String],
}

pub async fn handle_exec(args: ExecArgs<'_>) {
    if !args.stdin && args.env.is_empty() && !args.askpass {
        eprintln!("Error: at least one channel is required: --stdin, --env, or --askpass");
        std::process::exit(1);
    }

    if args.command.is_empty() {
        eprintln!("Error: missing child command after --");
        std::process::exit(1);
    }

    let project = args
        .project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);
    let vault = open_unlocked_vault();
    let secret = match vault.decrypt_credential_value_in_project(&project, args.credential) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);

    if args.stdin {
        command.stdin(Stdio::piped());
    } else if args.askpass {
        command.stdin(Stdio::null());
    }

    for env_name in args.env {
        command.env(env_name, &secret);
    }

    let askpass_handoff = if args.askpass {
        Some(configure_askpass_env(
            &mut command,
            args.credential,
            &project,
        ))
    } else {
        None
    };

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            cleanup_askpass_handoff(askpass_handoff.as_deref());
            eprintln!("Error: failed to spawn child command: {}", e);
            std::process::exit(1);
        }
    };

    if args.stdin {
        match child.stdin.take() {
            Some(mut stdin) => {
                if let Err(e) = writeln!(stdin, "{}", secret) {
                    let _ = child.kill();
                    let _ = child.wait();
                    cleanup_askpass_handoff(askpass_handoff.as_deref());
                    eprintln!("Error: failed to write secret to child stdin: {}", e);
                    audit_credential_exec(
                        &vault,
                        args.credential,
                        &args.command[0],
                        &channel_summary(&args),
                        Some(1),
                        &project,
                    );
                    std::process::exit(1);
                }
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                cleanup_askpass_handoff(askpass_handoff.as_deref());
                eprintln!("Error: child stdin was unavailable");
                audit_credential_exec(
                    &vault,
                    args.credential,
                    &args.command[0],
                    &channel_summary(&args),
                    Some(1),
                    &project,
                );
                std::process::exit(1);
            }
        }
    }

    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            cleanup_askpass_handoff(askpass_handoff.as_deref());
            eprintln!("Error: failed to wait for child command: {}", e);
            std::process::exit(1);
        }
    };
    cleanup_askpass_handoff(askpass_handoff.as_deref());
    let exit_code = exit_code(status);
    audit_credential_exec(
        &vault,
        args.credential,
        &args.command[0],
        &channel_summary(&args),
        Some(exit_code),
        &project,
    );
    std::process::exit(exit_code);
}

pub async fn handle_askpass() {
    let handoff = match read_askpass_handoff() {
        Ok(handoff) => handoff,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };
    let vault = open_unlocked_vault();
    let secret =
        match vault.decrypt_credential_value_in_project(&handoff.project, &handoff.credential) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

    audit_credential_exec(
        &vault,
        &handoff.credential,
        "askpass",
        "askpass",
        None,
        &handoff.project,
    );
    print!("{}", secret);
}

pub fn askpass_mode_enabled() -> bool {
    std::env::var(ASKPASS_HANDOFF_ENV).is_ok()
}

pub(super) fn open_unlocked_vault() -> Vault {
    match Vault::open_with_session() {
        Ok(vault) => vault,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn configure_askpass_env(command: &mut Command, credential: &str, project: &str) -> PathBuf {
    let helper = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: failed to locate askpass helper: {}", e);
            std::process::exit(1);
        }
    };
    let handoff_path = create_askpass_handoff(credential, project);

    command
        .env("SUDO_ASKPASS", &helper)
        .env("SSH_ASKPASS", &helper)
        .env("GIT_ASKPASS", &helper)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(ASKPASS_HANDOFF_ENV, &handoff_path);
    handoff_path
}

fn create_askpass_handoff(credential: &str, project: &str) -> PathBuf {
    let capability = match crate::random::alphanumeric(32, false) {
        Ok(capability) => capability,
        Err(e) => {
            eprintln!("Error: failed to create askpass handoff: {}", e);
            std::process::exit(1);
        }
    };
    let handoff = AskpassHandoff {
        capability: capability.clone(),
        credential: credential.to_string(),
        project: project.to_string(),
    };
    let payload = match serde_json::to_vec(&handoff) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("Error: failed to encode askpass handoff: {}", e);
            std::process::exit(1);
        }
    };
    let path = Vault::vault_dir()
        .join("askpass")
        .join(format!("{capability}.json"));
    if let Err(e) = secure_files::write_private(&path, &payload) {
        eprintln!("Error: failed to write askpass handoff: {}", e);
        std::process::exit(1);
    }
    path
}

fn read_askpass_handoff() -> Result<AskpassHandoff, String> {
    let path = match std::env::var(ASKPASS_HANDOFF_ENV) {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => return Err("askpass helper is not enabled".to_string()),
    };
    let raw = secure_files::read_private_string(&path, ASKPASS_HANDOFF_MAX_BYTES)
        .map_err(|error| format!("invalid askpass handoff: {error}"))?;
    let _ = fs::remove_file(&path);
    let handoff = serde_json::from_str::<AskpassHandoff>(&raw)
        .map_err(|error| format!("invalid askpass handoff: {error}"))?;
    if handoff.capability.len() != 32 || handoff.credential.is_empty() || handoff.project.is_empty()
    {
        return Err("invalid askpass handoff".to_string());
    }
    Ok(handoff)
}

fn cleanup_askpass_handoff(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

fn channel_summary(args: &ExecArgs<'_>) -> String {
    let mut channels = Vec::new();
    if args.stdin {
        channels.push("stdin");
    }
    if !args.env.is_empty() {
        channels.push("env");
    }
    if args.askpass {
        channels.push("askpass");
    }
    channels.join(",")
}

fn audit_credential_exec(
    vault: &Vault,
    credential: &str,
    child_program: &str,
    channels: &str,
    exit_status: Option<i32>,
    project: &str,
) {
    audit::log_event(
        vault.db(),
        "CredentialExec",
        Some(credential),
        None,
        Some(child_program),
        Some(channels),
        Some("exec"),
        exit_status.and_then(|code| u16::try_from(code).ok()),
        false,
        None,
        Some(project),
    );
}

pub(super) fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |signal| 128 + signal)
    }

    #[cfg(not(unix))]
    {
        1
    }
}
