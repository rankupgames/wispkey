use crate::audit;
use crate::core::{Vault, VaultError};

use super::shared::{json_output, print_json, prompt_password_confirm, read_unlock_password};

pub async fn handle_init() {
    if Vault::exists() {
        eprintln!(
            "Error: vault already exists at {}",
            Vault::vault_dir().display()
        );
        eprintln!("Delete {} to start fresh.", Vault::vault_dir().display());
        std::process::exit(1);
    }

    let password =
        match prompt_password_confirm("Enter master password: ", "Confirm master password: ") {
            Some(p) => p,
            None => {
                eprintln!("Error: passwords did not match");
                std::process::exit(1);
            }
        };

    match Vault::init(&password) {
        Ok(vault) => {
            audit::log_event(
                vault.db(),
                "VaultCreated",
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
            println!("Vault created at {}", Vault::vault_dir().display());
            println!("Vault is unlocked for this session (30 min timeout).");
            println!();
            println!("Next steps:");
            println!("  wispkey add \"my-api-key\" --type bearer_token --value \"sk-...\"");
            println!("  wispkey import .env");
            println!("  wispkey serve");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Unlocks the vault from a session, remembered protector, password file, env, or prompt.
pub async fn handle_unlock(
    timeout: Option<i64>,
    remember: bool,
    protector_timeout: Option<i64>,
    password_file: Option<String>,
) {
    let mut vault = match Vault::open() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let password = match read_unlock_password(password_file.as_deref()) {
        Ok(password) => password,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };

    let (source, protector_backend) = if let Some(password) = password {
        match vault.unlock_with_timeout(&password, timeout) {
            Ok(()) => ("password", None),
            Err(VaultError::InvalidPassword) => {
                eprintln!("Error: invalid master password");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match vault.restore_or_refresh_session(timeout) {
            Ok(()) => ("session", None),
            Err(VaultError::Locked | VaultError::SessionExpired | VaultError::SessionInvalid) => {
                match vault.unlock_from_protector(timeout) {
                    Ok(backend) => ("protector", Some(backend)),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    };

    let mut remembered = None;
    if remember {
        match vault.remember_protector(protector_timeout) {
            Ok(backend) => {
                audit::log_event(
                    vault.db(),
                    "ProtectorRemembered",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    Some(backend.label()),
                    None,
                );
                remembered = Some(backend);
            }
            Err(e) => {
                eprintln!("Error: failed to remember unlock: {e}");
                std::process::exit(1);
            }
        }
    }

    audit::log_event(
        vault.db(),
        "VaultUnlocked",
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(source),
        None,
    );

    let effective_timeout = timeout.unwrap_or_else(Vault::session_timeout_minutes);
    if json_output() {
        print_json(serde_json::json!({
            "unlocked": true,
            "source": source,
            "session_timeout_minutes": effective_timeout,
            "protector": remembered.or(protector_backend).map(|backend| backend.label()),
            "protector_timeout_minutes": remember.then_some(
                protector_timeout.unwrap_or_else(Vault::protector_timeout_minutes)
            ),
        }));
        return;
    }

    if effective_timeout > 0 {
        println!(
            "Vault unlocked ({} min session) via {source}.",
            effective_timeout
        );
    } else {
        println!("Vault unlocked (no expiry) via {source}.");
    }
    if let Some(backend) = remembered {
        let protector_minutes = protector_timeout.unwrap_or_else(Vault::protector_timeout_minutes);
        if protector_minutes > 0 {
            println!(
                "Remembered unlock stored in the {} protector ({} min).",
                backend.label(),
                protector_minutes
            );
        } else {
            println!(
                "Remembered unlock stored in the {} protector until `wispkey lock --forget`.",
                backend.label()
            );
        }
    }
}

/// Locks the current session and optionally forgets a remembered protector.
pub async fn handle_lock(forget: bool) {
    let vault = match Vault::open() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = Vault::lock_session() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    audit::log_event(
        vault.db(),
        "VaultLocked",
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some("session_revoked"),
        None,
    );

    if forget {
        if let Err(e) = Vault::forget_protector() {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        audit::log_event(
            vault.db(),
            "ProtectorForgotten",
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
    }

    if json_output() {
        print_json(serde_json::json!({
            "locked": true,
            "forgotten": forget,
        }));
        return;
    }

    if forget {
        println!("Vault locked and remembered unlock forgotten.");
    } else {
        println!("Vault locked. Remembered unlock, if any, remains until `wispkey lock --forget`.");
    }
}
