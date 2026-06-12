use crate::audit;
use crate::core::{Vault, VaultError};

use super::shared::{prompt_password, prompt_password_confirm};

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

/// Unlocks the vault with the master password and optional session timeout.
pub async fn handle_unlock(timeout: Option<i64>) {
    let mut vault = match Vault::open() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let password = prompt_password("Enter master password: ");

    match vault.unlock_with_timeout(&password, timeout) {
        Ok(()) => {
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
                None,
                None,
            );
            let effective_timeout = timeout.unwrap_or_else(Vault::session_timeout_minutes);
            if effective_timeout > 0 {
                println!("Vault unlocked ({} min session).", effective_timeout);
            } else {
                println!("Vault unlocked (no expiry).");
            }
        }
        Err(VaultError::InvalidPassword) => {
            eprintln!("Error: invalid master password");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
