use crate::core::{self, Vault};
use crate::secure_files;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
const BUNDLE_PASSPHRASE_ENV: &str = "WISPKEY_BUNDLE_PASSPHRASE";
const MIN_BUNDLE_PASSPHRASE_LEN: usize = 12;
const MAX_BUNDLE_PASSPHRASE_FILE_BYTES: u64 = 16 * 1024;

pub fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, Ordering::Relaxed);
}

pub(super) fn json_output() -> bool {
    JSON_OUTPUT.load(Ordering::Relaxed)
}

pub(super) fn print_json(value: serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("json output must serialize")
    );
}

pub(super) fn credential_json(cred: &core::Credential) -> serde_json::Value {
    serde_json::json!({
        "id": cred.id,
        "name": cred.name,
        "description": cred.description,
        "type": cred.credential_type.display_name(),
        "wisp_token": cred.wisp_token,
        "hosts": cred.hosts,
        "tags": cred.tags,
        "partition_id": cred.partition_id,
        "origin": cred.origin,
        "lifecycle_state": cred.lifecycle_state,
        "review_at": cred.review_at.map(|d| d.to_rfc3339()),
        "created_at": cred.created_at.to_rfc3339(),
        "updated_at": cred.updated_at.to_rfc3339(),
        "last_used_at": cred.last_used_at.map(|d| d.to_rfc3339()),
    })
}

pub(super) fn partition_json(vault: &Vault, partition: &core::Partition) -> serde_json::Value {
    serde_json::json!({
        "id": partition.id,
        "name": partition.name,
        "description": partition.description,
        "project_id": partition.project_id,
        "credential_count": vault.partition_credential_count(&partition.id).unwrap_or(0),
        "created_at": partition.created_at.to_rfc3339(),
        "updated_at": partition.updated_at.to_rfc3339(),
    })
}

pub(super) fn project_json(
    vault: &Vault,
    project: &core::Project,
    active: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "partition_count": vault.project_partition_count(&project.id).unwrap_or(0),
        "active": project.name == active,
        "created_at": project.created_at.to_rfc3339(),
        "updated_at": project.updated_at.to_rfc3339(),
    })
}

pub(super) fn prompt_password(prompt: &str) -> String {
    if let Ok(password) = std::env::var("WISPKEY_PASSWORD") {
        return password;
    }
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Error reading password: {}", e);
        eprintln!("Hint: set WISPKEY_PASSWORD env var for non-interactive use.");
        std::process::exit(1);
    })
}

pub(super) fn prompt_password_confirm(prompt1: &str, prompt2: &str) -> Option<String> {
    if let Ok(password) = std::env::var("WISPKEY_PASSWORD") {
        return Some(password);
    }
    let password1 = prompt_password(prompt1);
    let password2 = rpassword::prompt_password(prompt2).unwrap_or_else(|e| {
        eprintln!("Error reading password: {}", e);
        std::process::exit(1);
    });
    if password1 == password2 {
        Some(password1)
    } else {
        None
    }
}

pub(super) fn prompt_export_bundle_passphrase(passphrase_file: Option<&str>) -> String {
    let passphrase = read_bundle_passphrase(passphrase_file, true);
    validate_export_bundle_passphrase(&passphrase);
    passphrase
}

pub(super) fn prompt_import_bundle_passphrase(passphrase_file: Option<&str>) -> String {
    read_bundle_passphrase(passphrase_file, false)
}

fn read_bundle_passphrase(passphrase_file: Option<&str>, confirm_interactive: bool) -> String {
    if let Some(path) = passphrase_file {
        return read_bundle_passphrase_file(path);
    }
    if let Ok(passphrase) = std::env::var(BUNDLE_PASSPHRASE_ENV) {
        return passphrase;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!("Error: bundle passphrase is separate from WISPKEY_PASSWORD.");
        eprintln!(
            "Hint: set {BUNDLE_PASSPHRASE_ENV} or pass --bundle-passphrase-file for encrypted bundle operations."
        );
        std::process::exit(1);
    }

    if confirm_interactive {
        let passphrase1 = prompt_hidden_bundle_passphrase("Enter bundle passphrase: ");
        let passphrase2 = prompt_hidden_bundle_passphrase("Confirm bundle passphrase: ");
        if passphrase1 != passphrase2 {
            eprintln!("Error: bundle passphrases did not match");
            std::process::exit(1);
        }
        return passphrase1;
    }

    prompt_hidden_bundle_passphrase("Enter bundle passphrase: ")
}

fn read_bundle_passphrase_file(path: &str) -> String {
    let passphrase = match secure_files::read_private_string(
        Path::new(path),
        MAX_BUNDLE_PASSPHRASE_FILE_BYTES,
    ) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Error reading bundle passphrase file: {error}");
            std::process::exit(1);
        }
    };
    passphrase.trim_end_matches(['\n', '\r']).to_string()
}

fn prompt_hidden_bundle_passphrase(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|error| {
        eprintln!("Error reading bundle passphrase: {error}");
        eprintln!(
            "Hint: set {BUNDLE_PASSPHRASE_ENV} or pass --bundle-passphrase-file for non-interactive use."
        );
        std::process::exit(1);
    })
}

fn validate_export_bundle_passphrase(passphrase: &str) {
    if passphrase.chars().count() < MIN_BUNDLE_PASSPHRASE_LEN {
        eprintln!(
            "Error: bundle passphrase must be at least {MIN_BUNDLE_PASSPHRASE_LEN} characters."
        );
        eprintln!(
            "Hint: use a dedicated export passphrase; do not reuse WISPKEY_PASSWORD or send it with the bundle."
        );
        std::process::exit(1);
    }
}
