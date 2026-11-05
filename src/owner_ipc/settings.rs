//! Local desktop preferences and platform registration, available headlessly.

use super::protocol::error_body;
use crate::core::{Vault, VaultError};
use crate::secure_files;
use serde_json::{Value, json};
use std::path::PathBuf;

pub(super) fn get_settings_response() -> Result<Value, Value> {
    Ok(
        json!({"start_at_login":read_start_at_login(),"start_at_login_supported":cfg!(target_os="linux")}),
    )
}

pub(super) fn set_settings_response(params: &Value) -> Result<Value, Value> {
    if !cfg!(target_os = "linux") {
        return Err(error_body(
            "unsupported",
            "start at login is not supported on this platform",
        ));
    }
    let start_at_login = params
        .get("start_at_login")
        .and_then(Value::as_bool)
        .ok_or_else(|| error_body("invalid_input", "start_at_login is required"))?;
    write_start_at_login(start_at_login).map_err(|error| {
        error_body("unavailable", &format!("failed to write settings: {error}"))
    })?;
    Ok(json!({ "start_at_login": start_at_login }))
}

fn settings_path() -> PathBuf {
    Vault::vault_dir().join("tray.json")
}

fn read_start_at_login() -> bool {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| value.get("start_at_login")?.as_bool())
        .unwrap_or(false)
}

fn write_start_at_login(enabled: bool) -> Result<(), VaultError> {
    let encoded = serde_json::to_vec_pretty(&json!({ "start_at_login": enabled }))
        .map_err(|error| VaultError::InvalidBundle(error.to_string()))?;
    secure_files::write_private(&settings_path(), &encoded)?;
    #[cfg(target_os = "linux")]
    write_linux_autostart(enabled)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn autostart_exec_line() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wispkey"));
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wispkey");
    if name.starts_with("wispkey-tray") {
        format!("\"{}\"", exe.display())
    } else {
        format!("\"{}\" tray", exe.display())
    }
}

#[cfg(target_os = "linux")]
fn write_linux_autostart(enabled: bool) -> Result<(), VaultError> {
    let autostart_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autostart");
    let desktop_path = autostart_dir.join("wispkey-tray.desktop");
    if enabled {
        std::fs::create_dir_all(&autostart_dir)?;
        let desktop = format!(
            "[Desktop Entry]\nType=Application\nName=WispKey Tray\nExec={}\nX-GNOME-Autostart-enabled=true\n",
            autostart_exec_line()
        );
        std::fs::write(&desktop_path, desktop)?;
    } else if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)?;
    }
    Ok(())
}
