//! Private wire helpers shared by owner command adapters and framing.

use crate::core::VaultError;
use serde_json::{Value, json};

pub(super) const PROTOCOL_VERSION: u8 = 1;

pub(super) fn require_destination_confirmation(params: &Value) -> Result<(), Value> {
    if params.get("destination_confirmed").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(error_body(
            "confirmation_required",
            "confirm the destination project and partition before saving",
        ))
    }
}

pub(super) fn required_string(params: &Value, key: &str) -> Result<String, Value> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| error_body("invalid_input", &format!("{key} is required")))
}

pub(super) fn optional_string(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn vault_error(error: VaultError) -> Value {
    let code = match error {
        VaultError::NotFound => "not_initialized",
        VaultError::Locked | VaultError::SessionInvalid => "locked",
        VaultError::InvalidPassword => "unauthorized",
        VaultError::DuplicateCredential(_) => "duplicate",
        VaultError::EmptyCredentialName | VaultError::EmptyCredentialValue => "invalid_input",
        VaultError::InvalidCredentialType(_) | VaultError::InvalidCredentialTemplate(_) => {
            "invalid_input"
        }
        VaultError::ProjectNotFound(_) | VaultError::PartitionNotFound(_) => "invalid_input",
        _ => "unavailable",
    };
    error_body(code, &error.to_string())
}

pub(super) fn error_body(code: &str, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

pub(super) fn clear_request_values(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(clear_request_values),
        Value::Object(fields) => fields.values_mut().for_each(clear_request_values),
        _ => {}
    }
}
