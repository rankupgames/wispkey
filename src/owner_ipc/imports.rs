//! Owner-local staged import commands and metadata projections.

use super::protocol::{error_body, require_destination_confirmation, required_string, vault_error};
use crate::core::{self, Vault};
use crate::local_import::{
    CommitRequest, ImportError, ImportPreview, ImportSession, PreviewRequest,
};
use serde_json::{Value, json};
use std::sync::{Mutex, MutexGuard, OnceLock};

static IMPORTS: OnceLock<Mutex<ImportSession>> = OnceLock::new();

fn imports() -> Result<MutexGuard<'static, ImportSession>, Value> {
    IMPORTS
        .get_or_init(|| Mutex::new(ImportSession::new()))
        .lock()
        .map_err(|_| {
            error_body(
                "unavailable",
                "local import is unavailable; restart the desktop",
            )
        })
}

pub(super) fn clear_imports() {
    if let Ok(mut session) = imports() {
        session.clear();
    }
}

pub(super) fn expire_imports() {
    if let Ok(mut session) = imports() {
        session.expire();
        if session.has_plans() && Vault::session_metadata().is_err() {
            session.clear();
        }
    }
}

pub(super) fn preview(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let project = match params.get("project") {
        None => core::resolve_active_project(),
        Some(Value::String(project)) if !project.trim().is_empty() => project.clone(),
        _ => return Err(error_body("invalid_input", "import project is required")),
    };
    if ["source", "paths", "directory"]
        .iter()
        .filter(|key| params.get(**key).is_some())
        .count()
        != 1
    {
        return Err(error_body(
            "invalid_input",
            "choose exactly one import source",
        ));
    }
    let source = if let Some(source) = params.get("source") {
        source.clone()
    } else if let Some(paths) = params.get("paths") {
        json!({"kind": "files", "paths": paths})
    } else if let Some(directory) = params.get("directory") {
        json!({"kind": "directory", "path": directory})
    } else {
        return Err(error_body(
            "invalid_input",
            "choose files, a project folder or clipboard import",
        ));
    };
    let request: PreviewRequest = serde_json::from_value(json!({
        "source": source, "project": project, "environment": params.get("environment")
    }))
    .map_err(|_| error_body("invalid_input", "import input is invalid"))?;
    preview_json(imports()?.preview(&vault, request).map_err(import_error)?)
}

pub(super) fn review(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let id = required_string(params, "plan_id")?;
    preview_json(imports()?.review(&vault, &id).map_err(import_error)?)
}

pub(super) fn commit(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    require_destination_confirmation(params)?;
    let rows = params
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| error_body("invalid_input", "import selection is required"))?;
    let selections: Vec<Value> = rows.iter().map(|row| {
        let hosts = match row.get("hosts") {
            Some(Value::String(hosts)) => json!(hosts.split(',').map(str::trim).filter(|host| !host.is_empty()).collect::<Vec<_>>()),
            Some(value) => value.clone(),
            None => json!([]),
        };
        json!({"id": row.get("id"), "selected": row.get("selected"), "hosts": hosts,
            "environment": row.get("environment"),
            "conflict_action": row.get("action").or_else(|| row.get("conflict_action")).cloned().unwrap_or(json!("unresolved"))})
    }).collect();
    let request: CommitRequest = serde_json::from_value(json!({
        "plan_id": params.get("plan_id"), "project": params.get("project"),
        "items": selections,
        "replace_http_values": params.get("rewrite_http").or_else(|| params.get("replace_http_values")).cloned().unwrap_or(json!(false)),
        "destination_confirmed": true
    })).map_err(|_| error_body("invalid_input", "import selection is invalid"))?;
    let outcome = imports()?.commit(&vault, request).map_err(import_error)?;
    Ok(
        json!({"imported": outcome.stored, "reused": outcome.reused, "skipped": outcome.skipped,
        "credentials": outcome.credentials, "source_update_failed": outcome.source_update_failed,
        "files": outcome.sources.iter().map(|source| json!({"path": source.source, "updated": source.updated,
            "status": match source.status {"tokens_written" => "updated", "not_changed" => "failed", _ => "unchanged"}
        })).collect::<Vec<_>>() }),
    )
}

pub(super) fn cancel(params: &Value) -> Result<Value, Value> {
    let mut session = imports()?;
    if let Some(id) = params.get("plan_id").and_then(Value::as_str) {
        session.cancel(id).map_err(import_error)?;
    } else {
        session.clear();
    }
    Ok(json!({"cancelled": true}))
}

fn preview_json(preview: ImportPreview) -> Result<Value, Value> {
    Ok(
        json!({"plan_id": preview.plan_id, "project": preview.project, "expires_at": preview.expires_at,
        "items": preview.items.iter().map(|item| json!({"id": item.id, "key": item.key, "name": item.name,
            "type": item.credential_type, "source": item.source, "environment": item.environment,
            "conflict": matches!(item.conflict, "different" | "scope_conflict"), "conflict_status": item.conflict,
            "tokenizable": item.tokenizable, "needs_hosts": item.tokenizable && item.conflict == "new", "hosts": item.hosts
        })).collect::<Vec<_>>(),
        "warnings": preview.warnings.iter().map(|message| json!({"message": message})).collect::<Vec<_>>() }),
    )
}

fn import_error(error: ImportError) -> Value {
    error_body(error.code(), &error.to_string())
}
