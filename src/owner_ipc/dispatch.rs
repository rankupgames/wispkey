//! Owner command orchestration; transport and native UI stay outside.

use super::protocol::{
    PROTOCOL_VERSION, clear_request_values, error_body, optional_string,
    require_destination_confirmation, required_string, vault_error,
};
use super::{imports, settings};
use crate::audit;
use crate::core::{
    self, AddCredentialRequest, CredentialType, OvhApiTemplate, Vault, VaultError,
    expand_credential_template,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub(super) fn handle_request(mut request: Value) -> Value {
    let started = std::time::Instant::now();
    let id = request
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let empty = json!({});
    let params = request.get("params").unwrap_or(&empty);
    // Input may contain clipboard/configuration text. Log method metadata only,
    // before any renderer, telemetry or persistent log can see request values.
    tracing::info!("owner ipc request");

    let result = match method.as_str() {
        "status" => status_response(),
        "unlock" => unlock_response(params),
        "lock" => {
            imports::clear_imports();
            lock_response()
        }
        "list_credentials" => list_credentials_response(params),
        "list_projects" => list_projects_response(),
        "list_partitions" => list_partitions_response(params),
        "add_credential" => add_credential_response(params),
        "add_template" => add_template_response(params),
        "generate_login" => generate_login_response(params),
        "initialize" => initialize(params),
        "create_project" => create_project_response(params),
        "create_partition" => create_partition_response(params),
        "get_token" | "rotate_credential" | "remove_credential" => {
            credential_action(&method, params)
        }
        "import_preview" => imports::preview(params),
        "import_review" => imports::review(params),
        "import_commit" => imports::commit(params),
        "import_cancel" => imports::cancel(params),
        "get_settings" => settings::get_settings_response(),
        "set_settings" => settings::set_settings_response(params),
        "shutdown" => Ok(json!({ "ok": true, "shutdown": true })),
        "" => Err(error_body("invalid_input", "method is required")),
        _ => Err(error_body("invalid_input", "unknown owner action")),
    };

    tracing::info!(
        phase = "request_handling",
        elapsed_ms = started.elapsed().as_millis() as u64,
        succeeded = result.is_ok(),
        "owner ipc request completed"
    );
    clear_request_values(&mut request);
    match result {
        Ok(value) => json!({ "id": id, "ok": true, "result": value }),
        Err(error) => json!({ "id": id, "ok": false, "error": error }),
    }
}

fn status_response() -> Result<Value, Value> {
    imports::expire_imports();
    if !Vault::exists() {
        return Ok(json!({
            "initialized": false,
            "session_active": false,
            "session_protection": Vault::session_protection_label(),
            "vault_path": Vault::vault_dir().to_string_lossy(),
            "active_project": core::resolve_active_project(),
            "credential_count": 0,
            "owner_pid": std::process::id(),
            "protocol_version": PROTOCOL_VERSION,
        }));
    }
    let vault = Vault::open().map_err(vault_error)?;
    let session_active = Vault::open_with_session().is_ok();
    if !session_active {
        imports::clear_imports();
    }
    Ok(json!({
        "initialized": true,
        "session_active": session_active,
        "session_protection": Vault::session_protection_label(),
        "vault_path": Vault::vault_dir().to_string_lossy(),
        "active_project": core::resolve_active_project(),
        "credential_count": vault.credential_count().map_err(vault_error)?,
        "created_at": vault.vault_created_at().map_err(vault_error)?,
        "owner_pid": std::process::id(),
        "protocol_version": PROTOCOL_VERSION,
    }))
}

fn unlock_response(params: &Value) -> Result<Value, Value> {
    if params
        .get("remember")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(error_body("invalid_input", "remember must be a boolean"));
    }
    let password = zeroize::Zeroizing::new(required_string(params, "password")?);
    let mut vault = Vault::open().map_err(vault_error)?;
    vault
        .unlock_with_timeout(&password, None)
        .map_err(vault_error)?;
    if params.get("remember").and_then(Value::as_bool) == Some(true)
        && let Err(error) = vault.remember_protector(None)
    {
        vault.lock().map_err(vault_error)?;
        return Err(vault_error(error));
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
        None,
        None,
    );
    Ok(json!({ "session_active": true }))
}

fn lock_response() -> Result<Value, Value> {
    let mut vault = Vault::open().map_err(vault_error)?;
    vault.lock().map_err(vault_error)?;
    Ok(json!({ "session_active": false }))
}

fn list_credentials_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let all_projects = params
        .get("all_projects")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let project = params
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    // Keep scope labels and credentials in the same SQLite read snapshot.
    let snapshot = vault
        .db()
        .unchecked_transaction()
        .map_err(VaultError::from)
        .map_err(vault_error)?;
    let credentials = if all_projects {
        vault.list_credentials().map_err(vault_error)?
    } else {
        vault
            .list_credentials_in_project(&project)
            .map_err(vault_error)?
    };
    let partitions = vault.list_partitions().map_err(vault_error)?;
    let projects = vault.list_projects().map_err(vault_error)?;
    snapshot
        .commit()
        .map_err(VaultError::from)
        .map_err(vault_error)?;
    Ok(json!({
        "project": if all_projects { "*".to_string() } else { project.clone() },
        "credentials": credentials.iter().map(|credential| {
            let mut metadata = credential_metadata(credential);
            let partition = partitions.iter().find(|partition| Some(&partition.id) == credential.partition_id.as_ref())
                .ok_or_else(|| error_body("unavailable", "credential partition is unavailable"))?;
            let project = projects.iter().find(|project| Some(&project.id) == partition.project_id.as_ref())
                .ok_or_else(|| error_body("unavailable", "credential project is unavailable"))?;
            metadata["partition"] = json!(partition.name);
            metadata["project"] = json!(project.name);
            Ok(metadata)
        }).collect::<Result<Vec<_>, Value>>()?,
    }))
}

fn list_projects_response() -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let active = core::resolve_active_project();
    let projects = vault.list_projects().map_err(vault_error)?;
    Ok(json!({
        "projects": projects.iter().map(|project| {
            Ok(json!({
                "name": project.name,
                "description": project.description,
                "active": project.name == active,
                "partition_count": vault.project_partition_count(&project.id).map_err(vault_error)?,
            }))
        }).collect::<Result<Vec<_>, Value>>()?,
    }))
}

fn list_partitions_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let project = params
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    let partitions = vault
        .list_partitions_in_project(&project)
        .map_err(vault_error)?;
    Ok(json!({
        "project": project,
        "partitions": partitions.iter().map(|partition| {
            Ok(json!({
                "name": partition.name,
                "description": partition.description,
                "credential_count": vault.partition_credential_count(&partition.id).map_err(vault_error)?,
            }))
        }).collect::<Result<Vec<_>, Value>>()?,
    }))
}

fn add_credential_response(params: &Value) -> Result<Value, Value> {
    require_destination_confirmation(params)?;
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let name = required_string(params, "name")?;
    let type_str = params
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("api_key");
    let value = required_string(params, "value")?;
    let credential_type = CredentialType::from_str_with_params(
        type_str,
        params.get("header_name").and_then(Value::as_str),
        params.get("param_name").and_then(Value::as_str),
    )
    .map_err(vault_error)?;
    if credential_type == CredentialType::WebsiteLogin {
        return Err(error_body(
            "invalid_input",
            "website_login credentials must be created with generate_login",
        ));
    }
    let description = optional_string(params, "description");
    let hosts = optional_string(params, "hosts");
    let tags = optional_string(params, "tags");
    let partition = optional_string(params, "partition");
    let project = optional_string(params, "project");
    let project_name = project
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(core::resolve_active_project);
    let created = vault
        .add_credential(AddCredentialRequest {
            name: &name,
            credential_type,
            value: &value,
            description: description.as_deref(),
            hosts: hosts.as_deref(),
            tags: tags.as_deref(),
            partition: partition.as_deref(),
            project: project.as_deref(),
            origin: None,
            lifecycle_state: None,
            review_at: None,
        })
        .map_err(vault_error)?;
    audit::log_event(
        vault.db(),
        "CredentialAdded",
        Some(&name),
        Some(&created.wisp_token),
        None,
        None,
        None,
        None,
        false,
        None,
        Some(&project_name),
    );
    Ok(json!({
        "credentials": [credential_metadata(&created)],
        "project": project_name,
    }))
}

fn add_template_response(params: &Value) -> Result<Value, Value> {
    require_destination_confirmation(params)?;
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let template = required_string(params, "template")?;
    let name_prefix = required_string(params, "name_prefix")?;
    let application_key = required_string(params, "application_key")?;
    let application_secret = required_string(params, "application_secret")?;
    let consumer_key = required_string(params, "consumer_key")?;
    let description = optional_string(params, "description");
    let hosts = optional_string(params, "hosts");
    let tags = optional_string(params, "tags");
    let partition = optional_string(params, "partition");
    let project = optional_string(params, "project");
    let owned = expand_credential_template(
        &template,
        OvhApiTemplate {
            name_prefix: &name_prefix,
            application_key: &application_key,
            application_secret: &application_secret,
            consumer_key: &consumer_key,
            description: description.as_deref(),
            hosts: hosts.as_deref(),
            tags: tags.as_deref(),
            partition: partition.as_deref(),
            project: project.as_deref(),
        },
    )
    .map_err(vault_error)?;
    let requests: Vec<_> = owned.iter().map(|item| item.as_request()).collect();
    let created = vault
        .add_credentials_atomic(&requests)
        .map_err(vault_error)?;
    let project_name = project.unwrap_or_else(core::resolve_active_project);
    for credential in &created {
        audit::log_event(
            vault.db(),
            "CredentialAdded",
            Some(&credential.name),
            Some(&credential.wisp_token),
            None,
            None,
            None,
            None,
            false,
            None,
            Some(&project_name),
        );
    }
    Ok(json!({
        "credentials": created.iter().map(credential_metadata).collect::<Vec<_>>(),
        "project": project_name,
    }))
}

fn generate_login_response(params: &Value) -> Result<Value, Value> {
    require_destination_confirmation(params)?;
    let name = required_string(params, "name")?;
    let username = required_string(params, "username")?;
    let url = required_string(params, "url")?;
    let project = optional_string(params, "project").unwrap_or_else(core::resolve_active_project);
    let partition = optional_string(params, "partition");
    let vault = Vault::open_with_session().map_err(vault_error)?;
    // The generation form explicitly confirms creating this destination when
    // needed. Validate the URL before creating any metadata containers.
    core::parse_https_origin(&url).map_err(vault_error)?;
    match vault.get_project(&project) {
        Ok(_) => {}
        Err(VaultError::ProjectNotFound(_)) => {
            vault.create_project(&project, "").map_err(vault_error)?;
        }
        Err(error) => return Err(vault_error(error)),
    }
    if let Some(partition) = partition.as_deref() {
        match vault.get_partition_in_project(&project, partition) {
            Ok(_) => {}
            Err(VaultError::PartitionNotFound(_)) => {
                vault
                    .create_partition(partition, "", Some(&project))
                    .map_err(vault_error)?;
            }
            Err(error) => return Err(vault_error(error)),
        }
    }
    let credential = vault
        .generate_website_login(core::GenerateWebsiteLoginRequest {
            name: &name,
            username: &username,
            url: &url,
            project: Some(&project),
            partition: partition.as_deref(),
            review_at: Some(chrono::Utc::now() + chrono::Duration::days(180)),
            length: None,
            symbols: true,
        })
        .map_err(vault_error)?;
    audit::log_event(
        vault.db(),
        "WebsiteLoginCreated",
        Some(&name),
        None,
        Some(&credential.origin),
        None,
        None,
        None,
        false,
        None,
        Some(&project),
    );
    Ok(
        json!({ "credential": credential_metadata(&credential), "origin": credential.origin,
        "lifecycle_state": credential.lifecycle_state, "review_at": credential.review_at }),
    )
}

fn credential_metadata(credential: &core::Credential) -> Value {
    json!({
        "id": credential.id,
        "name": credential.name,
        "description": credential.description,
        "type": credential.credential_type.display_name(),
        "hosts": credential.hosts,
        "tags": credential.tags,
        "partition_id": credential.partition_id,
        "created_at": credential.created_at.to_rfc3339(),
        "updated_at": credential.updated_at.to_rfc3339(),
        "last_used_at": credential.last_used_at.map(|date| date.to_rfc3339()),
    })
}

fn initialize(params: &Value) -> Result<Value, Value> {
    if Vault::exists() {
        return Err(error_body("already_initialized", "a vault already exists"));
    }
    let password = Zeroizing::new(required_string(params, "password")?);
    let confirmation = Zeroizing::new(required_string(params, "password_confirmation")?);
    if *password != *confirmation {
        return Err(error_body("invalid_input", "passwords do not match"));
    }
    let vault = Vault::init(&password).map_err(vault_error)?;
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
    Ok(json!({"initialized": true, "session_active": true}))
}

fn create_project_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    require_destination_confirmation(params)?;
    let name = required_string(params, "name")?;
    let description = params
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let project = vault
        .create_project(&name, description)
        .map_err(vault_error)?;
    Ok(json!({"name": project.name}))
}

fn create_partition_response(params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    require_destination_confirmation(params)?;
    let name = required_string(params, "name")?;
    let project = required_string(params, "project")?;
    let description = params
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let partition = vault
        .create_partition(&name, description, Some(&project))
        .map_err(vault_error)?;
    Ok(json!({"name": partition.name, "project": project}))
}

fn credential_action(method: &str, params: &Value) -> Result<Value, Value> {
    let vault = Vault::open_with_session().map_err(vault_error)?;
    let name = required_string(params, "name")?;
    let project = required_string(params, "project")?;
    let credential = vault
        .get_credential_in_project(&project, &name)
        .map_err(vault_error)?;
    if method == "get_token" {
        // Only the native host consumes this capability to copy it. No value is decrypted.
        return Ok(json!({"token": credential.wisp_token}));
    }
    require_destination_confirmation(params)?;
    let action = if method == "rotate_credential" {
        vault
            .rotate_wisp_token_in_project(&project, &name)
            .map_err(vault_error)?;
        "CredentialRotated"
    } else {
        vault
            .remove_credential_in_project(&project, &name)
            .map_err(vault_error)?;
        "CredentialRemoved"
    };
    audit::log_event(
        vault.db(),
        action,
        Some(&name),
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        Some(&project),
    );
    Ok(json!({"credential": credential_metadata(&credential), "project": project}))
}
