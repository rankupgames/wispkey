use chrono::Duration;

use crate::audit;
use crate::core::{
    AccessRequest, BootstrapJoinResult, BootstrapToken, CreateBootstrapTokenResult,
    EnrollInstanceResult, Instance, InstanceScopeInput, RotateInstanceSecretResult, Vault,
};

use super::shared::{json_output, print_json};

pub async fn handle_instance_enroll(
    name: &str,
    description: &str,
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
) {
    let vault = open_vault();
    let scopes = build_scope_inputs(partitions, projects, credentials, tags);

    match vault.enroll_instance(name, description, &scopes) {
        Ok(result) => {
            if json_output() {
                print_json(enrollment_json(&result));
                return;
            }
            println!("Instance '{}' enrolled.", result.instance.name);
            println!("ID: {}", result.instance.id);
            println!("Secret: {}", result.secret);
            println!("Secret is shown once. Store it before closing this terminal.");
            if !result.instance.scopes.is_empty() {
                println!("Scopes: {}", scope_summary(&result.instance));
            }
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_list() {
    let vault = open_vault();
    match vault.list_instances() {
        Ok(instances) => {
            if json_output() {
                print_json(serde_json::json!({
                    "instances": instances.iter().map(instance_json).collect::<Vec<_>>(),
                }));
                return;
            }

            println!(
                "{:<24} {:<10} {:<8} {:<30} LAST SEEN",
                "NAME", "STATUS", "PENDING", "SCOPES"
            );
            println!("{}", "-".repeat(92));
            for instance in &instances {
                let last_seen = instance
                    .last_seen_at
                    .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<24} {:<10} {:<8} {:<30} {}",
                    instance.name,
                    instance.status,
                    instance.pending_request_count,
                    scope_summary(instance),
                    last_seen
                );
            }
            println!();
            println!("{} instance(s)", instances.len());
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_show(name: &str) {
    let vault = open_vault();
    match vault.get_instance(name) {
        Ok(instance) => {
            if json_output() {
                print_json(serde_json::json!({
                    "instance": instance_json(&instance),
                }));
                return;
            }
            println!("Name: {}", instance.name);
            println!("ID: {}", instance.id);
            println!("Status: {}", instance.status);
            println!("Description: {}", instance.description);
            println!("Created: {}", instance.created_at.to_rfc3339());
            println!("Updated: {}", instance.updated_at.to_rfc3339());
            println!(
                "Secret rotated: {}",
                instance.secret_rotated_at.to_rfc3339()
            );
            println!(
                "Previous secret expires: {}",
                instance
                    .previous_secret_expires_at
                    .map(|timestamp| timestamp.to_rfc3339())
                    .unwrap_or_else(|| "-".to_string())
            );
            println!(
                "Last seen: {}",
                instance
                    .last_seen_at
                    .map(|timestamp| timestamp.to_rfc3339())
                    .unwrap_or_else(|| "-".to_string())
            );
            println!("Pending requests: {}", instance.pending_request_count);
            println!("Scopes:");
            if instance.scopes.is_empty() {
                println!("  none");
            } else {
                for scope in &instance.scopes {
                    println!("  {}: {}", scope.scope_type, scope.scope_value);
                }
            }
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_scope_add(
    name: &str,
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
) {
    mutate_scopes(name, partitions, projects, credentials, tags, true).await;
}

pub async fn handle_instance_scope_remove(
    name: &str,
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
) {
    mutate_scopes(name, partitions, projects, credentials, tags, false).await;
}

pub async fn handle_instance_revoke(name: &str) {
    let vault = open_vault();
    match vault.revoke_instance(name) {
        Ok(instance) => {
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "instance": instance_json(&instance),
                }));
                return;
            }
            println!("Instance '{}' revoked.", instance.name);
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_rotate_secret(name: &str, if_older_than: Option<&str>, grace: &str) {
    let if_older_than = if_older_than
        .map(|value| parse_duration(value, "if-older-than", false))
        .transpose()
        .unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        });
    let grace = parse_duration(grace, "grace", true).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });

    let vault = open_vault();
    match vault.rotate_instance_secret(name, if_older_than, grace) {
        Ok(result) => {
            if result.rotated {
                audit_instance_secret_rotated(&vault, &result);
            }
            if json_output() {
                print_json(rotation_json(&result));
                return;
            }
            if !result.rotated {
                println!(
                    "Instance '{}' is not due for secret rotation.",
                    result.instance.name
                );
                println!(
                    "Last rotated: {}",
                    result.instance.secret_rotated_at.to_rfc3339()
                );
                return;
            }

            println!("Instance '{}' secret rotated.", result.instance.name);
            println!(
                "Secret: {}",
                result
                    .secret
                    .as_deref()
                    .expect("rotated result has a secret")
            );
            println!("Secret is shown once. Store it before closing this terminal.");
            match result.instance.previous_secret_expires_at {
                Some(expires_at) => println!(
                    "The previous secret remains valid until {} or until the new secret first authenticates.",
                    expires_at.to_rfc3339()
                ),
                None => println!("The previous secret was retired immediately."),
            }
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_requests(instance: Option<&str>, pending_only: bool) {
    let vault = open_vault();
    match vault.list_access_requests(instance, pending_only) {
        Ok(requests) => {
            if json_output() {
                print_json(serde_json::json!({
                    "pending_only": pending_only,
                    "instance": instance,
                    "requests": requests.iter().map(access_request_json).collect::<Vec<_>>(),
                }));
                return;
            }
            println!(
                "{:<36} {:<20} {:<20} {:<10} CREATED",
                "ID", "INSTANCE", "CREDENTIAL", "STATUS"
            );
            println!("{}", "-".repeat(100));
            for request in &requests {
                println!(
                    "{:<36} {:<20} {:<20} {:<10} {}",
                    request.id,
                    request.instance_name,
                    request.credential_name,
                    request.status,
                    request.created_at.format("%Y-%m-%d %H:%M")
                );
            }
            println!();
            println!("{} request(s)", requests.len());
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_approve(request_id: &str) {
    decide_request(request_id, true).await;
}

pub async fn handle_instance_deny(request_id: &str) {
    decide_request(request_id, false).await;
}

pub async fn handle_instance_bootstrap_create(
    description: &str,
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
    ttl: Option<&str>,
    uses: Option<i64>,
) {
    let vault = open_vault();
    let scopes = build_scope_inputs(partitions, projects, credentials, tags);
    let ttl = ttl
        .map(|value| parse_duration(value, "ttl", false))
        .transpose()
        .unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        });

    match vault.create_bootstrap_token(description, &scopes, uses, ttl) {
        Ok(result) => {
            if json_output() {
                print_json(bootstrap_create_json(&result));
                return;
            }
            println!("Bootstrap token created.");
            println!("ID: {}", result.token.id);
            println!("Token: {}", result.plaintext_token);
            println!("Token is shown once. Store it before closing this terminal.");
            if !result.token.scopes.is_empty() {
                println!("Scopes: {}", scope_input_summary(&result.token.scopes));
            }
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_bootstrap_list() {
    let vault = open_vault();
    match vault.list_bootstrap_tokens() {
        Ok(tokens) => {
            if json_output() {
                print_json(serde_json::json!({
                    "bootstrap_tokens": tokens.iter().map(bootstrap_token_json).collect::<Vec<_>>(),
                }));
                return;
            }

            println!(
                "{:<36} {:<10} {:<11} {:<20} SCOPES",
                "ID", "STATUS", "USES", "EXPIRES"
            );
            println!("{}", "-".repeat(104));
            for token in &tokens {
                let uses = token
                    .max_uses
                    .map(|max| format!("{}/{}", token.used_count, max))
                    .unwrap_or_else(|| format!("{}/-", token.used_count));
                let expires = token
                    .expires_at
                    .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<36} {:<10} {:<11} {:<20} {}",
                    token.id,
                    token.status,
                    uses,
                    expires,
                    scope_input_summary(&token.scopes)
                );
            }
            println!();
            println!("{} bootstrap token(s)", tokens.len());
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_bootstrap_revoke(id: &str) {
    let vault = open_vault();
    match vault.revoke_bootstrap_token(id) {
        Ok(token) => {
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "bootstrap_token": bootstrap_token_json(&token),
                }));
                return;
            }
            println!("Bootstrap token '{}' revoked.", token.id);
        }
        Err(error) => exit_error(error),
    }
}

pub async fn handle_instance_join(bootstrap_token: &str, name: &str) {
    let vault = open_vault();
    match vault.redeem_bootstrap_token(bootstrap_token, name) {
        Ok(result) => {
            audit_instance_joined(&vault, &result);
            if json_output() {
                print_json(join_json(&result));
                return;
            }
            println!("Instance '{}' joined.", result.instance.name);
            println!("ID: {}", result.instance.id);
            println!("Secret: {}", result.secret);
            println!("Secret is shown once. Store it before closing this terminal.");
            if !result.instance.scopes.is_empty() {
                println!("Scopes: {}", scope_summary(&result.instance));
            }
        }
        Err(error) => exit_error(error),
    }
}

async fn mutate_scopes(
    name: &str,
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
    add: bool,
) {
    let requested = requested_scope_group(partitions, projects, credentials, tags);
    let (scope_type, values) = match requested {
        Some(group) => group,
        None => {
            eprintln!(
                "Error: provide exactly one scope selector: --partition, --project, --credential, or --tag"
            );
            std::process::exit(1);
        }
    };

    let vault = open_vault();
    let instance = match vault.get_instance(name) {
        Ok(instance) => instance,
        Err(error) => {
            exit_error(error);
        }
    };

    let mut changed = Vec::new();
    for value in values {
        let result = if add {
            vault
                .add_instance_scope(&instance.id, scope_type, value)
                .map(|_| ())
        } else {
            vault.remove_instance_scope(&instance.id, scope_type, value)
        };
        match result {
            Ok(()) => changed.push(value.clone()),
            Err(error) => exit_error(error),
        }
    }

    if json_output() {
        print_json(serde_json::json!({
            "ok": true,
            "instance": instance.name,
            "action": if add { "add" } else { "remove" },
            "scope_type": scope_type,
            "values": changed,
        }));
        return;
    }

    let verb = if add { "Added" } else { "Removed" };
    println!(
        "{} {} scope(s) on instance '{}': {}",
        verb,
        scope_type,
        instance.name,
        changed.join(", ")
    );
}

async fn decide_request(request_id: &str, approve: bool) {
    let vault = open_vault();
    match vault.decide_access_request(request_id, approve) {
        Ok(request) => {
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "request": access_request_json(&request),
                }));
                return;
            }
            let action = if approve { "approved" } else { "denied" };
            println!("Access request '{}' {}.", request.id, action);
        }
        Err(error) => exit_error(error),
    }
}

fn open_vault() -> Vault {
    match Vault::open_with_session() {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        }
    }
}

fn exit_error(error: impl std::fmt::Display) -> ! {
    eprintln!("Error: {}", error);
    std::process::exit(1);
}

fn build_scope_inputs(
    partitions: &[String],
    projects: &[String],
    credentials: &[String],
    tags: &[String],
) -> Vec<InstanceScopeInput> {
    let mut scopes = Vec::new();
    scopes.extend(
        partitions
            .iter()
            .map(|value| InstanceScopeInput::new("partition", value)),
    );
    scopes.extend(
        projects
            .iter()
            .map(|value| InstanceScopeInput::new("project", value)),
    );
    scopes.extend(
        credentials
            .iter()
            .map(|value| InstanceScopeInput::new("credential", value)),
    );
    scopes.extend(
        tags.iter()
            .map(|value| InstanceScopeInput::new("tag", value)),
    );
    scopes
}

fn parse_duration(value: &str, label: &str, allow_zero: bool) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let (digits, unit) = value.split_at(
        value
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let amount: i64 = digits
        .parse()
        .map_err(|_| format!("{label} must start with a number"))?;
    if amount < 0 || (!allow_zero && amount == 0) {
        return Err(format!(
            "{label} must be {}",
            if allow_zero {
                "non-negative"
            } else {
                "positive"
            }
        ));
    }
    let seconds_per_unit = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("{label} unit must be one of s, m, h, or d")),
    };
    amount
        .checked_mul(seconds_per_unit)
        .and_then(Duration::try_seconds)
        .ok_or_else(|| format!("{label} is too large"))
}

fn requested_scope_group<'a>(
    partitions: &'a [String],
    projects: &'a [String],
    credentials: &'a [String],
    tags: &'a [String],
) -> Option<(&'static str, &'a [String])> {
    let groups = [
        ("partition", partitions),
        ("project", projects),
        ("credential", credentials),
        ("tag", tags),
    ];
    let mut selected = groups
        .iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(scope_type, values)| (*scope_type, *values));
    let first = selected.next()?;
    if selected.next().is_some() {
        return None;
    }
    Some(first)
}

fn scope_summary(instance: &Instance) -> String {
    if instance.scopes.is_empty() {
        return "-".to_string();
    }
    instance
        .scopes
        .iter()
        .map(|scope| format!("{}:{}", scope.scope_type, scope.scope_value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn scope_input_summary(scopes: &[InstanceScopeInput]) -> String {
    if scopes.is_empty() {
        return "-".to_string();
    }
    scopes
        .iter()
        .map(|scope| format!("{}:{}", scope.scope_type, scope.scope_value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn enrollment_json(result: &EnrollInstanceResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "id": result.instance.id,
        "name": result.instance.name,
        "secret": result.secret,
        "instance": instance_json(&result.instance),
    })
}

fn instance_json(instance: &Instance) -> serde_json::Value {
    serde_json::json!({
        "id": instance.id,
        "name": instance.name,
        "status": instance.status,
        "description": instance.description,
        "scopes": instance.scopes.iter().map(|scope| serde_json::json!({
            "id": scope.id,
            "instance_id": scope.instance_id,
            "scope_type": scope.scope_type,
            "scope_value": scope.scope_value,
            "created_at": scope.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "pending_request_count": instance.pending_request_count,
        "created_at": instance.created_at.to_rfc3339(),
        "updated_at": instance.updated_at.to_rfc3339(),
        "last_seen_at": instance.last_seen_at.map(|timestamp| timestamp.to_rfc3339()),
        "secret_rotated_at": instance.secret_rotated_at.to_rfc3339(),
        "previous_secret_expires_at": instance
            .previous_secret_expires_at
            .map(|timestamp| timestamp.to_rfc3339()),
    })
}

fn rotation_json(result: &RotateInstanceSecretResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "rotated": result.rotated,
        "id": result.instance.id,
        "name": result.instance.name,
        "secret": result.secret,
        "secret_rotated_at": result.instance.secret_rotated_at.to_rfc3339(),
        "previous_secret_expires_at": result
            .instance
            .previous_secret_expires_at
            .map(|timestamp| timestamp.to_rfc3339()),
        "instance": instance_json(&result.instance),
    })
}

fn access_request_json(request: &AccessRequest) -> serde_json::Value {
    serde_json::json!({
        "id": request.id,
        "instance_id": request.instance_id,
        "instance_name": request.instance_name,
        "credential_name": request.credential_name,
        "status": request.status,
        "reason": request.reason,
        "created_at": request.created_at.to_rfc3339(),
        "decided_at": request.decided_at.map(|timestamp| timestamp.to_rfc3339()),
    })
}

fn bootstrap_create_json(result: &CreateBootstrapTokenResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "id": result.token.id,
        "token": result.plaintext_token,
        "bootstrap_token": bootstrap_token_json(&result.token),
    })
}

fn bootstrap_token_json(token: &BootstrapToken) -> serde_json::Value {
    serde_json::json!({
        "id": token.id,
        "description": token.description,
        "scopes": token.scopes.iter().map(|scope| serde_json::json!({
            "scope_type": scope.scope_type,
            "scope_value": scope.scope_value,
        })).collect::<Vec<_>>(),
        "max_uses": token.max_uses,
        "used_count": token.used_count,
        "expires_at": token.expires_at.map(|timestamp| timestamp.to_rfc3339()),
        "status": token.status,
        "created_at": token.created_at.to_rfc3339(),
    })
}

fn join_json(result: &BootstrapJoinResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "id": result.instance.id,
        "name": result.instance.name,
        "secret": result.secret,
        "bootstrap_token_id": result.bootstrap_token_id,
        "instance": instance_json(&result.instance),
    })
}

pub(crate) fn audit_instance_joined(vault: &Vault, result: &BootstrapJoinResult) {
    let scope_json = serde_json::to_string(
        &result
            .instance
            .scopes
            .iter()
            .map(|scope| {
                serde_json::json!({
                    "scope_type": scope.scope_type,
                    "scope_value": scope.scope_value,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string());
    audit::log_event(
        vault.db(),
        "InstanceJoined",
        Some(&result.instance.name),
        None,
        Some(&result.bootstrap_token_id),
        None,
        None,
        None,
        false,
        Some(&scope_json),
        None,
    );
}

fn audit_instance_secret_rotated(vault: &Vault, result: &RotateInstanceSecretResult) {
    let details = result
        .instance
        .previous_secret_expires_at
        .map(|timestamp| format!("previous_secret_expires_at={}", timestamp.to_rfc3339()))
        .unwrap_or_else(|| "previous_secret_retired_immediately".to_string());
    audit::log_event(
        vault.db(),
        "InstanceSecretRotated",
        Some(&result.instance.name),
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&details),
        None,
    );
}
