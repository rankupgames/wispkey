use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::StatusCode;
use regex::Regex;

use crate::audit;
use crate::core::{CredentialType, Vault};
use crate::policy::PolicyEngine;

use super::{ProxyActionResult, error_response};

pub(super) fn replace_tokens_in_uri(
    uri: &str,
    vault: Option<&Vault>,
    wisp_pattern: &Regex,
    context: &TokenRequestContext<'_>,
    used_credentials: &mut Vec<(String, String)>,
) -> ProxyActionResult<String> {
    if !wisp_pattern.is_match(uri) {
        return Ok(uri.to_string());
    }
    inject_tokens_in_value(uri, vault, wisp_pattern, context, used_credentials)
}

/// Checks if a credential's project matches the active project scope.
/// Returns `Some(reason)` with the denial reason if the credential is out of scope,
/// or `None` if access is allowed.
fn check_project_scope(
    vault: &Vault,
    cred: &crate::core::Credential,
    project_scope: &Option<String>,
) -> Option<String> {
    let active_project = project_scope.as_ref()?;
    let partition_id = cred.partition_id.as_ref()?;
    let cred_project = vault
        .get_partition_project_name(partition_id)
        .ok()
        .flatten()?;
    if cred_project != *active_project {
        Some(format!(
            "credential '{}' belongs to project '{}', not active project '{}'",
            cred.name, cred_project, active_project
        ))
    } else {
        None
    }
}

pub(super) fn inject_credential(
    credential_type: &CredentialType,
    real_value: &str,
    original_header_value: &str,
    token: &str,
) -> String {
    match credential_type {
        CredentialType::BearerToken
        | CredentialType::ApiKey
        | CredentialType::CustomHeader { .. }
        | CredentialType::QueryParam { .. } => original_header_value.replace(token, real_value),
        CredentialType::BasicAuth => {
            let encoded = BASE64.encode(real_value.as_bytes());
            original_header_value.replace(token, &format!("Basic {}", encoded))
        }
    }
}

pub(super) fn check_host_restriction(allowed_hosts: &[String], target_host: &str) -> bool {
    allowed_hosts.is_empty()
        || allowed_hosts
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, target_host))
}

struct EnvCredentialResolution {
    name: String,
    env_key: String,
    value: String,
}

pub(super) struct TokenRequestContext<'a> {
    pub(super) target_host: &'a str,
    pub(super) target_path: &'a str,
    pub(super) http_method: &'a str,
    pub(super) project_scope: &'a Option<String>,
    pub(super) policy_engine: &'a PolicyEngine,
}

struct ResolvedToken {
    credential_name: String,
    token: String,
    credential_type: CredentialType,
    value: String,
}

pub(super) fn inject_tokens_in_value(
    value: &str,
    vault: Option<&Vault>,
    wisp_pattern: &Regex,
    context: &TokenRequestContext<'_>,
    used_credentials: &mut Vec<(String, String)>,
) -> ProxyActionResult<String> {
    if !wisp_pattern.is_match(value) {
        return Ok(value.to_string());
    }

    let tokens: Vec<String> = wisp_pattern
        .find_iter(value)
        .map(|token_match| token_match.as_str().to_string())
        .collect();
    let mut replaced = value.to_string();

    for token in tokens {
        let resolved = resolve_token_for_request(vault, &token, context)?;
        replaced = inject_credential(
            &resolved.credential_type,
            &resolved.value,
            &replaced,
            &resolved.token,
        );
        used_credentials.push((resolved.credential_name, resolved.token));
    }

    Ok(replaced)
}

fn resolve_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> ProxyActionResult<ResolvedToken> {
    let Some(vault) = vault else {
        return resolve_env_token_for_request(None, token, context);
    };

    match vault.lookup_by_wisp_token(token) {
        Ok((cred, real_value)) => {
            if let Some(reason) = check_project_scope(vault, &cred, context.project_scope) {
                audit_denial(
                    vault,
                    "CredentialDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &reason,
                );
                return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
            }

            if !check_host_restriction(&cred.hosts, context.target_host) {
                let reason = format!(
                    "host '{}' not allowed for credential '{}'",
                    context.target_host, cred.name
                );
                audit_denial(
                    vault,
                    "CredentialDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &reason,
                );
                return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
            }

            if let Some(denial) = context.policy_engine.evaluate(
                &cred.name,
                None,
                context.target_host,
                context.target_path,
                context.http_method,
            ) {
                audit_denial(
                    vault,
                    "PolicyDenied",
                    Some(&cred.name),
                    token,
                    context,
                    &denial.reason,
                );
                return Err(Box::new(error_response(
                    StatusCode::FORBIDDEN,
                    &denial.reason,
                )));
            }

            Ok(ResolvedToken {
                credential_name: cred.name,
                token: token.to_string(),
                credential_type: cred.credential_type,
                value: real_value,
            })
        }
        Err(_) => {
            if let Ok(resolved) = resolve_env_token_for_request(Some(vault), token, context) {
                return Ok(resolved);
            }

            let reason = format!("wisp token '{}' was not found in the active vault", token);
            audit_denial(vault, "CredentialDenied", None, token, context, &reason);
            Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)))
        }
    }
}

fn resolve_env_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> ProxyActionResult<ResolvedToken> {
    let Some(env_credential) = try_env_sideload(token) else {
        let reason = if vault.is_some() {
            format!("wisp token '{}' was not found in the active vault", token)
        } else {
            format!(
                "wisp token '{}' requires an unlocked vault or matching WISPKEY_SIDELOAD_* env var",
                token
            )
        };
        return Err(Box::new(error_response(StatusCode::FORBIDDEN, &reason)));
    };

    if let Some(denial) = context.policy_engine.evaluate(
        &env_credential.name,
        None,
        context.target_host,
        context.target_path,
        context.http_method,
    ) {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            &denial.reason,
        )));
    }

    if let Some(vault) = vault {
        audit::log_event(
            vault.db(),
            "SideloadUsed",
            Some(&env_credential.env_key),
            Some(token),
            Some(context.target_host),
            Some(context.target_path),
            Some(context.http_method),
            None,
            false,
            Some("used env sideload credential"),
            context.project_scope.as_deref(),
        );
    }

    Ok(ResolvedToken {
        credential_name: env_credential.env_key,
        token: token.to_string(),
        credential_type: CredentialType::BearerToken,
        value: env_credential.value,
    })
}

fn audit_denial(
    vault: &Vault,
    event_type: &str,
    credential_name: Option<&str>,
    token: &str,
    context: &TokenRequestContext<'_>,
    reason: &str,
) {
    audit::log_event(
        vault.db(),
        event_type,
        credential_name,
        Some(token),
        Some(context.target_host),
        Some(context.target_path),
        Some(context.http_method),
        None,
        true,
        Some(reason),
        context.project_scope.as_deref(),
    );
}

/// Attempts to find a sideloaded credential value from environment variables.
/// Supports deterministic MCP sideload tokens (`wk_env_<slug>`).
fn try_env_sideload(token: &str) -> Option<EnvCredentialResolution> {
    crate::env_sideload::value_for_token(token).map(|(credential, value)| EnvCredentialResolution {
        name: credential.name,
        env_key: credential.env_key,
        value,
    })
}
