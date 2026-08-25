use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use regex::Regex;

use crate::audit;
use crate::core::{CredentialType, Vault};
use crate::policy::PolicyEngine;

use super::management::json_response;
use super::{InstanceIdentity, ProxyActionResult, error_response};

const WISP_TOKEN_PREFIX: &str = "wk_";
const VAULT_TOKEN_RANDOM_LEN: usize = 8;

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

#[cfg(test)]
pub(super) fn inject_credential(
    credential_type: &CredentialType,
    real_value: &str,
    original_header_value: &str,
    token: &str,
) -> String {
    let replacement = credential_replacement_value(credential_type, real_value);
    original_header_value.replacen(token, &replacement, 1)
}

fn credential_replacement_value(credential_type: &CredentialType, real_value: &str) -> String {
    match credential_type {
        CredentialType::BearerToken
        | CredentialType::ApiKey
        | CredentialType::CustomHeader { .. }
        | CredentialType::QueryParam { .. }
        | CredentialType::WebsiteLogin => real_value.to_string(),
        CredentialType::BasicAuth => {
            let encoded = BASE64.encode(real_value.as_bytes());
            format!("Basic {}", encoded)
        }
    }
}

pub(super) fn check_host_restriction(allowed_hosts: &[String], target_host: &str) -> bool {
    let target_host = target_host.to_ascii_lowercase();
    allowed_hosts.is_empty()
        || allowed_hosts
            .iter()
            .any(|pattern| glob_match::glob_match(&pattern.to_ascii_lowercase(), &target_host))
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
    pub(super) instance: Option<&'a InstanceIdentity>,
}

struct ResolvedToken {
    credential_name: String,
    token: String,
    credential_type: CredentialType,
    value: String,
}

enum TokenResolution {
    Resolved(ResolvedToken),
    NotFound,
    Denied(Box<Response<Full<Bytes>>>),
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

    let sideload_tokens: Vec<String> = crate::env_sideload::list_available()
        .into_iter()
        .map(|credential| credential.token)
        .collect();
    let mut replaced = String::with_capacity(value.len());
    let mut cursor = 0;

    for candidate_match in wisp_pattern.find_iter(value) {
        replaced.push_str(&value[cursor..candidate_match.start()]);
        replace_tokens_in_candidate(
            candidate_match.as_str(),
            vault,
            context,
            used_credentials,
            &sideload_tokens,
            &mut replaced,
        )?;
        cursor = candidate_match.end();
    }

    replaced.push_str(&value[cursor..]);
    Ok(replaced)
}

fn replace_tokens_in_candidate(
    candidate: &str,
    vault: Option<&Vault>,
    context: &TokenRequestContext<'_>,
    used_credentials: &mut Vec<(String, String)>,
    sideload_tokens: &[String],
    output: &mut String,
) -> ProxyActionResult<()> {
    let mut cursor = 0;

    while cursor < candidate.len() {
        let Some(relative_start) = candidate[cursor..].find(WISP_TOKEN_PREFIX) else {
            output.push_str(&candidate[cursor..]);
            break;
        };
        let start = cursor + relative_start;
        output.push_str(&candidate[cursor..start]);

        let token_candidate = &candidate[start..];
        let (resolved, consumed) =
            resolve_token_prefix_for_request(vault, token_candidate, context, sideload_tokens)?;
        output.push_str(&credential_replacement_value(
            &resolved.credential_type,
            &resolved.value,
        ));
        used_credentials.push((resolved.credential_name, resolved.token));
        cursor = start + consumed;
    }

    Ok(())
}

fn resolve_token_prefix_for_request(
    vault: Option<&Vault>,
    candidate: &str,
    context: &TokenRequestContext<'_>,
    sideload_tokens: &[String],
) -> ProxyActionResult<(ResolvedToken, usize)> {
    for prefix_len in candidate_prefix_lengths(candidate, sideload_tokens) {
        let token = &candidate[..prefix_len];
        match try_resolve_exact_token_for_request(vault, token, context) {
            TokenResolution::Resolved(resolved) => return Ok((resolved, prefix_len)),
            TokenResolution::NotFound => {}
            TokenResolution::Denied(response) => return Err(response),
        }
    }

    Err(missing_token_response(vault, candidate, context))
}

fn candidate_prefix_lengths(candidate: &str, sideload_tokens: &[String]) -> Vec<usize> {
    candidate_prefix_lengths_with_sideload_tokens(
        candidate,
        sideload_tokens.iter().map(String::as_str),
    )
}

pub(super) fn candidate_prefix_lengths_with_sideload_tokens<'a>(
    candidate: &str,
    sideload_tokens: impl IntoIterator<Item = &'a str>,
) -> Vec<usize> {
    let mut lengths = Vec::new();

    for token in sideload_tokens {
        if candidate.starts_with(token) {
            lengths.push(token.len());
        }
    }

    let bytes = candidate.as_bytes();
    for separator in 3..bytes.len() {
        if bytes[separator] != b'_' {
            continue;
        }
        let end = separator + 1 + VAULT_TOKEN_RANDOM_LEN;
        if end <= bytes.len()
            && bytes[separator + 1..end]
                .iter()
                .all(u8::is_ascii_alphanumeric)
        {
            lengths.push(end);
        }
    }

    lengths.sort_unstable_by(|left, right| right.cmp(left));
    lengths.dedup();
    lengths
}

fn try_resolve_exact_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> TokenResolution {
    let Some(vault) = vault else {
        return try_resolve_env_token_for_request(None, token, context);
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
                return TokenResolution::Denied(Box::new(error_response(
                    StatusCode::FORBIDDEN,
                    &reason,
                )));
            }

            if let Some(instance) = context.instance {
                let in_scope = vault
                    .credential_in_scope(&instance.id, &cred.id)
                    .unwrap_or(false);
                if !in_scope {
                    let reason = format!("out_of_scope instance={}", instance.name);
                    let access_request = vault
                        .create_or_reuse_access_request(
                            &instance.id,
                            &cred.id,
                            "access requested by proxy token injection",
                        )
                        .ok();
                    audit_denial(
                        vault,
                        "CredentialDenied",
                        Some(&cred.name),
                        token,
                        context,
                        &reason,
                    );
                    return TokenResolution::Denied(Box::new(out_of_scope_response(
                        &cred.name,
                        instance,
                        access_request.as_ref().map(|request| request.id.as_str()),
                    )));
                }
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
                return TokenResolution::Denied(Box::new(error_response(
                    StatusCode::FORBIDDEN,
                    &reason,
                )));
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
                return TokenResolution::Denied(Box::new(error_response(
                    StatusCode::FORBIDDEN,
                    &denial.reason,
                )));
            }

            TokenResolution::Resolved(ResolvedToken {
                credential_name: cred.name,
                token: token.to_string(),
                credential_type: cred.credential_type,
                value: real_value,
            })
        }
        Err(_) => try_resolve_env_token_for_request(Some(vault), token, context),
    }
}

fn try_resolve_env_token_for_request(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> TokenResolution {
    match resolve_env_token_for_request(vault, token, context) {
        Ok(resolved) => TokenResolution::Resolved(resolved),
        Err(response) => {
            if try_env_sideload(token).is_some() {
                TokenResolution::Denied(response)
            } else {
                TokenResolution::NotFound
            }
        }
    }
}

fn missing_token_response(
    vault: Option<&Vault>,
    token: &str,
    context: &TokenRequestContext<'_>,
) -> Box<Response<Full<Bytes>>> {
    let reason = if vault.is_some() {
        format!("wisp token '{}' was not found in the active vault", token)
    } else {
        format!(
            "wisp token '{}' requires an unlocked vault or matching WISPKEY_SIDELOAD_* env var",
            token
        )
    };
    if let Some(vault) = vault {
        audit_denial(vault, "CredentialDenied", None, token, context, &reason);
    }
    Box::new(error_response(StatusCode::FORBIDDEN, &reason))
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

    if let Some(instance) = context.instance {
        let reason = format!(
            "environment sideload credential '{}' is not available to identity-authenticated instances",
            env_credential.env_key
        );
        if let Some(vault) = vault {
            audit_denial(
                vault,
                "CredentialDenied",
                Some(&env_credential.env_key),
                token,
                context,
                &reason,
            );
        }
        return Err(Box::new(sideload_out_of_scope_response(
            &env_credential.env_key,
            instance,
        )));
    }

    if let Some(denial) = context.policy_engine.evaluate(
        &env_credential.name,
        None,
        context.target_host,
        context.target_path,
        context.http_method,
    ) {
        if let Some(vault) = vault {
            audit_denial(
                vault,
                "PolicyDenied",
                Some(&env_credential.env_key),
                token,
                context,
                &denial.reason,
            );
        } else {
            audit::log_fallback_event(
                "PolicyDenied",
                Some(&env_credential.env_key),
                Some(token),
                Some(context.target_host),
                Some(context.target_path),
                Some(context.http_method),
                None,
                true,
                Some(&denial.reason),
                context.project_scope.as_deref(),
            );
        }
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
    } else {
        audit::log_fallback_event(
            "SideloadUsed",
            Some(&env_credential.env_key),
            Some(token),
            Some(context.target_host),
            Some(context.target_path),
            Some(context.http_method),
            None,
            false,
            Some("used env sideload credential without unlocked vault"),
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

fn out_of_scope_response(
    credential_name: &str,
    instance: &InstanceIdentity,
    access_request_id: Option<&str>,
) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::FORBIDDEN,
        &serde_json::json!({
            "error": "out_of_scope",
            "credential": credential_name,
            "instance": instance.name,
            "access_request": access_request_id,
            "message": "access requested; awaiting host approval",
        }),
    )
}

fn sideload_out_of_scope_response(
    credential_name: &str,
    instance: &InstanceIdentity,
) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::FORBIDDEN,
        &serde_json::json!({
            "error": "out_of_scope",
            "credential": credential_name,
            "instance": instance.name,
            "access_request": null,
            "message": "environment sideload credentials cannot be authorized for identity-authenticated instances",
        }),
    )
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
