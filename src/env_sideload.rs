/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Environment-backed sideload credentials for MCP/proxy use.
 * Created: 2026-05-23
 */

const SIDELOAD_ENV_PREFIX: &str = "WISPKEY_SIDELOAD_";
const SIDELOAD_TOKEN_PREFIX: &str = "wk_env_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSideloadCredential {
    pub name: String,
    pub env_key: String,
    pub token: String,
}

/// Lists non-empty `WISPKEY_SIDELOAD_*` variables without exposing their values.
#[must_use]
pub fn list_available() -> Vec<EnvSideloadCredential> {
    list_from_env_vars(
        std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?))),
    )
}

/// Finds a sideload credential by user-facing credential name.
#[must_use]
pub fn credential_for_name(name: &str) -> Option<EnvSideloadCredential> {
    let env_key = env_key_for_name(name)?;
    credential_for_populated_env_key(&env_key)
}

/// Expected env var for a user-facing credential name.
#[must_use]
pub fn env_key_for_name(name: &str) -> Option<String> {
    let slug = slug_from_name(name)?;
    Some(format!("{SIDELOAD_ENV_PREFIX}{slug}"))
}

/// Resolves a sideload token to its env key and secret value.
#[must_use]
pub fn value_for_token(token: &str) -> Option<(EnvSideloadCredential, String)> {
    let env_key = env_key_for_token(token)?;
    let value = std::env::var(&env_key)
        .ok()
        .filter(|value| !value.is_empty())?;
    let credential = credential_for_env_key(&env_key)?;
    Some((credential, value))
}

fn list_from_env_vars(
    vars: impl IntoIterator<Item = (String, String)>,
) -> Vec<EnvSideloadCredential> {
    let mut credentials: Vec<_> = vars
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .filter_map(|(key, _)| credential_for_env_key(&key))
        .collect();

    credentials.sort_by(|left, right| left.name.cmp(&right.name));
    credentials.dedup_by(|left, right| left.name == right.name);
    credentials
}

fn credential_for_populated_env_key(env_key: &str) -> Option<EnvSideloadCredential> {
    if std::env::var(env_key)
        .ok()
        .filter(|value| !value.is_empty())
        .is_some()
    {
        credential_for_env_key(env_key)
    } else {
        None
    }
}

fn credential_for_env_key(env_key: &str) -> Option<EnvSideloadCredential> {
    let slug = env_key.strip_prefix(SIDELOAD_ENV_PREFIX)?;
    if !valid_slug(slug) {
        return None;
    }

    Some(EnvSideloadCredential {
        name: name_from_slug(slug),
        env_key: env_key.to_string(),
        token: format!("{SIDELOAD_TOKEN_PREFIX}{}", slug.to_ascii_lowercase()),
    })
}

fn env_key_for_token(token: &str) -> Option<String> {
    let body = token.strip_prefix("wk_")?;

    if let Some(slug) = body.strip_prefix("env_")
        && valid_slug(slug)
    {
        return Some(format!(
            "{SIDELOAD_ENV_PREFIX}{}",
            slug.to_ascii_uppercase()
        ));
    }

    None
}

fn slug_from_name(name: &str) -> Option<String> {
    let mut slug = String::new();
    let mut last_was_separator = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_uppercase());
            last_was_separator = false;
        } else if matches!(ch, '-' | '_' | '.' | ' ') && !slug.is_empty() && !last_was_separator {
            slug.push('_');
            last_was_separator = true;
        }
    }

    while slug.ends_with('_') {
        slug.pop();
    }

    if slug.is_empty() { None } else { Some(slug) }
}

fn name_from_slug(slug: &str) -> String {
    slug.to_ascii_lowercase().replace('_', "-")
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_name_to_sideload_env_key() {
        assert_eq!(
            env_key_for_name("github-pat"),
            Some("WISPKEY_SIDELOAD_GITHUB_PAT".to_string())
        );
        assert_eq!(
            env_key_for_name(" OpenAI.API key "),
            Some("WISPKEY_SIDELOAD_OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn lists_sideloads_without_values() {
        let listed = list_from_env_vars([
            ("WISPKEY_SIDELOAD_OPENAI".to_string(), "secret".to_string()),
            ("WISPKEY_SIDELOAD_EMPTY".to_string(), String::new()),
            ("OTHER_TOKEN".to_string(), "ignored".to_string()),
        ]);

        assert_eq!(
            listed,
            vec![EnvSideloadCredential {
                name: "openai".to_string(),
                env_key: "WISPKEY_SIDELOAD_OPENAI".to_string(),
                token: "wk_env_openai".to_string(),
            }]
        );
    }

    #[test]
    fn resolves_sideload_tokens_to_env_keys() {
        assert_eq!(
            env_key_for_token("wk_env_github_pat"),
            Some("WISPKEY_SIDELOAD_GITHUB_PAT".to_string())
        );
        assert_eq!(env_key_for_token("wk_openai_abc123"), None);
    }

    #[test]
    fn ignores_old_fallback_prefix() {
        let listed =
            list_from_env_vars([("WISPKEY_FALLBACK_OPENAI".to_string(), "secret".to_string())]);

        assert!(listed.is_empty());
    }
}
