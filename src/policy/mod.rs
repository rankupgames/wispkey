/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: TOML-based policy engine. Evaluates per-credential, per-host, per-path,
 *              per-method rules with rate limiting and time window restrictions.
 *              Policies loaded from ~/.wispkey/policies.toml.
 * Created: 2026-04-13
 * Last Modified: 2026-04-13
 */

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Local, NaiveTime};
use serde::{Deserialize, Serialize};

use crate::core::Vault;

/// Top-level policies configuration (deserialized from TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub policy: Vec<Policy>,
}

/// A single access policy rule with host, path, method, and rate-limit constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub denied_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub denied_paths: Vec<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<String>,
    #[serde(default)]
    pub time_window: Option<String>,
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug)]
struct RateLimit {
    max_requests: u64,
    window: Duration,
}

struct RateBucket {
    timestamps: Vec<Instant>,
}

/// Evaluates requests against loaded policies and enforces rate limits.
pub struct PolicyEngine {
    policies: Vec<Policy>,
    rate_buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
}

/// Describes why a policy denied a request.
#[derive(Debug)]
pub struct PolicyDenial {
    #[allow(dead_code)]
    pub policy_name: String,
    pub reason: String,
}

impl PolicyEngine {
    /// Loads policies from the default TOML file on disk.
    pub fn load() -> Self {
        let config = load_policies_from_disk();
        PolicyEngine {
            policies: config.policy,
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub fn from_config(config: PolicyConfig) -> Self {
        PolicyEngine {
            policies: config.policy,
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the loaded policy list.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Evaluate all policies against a request context. Returns the first denial, or None if allowed.
    pub fn evaluate(&self, credential_name: &str, agent_name: Option<&str>, host: &str, path: &str, method: &str) -> Option<PolicyDenial> {
        for policy in &self.policies {
            if let Some(denial) = self.evaluate_single(policy, credential_name, agent_name, host, path, method) {
                return Some(denial);
            }
        }
        None
    }

    fn evaluate_single(&self, policy: &Policy, credential_name: &str, agent_name: Option<&str>, host: &str, path: &str, method: &str) -> Option<PolicyDenial> {
        if !policy_matches_credential(policy, credential_name) {
            return None;
        }
        if !policy_matches_agent(policy, agent_name) {
            return None;
        }

        if policy.deny {
            return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("credential '{}' blocked by deny policy '{}'", credential_name, policy.name) });
        }

        if !policy.allowed_hosts.is_empty() && !policy.allowed_hosts.iter().any(|h| glob_match::glob_match(h, host)) {
            return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("host '{}' not in allowed_hosts for policy '{}'", host, policy.name) });
        }
        if policy.denied_hosts.iter().any(|h| glob_match::glob_match(h, host)) {
            return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("host '{}' blocked by denied_hosts in policy '{}'", host, policy.name) });
        }

        if !policy.allowed_methods.is_empty() {
            let method_upper = method.to_uppercase();
            if !policy.allowed_methods.iter().any(|m| m.to_uppercase() == method_upper) {
                return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("method '{}' not in allowed_methods for policy '{}'", method, policy.name) });
            }
        }

        if !policy.allowed_paths.is_empty() && !policy.allowed_paths.iter().any(|p| glob_match::glob_match(p, path)) {
            return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("path '{}' not in allowed_paths for policy '{}'", path, policy.name) });
        }
        if policy.denied_paths.iter().any(|p| glob_match::glob_match(p, path)) {
            return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("path '{}' blocked by denied_paths in policy '{}'", path, policy.name) });
        }

        if let Some(ref window_str) = policy.time_window
            && let Some(denial) = check_time_window(&policy.name, window_str)
        {
            return Some(denial);
        }

        if let Some(ref limit_str) = policy.rate_limit
            && let Some(parsed) = parse_rate_limit(limit_str)
        {
            let bucket_key = format!("{}:{}", policy.name, credential_name);
            if let Ok(mut buckets) = self.rate_buckets.lock() {
                let bucket = buckets.entry(bucket_key).or_insert_with(|| RateBucket { timestamps: Vec::new() });
                let now = Instant::now();
                bucket.timestamps.retain(|t| now.duration_since(*t) < parsed.window);
                if bucket.timestamps.len() as u64 >= parsed.max_requests {
                    return Some(PolicyDenial { policy_name: policy.name.clone(), reason: format!("rate limit exceeded ({}) for policy '{}'", limit_str, policy.name) });
                }
                bucket.timestamps.push(now);
            }
        }

        None
    }
}

fn policy_matches_credential(policy: &Policy, credential_name: &str) -> bool {
    match &policy.credential {
        Some(pattern) => glob_match::glob_match(pattern, credential_name),
        None => true,
    }
}

fn policy_matches_agent(policy: &Policy, agent_name: Option<&str>) -> bool {
    match (&policy.agent, agent_name) {
        (Some(pattern), Some(name)) => glob_match::glob_match(pattern, name),
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn parse_rate_limit(s: &str) -> Option<RateLimit> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let max_requests: u64 = parts[0].trim().parse().ok()?;
    let window = match parts[1].trim().to_lowercase().as_str() {
        "second" | "s" => Duration::from_secs(1),
        "minute" | "m" => Duration::from_secs(60),
        "hour" | "h" => Duration::from_secs(3600),
        "day" | "d" => Duration::from_secs(86400),
        _ => return None,
    };
    Some(RateLimit { max_requests, window })
}

fn check_time_window(policy_name: &str, window_str: &str) -> Option<PolicyDenial> {
    let parts: Vec<&str> = window_str.splitn(2, '-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start = NaiveTime::parse_from_str(parts[0].trim(), "%H:%M").ok()?;
    let end = NaiveTime::parse_from_str(parts[1].trim(), "%H:%M").ok()?;
    let now = Local::now().time();

    let in_window = if start <= end {
        now >= start && now < end
    } else {
        now >= start || now < end
    };

    if !in_window {
        Some(PolicyDenial {
            policy_name: policy_name.to_string(),
            reason: format!("current time {} outside allowed window {}", now.format("%H:%M"), window_str),
        })
    } else {
        None
    }
}

/// Returns the path to the policies TOML file.
pub fn policies_path() -> PathBuf {
    Vault::vault_dir().join("policies.toml")
}

/// Reads and parses the policies TOML file, returning empty config on failure.
pub fn load_policies_from_disk() -> PolicyConfig {
    let path = policies_path();
    if !path.exists() {
        return PolicyConfig { policy: Vec::new() };
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
            tracing::warn!("Failed to parse policies.toml: {}", e);
            PolicyConfig { policy: Vec::new() }
        }),
        Err(e) => {
            tracing::warn!("Failed to read policies.toml: {}", e);
            PolicyConfig { policy: Vec::new() }
        }
    }
}

/// Serializes and writes the policies config to the TOML file.
#[allow(dead_code)]
pub fn save_policies(config: &PolicyConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = policies_path();
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine(policies: Vec<Policy>) -> PolicyEngine {
        PolicyEngine::from_config(PolicyConfig { policy: policies })
    }

    #[test]
    fn no_policies_allows_all() {
        let engine = test_engine(vec![]);
        assert!(engine.evaluate("any-cred", None, "any.host", "/any/path", "GET").is_none());
    }

    #[test]
    fn deny_policy_blocks() {
        let engine = test_engine(vec![Policy {
            name: "block-prod".into(),
            agent: None,
            credential: Some("aws-prod".into()),
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: true,
        }]);
        let result = engine.evaluate("aws-prod", None, "aws.com", "/", "GET");
        assert!(result.is_some());
        assert!(result.unwrap().reason.contains("deny policy"));
    }

    #[test]
    fn deny_policy_skips_non_matching_credential() {
        let engine = test_engine(vec![Policy {
            name: "block-prod".into(),
            agent: None,
            credential: Some("aws-prod".into()),
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: true,
        }]);
        assert!(engine.evaluate("aws-dev", None, "aws.com", "/", "GET").is_none());
    }

    #[test]
    fn allowed_methods_restricts() {
        let engine = test_engine(vec![Policy {
            name: "read-only".into(),
            agent: None,
            credential: Some("*".into()),
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec!["GET".into()],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("any", None, "host", "/", "GET").is_none());
        assert!(engine.evaluate("any", None, "host", "/", "POST").is_some());
    }

    #[test]
    fn denied_paths_blocks() {
        let engine = test_engine(vec![Policy {
            name: "no-admin".into(),
            agent: None,
            credential: None,
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec!["/admin/**".into()],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("cred", None, "host", "/admin/users", "GET").is_some());
        assert!(engine.evaluate("cred", None, "host", "/api/data", "GET").is_none());
    }

    #[test]
    fn denied_hosts_blocks() {
        let engine = test_engine(vec![Policy {
            name: "no-evil".into(),
            agent: None,
            credential: None,
            allowed_hosts: vec![],
            denied_hosts: vec!["*.evil.com".into()],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("cred", None, "api.evil.com", "/", "GET").is_some());
        assert!(engine.evaluate("cred", None, "api.good.com", "/", "GET").is_none());
    }

    #[test]
    fn allowed_hosts_restricts() {
        let engine = test_engine(vec![Policy {
            name: "only-api".into(),
            agent: None,
            credential: None,
            allowed_hosts: vec!["api.example.com".into()],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("cred", None, "api.example.com", "/", "GET").is_none());
        assert!(engine.evaluate("cred", None, "other.com", "/", "GET").is_some());
    }

    #[test]
    fn rate_limit_enforces() {
        let engine = test_engine(vec![Policy {
            name: "limited".into(),
            agent: None,
            credential: Some("test-cred".into()),
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: Some("3/minute".into()),
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("test-cred", None, "h", "/", "GET").is_none());
        assert!(engine.evaluate("test-cred", None, "h", "/", "GET").is_none());
        assert!(engine.evaluate("test-cred", None, "h", "/", "GET").is_none());
        let fourth = engine.evaluate("test-cred", None, "h", "/", "GET");
        assert!(fourth.is_some());
        assert!(fourth.unwrap().reason.contains("rate limit"));
    }

    #[test]
    fn parse_rate_limit_variants() {
        assert!(parse_rate_limit("10/minute").is_some());
        assert!(parse_rate_limit("5/hour").is_some());
        assert!(parse_rate_limit("100/day").is_some());
        assert!(parse_rate_limit("1/second").is_some());
        assert!(parse_rate_limit("bad").is_none());
    }

    #[test]
    fn agent_scoping_matches() {
        let engine = test_engine(vec![Policy {
            name: "claude-only".into(),
            agent: Some("claude-code".into()),
            credential: None,
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec!["GET".into()],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("cred", Some("claude-code"), "h", "/", "POST").is_some());
        assert!(engine.evaluate("cred", Some("claude-code"), "h", "/", "GET").is_none());
        assert!(engine.evaluate("cred", Some("cursor"), "h", "/", "POST").is_none());
        assert!(engine.evaluate("cred", None, "h", "/", "POST").is_none());
    }

    #[test]
    fn credential_glob_matching() {
        let engine = test_engine(vec![Policy {
            name: "aws-all".into(),
            agent: None,
            credential: Some("aws-*".into()),
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec!["GET".into()],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: None,
            deny: false,
        }]);
        assert!(engine.evaluate("aws-prod", None, "h", "/", "POST").is_some());
        assert!(engine.evaluate("aws-dev", None, "h", "/", "POST").is_some());
        assert!(engine.evaluate("openai-key", None, "h", "/", "POST").is_none());
    }
}
