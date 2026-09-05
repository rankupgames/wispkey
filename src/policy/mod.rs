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
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, NaiveTime};
use serde::{Deserialize, Serialize};

use crate::core::Vault;

/// Top-level policies configuration (deserialized from TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub policy: Vec<Policy>,
}

pub(crate) const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_POLICY_COUNT: usize = 1024;

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
    window: Duration,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyOutcome {
    Skipped,
    Allowed,
    Denied,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyTrace {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) matched: bool,
    pub(crate) outcome: PolicyOutcome,
    pub(crate) reason: Option<String>,
    pub(crate) rate_limit_checked: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) severity: &'static str,
    pub(crate) policy_index: Option<usize>,
    pub(crate) policy_name: Option<String>,
    pub(crate) message: &'static str,
    pub(crate) proven: bool,
    pub(crate) related_policy_index: Option<usize>,
    pub(crate) related_policy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicySimulation {
    pub(crate) evaluated_at: DateTime<Local>,
    pub(crate) evaluations: Vec<PolicyTrace>,
    pub(crate) decisive_policy_index: Option<usize>,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PolicyRequest<'a> {
    pub(crate) credential_name: &'a str,
    pub(crate) agent_name: Option<&'a str>,
    pub(crate) host: &'a str,
    pub(crate) path: &'a str,
    pub(crate) method: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyInputError {
    Io,
    TooLarge,
    InvalidUtf8,
    Parse,
}

impl fmt::Display for PolicyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io => "could not read policy file",
            Self::TooLarge => "policy file exceeds the size limit",
            Self::InvalidUtf8 => "policy file is not valid UTF-8",
            Self::Parse => "policy file is not valid TOML",
        };
        formatter.write_str(message)
    }
}

enum RateState<'a> {
    Live(&'a Mutex<HashMap<String, RateBucket>>),
    Fresh(&'a mut HashMap<String, RateBucket>, Instant),
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

    pub(crate) fn from_config(config: PolicyConfig) -> Self {
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
    pub fn evaluate(
        &self,
        credential_name: &str,
        agent_name: Option<&str>,
        host: &str,
        path: &str,
        method: &str,
    ) -> Option<PolicyDenial> {
        self.evaluate_with_clock(
            PolicyRequest {
                credential_name,
                agent_name,
                host,
                path,
                method,
            },
            Local::now(),
            RateState::Live(&self.rate_buckets),
        )
    }

    #[cfg(test)]
    pub(crate) fn simulate(
        &self,
        request: PolicyRequest<'_>,
        evaluated_at: DateTime<Local>,
    ) -> PolicySimulation {
        let diagnostics = self.diagnostics();
        self.simulate_with_diagnostics(request, evaluated_at, &diagnostics)
    }

    pub(crate) fn simulate_with_diagnostics(
        &self,
        request: PolicyRequest<'_>,
        evaluated_at: DateTime<Local>,
        diagnostics: &[PolicyDiagnostic],
    ) -> PolicySimulation {
        let mut evaluations = Vec::with_capacity(self.policies.len());
        let mut decisive_policy_index = None;
        let mut simulation_buckets = HashMap::new();
        let mut rate_state = RateState::Fresh(&mut simulation_buckets, Instant::now());

        for (index, policy) in self.policies.iter().enumerate() {
            let trace =
                self.evaluate_single(index, policy, request, evaluated_at.time(), &mut rate_state);
            if decisive_policy_index.is_none() && trace.outcome == PolicyOutcome::Denied {
                decisive_policy_index = Some(index);
            }
            evaluations.push(trace);
        }

        PolicySimulation {
            evaluated_at,
            evaluations,
            decisive_policy_index,
            diagnostics: diagnostics.to_vec(),
        }
    }

    fn evaluate_with_clock(
        &self,
        request: PolicyRequest<'_>,
        evaluated_at: DateTime<Local>,
        mut rate_state: RateState<'_>,
    ) -> Option<PolicyDenial> {
        for (index, policy) in self.policies.iter().enumerate() {
            let trace =
                self.evaluate_single(index, policy, request, evaluated_at.time(), &mut rate_state);
            if trace.outcome == PolicyOutcome::Denied {
                return Some(PolicyDenial {
                    policy_name: trace.name,
                    reason: trace
                        .reason
                        .unwrap_or_else(|| "policy denied the request".to_string()),
                });
            }
        }
        None
    }

    #[cfg(test)]
    fn evaluate_at(
        &self,
        request: PolicyRequest<'_>,
        evaluated_at: DateTime<Local>,
    ) -> Option<PolicyDenial> {
        self.evaluate_with_clock(request, evaluated_at, RateState::Live(&self.rate_buckets))
    }

    fn evaluate_single(
        &self,
        index: usize,
        policy: &Policy,
        request: PolicyRequest<'_>,
        local_time: NaiveTime,
        rate_state: &mut RateState<'_>,
    ) -> PolicyTrace {
        let name = policy.name.clone();
        if !policy_matches_credential(policy, request.credential_name) {
            return PolicyTrace {
                index,
                name,
                matched: false,
                outcome: PolicyOutcome::Skipped,
                reason: Some("credential selector did not match".to_string()),
                rate_limit_checked: false,
            };
        }
        if !policy_matches_agent(policy, request.agent_name) {
            return PolicyTrace {
                index,
                name,
                matched: false,
                outcome: PolicyOutcome::Skipped,
                reason: Some("agent selector did not match".to_string()),
                rate_limit_checked: false,
            };
        }

        if policy.deny {
            return denied_trace(
                index,
                name,
                format!(
                    "credential '{}' blocked by deny policy '{}'",
                    request.credential_name, policy.name
                ),
                false,
            );
        }

        if !policy.allowed_hosts.is_empty()
            && !policy.allowed_hosts.iter().any(|h| {
                glob_match::glob_match(&h.to_ascii_lowercase(), &request.host.to_ascii_lowercase())
            })
        {
            return denied_trace(
                index,
                name,
                format!(
                    "host '{}' not in allowed_hosts for policy '{}'",
                    request.host, policy.name
                ),
                false,
            );
        }
        if policy.denied_hosts.iter().any(|h| {
            glob_match::glob_match(&h.to_ascii_lowercase(), &request.host.to_ascii_lowercase())
        }) {
            return denied_trace(
                index,
                name,
                format!(
                    "host '{}' blocked by denied_hosts in policy '{}'",
                    request.host, policy.name
                ),
                false,
            );
        }

        if !policy.allowed_methods.is_empty() {
            let method_upper = request.method.to_uppercase();
            if !policy
                .allowed_methods
                .iter()
                .any(|m| m.to_uppercase() == method_upper)
            {
                return denied_trace(
                    index,
                    name,
                    format!(
                        "method '{}' not in allowed_methods for policy '{}'",
                        request.method, policy.name
                    ),
                    false,
                );
            }
        }

        if !policy.allowed_paths.is_empty()
            && !policy
                .allowed_paths
                .iter()
                .any(|p| glob_match::glob_match(p, request.path))
        {
            return denied_trace(
                index,
                name,
                format!(
                    "path '{}' not in allowed_paths for policy '{}'",
                    request.path, policy.name
                ),
                false,
            );
        }
        if policy
            .denied_paths
            .iter()
            .any(|p| glob_match::glob_match(p, request.path))
        {
            return denied_trace(
                index,
                name,
                format!(
                    "path '{}' blocked by denied_paths in policy '{}'",
                    request.path, policy.name
                ),
                false,
            );
        }

        if let Some(ref window_str) = policy.time_window
            && let Some(denial) = check_time_window(&policy.name, window_str, local_time)
        {
            return denied_trace(index, name, denial.reason, false);
        }

        if let Some(ref limit_str) = policy.rate_limit {
            let Some(parsed) = parse_rate_limit(limit_str) else {
                return denied_trace(
                    index,
                    name,
                    "invalid rate limit configuration; request denied".to_string(),
                    true,
                );
            };
            if let Some(reason) = check_rate_limit(
                &policy.name,
                request.credential_name,
                limit_str,
                parsed,
                rate_state,
            ) {
                return denied_trace(index, name, reason, true);
            }

            return allowed_trace(index, name, true);
        }

        allowed_trace(index, name, false)
    }

    #[cfg(test)]
    fn diagnostics(&self) -> Vec<PolicyDiagnostic> {
        policy_diagnostics_for_policies(&self.policies)
    }
}

pub(crate) fn policy_diagnostics(config: &PolicyConfig) -> Vec<PolicyDiagnostic> {
    policy_diagnostics_for_policies(&config.policy)
}

fn policy_diagnostics_for_policies(policies: &[Policy]) -> Vec<PolicyDiagnostic> {
    let mut diagnostics = Vec::new();
    if policies.len() > MAX_POLICY_COUNT {
        diagnostics.push(PolicyDiagnostic {
            code: "policy_count_limit",
            severity: "error",
            policy_index: None,
            policy_name: None,
            message: "policy count exceeds the runtime and simulation limit; effective config denies all",
            proven: true,
            related_policy_index: None,
            related_policy_name: None,
        });
    }

    for (index, policy) in policies.iter().enumerate() {
        if policy
            .rate_limit
            .as_deref()
            .is_some_and(|value| parse_rate_limit(value).is_none())
        {
            diagnostics.push(PolicyDiagnostic {
                code: "invalid_rate_limit",
                severity: "error",
                policy_index: Some(index),
                policy_name: Some(policy.name.clone()),
                message: "rate_limit is invalid; matching requests deny at runtime",
                proven: true,
                related_policy_index: None,
                related_policy_name: None,
            });
        }
        if policy
            .time_window
            .as_deref()
            .is_some_and(|value| parse_time_window(value).is_none())
        {
            diagnostics.push(PolicyDiagnostic {
                code: "invalid_time_window",
                severity: "error",
                policy_index: Some(index),
                policy_name: Some(policy.name.clone()),
                message: "time_window is invalid; matching requests deny at runtime",
                proven: true,
                related_policy_index: None,
                related_policy_name: None,
            });
        }

        if let Some(shadowing_index) = (0..index).find(|earlier_index| {
            let earlier = &policies[*earlier_index];
            earlier.deny && deny_selectors_cover(earlier, policy)
        }) {
            let shadowing_policy = &policies[shadowing_index];
            diagnostics.push(PolicyDiagnostic {
                code: "shadowed_rule",
                severity: "warning",
                policy_index: Some(index),
                policy_name: Some(policy.name.clone()),
                message: "an earlier deny policy provably denies every request this rule can match",
                proven: true,
                related_policy_index: Some(shadowing_index),
                related_policy_name: Some(shadowing_policy.name.clone()),
            });
        }
    }
    diagnostics
}

fn allowed_trace(index: usize, name: String, rate_limit_checked: bool) -> PolicyTrace {
    PolicyTrace {
        index,
        name,
        matched: true,
        outcome: PolicyOutcome::Allowed,
        reason: None,
        rate_limit_checked,
    }
}

fn denied_trace(
    index: usize,
    name: String,
    reason: String,
    rate_limit_checked: bool,
) -> PolicyTrace {
    PolicyTrace {
        index,
        name,
        matched: true,
        outcome: PolicyOutcome::Denied,
        reason: Some(reason),
        rate_limit_checked,
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
        // Keep agent-scoped restrictions active when the runtime has no trusted
        // agent identity. Missing identity must not bypass a restriction.
        (Some(_), None) => true,
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
    Some(RateLimit {
        max_requests,
        window,
    })
}

fn check_rate_limit(
    policy_name: &str,
    credential_name: &str,
    limit_str: &str,
    parsed: RateLimit,
    rate_state: &mut RateState<'_>,
) -> Option<String> {
    let denial_reason = || {
        format!(
            "rate limit exceeded ({}) for policy '{}'",
            limit_str, policy_name
        )
    };

    match rate_state {
        RateState::Live(buckets) => {
            let bucket_key = format!("{}:{}", policy_name, credential_name);
            if let Ok(mut buckets) = buckets.lock() {
                let now = Instant::now();
                for bucket in buckets.values_mut() {
                    bucket
                        .timestamps
                        .retain(|timestamp| now.duration_since(*timestamp) < bucket.window);
                }
                buckets.retain(|_, bucket| !bucket.timestamps.is_empty());

                let bucket = buckets.entry(bucket_key).or_insert_with(|| RateBucket {
                    timestamps: Vec::new(),
                    window: parsed.window,
                });
                bucket.window = parsed.window;
                bucket
                    .timestamps
                    .retain(|timestamp| now.duration_since(*timestamp) < parsed.window);
                if bucket.timestamps.len() as u64 >= parsed.max_requests {
                    return Some(denial_reason());
                }
                bucket.timestamps.push(now);
            }
            None
        }
        RateState::Fresh(buckets, base_time) => {
            let bucket_key = format!("{}:{}", policy_name, credential_name);
            let bucket = buckets.entry(bucket_key).or_insert_with(|| RateBucket {
                timestamps: Vec::new(),
                window: parsed.window,
            });
            bucket.window = parsed.window;
            bucket
                .timestamps
                .retain(|timestamp| base_time.duration_since(*timestamp) < parsed.window);
            if bucket.timestamps.len() as u64 >= parsed.max_requests {
                return Some(denial_reason());
            }
            bucket.timestamps.push(*base_time);
            None
        }
    }
}

fn parse_time_window(window_str: &str) -> Option<(NaiveTime, NaiveTime)> {
    let parts: Vec<&str> = window_str.splitn(2, '-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = NaiveTime::parse_from_str(parts[0].trim(), "%H:%M").ok()?;
    let end = NaiveTime::parse_from_str(parts[1].trim(), "%H:%M").ok()?;
    Some((start, end))
}

fn check_time_window(policy_name: &str, window_str: &str, now: NaiveTime) -> Option<PolicyDenial> {
    let Some((start, end)) = parse_time_window(window_str) else {
        return Some(invalid_time_window_denial(policy_name));
    };

    let in_window = if start <= end {
        now >= start && now < end
    } else {
        now >= start || now < end
    };

    if !in_window {
        Some(PolicyDenial {
            policy_name: policy_name.to_string(),
            reason: format!(
                "current time {} outside allowed window {}",
                now.format("%H:%M"),
                window_str
            ),
        })
    } else {
        None
    }
}

fn deny_selectors_cover(earlier: &Policy, later: &Policy) -> bool {
    selector_covers(earlier.credential.as_deref(), later.credential.as_deref())
        && selector_covers(earlier.agent.as_deref(), later.agent.as_deref())
}

fn selector_covers(earlier: Option<&str>, later: Option<&str>) -> bool {
    match (earlier, later) {
        (None, _) => true,
        (Some("*"), _) => true,
        (Some(left), Some(right)) => left == right,
        (Some(_), None) => false,
    }
}

fn invalid_time_window_denial(policy_name: &str) -> PolicyDenial {
    PolicyDenial {
        policy_name: policy_name.to_string(),
        reason: "invalid time window configuration; request denied".to_string(),
    }
}

/// Returns the path to the policies TOML file.
pub fn policies_path() -> PathBuf {
    Vault::vault_dir().join("policies.toml")
}

pub(crate) fn parse_policy_config(content: &str) -> Result<PolicyConfig, PolicyInputError> {
    toml::from_str::<PolicyConfig>(content).map_err(|_| PolicyInputError::Parse)
}

pub(crate) fn parse_evaluation_time(value: &str) -> Result<DateTime<Local>, ()> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Local))
        .map_err(|_| ())
}

pub(crate) fn load_policy_config_from_path(path: &Path) -> Result<PolicyConfig, PolicyInputError> {
    let file = File::open(path).map_err(|_| PolicyInputError::Io)?;
    let metadata = file.metadata().map_err(|_| PolicyInputError::Io)?;
    if !metadata.is_file() {
        return Err(PolicyInputError::Io);
    }
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        return Err(PolicyInputError::TooLarge);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = file.take(MAX_POLICY_FILE_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyInputError::Io)?;
    if bytes.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(PolicyInputError::TooLarge);
    }
    let content = String::from_utf8(bytes).map_err(|_| PolicyInputError::InvalidUtf8)?;
    parse_policy_config(&content)
}

/// Reads and validates the policies TOML file, denying all credential use on failure.
pub fn load_policies_from_disk() -> PolicyConfig {
    let path = policies_path();
    if !path.exists() {
        return PolicyConfig { policy: Vec::new() };
    }
    match load_policy_config_from_path(&path) {
        Ok(config) => {
            let (effective_config, valid) = effective_policy_config(config);
            if !valid {
                tracing::warn!("Invalid policies.toml; denying credential use");
            }
            effective_config
        }
        Err(error) => {
            tracing::warn!("Failed to load policies.toml: {}", error);
            invalid_policy_config()
        }
    }
}

/// Validates policy fields whose string formats are enforced at request time.
pub fn validate_policy_config(config: &PolicyConfig) -> Result<(), String> {
    if config.policy.len() > MAX_POLICY_COUNT {
        return Err("policy count exceeds the runtime and simulation limit".to_string());
    }
    for policy in &config.policy {
        if let Some(rate_limit) = &policy.rate_limit
            && parse_rate_limit(rate_limit).is_none()
        {
            return Err("policy contains an invalid rate_limit".to_string());
        }
        if let Some(time_window) = &policy.time_window
            && parse_time_window(time_window).is_none()
        {
            return Err("policy contains an invalid time_window".to_string());
        }
    }
    Ok(())
}

pub(crate) fn effective_policy_config(config: PolicyConfig) -> (PolicyConfig, bool) {
    match validate_policy_config(&config) {
        Ok(()) => (config, true),
        Err(_) => (invalid_policy_config(), false),
    }
}

fn invalid_policy_config() -> PolicyConfig {
    PolicyConfig {
        policy: vec![Policy {
            name: "invalid-policy-config".to_string(),
            agent: None,
            credential: None,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_methods: Vec::new(),
            denied_paths: Vec::new(),
            allowed_paths: Vec::new(),
            rate_limit: None,
            time_window: None,
            deny: true,
        }],
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
    use chrono::TimeZone;

    fn test_engine(policies: Vec<Policy>) -> PolicyEngine {
        PolicyEngine::from_config(PolicyConfig { policy: policies })
    }

    fn empty_policy(name: &str) -> Policy {
        Policy {
            name: name.to_string(),
            agent: None,
            credential: None,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_methods: Vec::new(),
            denied_paths: Vec::new(),
            allowed_paths: Vec::new(),
            rate_limit: None,
            time_window: None,
            deny: false,
        }
    }

    fn request<'a>(credential_name: &'a str) -> PolicyRequest<'a> {
        PolicyRequest {
            credential_name,
            agent_name: None,
            host: "api.example.com",
            path: "/v1/data",
            method: "GET",
        }
    }

    fn local_at(hour: u32, minute: u32) -> DateTime<Local> {
        Local
            .with_ymd_and_hms(2026, 1, 2, hour, minute, 0)
            .single()
            .expect("test timestamp must be unambiguous")
    }

    #[test]
    fn no_policies_allows_all() {
        let engine = test_engine(vec![]);
        assert!(
            engine
                .evaluate("any-cred", None, "any.host", "/any/path", "GET")
                .is_none()
        );
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
        assert!(
            engine
                .evaluate("aws-dev", None, "aws.com", "/", "GET")
                .is_none()
        );
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
        assert!(
            engine
                .evaluate("cred", None, "host", "/admin/users", "GET")
                .is_some()
        );
        assert!(
            engine
                .evaluate("cred", None, "host", "/api/data", "GET")
                .is_none()
        );
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
        assert!(
            engine
                .evaluate("cred", None, "api.evil.com", "/", "GET")
                .is_some()
        );
        assert!(
            engine
                .evaluate("cred", None, "api.good.com", "/", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("cred", None, "API.EVIL.COM", "/", "GET")
                .is_some()
        );
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
        assert!(
            engine
                .evaluate("cred", None, "api.example.com", "/", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("cred", None, "other.com", "/", "GET")
                .is_some()
        );
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
        assert!(
            engine
                .evaluate("test-cred", None, "h", "/", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("test-cred", None, "h", "/", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("test-cred", None, "h", "/", "GET")
                .is_none()
        );
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
    fn invalid_policy_formats_fail_closed() {
        let invalid_time = test_engine(vec![Policy {
            name: "bad-time".into(),
            agent: None,
            credential: None,
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: None,
            time_window: Some("09:00-17:00 America/New_York".into()),
            deny: false,
        }]);
        assert!(
            invalid_time
                .evaluate("cred", None, "host", "/", "GET")
                .is_some()
        );

        let invalid_rate = test_engine(vec![Policy {
            name: "bad-rate".into(),
            agent: None,
            credential: None,
            allowed_hosts: vec![],
            denied_hosts: vec![],
            allowed_methods: vec![],
            denied_paths: vec![],
            allowed_paths: vec![],
            rate_limit: Some("not-a-rate".into()),
            time_window: None,
            deny: false,
        }]);
        assert!(
            invalid_rate
                .evaluate("cred", None, "host", "/", "GET")
                .is_some()
        );
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
        assert!(
            engine
                .evaluate("cred", Some("claude-code"), "h", "/", "POST")
                .is_some()
        );
        assert!(
            engine
                .evaluate("cred", Some("claude-code"), "h", "/", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("cred", Some("cursor"), "h", "/", "POST")
                .is_none()
        );
        assert!(engine.evaluate("cred", None, "h", "/", "POST").is_some());
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
        assert!(
            engine
                .evaluate("aws-prod", None, "h", "/", "POST")
                .is_some()
        );
        assert!(engine.evaluate("aws-dev", None, "h", "/", "POST").is_some());
        assert!(
            engine
                .evaluate("openai-key", None, "h", "/", "POST")
                .is_none()
        );
    }

    #[test]
    fn simulation_does_not_consume_live_rate_capacity() {
        let mut policy = empty_policy("limited");
        policy.credential = Some("test-cred".into());
        policy.rate_limit = Some("1/minute".into());
        let engine = test_engine(vec![policy]);

        let simulation = engine.simulate(request("test-cred"), local_at(12, 0));

        assert_eq!(simulation.decisive_policy_index, None);
        assert!(simulation.evaluations[0].rate_limit_checked);
        assert!(engine.rate_buckets.lock().expect("rate lock").is_empty());
        assert!(
            engine
                .evaluate("test-cred", None, "api.example.com", "/v1/data", "GET")
                .is_none()
        );
        assert!(
            engine
                .evaluate("test-cred", None, "api.example.com", "/v1/data", "GET")
                .is_some()
        );
    }

    #[test]
    fn simulation_preserves_ordered_rate_checks_in_local_state() {
        let mut first = empty_policy("same-bucket");
        first.rate_limit = Some("1/minute".into());
        let mut second = empty_policy("same-bucket");
        second.rate_limit = Some("1/minute".into());
        let engine = test_engine(vec![first, second]);

        let simulation = engine.simulate(request("cred"), local_at(12, 0));

        assert_eq!(simulation.decisive_policy_index, Some(1));
        assert!(
            engine
                .evaluate("cred", None, "api.example.com", "/v1/data", "GET")
                .is_some()
        );
        assert_eq!(engine.rate_buckets.lock().expect("rate lock").len(), 1);
    }

    #[test]
    fn simulation_and_runtime_share_injected_time_window_check() {
        let mut policy = empty_policy("business-hours");
        policy.time_window = Some("09:00-17:00".into());
        let engine = test_engine(vec![policy]);
        let inside = local_at(10, 0);
        let outside = local_at(18, 0);

        let inside_simulation = engine.simulate(request("cred"), inside);
        let inside_runtime = engine
            .evaluate_at(request("cred"), inside)
            .map(|denial| denial.reason);
        let outside_simulation = engine.simulate(request("cred"), outside);
        let outside_runtime = engine
            .evaluate_at(request("cred"), outside)
            .map(|denial| denial.reason);

        assert_eq!(inside_simulation.decisive_policy_index, None);
        assert_eq!(inside_runtime, None);
        assert_eq!(outside_simulation.decisive_policy_index, Some(0));
        assert_eq!(
            outside_runtime,
            Some("current time 18:00 outside allowed window 09:00-17:00".into())
        );
    }

    #[test]
    fn diagnostics_only_report_proven_shadow_rules() {
        let mut deny_all = empty_policy("deny-all");
        deny_all.deny = true;
        let mut later = empty_policy("later-rule");
        later.credential = Some("credential".into());
        let mut uncertain = empty_policy("uncertain-rule");
        uncertain.credential = Some("credential-*".into());
        let engine = test_engine(vec![deny_all, later, uncertain]);

        let simulation = engine.simulate(request("credential"), local_at(12, 0));

        let shadowed = simulation
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "shadowed_rule")
            .map(|diagnostic| diagnostic.policy_name.as_deref().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(shadowed, vec!["later-rule", "uncertain-rule"]);
        assert!(simulation.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != "shadowed_rule"
                || (diagnostic.related_policy_index == Some(0)
                    && diagnostic.related_policy_name.as_deref() == Some("deny-all"))
        }));
        assert!(
            simulation
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.proven)
        );
    }

    #[test]
    fn invalid_rule_diagnostics_share_runtime_denials() {
        let mut policy = empty_policy("invalid");
        policy.rate_limit = Some("not-a-rate".into());
        policy.time_window = Some("not-a-window".into());
        let engine = test_engine(vec![policy]);

        let simulation = engine.simulate(request("cred"), local_at(12, 0));

        assert_eq!(simulation.decisive_policy_index, Some(0));
        assert!(
            simulation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "invalid_rate_limit")
        );
        assert!(
            simulation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "invalid_time_window")
        );
    }

    #[test]
    fn oversized_policy_config_uses_effective_deny_all_config() {
        let config = PolicyConfig {
            policy: (0..=MAX_POLICY_COUNT)
                .map(|index| empty_policy(&format!("policy-{index}")))
                .collect(),
        };

        let (effective, valid) = effective_policy_config(config);

        assert!(!valid);
        assert_eq!(effective.policy.len(), 1);
        assert_eq!(effective.policy[0].name, "invalid-policy-config");
        assert!(effective.policy[0].deny);
    }
}
