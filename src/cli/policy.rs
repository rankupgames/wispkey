use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use chrono::{DateTime, Local};
use serde::Deserialize;

use super::shared::{json_output, print_json};
use crate::policy::{
    MAX_POLICY_FILE_BYTES, PolicyConfig, PolicyDiagnostic, PolicyEngine, PolicyInputError,
    PolicyOutcome, PolicyRequest, PolicySimulation, PolicyTrace,
};

const CASE_FILE_SCHEMA_VERSION: u32 = 1;
const MAX_CASE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CASE_COUNT: usize = 256;
const OUTPUT_SCHEMA_VERSION: u32 = 1;

pub struct PolicyTestArgs<'a> {
    pub credential: Option<&'a str>,
    pub host: Option<&'a str>,
    pub path: Option<&'a str>,
    pub method: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub policy_file: Option<&'a str>,
    pub at: Option<&'a str>,
    pub cases: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct CaseFile {
    schema_version: u32,
    cases: Vec<PolicyCase>,
}

#[derive(Debug, Deserialize)]
struct PolicyCase {
    #[serde(default)]
    name: Option<String>,
    request: CaseRequest,
    expected: ExpectedDecision,
}

#[derive(Debug, Deserialize)]
struct CaseRequest {
    credential: String,
    host: String,
    path: String,
    method: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExpectedDecision {
    Allow,
    Deny,
}

#[derive(Clone, Copy)]
enum CommandMode {
    Test,
    Explain,
}

impl CommandMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Explain => "explain",
        }
    }
}

struct PolicySource {
    kind: &'static str,
    path: String,
}

struct RequestInput<'a> {
    credential: &'a str,
    host: &'a str,
    path: &'a str,
    method: &'a str,
    agent: Option<&'a str>,
}

struct SimulationInput<'a> {
    request: RequestInput<'a>,
    at_input: Option<&'a str>,
}

pub async fn handle_policy_test(args: PolicyTestArgs<'_>) {
    run_policy_command(args, CommandMode::Test).await;
}

pub async fn handle_policy_explain(args: PolicyTestArgs<'_>) {
    run_policy_command(args, CommandMode::Explain).await;
}

async fn run_policy_command(args: PolicyTestArgs<'_>, mode: CommandMode) {
    let output_mode = if args.cases.is_some() {
        "cases"
    } else {
        "single"
    };
    let (engine, source, diagnostics) = match load_policy_engine(args.policy_file) {
        Ok(value) => value,
        Err(message) => exit_with_error(mode, output_mode, "policy_input", message),
    };

    if let Some(cases_path) = args.cases {
        if !matches!(mode, CommandMode::Test) {
            exit_with_error(
                mode,
                output_mode,
                "invalid_arguments",
                "--cases is supported only by `policy test`",
            );
        }
        if has_single_request_input(&args) {
            exit_with_error(
                mode,
                output_mode,
                "invalid_arguments",
                "--cases cannot be combined with single-request options",
            );
        }

        let case_file = match read_case_file(cases_path) {
            Ok(file) => file,
            Err(message) => exit_with_error(mode, output_mode, "case_input", message),
        };
        run_cases(
            &engine,
            &source,
            &diagnostics,
            cases_path,
            args.at,
            case_file,
            mode,
        );
        return;
    }

    let request = match required_request(&args) {
        Ok(request) => request,
        Err(message) => exit_with_error(mode, output_mode, "invalid_arguments", message),
    };
    let evaluated_at = match parse_requested_time(args.at) {
        Ok(timestamp) => timestamp,
        Err(message) => exit_with_error(mode, output_mode, "invalid_time", message),
    };
    let simulation = engine.simulate_with_diagnostics(
        PolicyRequest {
            credential_name: request.credential,
            agent_name: request.agent,
            host: request.host,
            path: request.path,
            method: request.method,
        },
        evaluated_at,
        &diagnostics,
    );
    let input = SimulationInput {
        request,
        at_input: args.at,
    };

    if json_output() {
        print_json(single_result_json(mode, &source, &input, &simulation));
    } else {
        print_text_result(mode, &source, &input, &simulation);
    }
}

fn load_policy_engine(
    policy_file: Option<&str>,
) -> Result<(PolicyEngine, PolicySource, Vec<PolicyDiagnostic>), &'static str> {
    match policy_file {
        Some(path) if path == "-" => {
            let content = read_bounded_text(path, MAX_POLICY_FILE_BYTES)
                .map_err(|_| "could not read candidate policy input")?;
            let config =
                crate::policy::parse_policy_config(&content).map_err(policy_input_error_message)?;
            let diagnostics = crate::policy::policy_diagnostics(&config);
            let (effective_config, _) = crate::policy::effective_policy_config(config);
            Ok((
                PolicyEngine::from_config(effective_config),
                PolicySource {
                    kind: "candidate",
                    path: "-".to_string(),
                },
                diagnostics,
            ))
        }
        Some(path) => {
            let config = crate::policy::load_policy_config_from_path(Path::new(path))
                .map_err(policy_input_error_message)?;
            let diagnostics = crate::policy::policy_diagnostics(&config);
            let (effective_config, _) = crate::policy::effective_policy_config(config);
            Ok((
                PolicyEngine::from_config(effective_config),
                PolicySource {
                    kind: "candidate",
                    path: path.to_string(),
                },
                diagnostics,
            ))
        }
        None => {
            let path = crate::policy::policies_path();
            let config = if path.exists() {
                crate::policy::load_policy_config_from_path(&path)
                    .map_err(policy_input_error_message)?
            } else {
                PolicyConfig { policy: Vec::new() }
            };
            let diagnostics = crate::policy::policy_diagnostics(&config);
            let (effective_config, _) = crate::policy::effective_policy_config(config);
            Ok((
                PolicyEngine::from_config(effective_config),
                PolicySource {
                    kind: "installed",
                    path: path.display().to_string(),
                },
                diagnostics,
            ))
        }
    }
}

fn policy_input_error_message(error: PolicyInputError) -> &'static str {
    match error {
        PolicyInputError::Io => "could not read policy input",
        PolicyInputError::TooLarge => "policy input exceeds the size limit",
        PolicyInputError::InvalidUtf8 => "policy input is not valid UTF-8",
        PolicyInputError::Parse => "policy input is not valid TOML",
    }
}

fn required_request<'a>(args: &'a PolicyTestArgs<'a>) -> Result<RequestInput<'a>, &'static str> {
    match (args.credential, args.host, args.path, args.method) {
        (Some(credential), Some(host), Some(path), Some(method)) => Ok(RequestInput {
            credential,
            host,
            path,
            method,
            agent: args.agent,
        }),
        _ => Err("single-request mode requires --credential, --host, --path, and --method"),
    }
}

fn has_single_request_input(args: &PolicyTestArgs<'_>) -> bool {
    args.credential.is_some()
        || args.host.is_some()
        || args.path.is_some()
        || args.method.is_some()
        || args.agent.is_some()
}

fn parse_requested_time(value: Option<&str>) -> Result<DateTime<Local>, &'static str> {
    match value {
        Some(value) => crate::policy::parse_evaluation_time(value)
            .map_err(|_| "--at must be an RFC3339 timestamp with an explicit offset"),
        None => Ok(Local::now()),
    }
}

fn read_case_file(path: &str) -> Result<CaseFile, &'static str> {
    let content =
        read_bounded_text(path, MAX_CASE_FILE_BYTES).map_err(|_| "could not read case input")?;
    let case_file = serde_json::from_str::<CaseFile>(&content)
        .map_err(|_| "case input is not valid versioned JSON")?;
    if case_file.schema_version != CASE_FILE_SCHEMA_VERSION {
        return Err("unsupported case input schema version");
    }
    if case_file.cases.is_empty() {
        return Err("case input must contain at least one case");
    }
    if case_file.cases.len() > MAX_CASE_COUNT {
        return Err("case input contains too many cases");
    }
    Ok(case_file)
}

fn read_bounded_text(path: &str, max_bytes: u64) -> io::Result<String> {
    let mut bytes = Vec::new();
    if path == "-" {
        io::stdin().take(max_bytes + 1).read_to_end(&mut bytes)?;
    } else {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input too large",
            ));
        }
        file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input too large",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not UTF-8"))
}

fn run_cases(
    engine: &PolicyEngine,
    source: &PolicySource,
    diagnostics: &[PolicyDiagnostic],
    cases_path: &str,
    at_override: Option<&str>,
    case_file: CaseFile,
    mode: CommandMode,
) {
    let mut results = Vec::with_capacity(case_file.cases.len());
    let mut mismatches = 0;

    for (index, case) in case_file.cases.iter().enumerate() {
        let at_input = case.request.at.as_deref().or(at_override);
        let evaluated_at = match parse_requested_time(at_input) {
            Ok(timestamp) => timestamp,
            Err(message) => exit_with_error(mode, "cases", "invalid_time", message),
        };
        let request = RequestInput {
            credential: &case.request.credential,
            host: &case.request.host,
            path: &case.request.path,
            method: &case.request.method,
            agent: case.request.agent.as_deref(),
        };
        let simulation = engine.simulate_with_diagnostics(
            PolicyRequest {
                credential_name: request.credential,
                agent_name: request.agent,
                host: request.host,
                path: request.path,
                method: request.method,
            },
            evaluated_at,
            diagnostics,
        );
        let input = SimulationInput { request, at_input };
        let expected = expected_decision(&case.expected);
        let actual = actual_decision(&simulation);
        let passed = expected == actual;
        if !passed {
            mismatches += 1;
        }

        let mut result = single_result_json(mode, source, &input, &simulation);
        if let Some(object) = result.as_object_mut() {
            object.insert(
                "case".to_string(),
                serde_json::json!({
                    "index": index,
                    "name": case.name.as_deref().unwrap_or(""),
                    "expected": expected,
                    "actual": actual,
                    "passed": passed,
                }),
            );
        }
        results.push(result);
    }

    if json_output() {
        print_json(serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "command": mode.as_str(),
            "mode": "cases",
            "source": source_json(source),
            "case_file": {
                "path": cases_path,
                "schema_version": CASE_FILE_SCHEMA_VERSION,
                "count": results.len(),
            },
            "passed": mismatches == 0,
            "mismatches": mismatches,
            "results": results,
            "rate_limit": rate_limit_json(),
        }));
    } else {
        println!(
            "Policy test cases: {} passed, {} mismatched",
            results.len() - mismatches,
            mismatches
        );
        for result in &results {
            let case = &result["case"];
            println!(
                "  {}: {} (expected {}, got {})",
                case["name"]
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .unwrap_or("case"),
                if case["passed"].as_bool().unwrap_or(false) {
                    "PASS"
                } else {
                    "FAIL"
                },
                case["expected"].as_str().unwrap_or("unknown"),
                case["actual"].as_str().unwrap_or("unknown")
            );
        }
    }

    if mismatches > 0 {
        std::process::exit(1);
    }
}

fn expected_decision(expected: &ExpectedDecision) -> &'static str {
    match expected {
        ExpectedDecision::Allow => "allow",
        ExpectedDecision::Deny => "deny",
    }
}

fn actual_decision(simulation: &PolicySimulation) -> &'static str {
    if simulation.decisive_policy_index.is_some() {
        "deny"
    } else {
        "allow"
    }
}

fn decision_reason(simulation: &PolicySimulation) -> &str {
    simulation
        .decisive_policy_index
        .and_then(|index| {
            simulation
                .evaluations
                .iter()
                .find(|trace| trace.index == index)
        })
        .and_then(|trace| trace.reason.as_deref())
        .unwrap_or("no policy denied the request")
}

fn single_result_json(
    mode: CommandMode,
    source: &PolicySource,
    input: &SimulationInput<'_>,
    simulation: &PolicySimulation,
) -> serde_json::Value {
    let decisive = simulation.decisive_policy_index.and_then(|index| {
        simulation
            .evaluations
            .iter()
            .find(|trace| trace.index == index)
    });
    let evaluations = simulation
        .evaluations
        .iter()
        .map(trace_json)
        .collect::<Vec<_>>();
    let matching_policies = simulation
        .evaluations
        .iter()
        .filter(|trace| trace.matched)
        .map(trace_json)
        .collect::<Vec<_>>();
    let mut diagnostics = simulation
        .diagnostics
        .iter()
        .map(diagnostic_json)
        .collect::<Vec<_>>();
    diagnostics.push(agent_diagnostic(input.request.agent));

    serde_json::json!({
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "command": mode.as_str(),
        "mode": "single",
        "source": source_json(source),
        "request": {
            "credential": input.request.credential,
            "host": input.request.host,
            "path": input.request.path,
            "method": input.request.method,
            "agent": input.request.agent,
        },
        "evaluation_time": {
            "input": input.at_input,
            "local": simulation.evaluated_at.to_rfc3339(),
            "local_clock": simulation.evaluated_at.format("%H:%M").to_string(),
            "source": if input.at_input.is_some() { "injected" } else { "current_local_time" },
            "semantics": "time_window uses the machine local clock",
        },
        "agent_identity": agent_identity_json(input.request.agent),
        "decision": actual_decision(simulation),
        "decision_reason": decision_reason(simulation),
        "matching_policies": matching_policies,
        "evaluations": evaluations,
        "decisive_policy": decisive.map(decisive_policy_json),
        "diagnostics": diagnostics,
        "rate_limit": rate_limit_json_with_evaluations(&simulation.evaluations),
    })
}

fn source_json(source: &PolicySource) -> serde_json::Value {
    serde_json::json!({
        "kind": source.kind,
        "path": source.path,
    })
}

fn trace_json(trace: &PolicyTrace) -> serde_json::Value {
    let outcome = match trace.outcome {
        PolicyOutcome::Skipped => "skipped",
        PolicyOutcome::Allowed => "allow",
        PolicyOutcome::Denied => "deny",
    };
    serde_json::json!({
        "index": trace.index,
        "name": trace.name,
        "matched": trace.matched,
        "outcome": outcome,
        "reason": trace.reason,
        "rate_limit_checked": trace.rate_limit_checked,
    })
}

fn decisive_policy_json(trace: &PolicyTrace) -> serde_json::Value {
    serde_json::json!({
        "index": trace.index,
        "name": trace.name,
        "reason": trace.reason,
    })
}

fn diagnostic_json(diagnostic: &crate::policy::PolicyDiagnostic) -> serde_json::Value {
    serde_json::json!({
        "code": diagnostic.code,
        "severity": diagnostic.severity,
        "policy_index": diagnostic.policy_index,
        "policy_name": diagnostic.policy_name,
        "message": diagnostic.message,
        "proven": diagnostic.proven,
        "related_policy_index": diagnostic.related_policy_index,
        "related_policy_name": diagnostic.related_policy_name,
    })
}

fn agent_identity_json(agent: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "provided": agent.is_some(),
        "value": agent,
        "trust": if agent.is_some() { "untrusted_input" } else { "missing" },
        "trusted_for_production": false,
        "matching_semantics": "canonical_runtime_policy_matching",
        "proxy_identity": "absent_on_current_proxy_path",
        "provided_label_may_differ_from_proxy": agent.is_some(),
    })
}

fn agent_diagnostic(agent: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "code": if agent.is_some() { "agent_identity_untrusted" } else { "agent_identity_missing" },
        "severity": "warning",
        "policy_index": null,
        "policy_name": null,
        "message": if agent.is_some() {
            "--agent is used only as untrusted what-if input and is not a trusted production identity"
        } else {
            "no agent identity was supplied; simulation does not establish a production identity"
        },
        "proven": true,
    })
}

fn rate_limit_json() -> serde_json::Value {
    serde_json::json!({
        "state": "fresh_offline",
        "capacity_consumed": false,
        "simulation_state": "fresh_local_non_live",
        "live_capacity_measured": false,
        "note": "rate limits use empty simulation state; live proxy capacity is not measured",
    })
}

fn rate_limit_json_with_evaluations(evaluations: &[PolicyTrace]) -> serde_json::Value {
    let mut value = rate_limit_json();
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "policies_checked".to_string(),
            serde_json::Value::from(
                evaluations
                    .iter()
                    .filter(|trace| trace.rate_limit_checked)
                    .count() as u64,
            ),
        );
    }
    value
}

fn print_text_result(
    mode: CommandMode,
    source: &PolicySource,
    input: &SimulationInput<'_>,
    simulation: &PolicySimulation,
) {
    println!(
        "Policy {}: {}",
        mode.as_str(),
        actual_decision(simulation).to_uppercase()
    );
    println!(
        "  request: {} {} {} with {}",
        input.request.method, input.request.host, input.request.path, input.request.credential
    );
    println!("  policy source: {} ({})", source.path, source.kind);
    println!("  decision reason: {}", decision_reason(simulation));
    println!(
        "  agent identity: {}",
        input
            .request
            .agent
            .map(|agent| format!("{} (untrusted input)", agent))
            .unwrap_or_else(|| "missing (not a production identity)".to_string())
    );
    println!(
        "  evaluation time: {} local ({})",
        simulation.evaluated_at.format("%Y-%m-%dT%H:%M:%S%:z"),
        if input.at_input.is_some() {
            "injected"
        } else {
            "current"
        }
    );
    println!("  rate limits: fresh offline local state; no live capacity consumed");
    println!("  matching policies:");
    for trace in simulation.evaluations.iter().filter(|trace| trace.matched) {
        println!(
            "    [{}] {} -> {}{}",
            trace.index,
            trace.name,
            match trace.outcome {
                PolicyOutcome::Allowed => "allow",
                PolicyOutcome::Denied => "deny",
                PolicyOutcome::Skipped => "skipped",
            },
            trace
                .reason
                .as_deref()
                .map(|reason| format!(": {reason}"))
                .unwrap_or_default()
        );
    }
    if let Some(index) = simulation.decisive_policy_index {
        if let Some(trace) = simulation
            .evaluations
            .iter()
            .find(|trace| trace.index == index)
        {
            println!(
                "  decisive policy: [{}] {}: {}",
                index,
                trace.name,
                trace.reason.as_deref().unwrap_or("denied")
            );
        }
    } else {
        println!("  decisive policy: none");
    }
    for diagnostic in &simulation.diagnostics {
        if let (Some(index), Some(name)) = (
            diagnostic.related_policy_index,
            diagnostic.related_policy_name.as_deref(),
        ) {
            println!(
                "  diagnostic: {} [{}] {} (related policy [{}] {})",
                diagnostic.severity, diagnostic.code, diagnostic.message, index, name
            );
        } else {
            println!(
                "  diagnostic: {} [{}] {}",
                diagnostic.severity, diagnostic.code, diagnostic.message
            );
        }
    }
}

fn exit_with_error(
    mode: CommandMode,
    output_mode: &'static str,
    code: &'static str,
    message: &'static str,
) -> ! {
    if json_output() {
        print_json(serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "command": mode.as_str(),
            "mode": output_mode,
            "error": {
                "code": code,
                "message": message,
            },
        }));
    } else {
        eprintln!("Error: {message}");
    }
    std::process::exit(1)
}

/// Lists the installed policies without opening or unlocking the vault.
pub async fn handle_policy_list() {
    let config = crate::policy::load_policies_from_disk();
    if config.policy.is_empty() {
        println!("No policies configured.");
        println!("Run `wispkey policy init` to create a template policies.toml");
        return;
    }
    println!(
        "{} policies loaded from {}",
        config.policy.len(),
        crate::policy::policies_path().display()
    );
    println!();
    for policy in &config.policy {
        println!("  [{}]", policy.name);
        if let Some(ref cred) = policy.credential {
            println!("    credential: {}", cred);
        }
        if let Some(ref agent) = policy.agent {
            println!("    agent: {}", agent);
        }
        if !policy.allowed_methods.is_empty() {
            println!("    allowed_methods: {}", policy.allowed_methods.join(", "));
        }
        if !policy.allowed_hosts.is_empty() {
            println!("    allowed_hosts: {}", policy.allowed_hosts.join(", "));
        }
        if !policy.denied_hosts.is_empty() {
            println!("    denied_hosts: {}", policy.denied_hosts.join(", "));
        }
        if !policy.denied_paths.is_empty() {
            println!("    denied_paths: {}", policy.denied_paths.join(", "));
        }
        if !policy.allowed_paths.is_empty() {
            println!("    allowed_paths: {}", policy.allowed_paths.join(", "));
        }
        if let Some(ref rl) = policy.rate_limit {
            println!("    rate_limit: {}", rl);
        }
        if let Some(ref tw) = policy.time_window {
            println!("    time_window: {}", tw);
        }
        if policy.deny {
            println!("    deny: true");
        }
        println!();
    }
}

/// Writes a commented `policies.toml` template when the file does not exist.
pub async fn handle_policy_init() {
    let path = crate::policy::policies_path();
    if path.exists() {
        println!("Policies file already exists at {}", path.display());
        return;
    }
    let template = r#"# WispKey Policy Configuration
# Each [[policy]] block defines an access rule evaluated on every proxied request.
# Policies are evaluated in order; the first match that denies wins.

# Example: restrict production AWS credentials to GET-only
# [[policy]]
# name = "restrict-aws-prod"
# credential = "aws-prod"
# allowed_methods = ["GET"]
# denied_paths = ["/admin*", "/delete*"]
# rate_limit = "10/minute"

# Example: block all access to a credential
# [[policy]]
# name = "block-deprecated"
# credential = "old-api-key"
# deny = true

# Example: time-windowed access
# [[policy]]
# name = "business-hours-only"
# credential = "billing-api"
# time_window = "09:00-17:00"
"#;
    std::fs::write(&path, template).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
    println!("Created policies template at {}", path.display());
}

/// Parses `policies.toml` and reports success or TOML validation errors.
pub async fn handle_policy_check() {
    let path = crate::policy::policies_path();
    if !path.exists() {
        eprintln!("No policies file at {}", path.display());
        eprintln!("Run `wispkey policy init` to create one.");
        std::process::exit(1);
    }
    let config = crate::policy::load_policy_config_from_path(&path).unwrap_or_else(|error| {
        eprintln!("INVALID -- {}", policy_input_error_message(error));
        std::process::exit(1);
    });
    match crate::policy::validate_policy_config(&config) {
        Ok(()) => {
            println!(
                "OK -- {} policies parsed from {}",
                config.policy.len(),
                path.display()
            );
            for policy in &config.policy {
                println!("  [{}] ok", policy.name);
            }
        }
        Err(_) => {
            eprintln!("INVALID -- policy rule validation failed");
            std::process::exit(1);
        }
    }
}
