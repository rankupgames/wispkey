mod common;

use common::{run_wispkey, write_private_test_file};
use serde_json::Value;

fn parse_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected JSON output: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn policy_explain_reports_ordered_matches_first_denial_and_untrusted_agent() {
    let directory = tempfile::tempdir().expect("temporary policy directory");
    let policy_path = directory.path().join("candidate.toml");
    write_private_test_file(
        &policy_path,
        r#"[[policy]]
name = "read-only"
credential = "aws-prod"
allowed_hosts = ["api.example.com"]
allowed_methods = ["GET"]
allowed_paths = ["/v1/**"]
rate_limit = "1/minute"

[[policy]]
name = "later-deny"
credential = "aws-prod"
deny = true

[[policy]]
name = "other-credential"
credential = "other-*"
deny = true
"#,
    );

    let output = run_wispkey(
        directory.path(),
        &[
            "policy",
            "explain",
            "--format",
            "json",
            "--policy-file",
            policy_path.to_str().expect("policy path"),
            "--credential",
            "aws-prod",
            "--host",
            "api.example.com",
            "--path",
            "/v1/data",
            "--method",
            "POST",
            "--agent",
            "claude-code",
            "--at",
            "2026-09-05T14:30:00Z",
        ],
    );

    assert!(
        output.status.success(),
        "explain failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_json(&output);

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["mode"], "single");
    assert_eq!(value["decision"], "deny");
    assert_eq!(value["decisive_policy"]["index"], 0);
    assert!(
        value["decisive_policy"]["reason"]
            .as_str()
            .expect("decisive reason")
            .contains("method")
    );
    let matching = value["matching_policies"].as_array().expect("matches");
    assert_eq!(matching.len(), 2);
    assert_eq!(matching[0]["name"], "read-only");
    assert_eq!(matching[1]["name"], "later-deny");
    assert_eq!(value["agent_identity"]["trust"], "untrusted_input");
    assert_eq!(value["agent_identity"]["trusted_for_production"], false);
    assert_eq!(value["rate_limit"]["state"], "fresh_offline");
    assert_eq!(value["rate_limit"]["capacity_consumed"], false);
    assert_eq!(value["rate_limit"]["live_capacity_measured"], false);
    assert!(
        value["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "agent_identity_untrusted")
    );
    assert!(!directory.path().join("vault.db").exists());
}

#[test]
fn invalid_policy_fails_closed_for_installed_candidate_and_batch_simulation() {
    let directory = tempfile::tempdir().expect("temporary policy directory");
    let candidate_path = directory.path().join("candidate.toml");
    let installed_path = directory.path().join("policies.toml");
    let cases_path = directory.path().join("cases.json");
    let invalid_marker = "INVALID_RATE_MARKER";
    let policy = format!(
        "[[policy]]\nname = \"bad-rate\"\ncredential = \"other-credential\"\nrate_limit = \"{invalid_marker}\"\n\n[[policy]]\nname = \"target-allow\"\ncredential = \"target\"\nallowed_methods = [\"GET\"]\n"
    );
    write_private_test_file(&candidate_path, &policy);
    write_private_test_file(
        &cases_path,
        r#"{
  "schema_version": 1,
  "cases": [
    {
      "name": "invalid-config-must-deny",
      "request": {
        "credential": "target",
        "host": "api.example.com",
        "path": "/v1/data",
        "method": "GET"
      },
      "expected": "allow"
    }
  ]
}
"#,
    );

    let candidate = run_wispkey(
        directory.path(),
        &[
            "policy",
            "explain",
            "--format",
            "json",
            "--policy-file",
            candidate_path.to_str().expect("candidate path"),
            "--credential",
            "target",
            "--host",
            "api.example.com",
            "--path",
            "/v1/data",
            "--method",
            "GET",
        ],
    );
    assert!(candidate.status.success());
    assert_invalid_policy_output(&parse_json(&candidate), invalid_marker);

    write_private_test_file(&installed_path, &policy);
    let installed = run_wispkey(
        directory.path(),
        &[
            "policy",
            "explain",
            "--format",
            "json",
            "--credential",
            "target",
            "--host",
            "api.example.com",
            "--path",
            "/v1/data",
            "--method",
            "GET",
        ],
    );
    assert!(installed.status.success());
    assert_invalid_policy_output(&parse_json(&installed), invalid_marker);

    let batch = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--policy-file",
            candidate_path.to_str().expect("candidate path"),
            "--cases",
            cases_path.to_str().expect("cases path"),
        ],
    );
    assert!(!batch.status.success());
    let batch_json = parse_json(&batch);
    assert_eq!(batch_json["passed"], false);
    assert_eq!(batch_json["mismatches"], 1);
    assert_eq!(batch_json["results"][0]["decision"], "deny");
    assert_eq!(batch_json["results"][0]["case"]["passed"], false);
    assert_invalid_policy_output(&batch_json["results"][0], invalid_marker);
}

fn assert_invalid_policy_output(value: &Value, invalid_marker: &str) {
    assert_eq!(value["decision"], "deny");
    assert_eq!(value["decisive_policy"]["name"], "invalid-policy-config");
    assert!(
        value["decision_reason"]
            .as_str()
            .expect("decision reason")
            .contains("invalid-policy-config")
    );
    assert!(
        value["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|diagnostic| {
                diagnostic["code"] == "invalid_rate_limit"
                    && diagnostic["policy_index"] == 0
                    && diagnostic["policy_name"] == "bad-rate"
            })
    );
    let output = value.to_string();
    assert!(!output.contains(invalid_marker));
}

#[test]
fn policy_test_cases_pass_and_mismatch_returns_nonzero() {
    let directory = tempfile::tempdir().expect("temporary policy directory");
    let policy_path = directory.path().join("candidate.toml");
    let cases_path = directory.path().join("cases.json");
    write_private_test_file(
        &policy_path,
        r#"[[policy]]
name = "read-only"
credential = "aws-prod"
allowed_methods = ["GET"]
"#,
    );
    write_private_test_file(
        &cases_path,
        r#"{
  "schema_version": 1,
  "cases": [
    {
      "name": "read",
      "request": {
        "credential": "aws-prod",
        "host": "api.example.com",
        "path": "/v1/data",
        "method": "GET"
      },
      "expected": "allow"
    },
    {
      "name": "write",
      "request": {
        "credential": "aws-prod",
        "host": "api.example.com",
        "path": "/v1/data",
        "method": "POST"
      },
      "expected": "deny"
    }
  ]
}
"#,
    );

    let passing = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--policy-file",
            policy_path.to_str().expect("policy path"),
            "--cases",
            cases_path.to_str().expect("cases path"),
            "--at",
            "2026-09-05T14:30:00Z",
        ],
    );
    assert!(passing.status.success());
    let passing_json = parse_json(&passing);
    assert_eq!(passing_json["passed"], true);
    assert_eq!(passing_json["mismatches"], 0);
    assert_eq!(
        passing_json["results"].as_array().expect("results").len(),
        2
    );
    assert_eq!(
        passing_json["results"][0]["decision_reason"],
        "no policy denied the request"
    );

    write_private_test_file(
        &cases_path,
        &std::fs::read_to_string(&cases_path)
            .expect("cases content")
            .replace("\"expected\": \"deny\"", "\"expected\": \"allow\""),
    );
    let failing = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--policy-file",
            policy_path.to_str().expect("policy path"),
            "--cases",
            cases_path.to_str().expect("cases path"),
        ],
    );
    assert!(!failing.status.success());
    let failing_json = parse_json(&failing);
    assert_eq!(failing_json["passed"], false);
    assert_eq!(failing_json["mismatches"], 1);
}

#[test]
fn policy_input_errors_are_bounded_and_redacted() {
    let directory = tempfile::tempdir().expect("temporary policy directory");
    let policy_path = directory.path().join("malformed.toml");
    let cases_path = directory.path().join("malformed.json");
    let oversized_path = directory.path().join("oversized.toml");
    let too_many_cases_path = directory.path().join("too-many-cases.json");
    let policy_secret_marker = "POLICY_SECRET_MARKER";
    let case_secret_marker = "CASE_SECRET_MARKER";
    write_private_test_file(
        &policy_path,
        &format!("[[policy]\nname = \"{policy_secret_marker}\"\n"),
    );
    write_private_test_file(
        &cases_path,
        &format!("{{\"schema_version\":1,\"cases\":[{{\"request\":\"{case_secret_marker}"),
    );
    write_private_test_file(&oversized_path, &"x".repeat(1024 * 1024 + 1));
    let case = r#"{"request":{"credential":"cred","host":"host","path":"/","method":"GET"},"expected":"allow"}"#;
    let cases = (0..257).map(|_| case).collect::<Vec<_>>().join(",");
    write_private_test_file(
        &too_many_cases_path,
        &format!(r#"{{"schema_version":1,"cases":[{cases}]}}"#),
    );

    let policy_output = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--policy-file",
            policy_path.to_str().expect("policy path"),
            "--credential",
            "cred",
            "--host",
            "host",
            "--path",
            "/",
            "--method",
            "GET",
        ],
    );
    assert!(!policy_output.status.success());
    let policy_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&policy_output.stdout),
        String::from_utf8_lossy(&policy_output.stderr)
    );
    assert!(!policy_combined.contains(policy_secret_marker));
    assert!(policy_combined.contains("policy input is not valid TOML"));

    let cases_output = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--cases",
            cases_path.to_str().expect("cases path"),
        ],
    );
    assert!(!cases_output.status.success());
    let cases_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&cases_output.stdout),
        String::from_utf8_lossy(&cases_output.stderr)
    );
    assert!(!cases_combined.contains(case_secret_marker));
    assert!(cases_combined.contains("case input is not valid versioned JSON"));

    let oversized_output = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--policy-file",
            oversized_path.to_str().expect("oversized path"),
        ],
    );
    assert!(!oversized_output.status.success());
    let oversized_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&oversized_output.stdout),
        String::from_utf8_lossy(&oversized_output.stderr)
    );
    assert!(oversized_combined.contains("policy input exceeds the size limit"));

    let too_many_cases_output = run_wispkey(
        directory.path(),
        &[
            "policy",
            "test",
            "--format",
            "json",
            "--cases",
            too_many_cases_path.to_str().expect("too many cases path"),
        ],
    );
    assert!(!too_many_cases_output.status.success());
    let too_many_cases_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&too_many_cases_output.stdout),
        String::from_utf8_lossy(&too_many_cases_output.stderr)
    );
    assert!(too_many_cases_combined.contains("case input contains too many cases"));
}
