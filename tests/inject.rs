#![cfg(unix)]

mod common;

use common::*;

const INJECT_SECRET_ONE_NAME: &str = "inject-secret-one";
const INJECT_SECRET_ONE_VALUE: &str = "inject-secret-value-one";
const INJECT_SECRET_TWO_NAME: &str = "inject-secret-two";
const INJECT_SECRET_TWO_VALUE: &str = "inject-secret-value-two";

fn add_inject_secrets(vault_dir: &std::path::Path) {
    for (name, value) in [
        (INJECT_SECRET_ONE_NAME, INJECT_SECRET_ONE_VALUE),
        (INJECT_SECRET_TWO_NAME, INJECT_SECRET_TWO_VALUE),
    ] {
        run_wispkey_json(
            vault_dir,
            &[
                "--format", "json", "add", name, "--type", "api_key", "--value", value,
            ],
        );
    }
}

#[test]
fn inject_renders_template_to_owner_only_file_and_audits_without_values() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let template_dir = tempfile::tempdir().expect("template dir");
    init_vault(vault_dir.path());
    add_inject_secrets(vault_dir.path());

    let input = template_dir.path().join("template.txt");
    let output = template_dir.path().join("rendered.env");
    std::fs::write(
        &input,
        "one={{cred:inject-secret-one}}\ntwo={{ cred:inject-secret-two }}\nkeep={{ not-a-credential }}\n",
    )
    .expect("write template");
    let input_arg = input.to_string_lossy().to_string();
    let output_arg = output.to_string_lossy().to_string();

    let result = run_wispkey(
        vault_dir.path(),
        &["inject", "-i", &input_arg, "-o", &output_arg],
    );
    assert!(
        result.status.success(),
        "inject failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(INJECT_SECRET_ONE_VALUE));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(INJECT_SECRET_TWO_VALUE));

    let rendered = std::fs::read_to_string(&output).expect("read rendered output");
    assert_eq!(
        rendered,
        format!(
            "one={INJECT_SECRET_ONE_VALUE}\ntwo={INJECT_SECRET_TWO_VALUE}\nkeep={{{{ not-a-credential }}}}\n"
        )
    );
    assert_eq!(file_mode(&output), 0o600);

    let log = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "log", "--last", "10"],
    );
    let entries = log["entries"].as_array().expect("entries array");
    let inject_entry = entries
        .iter()
        .find(|entry| entry["event_type"] == "CredentialInject")
        .expect("CredentialInject audit entry");
    let credential_names = inject_entry["credential_name"]
        .as_str()
        .expect("credential names");
    assert!(credential_names.contains(INJECT_SECRET_ONE_NAME));
    assert!(credential_names.contains(INJECT_SECRET_TWO_NAME));
    assert_eq!(inject_entry["target_path"], output_arg);
    assert_eq!(inject_entry["http_method"], "inject");
    let raw_log = serde_json::to_string(&log).expect("log json");
    assert!(!raw_log.contains(INJECT_SECRET_ONE_VALUE));
    assert!(!raw_log.contains(INJECT_SECRET_TWO_VALUE));
}

#[test]
fn inject_missing_credential_fails_without_writing_output() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    let template_dir = tempfile::tempdir().expect("template dir");
    init_vault(vault_dir.path());

    let input = template_dir.path().join("template.txt");
    let output = template_dir.path().join("rendered.env");
    std::fs::write(&input, "missing={{ cred:missing-secret }}\n").expect("write template");
    let input_arg = input.to_string_lossy().to_string();
    let output_arg = output.to_string_lossy().to_string();

    let result = run_wispkey(
        vault_dir.path(),
        &["inject", "-i", &input_arg, "-o", &output_arg],
    );
    assert!(!result.status.success());
    assert!(!output.exists(), "output should not have been written");
}
