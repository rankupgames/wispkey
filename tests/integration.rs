use std::process::Command;

fn wispkey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wispkey"))
}

#[test]
fn version_flag_prints_version() {
    let output = wispkey_bin().arg("--version").output().expect("failed to run wispkey");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wispkey"), "expected version output, got: {stdout}");
}

#[test]
fn help_flag_shows_commands() {
    let output = wispkey_bin().arg("--help").output().expect("failed to run wispkey");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("init"));
    assert!(stdout.contains("add"));
    assert!(stdout.contains("serve"));
    assert!(stdout.contains("import"));
    assert!(stdout.contains("cloud"));
    assert!(stdout.contains("mcp"));
}

#[test]
fn status_without_vault_shows_error() {
    let output = wispkey_bin()
        .arg("status")
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("vault") || combined.contains("Vault") || combined.contains("No vault") || combined.contains("not found"), "expected vault-related output, got: {combined}");
}

#[test]
fn cloud_status_shows_coming_soon_or_status() {
    let output = wispkey_bin()
        .args(["cloud", "status"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("Cloud") || combined.contains("cloud") || combined.contains("vault"), "expected cloud-related output, got: {combined}");
}

#[test]
fn policy_list_without_vault_fails_gracefully() {
    let output = wispkey_bin()
        .args(["policy", "list"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("polic") || combined.contains("No") || combined.contains("vault"), "expected policy or vault output, got: {combined}");
}
