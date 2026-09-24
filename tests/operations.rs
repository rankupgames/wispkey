use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const CANARY: &str = "synthetic-catalog-canary-do-not-render";

fn cli(vault: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wispkey"))
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault)
        .env("WISPKEY_PASSWORD", CANARY)
        .env("WISPKEY_REQUESTER", "spoofed")
        .env("USERNAME", "spoofed")
        .env("USER", "spoofed")
        .output()
        .expect("run preflight")
}

fn principal(vault: &Path) -> String {
    let output = cli(vault, &["--format", "json", "operation", "identity"]);
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["source"], "operating_system");
    assert_eq!(value["scope"], "local_os_account");
    let identity = value["principal"].as_str().unwrap();
    assert!(!identity.contains("spoofed"));
    #[cfg(unix)]
    assert_eq!(identity, format!("unix-uid:{}", unsafe { libc::geteuid() }));
    #[cfg(windows)]
    assert!(identity.starts_with("windows-sid:S-1-"));
    identity.to_owned()
}

fn catalog(principal: &str) -> String {
    format!(
        r#"version = 1
[[operation]]
id = "maintenance"
kind = "ssh-helper"
project_id = "default"
credential_id = "5af05c13-1c0a-4394-a7a3-7f457ff74a40"
requester_principal = "{principal}"
environment_id = "preview"
target_id = "worker"
expires_at = "2099-01-01T00:00:00Z"
max_grant_seconds = 300
max_runtime_seconds = 60
connect_timeout_seconds = 10
max_concurrency = 1
[operation.ssh]
address = "192.0.2.1"
port = 22
account = "maintenance"
host_key_algorithm = "ssh-ed25519"
host_key_sha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
helper_path = "/usr/local/libexec/maintenance"
identity_file = "/nonexistent/restricted-key"
"#
    )
}

fn write_catalog(root: &Path, principal: &str, contents: &str) -> PathBuf {
    let path = root.join("operations.toml");
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = principal;
    }
    #[cfg(windows)]
    {
        // Limit changes to this disposable test file. icacls never sees a value
        // from the catalog: only its path and the process account SID.
        let sid = principal.strip_prefix("windows-sid:").unwrap();
        let status = Command::new("icacls")
            .arg(&path)
            .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(F)")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        // Elevated Windows runners can create files owned by Administrators.
        // The catalog reader requires the process account SID as actual owner.
        let status = Command::new("icacls")
            .arg(&path)
            .args(["/setowner", &format!("*{sid}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    path
}

fn check(vault: &Path, path: &Path, operation: Option<&str>) -> Output {
    let mut args = vec![
        "--format",
        "json",
        "operation",
        "check",
        "--config",
        path.to_str().unwrap(),
    ];
    if let Some(operation) = operation {
        args.extend(["--operation", operation]);
    }
    cli(vault, &args)
}

#[test]
fn private_preflight_requires_no_vault_and_does_not_claim_live_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let vault = root.join("no-vault");
    let identity = principal(&vault);
    let raw = catalog(&identity);
    let path = write_catalog(&root, &identity, &raw);
    let before = std::fs::read(&path).unwrap();
    let output = check(&vault, &path, Some("maintenance"));
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["configuration_valid"], true);
    assert_eq!(report["checked_operations"], 1);
    for key in [
        "credential_verified",
        "live_target_verified",
        "execution_available",
    ] {
        assert_eq!(report[key], false);
    }
    assert!(!vault.exists());
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));

    write_catalog(
        &root,
        &identity,
        &format!("# synthetic formatting change\n{raw}"),
    );
    let after: Value = serde_json::from_slice(&check(&vault, &path, None).stdout).unwrap();
    assert_eq!(report["catalog_revision"], after["catalog_revision"]);
    let missing = check(&vault, &path, Some(CANARY));
    assert!(!missing.status.success());
    assert!(!String::from_utf8_lossy(&missing.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&missing.stderr).contains(CANARY));
}

#[test]
fn preflight_failures_never_echo_catalog_values_or_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let vault = root.join("no-vault");
    let identity = principal(&vault);
    let raw = catalog(&identity);
    let other_principal = if identity.starts_with("unix-") {
        "windows-sid:S-1-5-18"
    } else {
        "unix-uid:1000"
    };
    for invalid in [
        format!("{raw}unexpected_secret = \"{CANARY}\"\n"),
        format!("{CANARY} = broken TOML"),
        raw.replace(&identity, other_principal),
        raw.replace("2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z"),
    ] {
        let path = write_catalog(&root, &identity, &invalid);
        let output = check(&vault, &path, None);
        assert!(!output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["configuration_valid"], false);
        assert_eq!(report["execution_available"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    }
    let output = check(&vault, &root.join(CANARY), None);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    assert!(!vault.exists());
}
