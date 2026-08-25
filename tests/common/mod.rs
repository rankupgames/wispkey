#![allow(dead_code)]

use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

pub const TEST_BUNDLE_PASSPHRASE: &str = "test-bundle-passphrase";

pub fn wispkey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wispkey"))
}

/// Ensures spawned proxy processes are stopped even when a test assertion fails.
pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn run_wispkey(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    wispkey_bin()
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .output()
        .expect("failed to run wispkey")
}

pub fn run_wispkey_bundle(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    run_wispkey_with_bundle_passphrase(vault_dir, args, TEST_BUNDLE_PASSPHRASE)
}

pub fn run_wispkey_with_bundle_passphrase(
    vault_dir: &Path,
    args: &[&str],
    passphrase: &str,
) -> std::process::Output {
    wispkey_bin()
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .env("WISPKEY_BUNDLE_PASSPHRASE", passphrase)
        .output()
        .expect("failed to run wispkey")
}

pub fn run_wispkey_json(vault_dir: &Path, args: &[&str]) -> Value {
    let output = run_wispkey(vault_dir, args);
    output_json(args, output)
}

pub fn run_wispkey_bundle_json(vault_dir: &Path, args: &[&str]) -> Value {
    let output = run_wispkey_bundle(vault_dir, args);
    output_json(args, output)
}

pub fn output_json(args: &[&str], output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected json output for {:?}: {error}\nstdout:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

pub fn wait_for_owner_info(vault_dir: &Path) -> Value {
    let owner_info_path = vault_dir.join("owner.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(raw) = std::fs::read_to_string(&owner_info_path)
            && let Ok(value) = serde_json::from_str::<Value>(&raw)
            && value.get("endpoint").and_then(Value::as_str).is_some()
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "owner IPC did not write owner.json in time"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn wait_for_proxy_info(vault_dir: &Path) -> Value {
    let proxy_info_path = vault_dir.join("proxy.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(raw) = std::fs::read_to_string(&proxy_info_path)
            && let Ok(value) = serde_json::from_str::<Value>(&raw)
            && value.get("port").and_then(Value::as_u64).is_some()
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not write proxy.json in time"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn wait_for_child_exit(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn write_private_test_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write private test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict private test file");
    }
}

pub fn init_vault(vault_dir: &Path) {
    let output = run_wispkey(vault_dir, &["init"]);
    assert!(
        output.status.success(),
        "init failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn credential_names(value: &Value) -> Vec<String> {
    value["credentials"]
        .as_array()
        .expect("credentials array")
        .iter()
        .map(|credential| {
            credential["name"]
                .as_str()
                .expect("credential name")
                .to_string()
        })
        .collect()
}

#[cfg(unix)]
pub fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}
