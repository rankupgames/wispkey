#![allow(dead_code)]

use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

pub const TEST_BUNDLE_PASSPHRASE: &str = "test-bundle-passphrase";

pub fn wispkey_bin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wispkey"));
    command
        .env_remove("WISPKEY_PROJECT")
        .env_remove("WISPKEY_SESSION_TIMEOUT");
    command
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
        .env("WISPKEY_PROTECTOR", "file")
        .output()
        .expect("failed to run wispkey")
}

pub fn run_wispkey_without_password(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    wispkey_bin()
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env_remove("WISPKEY_PASSWORD")
        .env("WISPKEY_PROTECTOR", "file")
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
        .env("WISPKEY_PROTECTOR", "file")
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
    let vault_dir = vault_dir.to_path_buf();
    std::thread::spawn(move || wait_for_owner_info_blocking(&vault_dir))
        .join()
        .expect("owner ipc wait thread")
}

fn wait_for_owner_info_blocking(vault_dir: &Path) -> Value {
    let owner_info_path = vault_dir.join("owner.json");
    let socket_path = vault_dir.join("owner.sock");
    let deadline = Instant::now() + Duration::from_secs(if cfg!(windows) { 20 } else { 10 });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("owner ipc wait runtime");

    loop {
        if Instant::now() >= deadline {
            panic!("owner IPC did not become live in time");
        }

        if let Ok(raw) = std::fs::read_to_string(&owner_info_path)
            && let Ok(value) = serde_json::from_str::<Value>(&raw)
            && value.get("endpoint").and_then(Value::as_str).is_some()
            && runtime.block_on(wispkey::owner_ipc::is_live_at(
                &socket_path,
                &owner_info_path,
            ))
        {
            return value;
        }

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
    #[cfg(not(windows))]
    std::fs::write(path, contents).expect("write private test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict private test file");
    }
    #[cfg(windows)]
    {
        use std::io::Write;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let identity = run_wispkey_json(
            path.parent().expect("fixture directory"),
            &["--format", "json", "operation", "identity"],
        );
        let sid = identity["principal"]
            .as_str()
            .unwrap()
            .strip_prefix("windows-sid:")
            .unwrap();
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            },
            0,
            "fixture security descriptor"
        );
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        unsafe {
            LocalFree(descriptor.cast());
        }
        assert_ne!(
            handle, INVALID_HANDLE_VALUE,
            "create private fixture: {error}"
        );
        let mut file = unsafe { std::fs::File::from_raw_handle(handle) };
        file.write_all(contents.as_bytes())
            .expect("write private fixture");
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

/// Fixture owner classification for rows the CLI cannot broaden without a terminal
/// (`login generate`, `login add-existing`).
pub fn classify_routine(vault_dir: &Path, name: &str) {
    let db = rusqlite::Connection::open(vault_dir.join("vault.db")).expect("open vault db");
    let classified = db
        .execute(
            "UPDATE credentials SET access_ring='routine' WHERE name=?1",
            [name],
        )
        .expect("classify");
    assert_eq!(classified, 1);
}
