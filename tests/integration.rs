use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const TEST_BUNDLE_PASSPHRASE: &str = "test-bundle-passphrase";

fn wispkey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wispkey"))
}

/// Ensures spawned proxy processes are stopped even when a test assertion fails.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_wispkey(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    wispkey_bin()
        .args(args)
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .output()
        .expect("failed to run wispkey")
}

fn run_wispkey_bundle(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    run_wispkey_with_bundle_passphrase(vault_dir, args, TEST_BUNDLE_PASSPHRASE)
}

fn run_wispkey_with_bundle_passphrase(
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

fn run_wispkey_json(vault_dir: &Path, args: &[&str]) -> Value {
    let output = run_wispkey(vault_dir, args);
    output_json(args, output)
}

fn run_wispkey_bundle_json(vault_dir: &Path, args: &[&str]) -> Value {
    let output = run_wispkey_bundle(vault_dir, args);
    output_json(args, output)
}

fn output_json(args: &[&str], output: std::process::Output) -> Value {
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

fn write_private_test_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write private test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict private test file");
    }
}

fn init_vault(vault_dir: &Path) {
    let output = run_wispkey(vault_dir, &["init"]);
    assert!(
        output.status.success(),
        "init failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn credential_names(value: &Value) -> Vec<String> {
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
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn version_flag_prints_version() {
    let output = wispkey_bin()
        .arg("--version")
        .output()
        .expect("failed to run wispkey");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wispkey"),
        "expected version output, got: {stdout}"
    );
}

#[test]
fn help_flag_shows_commands() {
    let output = wispkey_bin()
        .arg("--help")
        .output()
        .expect("failed to run wispkey");
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
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("vault")
            || combined.contains("Vault")
            || combined.contains("No vault")
            || combined.contains("not found"),
        "expected vault-related output, got: {combined}"
    );
}

#[test]
fn cloud_status_shows_coming_soon_or_status() {
    let output = wispkey_bin()
        .args(["cloud", "status"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Cloud") || combined.contains("cloud") || combined.contains("vault"),
        "expected cloud-related output, got: {combined}"
    );
}

#[test]
fn policy_list_without_vault_fails_gracefully() {
    let output = wispkey_bin()
        .args(["policy", "list"])
        .env("HOME", "/tmp/wispkey-test-nonexistent")
        .output()
        .expect("failed to run wispkey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("polic") || combined.contains("No") || combined.contains("vault"),
        "expected policy or vault output, got: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn vault_directory_and_session_file_are_owner_only_on_unix() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    assert_eq!(file_mode(vault_dir.path()), 0o700);
    assert_eq!(file_mode(&vault_dir.path().join("session")), 0o600);
}

#[test]
fn cli_project_scoping_json_contract_is_real() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "create",
            "client-alpha",
            "--description",
            "Client Alpha",
        ],
    );
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "default-key",
            "--type",
            "api_key",
            "--value",
            "default-secret",
        ],
    );
    run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
            "--project",
            "client-alpha",
        ],
    );

    let default_list = run_wispkey_json(vault_dir.path(), &["--format", "json", "list"]);
    assert_eq!(credential_names(&default_list), vec!["default-key"]);
    assert_eq!(default_list["project"], "default");

    let client_list = run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "list", "--project", "client-alpha"],
    );
    assert_eq!(credential_names(&client_list), vec!["client-key"]);
    assert_eq!(client_list["project"], "client-alpha");

    run_wispkey_json(
        vault_dir.path(),
        &["--format", "json", "project", "use", "client-alpha"],
    );
    let active_list = run_wispkey_json(vault_dir.path(), &["--format", "json", "list"]);
    assert_eq!(credential_names(&active_list), vec!["client-key"]);
    assert_eq!(active_list["project"], "client-alpha");

    let projects = run_wispkey_json(vault_dir.path(), &["--format", "json", "project", "list"]);
    let client_project = projects["projects"]
        .as_array()
        .expect("projects array")
        .iter()
        .find(|project| project["name"] == "client-alpha")
        .expect("client-alpha project");
    assert_eq!(client_project["active"], true);
    assert_eq!(client_project["partition_count"], 1);
}

#[test]
fn cli_project_and_single_credential_bundle_roundtrips_are_real() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let project_dest_dir = tempfile::tempdir().expect("project destination vault dir");
    let credential_dest_dir = tempfile::tempdir().expect("credential destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let project_bundle = bundle_dir.path().join("client-alpha.wkbundle");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "create", "client-alpha"],
    );
    let added = run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "bearer_token",
            "--value",
            "client-secret",
            "--hosts",
            "api.example.com",
            "--tags",
            "client,prod",
            "--project",
            "client-alpha",
        ],
    );
    assert_eq!(added["credential"]["name"], "client-key");

    let project_bundle_path = project_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "export",
            "client-alpha",
            "--output",
            &project_bundle_path,
        ],
    );
    assert!(project_bundle.exists(), "project bundle should be written");

    init_vault(project_dest_dir.path());
    let imported_project = run_wispkey_bundle_json(
        project_dest_dir.path(),
        &[
            "--format",
            "json",
            "project",
            "import",
            &project_bundle_path,
        ],
    );
    assert_eq!(imported_project["imported"], 1);
    let project_list = run_wispkey_json(
        project_dest_dir.path(),
        &["--format", "json", "list", "--project", "client-alpha"],
    );
    assert_eq!(credential_names(&project_list), vec!["client-key"]);
    assert_eq!(
        project_list["credentials"][0]["hosts"],
        serde_json::json!(["api.example.com"])
    );
    assert_eq!(
        project_list["credentials"][0]["tags"],
        serde_json::json!(["client", "prod"])
    );

    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );
    assert!(
        credential_bundle.exists(),
        "single credential bundle should be written"
    );

    init_vault(credential_dest_dir.path());
    let imported_credential = run_wispkey_bundle_json(
        credential_dest_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
            "--project",
            "shared-client",
            "--partition",
            "personal",
        ],
    );
    assert_eq!(imported_credential["imported"], 1);
    let credential_list = run_wispkey_json(
        credential_dest_dir.path(),
        &["--format", "json", "list", "--project", "shared-client"],
    );
    assert_eq!(credential_names(&credential_list), vec!["client-key"]);
}

#[test]
fn cli_partition_bundle_roundtrip_is_real() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let partition_bundle = bundle_dir.path().join("service-tokens.wkbundle");

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "create", "client-alpha"],
    );
    run_wispkey_json(
        source_dir.path(),
        &["--format", "json", "project", "use", "client-alpha"],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "create",
            "service-tokens",
            "--description",
            "Service tokens",
        ],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "service-key",
            "--type",
            "api_key",
            "--value",
            "service-secret",
            "--hosts",
            "api.service.test",
            "--tags",
            "service,prod",
            "--partition",
            "service-tokens",
        ],
    );

    let partition_bundle_path = partition_bundle.to_string_lossy().to_string();
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "export",
            "service-tokens",
            "--output",
            &partition_bundle_path,
        ],
    );
    assert!(
        partition_bundle.exists(),
        "partition bundle should be written"
    );

    init_vault(destination_dir.path());
    let imported = run_wispkey_bundle_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "partition",
            "import",
            &partition_bundle_path,
        ],
    );
    assert_eq!(imported["imported"], 1);

    let imported_list = run_wispkey_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "list",
            "--project",
            "client-alpha",
            "--partition",
            "service-tokens",
        ],
    );
    assert_eq!(credential_names(&imported_list), vec!["service-key"]);
    assert_eq!(
        imported_list["credentials"][0]["hosts"],
        serde_json::json!(["api.service.test"])
    );
    assert_eq!(
        imported_list["credentials"][0]["tags"],
        serde_json::json!(["service", "prod"])
    );
}

#[test]
fn bundle_passphrase_is_not_vault_password_fallback() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );

    let output = run_wispkey(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );
    assert!(
        !output.status.success(),
        "export should fail without a bundle passphrase"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WISPKEY_BUNDLE_PASSPHRASE") && stderr.contains("WISPKEY_PASSWORD"),
        "expected separate passphrase guidance, got:\n{stderr}"
    );
    assert!(
        !credential_bundle.exists(),
        "failed export must not write a bundle"
    );
}

#[test]
fn bundle_export_rejects_short_passphrase() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );

    let output = run_wispkey_with_bundle_passphrase(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
        "too-short",
    );
    assert!(!output.status.success(), "short passphrase should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least 12"),
        "expected length validation, got:\n{stderr}"
    );
}

#[test]
fn bundle_import_rejects_wrong_passphrase() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let credential_bundle = bundle_dir.path().join("client-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "client-key",
            "--type",
            "api_key",
            "--value",
            "client-secret",
        ],
    );
    run_wispkey_bundle_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "client-key",
            "--output",
            &credential_bundle_path,
        ],
    );

    init_vault(destination_dir.path());
    let output = run_wispkey_with_bundle_passphrase(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
        ],
        "wrong-passphrase-value",
    );
    assert!(!output.status.success(), "wrong passphrase should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("wrong password") || stderr.contains("invalid bundle"),
        "expected decryption failure, got:\n{stderr}"
    );
}

#[test]
fn bundle_passphrase_file_roundtrips_multiline_secret_through_proxy() {
    let source_dir = tempfile::tempdir().expect("source vault dir");
    let destination_dir = tempfile::tempdir().expect("destination vault dir");
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let secret_file = bundle_dir.path().join("private-key.txt");
    let passphrase_file = bundle_dir.path().join("bundle-passphrase.txt");
    let credential_bundle = bundle_dir.path().join("ssh-key.wkcred");
    let credential_bundle_path = credential_bundle.to_string_lossy().to_string();
    let secret_file_path = secret_file.to_string_lossy().to_string();
    let passphrase_file_path = passphrase_file.to_string_lossy().to_string();
    let expected_secret = "-----BEGIN PRIVATE KEY-----\nline-two\n-----END PRIVATE KEY-----\n";

    write_private_test_file(&secret_file, expected_secret);
    write_private_test_file(&passphrase_file, TEST_BUNDLE_PASSPHRASE);

    init_vault(source_dir.path());
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "ssh-key",
            "--type",
            "api_key",
            "--value-file",
            &secret_file_path,
            "--hosts",
            "127.0.0.1",
        ],
    );
    run_wispkey_json(
        source_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "export",
            "ssh-key",
            "--output",
            &credential_bundle_path,
            "--bundle-passphrase-file",
            &passphrase_file_path,
        ],
    );

    init_vault(destination_dir.path());
    run_wispkey_json(
        destination_dir.path(),
        &[
            "--format",
            "json",
            "credential",
            "import",
            &credential_bundle_path,
            "--bundle-passphrase-file",
            &passphrase_file_path,
        ],
    );
    let imported = run_wispkey_json(
        destination_dir.path(),
        &["--format", "json", "get", "ssh-key", "--show-token"],
    );
    let token = imported["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let expected_secret_for_thread = expected_secret.to_string();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        assert!(
            request.contains(&expected_secret_for_thread),
            "upstream should receive imported multiline secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_"),
            "upstream must not receive unresolved wisp token:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", destination_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let _guard = ChildGuard(child);

    let proxy_info_path = destination_dir.path().join("proxy.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let proxy_port = loop {
        if let Ok(raw) = std::fs::read_to_string(&proxy_info_path) {
            let value: Value = serde_json::from_str(&raw).expect("proxy info json");
            if let Some(port) = value["port"].as_u64() {
                break port as u16;
            }
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not write proxy.json in time"
        );
        thread::sleep(Duration::from_millis(50));
    };

    let body = token;
    let request = format!(
        "POST http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}

#[test]
fn proxy_swaps_wisp_token_before_local_upstream_receives_request() {
    let vault_dir = tempfile::tempdir().expect("temp vault dir");
    init_vault(vault_dir.path());

    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().expect("upstream address").port();
    let upstream_handle = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept upstream request");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read upstream request");
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        let normalized_request = request.to_ascii_lowercase();
        assert!(
            normalized_request.contains("authorization: bearer real-secret"),
            "upstream should receive real secret, got:\n{request}"
        );
        assert!(
            !request.contains("wk_"),
            "upstream must not receive unresolved wisp token:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write upstream response");
    });

    let added = run_wispkey_json(
        vault_dir.path(),
        &[
            "--format",
            "json",
            "add",
            "proxy-key",
            "--type",
            "bearer_token",
            "--value",
            "real-secret",
            "--hosts",
            "127.0.0.1",
        ],
    );
    let token = added["credential"]["wisp_token"]
        .as_str()
        .expect("wisp token")
        .to_string();

    let child = wispkey_bin()
        .args(["serve", "--random-port"])
        .env("WISPKEY_VAULT_PATH", vault_dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let _guard = ChildGuard(child);

    let proxy_info_path = vault_dir.path().join("proxy.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let proxy_port = loop {
        if let Ok(raw) = std::fs::read_to_string(&proxy_info_path) {
            let value: Value = serde_json::from_str(&raw).expect("proxy info json");
            if let Some(port) = value["port"].as_u64() {
                break port as u16;
            }
        }
        assert!(
            Instant::now() < deadline,
            "proxy did not write proxy.json in time"
        );
        thread::sleep(Duration::from_millis(50));
    };

    let mut proxy_stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    let request = format!(
        "GET http://127.0.0.1:{upstream_port}/test HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream_port}\r\n\
         Authorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    );
    proxy_stream
        .write_all(request.as_bytes())
        .expect("write proxy request");
    let mut response = String::new();
    proxy_stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected successful proxy response, got:\n{response}"
    );

    upstream_handle.join().expect("upstream assertion");
}
