#[path = "common/owner_ipc_capture.rs"]
mod capture;
mod common;

use capture::PhaseCapture;

use common::*;
use serde_json::json;
use std::io::Read;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use wispkey::owner_ipc;

struct OwnerServer {
    child: ChildGuard,
    logs: Arc<Mutex<Vec<u8>>>,
    reader: Option<thread::JoinHandle<()>>,
    phases: Arc<Mutex<PhaseCapture>>,
}

impl OwnerServer {
    fn stop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        if let Some(reader) = self.reader.take() {
            reader.join().expect("server log reader");
        }
    }

    fn captured_logs(&mut self) -> String {
        self.stop();
        String::from_utf8_lossy(&self.logs.lock().unwrap()).into_owned()
    }

    fn report_phase_baseline(&mut self) {
        self.stop();
        let (_, report) = self.phases.lock().unwrap().snapshot_since(0);
        if !report.is_empty() {
            eprintln!("{report}");
        }
    }
}

impl Drop for OwnerServer {
    fn drop(&mut self) {
        let failing = thread::panicking();
        let before_cleanup = if failing {
            let (index, report) = self
                .phases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot_since(0);
            eprintln!(
                "owner IPC failure phases before cleanup (server_pid={}):\n{report}",
                self.child.0.id()
            );
            index
        } else {
            0
        };
        self.stop();
        if failing {
            let (_, report) = self
                .phases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot_since(before_cleanup);
            if !report.is_empty() {
                eprintln!(
                    "owner IPC failure phases after drain (server_pid={}):\n{report}",
                    self.child.0.id()
                );
            }
        }
    }
}

fn start_owner_ipc(vault_dir: &std::path::Path) -> OwnerServer {
    let started = Instant::now();
    let mut child = ChildGuard(
        wispkey_bin()
            .args(["tray", "--ipc-only"])
            .env("WISPKEY_VAULT_PATH", vault_dir)
            .env("WISPKEY_PASSWORD", "test-password")
            .env("WISPKEY_PROTECTOR", "file")
            .env("WISPKEY_OWNER_IPC_DIAGNOSTICS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn owner ipc"),
    );
    let mut stderr = child.0.stderr.take().expect("server stderr");
    let logs = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&logs);
    let phases = Arc::new(Mutex::new(PhaseCapture::new(child.0.id())));
    let captured_phases = Arc::clone(&phases);
    let reader = thread::spawn(move || {
        let mut buffer = [0; 4096];
        while let Ok(size) = stderr.read(&mut buffer) {
            if size == 0 {
                break;
            }
            captured_phases.lock().unwrap().feed(&buffer[..size]);
            // Keep draining even after reaching the capture limit. An unread
            // pipe can block tracing before the server handles a request.
            let mut logs = captured.lock().unwrap();
            let keep = size.min(262_144_usize.saturating_sub(logs.len()));
            logs.extend_from_slice(&buffer[..keep]);
        }
    });
    let server = OwnerServer {
        child,
        logs,
        reader: Some(reader),
        phases,
    };
    wait_for_owner_info(vault_dir);
    eprintln!(
        "owner IPC readiness: {} ms (server_pid={})",
        started.elapsed().as_millis(),
        server.child.0.id()
    );
    server
}

async fn owner_call(vault_dir: &std::path::Path, request: serde_json::Value) -> serde_json::Value {
    let path = vault_dir.join("owner.sock");
    let started = Instant::now();
    owner_ipc::call(&path, request)
        .await
        .unwrap_or_else(|error| {
            let server_pid = std::fs::read(vault_dir.join("owner.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<owner_ipc::OwnerEndpoint>(&bytes).ok())
                .map_or(0, |endpoint| endpoint.pid);
            panic!(
                "owner IPC request failed after {} ms (server_pid={server_pid}): {error}",
                started.elapsed().as_millis()
            )
        })
}

#[tokio::test]
async fn desktop_initializes_once_and_shares_cli_lock_state() {
    let dir = tempfile::tempdir().expect("vault dir");
    let mut server = start_owner_ipc(dir.path());
    let status = owner_call(dir.path(), json!({"id":"status","method":"status"})).await;
    assert_eq!(status["result"]["initialized"], false);
    let mismatch = owner_call(
        dir.path(),
        json!({"id":"create","method":"initialize","params":{
            "password":"test-password", "password_confirmation":"different-fixture-password"
        }}),
    )
    .await;
    assert_eq!(mismatch["error"]["code"], "invalid_input");
    assert!(!dir.path().join("vault.db").exists());
    let initialized = owner_call(
        dir.path(),
        json!({"id":"create","method":"initialize","params":{
            "password":"test-password", "password_confirmation":"test-password"
        }}),
    )
    .await;
    assert_eq!(
        initialized["result"]["session_active"], true,
        "{initialized}"
    );
    let duplicate = owner_call(dir.path(), json!({"id":"again","method":"initialize","params":{
        "password":"replacement-fixture-password", "password_confirmation":"replacement-fixture-password"
    }})).await;
    assert_eq!(duplicate["error"]["code"], "already_initialized");
    let locked = owner_call(dir.path(), json!({"id":"lock","method":"lock"})).await;
    assert_eq!(locked["result"]["session_active"], false);
    let wrong = owner_call(
        dir.path(),
        json!({"id":"wrong","method":"unlock","params":{"password":"wrong-fixture-password"}}),
    )
    .await;
    assert_eq!(wrong["error"]["code"], "unauthorized");
    let unlocked = owner_call(dir.path(), json!({"id":"unlock","method":"unlock","params":{"password":"test-password","remember":true}})).await;
    assert_eq!(unlocked["result"]["session_active"], true, "{unlocked}");
    assert!(dir.path().join("session-protector").exists());
    let cli_status = wispkey_bin()
        .arg("status")
        .env("WISPKEY_VAULT_PATH", dir.path())
        .output()
        .expect("CLI status");
    assert!(cli_status.status.success());
    let logs = server.captured_logs();
    for value in [
        "test-password",
        "wrong-fixture-password",
        "replacement-fixture-password",
    ] {
        assert!(!logs.contains(value));
    }
}

#[tokio::test]
async fn desktop_import_review_is_metadata_only_and_commit_is_consumed() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let mut server = start_owner_ipc(dir.path());
    let source = dir.path().join(".env.desktop-fixture");
    let content = "FIXTURE_API_KEY=desktop-import-canary-value\nPORT=8123\n";
    std::fs::write(&source, content).expect("fixture source");
    for params in [
        json!({"paths":[source],"project":7}),
        json!({"paths":[source],"directory":dir.path(),"project":"desktop-fixture"}),
    ] {
        let rejected = owner_call(
            dir.path(),
            json!({"id":"invalid-preview","method":"import_preview","params":params}),
        )
        .await;
        assert_eq!(rejected["error"]["code"], "invalid_input");
    }
    let preview = owner_call(
        dir.path(),
        json!({"id":"preview","method":"import_preview","params":{
            "paths":[source],"project":"desktop-fixture"
        }}),
    )
    .await;
    assert_eq!(preview["ok"], true, "{preview}");
    let result = &preview["result"];
    assert!(!result.to_string().contains("desktop-import-canary-value"));
    assert!(!result.to_string().contains("wk_"));
    let item = result["items"]
        .as_array()
        .expect("preview items")
        .iter()
        .find(|item| item["key"] == "FIXTURE_API_KEY")
        .expect("secret key");
    let commit = json!({"id":"commit","method":"import_commit","params":{
        "plan_id":result["plan_id"],"project":"desktop-fixture", "environment":"desktop-fixture", "destination_confirmed":true,
        "items":result["items"].as_array().unwrap().iter().map(|row| json!({
            "id":row["id"],"environment":row["environment"],"selected":row["id"] == item["id"],"hosts":"api.example.test","action":"keep"
        })).collect::<Vec<_>>(), "rewrite_http":false
    }});
    let saved = owner_call(dir.path(), commit.clone()).await;
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(saved["result"]["imported"], 1);
    assert_eq!(saved["result"]["files"][0]["status"], "unchanged");
    assert_eq!(std::fs::read_to_string(&source).unwrap(), content);
    assert_eq!(
        owner_call(dir.path(), commit).await["error"]["code"],
        "plan_unavailable"
    );
    let list = owner_call(
        dir.path(),
        json!({"id":"list","method":"list_credentials","params":{"all_projects":true}}),
    )
    .await;
    let credential = list["result"]["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["project"] == "desktop-fixture")
        .expect("import destination");
    assert_eq!(credential["partition"], "desktop-fixture");
    assert!(!list.to_string().contains("desktop-import-canary-value"));
    assert!(!list.to_string().contains("wisp_token"));
    let logs = server.captured_logs();
    assert!(!logs.contains("desktop-import-canary-value"));
    assert!(!logs.contains("FIXTURE_API_KEY"));
}

#[tokio::test]
async fn generated_website_login_requires_destination_and_returns_only_metadata() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let mut server = start_owner_ipc(dir.path());
    let mut request = json!({ "id":"generate", "method":"generate_login", "params": {
        "name":"careers", "username":"synthetic@example.com", "url":"https://careers.example.com/login",
        "project":"career-ops", "partition":"job-applications"
    }});
    assert_eq!(owner_call(dir.path(), request.clone()).await["ok"], false);
    request["params"]["destination_confirmed"] = json!(true);
    let response = owner_call(dir.path(), request).await;
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["result"]["origin"], "https://careers.example.com");
    assert_eq!(response["result"]["lifecycle_state"], "pending");
    for forbidden in ["password", "wisp_token", "encrypted_value"] {
        assert!(!response.to_string().contains(forbidden));
    }
    // No owner IPC fill/reveal method accompanies the metadata-only generator.
    assert_eq!(
        owner_call(dir.path(), json!({"id":"reveal","method":"browser_fill"})).await["ok"],
        false
    );
    let logs = server.captured_logs();
    assert!(!logs.contains("encrypted_value"));
    server.report_phase_baseline();
}

#[tokio::test]
async fn repeated_owner_requests_do_not_block_on_test_logging() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    // Exceed a pipe buffer with synthetic, non-secret log fields.
    let request_id = "logging-load-".repeat(512);
    for _ in 0..40 {
        let response = tokio::time::timeout(
            Duration::from_secs(6),
            owner_call(dir.path(), json!({"id": request_id, "method": "status"})),
        )
        .await
        .expect("owner request stalled while collecting server logs");
        assert_eq!(response["ok"], true);
    }
}

#[tokio::test]
async fn concurrent_owner_clients_complete_against_one_server() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let path = dir.path().to_path_buf();
        clients.spawn(async move {
            for _ in 0..8 {
                let response =
                    owner_call(&path, json!({"id": "concurrency", "method": "status"})).await;
                assert_eq!(response["ok"], true);
            }
        });
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(result) = clients.join_next().await {
            result.expect("client task");
        }
    })
    .await
    .expect("concurrent owner requests stalled");
}

#[tokio::test]
async fn owner_ipc_adds_one_credential_without_returning_secret() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": {
                "name": "openai-key",
                "type": "bearer_token",
                "value": "sk-live-never-log-this",
                "description": "OpenAI",
                "tags": "openai",
                "hosts": "api.openai.com",
                "destination_confirmed": true
            }
        }),
    )
    .await;
    assert_eq!(response["ok"], true);
    let encoded = response.to_string();
    assert!(!encoded.contains("sk-live-never-log-this"));
    assert!(!encoded.contains("wk_"));
    assert_eq!(response["result"]["credentials"][0]["name"], "openai-key");

    let listed = owner_call(
        dir.path(),
        json!({ "id": "2", "method": "list_credentials" }),
    )
    .await;
    assert_eq!(listed["result"]["credentials"][0]["name"], "openai-key");
    assert!(!listed.to_string().contains("sk-live-never-log-this"));
    assert!(
        listed["result"]["credentials"][0]
            .get("wisp_token")
            .is_none()
    );
}

#[tokio::test]
async fn owner_ipc_ovh_duplicate_rolls_back_all() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let secret_file = dir.path().join("existing.txt");
    write_private_test_file(&secret_file, "already-there");
    let secret_path = secret_file.to_string_lossy().to_string();
    let add = run_wispkey(
        dir.path(),
        &[
            "add",
            "ovh-prod-application-key",
            "--type",
            "api_key",
            "--value-file",
            &secret_path,
        ],
    );
    assert!(
        add.status.success(),
        "failed to seed duplicate credential: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let _server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_template",
            "params": {
                "template": "ovh_api",
                "name_prefix": "ovh-prod",
                "application_key": "ak-secret",
                "application_secret": "as-secret",
                "consumer_key": "ck-secret",
                "destination_confirmed": true
            }
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "duplicate");

    let listed = owner_call(
        dir.path(),
        json!({ "id": "2", "method": "list_credentials" }),
    )
    .await;
    let names = credential_names(&listed["result"]);
    assert_eq!(names, vec!["ovh-prod-application-key"]);
    assert!(!listed.to_string().contains("as-secret"));
}

#[tokio::test]
async fn owner_ipc_ovh_success_creates_three() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let mut server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_template",
            "params": {
                "template": "ovh_api",
                "name_prefix": "ovh-prod",
                "application_key": "ak-secret",
                "application_secret": "as-secret",
                "consumer_key": "ck-secret",
                "hosts": "api.ovh.com",
                "destination_confirmed": true
            }
        }),
    )
    .await;
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(
        response["result"]["credentials"].as_array().unwrap().len(),
        3
    );
    let listed = owner_call(
        dir.path(),
        json!({ "id": "2", "method": "list_credentials" }),
    )
    .await;
    let mut names = credential_names(&listed["result"]);
    names.sort();
    assert_eq!(
        names,
        vec![
            "ovh-prod-application-key",
            "ovh-prod-application-secret",
            "ovh-prod-consumer-key"
        ]
    );
    server.report_phase_baseline();
}

#[tokio::test]
async fn owner_ipc_locked_vault_fails_closed() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let lock = run_wispkey(dir.path(), &["lock"]);
    assert!(lock.status.success());
    let _server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": { "name": "x", "value": "y", "destination_confirmed": true }
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "locked");
}

#[tokio::test]
async fn owner_ipc_empty_value_fails_closed() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": { "name": "blank", "value": "   ", "destination_confirmed": true }
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn owner_ipc_duplicate_name_fails_closed() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let first = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": { "name": "dup", "value": "one", "destination_confirmed": true }
        }),
    )
    .await;
    assert_eq!(first["ok"], true);
    let second = owner_call(
        dir.path(),
        json!({
            "id": "2",
            "method": "add_credential",
            "params": { "name": "dup", "value": "two", "destination_confirmed": true }
        }),
    )
    .await;
    assert_eq!(second["ok"], false);
    assert_eq!(second["error"]["code"], "duplicate");
}

#[tokio::test]
async fn owner_ipc_redacts_secrets_from_logs() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let mut server = start_owner_ipc(dir.path());
    let _response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": {
                "name": "logged-key",
                "value": "super-secret-log-probe-value",
                "destination_confirmed": true
            }
        }),
    )
    .await;
    let _ = owner_call(dir.path(), json!({ "id": "2", "method": "shutdown" })).await;
    let stderr = server.captured_logs();
    assert!(
        stderr.contains("owner ipc request completed"),
        "server log capture was empty"
    );
    assert!(
        !stderr.contains("super-secret-log-probe-value"),
        "secret leaked in stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn owner_socket_is_owner_only() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let mode = file_mode(&dir.path().join("owner.sock"));
    assert_eq!(mode, 0o600);
    let meta_mode = file_mode(&dir.path().join("owner.json"));
    assert_eq!(meta_mode, 0o600);
}

#[test]
fn unauthorized_peer_uid_fails_closed() {
    assert!(!owner_ipc::authorize_peer_uid(Some(1), 99));
}

#[tokio::test]
async fn owner_ipc_requires_explicit_destination_confirmation() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let response = owner_call(
        dir.path(),
        json!({
            "id": "1",
            "method": "add_credential",
            "params": { "name": "unconfirmed", "value": "secret" }
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "confirmation_required");
}

#[tokio::test]
async fn second_owner_server_is_rejected_without_replacing_discovery() {
    let dir = tempfile::tempdir().expect("vault dir");
    init_vault(dir.path());
    let _server = start_owner_ipc(dir.path());
    let original = std::fs::read(dir.path().join("owner.json")).expect("owner metadata");

    let second = wispkey_bin()
        .args(["tray", "--ipc-only"])
        .env("WISPKEY_VAULT_PATH", dir.path())
        .env("WISPKEY_PASSWORD", "test-password")
        .output()
        .expect("start second owner");

    assert!(!second.status.success());
    assert_eq!(
        std::fs::read(dir.path().join("owner.json")).expect("owner metadata"),
        original
    );
    assert!(
        owner_ipc::is_live_at(
            &dir.path().join("owner.sock"),
            &dir.path().join("owner.json")
        )
        .await
    );
}
