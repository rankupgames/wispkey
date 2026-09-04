mod common;

use common::*;
use serde_json::json;
use std::io::Read;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use wispkey::owner_ipc;

fn start_owner_ipc(vault_dir: &std::path::Path) -> ChildGuard {
    let child = wispkey_bin()
        .args(["tray", "--ipc-only"])
        .env("WISPKEY_VAULT_PATH", vault_dir)
        .env("WISPKEY_PASSWORD", "test-password")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn owner ipc");
    wait_for_owner_info(vault_dir);
    ChildGuard(child)
}

async fn owner_call(vault_dir: &std::path::Path, request: serde_json::Value) -> serde_json::Value {
    let path = vault_dir.join("owner.sock");
    owner_ipc::call(&path, request)
        .await
        .expect("owner ipc call")
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
    thread::sleep(Duration::from_millis(200));
    let mut stderr = String::new();
    if let Some(mut pipe) = server.0.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
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
