//! Real HTTP + SSH across three processes, using only disposable synthetic state.
//! Grants are seeded through internal test APIs, not a claim of human approval.
use super::{catalog::SshTarget, process_handoff_destination, runtime, ssh};
use crate::core::{AddCredentialRequest, CredentialType, Vault, operation_grants as grants};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(super) const CANARY: &str = "synthetic-process-handoff-selected-value";
const MASTER: &str = "synthetic-process-handoff-master";
const MARKER: &str = "wispkey-process-handoff-v1";

pub(super) fn write(path: &Path, value: &Value) {
    crate::secure_files::write_private(path, &serde_json::to_vec(value).unwrap()).unwrap();
}

async fn read_when_ready(path: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(value) = serde_json::from_slice(&bytes)
        {
            return value;
        }
        assert!(Instant::now() < deadline, "fixture readiness deadline");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(root: &Path, role: &str) -> Process {
    let home = root.join(role);
    std::fs::create_dir(&home).unwrap();
    let log = |suffix: &str| {
        let path = root.join(format!("{role}.{suffix}"));
        crate::secure_files::write_private(&path, b"").unwrap();
        Stdio::from(std::fs::File::options().write(true).open(path).unwrap())
    };
    Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("operations::process_handoff_tests::{role}_child"),
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", root)
            .env("WISPKEY_PROCESS_FIXTURE", root)
            .env("WISPKEY_VAULT_PATH", home.join("vault"))
            .env("WISPKEY_PROTECTOR", "file")
            .stdin(Stdio::null())
            .stdout(log("stdout"))
            .stderr(log("stderr"))
            .spawn()
            .unwrap(),
    )
}

fn child_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("WISPKEY_PROCESS_FIXTURE").expect("parent fixture required"),
    );
    assert!(root.is_absolute());
    assert_eq!(
        std::fs::read(root.join("marker")).unwrap(),
        MARKER.as_bytes()
    );
    let vault = PathBuf::from(std::env::var_os("WISPKEY_VAULT_PATH").unwrap());
    assert!(vault.starts_with(&root));
    assert!(!vault.exists());
    root
}

async fn finish(child: &mut Process) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "fixture child failed; captured output retained privately until cleanup"
            );
            return;
        }
        assert!(Instant::now() < deadline, "fixture shutdown deadline");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn private_output(bytes: &[u8], forbidden: &[&str]) {
    for value in forbidden {
        assert!(
            !bytes
                .windows(value.len())
                .any(|part| part == value.as_bytes()),
            "fixture output contained a canary"
        );
    }
}

#[tokio::test]
async fn separate_process_handoff_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    crate::secure_files::write_private(&root.join("marker"), MARKER.as_bytes()).unwrap();
    let mut executor = spawn(&root, "executor");
    read_when_ready(&root.join("executor-ready.json")).await;
    let mut destination = spawn(&root, "destination");
    let config = read_when_ready(&root.join("requester.json")).await;
    let discovery = read_when_ready(&root.join("executor/vault/proxy.json")).await;
    let port = discovery["port"].as_u64().unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let worker = config["instance"].as_str().unwrap();
    let secret = config["secret"].as_str().unwrap();
    let encoded_canary = STANDARD.encode(CANARY);
    let forbidden = [
        CANARY,
        MASTER,
        secret,
        encoded_canary.as_str(),
        config["other_secret"].as_str().unwrap(),
        config["revoked_secret"].as_str().unwrap(),
    ];
    let call = |name: &str, instance: String, password: String| {
        let client = client.clone();
        let grant = config["grants"][name]["grant_id"]
            .as_str()
            .unwrap()
            .to_owned();
        async move {
            let response = client
                .post(format!(
                    "http://127.0.0.1:{port}/api/operations/grants/{grant}/execute"
                ))
                .header("x-wispkey-instance-id", instance)
                .header("x-wispkey-instance-secret", password)
                .send()
                .await
                .unwrap();
            let code = response.status().as_u16();
            for (name, value) in response.headers() {
                private_output(name.as_str().as_bytes(), &forbidden);
                private_output(value.as_bytes(), &forbidden);
            }
            let bytes = response.bytes().await.unwrap();
            private_output(&bytes, &forbidden);
            (code, serde_json::from_slice::<Value>(&bytes).unwrap())
        }
    };
    assert_eq!(
        call("deliver", worker.into(), "wrong-secret".into())
            .await
            .0,
        401
    );
    assert_eq!(
        call(
            "deliver",
            config["other_instance"].as_str().unwrap().into(),
            config["other_secret"].as_str().unwrap().into()
        )
        .await
        .0,
        403
    );
    for name in ["cancelled", "expired", "stale"] {
        assert_eq!(call(name, worker.into(), secret.into()).await.0, 403);
    }
    assert_eq!(
        call(
            "revoked",
            config["revoked_instance"].as_str().unwrap().into(),
            config["revoked_secret"].as_str().unwrap().into()
        )
        .await
        .0,
        401
    );
    let (first, duplicate) = tokio::join!(
        call("deliver", worker.into(), secret.into()),
        call("deliver", worker.into(), secret.into())
    );
    assert!((first.0 == 200 && duplicate.0 == 403) || (first.0 == 403 && duplicate.0 == 200));
    let status = if first.0 == 200 { first.1 } else { duplicate.1 };
    assert_eq!(status["state"], "succeeded");
    assert_eq!(
        status["credential_ref"],
        config["grants"]["deliver"]["credential_ref"]
    );
    assert_eq!(call("deliver", worker.into(), secret.into()).await.0, 403);
    // The persistent destination is still listening. Send the same attempt directly
    // through the production SSH client, separately from executor grant rejection.
    let value = read_when_ready(&root.join("target.json")).await;
    let target = SshTarget {
        address: "127.0.0.1".parse().unwrap(),
        port: value["port"].as_u64().unwrap().try_into().unwrap(),
        account: "restricted".into(),
        host_key_algorithm: "ssh-ed25519".into(),
        host_key_sha256: value["host_key_sha256"].as_str().unwrap().into(),
        helper_path: "/fixture/deliver".into(),
        identity_file: value["identity_file"].as_str().unwrap().into(),
    };
    let released = AtomicBool::new(false);
    let (_sender, cancel) = tokio::sync::watch::channel(false);
    let replay = ssh::execute(
        &target,
        status["attempt_id"].as_str().unwrap(),
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(5),
        cancel,
        || {
            released.store(true, Ordering::SeqCst);
            Ok(CANARY.as_bytes().to_vec())
        },
    )
    .await;
    assert_eq!(replay.outcome, ssh::SshOutcome::OutcomeUnknown);
    assert!(!released.load(Ordering::SeqCst));
    for name in ["bad-pin", "bad-key"] {
        let (code, state) = call(name, worker.into(), secret.into()).await;
        assert_eq!(code, 200);
        assert_eq!(state["state"], "failed_child");
    }
    for name in ["stdout", "stderr", "malformed", "lost-ack"] {
        let (code, state) = call(name, worker.into(), secret.into()).await;
        assert_eq!(code, 200);
        assert_eq!(state["state"], "outcome_unknown");
        // A missing/suppressed acknowledgement never makes the grant reusable.
        assert_eq!(call(name, worker.into(), secret.into()).await.0, 403);
    }
    assert!(!root.join("destination/vault").exists());
    write(&root.join("finish.json"), &json!(true));
    finish(&mut executor).await;
    finish(&mut destination).await;
    let observed = read_when_ready(&root.join("destination-result.json")).await;
    assert_eq!(observed["counts"]["connections"], 8);
    assert!(observed["counts"]["rejected_keys"].as_u64().unwrap() >= 1);
    assert_eq!(observed["counts"]["reservations"], 5);
    assert_eq!(observed["counts"]["deliveries"], 5);
    assert_eq!(observed["counts"]["replays"], 1);
    assert_eq!(observed["persisted_attempts"], 5);
    assert_eq!(observed["persisted_deliveries"], 5);
    let audit = read_when_ready(&root.join("audit.json")).await;
    verify_audit(&audit, &config);
    let attempts = read_when_ready(&root.join("attempts.json")).await;
    assert_eq!(attempts.as_array().unwrap().len(), 7);
    for row in attempts.as_array().unwrap() {
        let op = row["operation"].as_str().unwrap();
        let expected = match op {
            "deliver" => ("succeeded", 1),
            "bad-pin" | "bad-key" => ("failed_child", 0),
            "stdout" | "stderr" | "malformed" | "lost-ack" => ("outcome_unknown", 1),
            _ => panic!("unexpected operation attempt"),
        };
        assert_eq!(row["state"], expected.0);
        assert_eq!(row["releases"], expected.1);
        assert_eq!(row["provider_releases"], 0);
        assert_eq!(row["old_password_releases"], 0);
    }
    for bytes in [
        serde_json::to_vec(&audit).unwrap(),
        serde_json::to_vec(&attempts).unwrap(),
        std::fs::read(root.join("destination/attempts.db")).unwrap(),
    ] {
        private_output(&bytes, &forbidden);
    }
    for role in ["executor", "destination"] {
        for suffix in ["stdout", "stderr"] {
            private_output(
                &std::fs::read(root.join(format!("{role}.{suffix}"))).unwrap(),
                &forbidden,
            );
        }
    }
}

fn verify_audit(audit: &Value, config: &Value) {
    let rows = audit.as_array().unwrap();
    assert_eq!(rows.len(), 38);
    for row in rows {
        let object = row.as_object().unwrap();
        let expected = [
            "timestamp",
            "requester",
            "operation",
            "target",
            "environment",
            "credential_ref",
            "expires_at",
            "result",
        ];
        assert_eq!(object.len(), expected.len());
        assert!(expected.iter().all(|key| object.contains_key(*key)));
        for time in ["timestamp", "expires_at"] {
            assert!(chrono::DateTime::parse_from_rfc3339(row[time].as_str().unwrap()).is_ok());
        }
        let result = row["result"].as_str().unwrap();
        assert!(matches!(
            result,
            "authorized"
                | "started"
                | "succeeded"
                | "failed_child"
                | "outcome_unknown"
                | "denied"
                | "denied_identity"
                | "canceled"
        ));
        if result == "denied_identity" {
            assert_eq!(row["requester"], "identity_missing");
            assert!(row["credential_ref"].is_null());
            continue;
        }
        let name = row["operation"].as_str().unwrap();
        let grant = &config["grants"][name];
        assert!(!grant.is_null(), "audit operation must be reviewed");
        assert_eq!(row["credential_ref"], grant["credential_ref"]);
        assert_eq!(row["target"], "fixture-destination");
        assert_eq!(row["environment"], "synthetic");
        let requester = if name == "revoked" {
            &config["revoked_instance"]
        } else {
            &config["instance"]
        };
        assert!(
            row["requester"] == *requester
                || (name == "deliver"
                    && result == "denied"
                    && row["requester"] == config["other_instance"])
        );
    }
    let count = |op: &str, result: &str| {
        rows.iter()
            .filter(|row| row["operation"] == op && row["result"] == result)
            .count()
    };
    for op in config["grants"].as_object().unwrap().keys() {
        assert_eq!(count(op, "authorized"), 1);
    }
    for op in [
        "deliver",
        "bad-pin",
        "bad-key",
        "stdout",
        "stderr",
        "malformed",
        "lost-ack",
    ] {
        assert_eq!(count(op, "started"), 1);
        let result = match op {
            "deliver" => "succeeded",
            "bad-pin" | "bad-key" => "failed_child",
            _ => "outcome_unknown",
        };
        assert_eq!(count(op, result), 1);
    }
    for op in ["cancelled", "expired", "stale", "revoked"] {
        assert_eq!(count(op, "started"), 0);
    }
    for op in [
        "cancelled",
        "expired",
        "stale",
        "stdout",
        "stderr",
        "malformed",
        "lost-ack",
    ] {
        assert_eq!(count(op, "denied"), 1);
    }
    assert_eq!(count("deliver", "denied"), 3);
    assert_eq!(count("cancelled", "canceled"), 1);
    assert_eq!(
        rows.iter()
            .filter(|row| row["result"] == "denied_identity")
            .count(),
        2
    );
}

#[test]
#[ignore = "child of separate-process handoff test; requires marked disposable root"]
fn destination_child() {
    let root = child_root();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(process_handoff_destination::run(&root));
}

#[test]
#[ignore = "child of separate-process handoff test; requires marked disposable root"]
fn executor_child() {
    let root = child_root();
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut vault = Vault::init(MASTER).unwrap();
        vault.unlock_with_timeout(MASTER, Some(5)).unwrap();
        let credential = vault.add_credential(AddCredentialRequest::new("selected", CredentialType::ApiKey, CANARY)).unwrap();
        let stale = vault.add_credential(AddCredentialRequest::new("stale-selected", CredentialType::ApiKey, CANARY)).unwrap();
        let worker = vault.enroll_instance("requester", "fixture", &[]).unwrap();
        let other = vault.enroll_instance("other", "fixture", &[]).unwrap();
        let revoked = vault.enroll_instance("revoked", "fixture", &[]).unwrap();
        write(&root.join("executor-ready.json"), &json!(true));
        let target = read_when_ready(&root.join("target.json")).await;
        let names = ["deliver","bad-pin","bad-key","stdout","stderr","malformed","lost-ack","expired","stale","revoked","cancelled"];
        let mut operations = Vec::new();
        for name in names {
            let mut peer = target.clone();
            let wrong = peer.as_object_mut().unwrap().remove("wrong_identity_file").unwrap();
            if name == "bad-pin" { peer["host_key_sha256"] = json!("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }
            if name == "bad-key" { peer["identity_file"] = wrong; }
            peer["helper_path"] = json!(format!("/fixture/{}", if matches!(name,"stdout"|"stderr"|"malformed"|"lost-ack") { name } else { "deliver" }));
            operations.push(json!({"id":name,"kind":"ssh-helper","project_id":"default",
                "credential_id":if name == "stale" { &stale.id } else { &credential.id },
                "requester_principal":format!("instance:{}",if name == "revoked" { &revoked.instance.id } else { &worker.instance.id }),
                "environment_id":"synthetic","target_id":"fixture-destination","expires_at":"2099-01-01T00:00:00Z",
                "max_grant_seconds":300,"max_runtime_seconds":10,"connect_timeout_seconds":5,"max_concurrency":1,"ssh":peer}));
        }
        let raw = toml::to_string(&json!({"version":2,"operation":operations})).unwrap();
        crate::secure_files::write_private(&runtime::catalog_path(), raw.as_bytes()).unwrap();
        // Test-only seeding: the production CLI still requires fresh human approval.
        let mut issued = serde_json::Map::new();
        for name in names { issued.insert(name.into(), serde_json::to_value(runtime::authorize(&vault,name,120,None).unwrap()).unwrap()); }
        grants::cancel_grant(&vault, issued["cancelled"]["grant_id"].as_str().unwrap()).unwrap();
        vault.revoke_instance(&revoked.instance.id).unwrap();
        // Seed an already-expired test grant without sleeps or changing the system clock.
        vault.db().execute("UPDATE operation_grants SET expires_at=?1 WHERE id=?2", rusqlite::params![
            (chrono::Utc::now()-chrono::Duration::seconds(1)).to_rfc3339(), issued["expired"]["grant_id"].as_str().unwrap()]).unwrap();
        // Actual whole-value replacement makes the old grant's credential revision stale.
        vault.prepare_value_update("default","personal","stale-selected").unwrap().commit("synthetic-replacement").unwrap();
        write(&root.join("requester.json"), &json!({"instance":worker.instance.id,"secret":worker.secret,
            "other_instance":other.instance.id,"other_secret":other.secret,"revoked_instance":revoked.instance.id,
            "revoked_secret":revoked.secret,"grants":issued}));
        let proxy = tokio::spawn(crate::proxy::start_proxy_with_listeners(vec![
            crate::proxy::transport::ListenConfig::new(crate::proxy::transport::ListenSpec::default_tcp(0),
                crate::proxy::transport::IdentityRequirement::Require)],false));
        read_when_ready(&root.join("finish.json")).await;
        write(&root.join("audit.json"), &serde_json::to_value(grants::owner_audit(&vault,100).unwrap()).unwrap());
        let mut statement = vault.db().prepare("SELECT g.operation,a.state,a.secret_released,a.provider_released,a.old_password_released FROM operation_attempts a JOIN operation_grants g ON a.grant_id=g.id ORDER BY g.operation").unwrap();
        let rows: Vec<Value> = statement.query_map([], |row| Ok(json!({"operation":row.get::<_,String>(0)?,"state":row.get::<_,String>(1)?,
            "releases":row.get::<_,u64>(2)?,"provider_releases":row.get::<_,u64>(3)?,"old_password_releases":row.get::<_,u64>(4)?}))).unwrap().map(Result::unwrap).collect();
        write(&root.join("attempts.json"), &json!(rows));
        Vault::lock_session().unwrap();
        proxy.abort();
        let _ = proxy.await;
    });
}
