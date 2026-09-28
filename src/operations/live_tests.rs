//! Opt-in tests for tests/support/cross_node_fixture.py; never use real credentials.
use super::{catalog::SshTarget, environment::*, ssh};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

const SECRET: &[u8] = b"synthetic-cross-node-canary-v1";

fn fixture() -> Value {
    let path = std::env::var("WISPKEY_TEST_CROSS_NODE_FIXTURE")
        .expect("run tests/support/cross_node_fixture.py");
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(value["marker"], "wispkey-disposable-cross-node-v1");
    value
}

#[tokio::test]
#[ignore = "requires disposable OpenSSH from tests/support/cross_node_fixture.py"]
async fn disposable_openssh_pin_delivery_and_replay() {
    let value = fixture();
    let target = SshTarget {
        address: "127.0.0.1".parse().unwrap(),
        port: value["ssh_port"].as_u64().unwrap().try_into().unwrap(),
        account: "wispkey-ssh".into(),
        host_key_algorithm: "ssh-ed25519".into(),
        host_key_sha256: value["ssh_fingerprint"].as_str().unwrap().into(),
        helper_path: "/usr/local/libexec/wispkey-operation-helper".into(),
        identity_file: value["ssh_identity"].as_str().unwrap().into(),
    };
    let mut wrong = target.clone();
    wrong.host_key_sha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    let released = AtomicBool::new(false);
    let (_sender, cancel) = watch::channel(false);
    let rejected = ssh::execute(
        &wrong,
        &uuid::Uuid::new_v4().to_string(),
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(5),
        cancel,
        || {
            released.store(true, Ordering::SeqCst);
            Ok(SECRET.to_vec())
        },
    )
    .await;
    assert_ne!(rejected.outcome, ssh::SshOutcome::Succeeded);
    assert!(!released.load(Ordering::SeqCst));
    let attempt = uuid::Uuid::new_v4().to_string();
    let (_sender, cancel) = watch::channel(false);
    let accepted = ssh::execute(
        &target,
        &attempt,
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(5),
        cancel,
        || Ok(SECRET.to_vec()),
    )
    .await;
    assert_eq!(accepted.outcome, ssh::SshOutcome::Succeeded);
    assert_eq!(accepted.exit_code, Some(0));
    let (_sender, cancel) = watch::channel(false);
    let replay = ssh::execute(
        &target,
        &attempt,
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(5),
        cancel,
        || {
            released.store(true, Ordering::SeqCst);
            Ok(SECRET.to_vec())
        },
    )
    .await;
    assert_ne!(replay.outcome, ssh::SshOutcome::Succeeded);
    assert!(!released.load(Ordering::SeqCst));
}

fn sign_target(target: &mut KubernetesTarget) {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    target.posture_public_key = STANDARD_NO_PAD.encode(key.public_key().as_ref());
    let ca = std::fs::read(&target.ca_file).unwrap();
    let now = chrono::Utc::now();
    let payload = serde_json::to_vec(&json!({
        "endpoint":target.endpoint,"ca_sha256":STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256,&ca).as_ref()),
        "cluster_id":target.cluster_id,"context":target.context,"environment_id":target.environment_id,
        "namespace_uid":target.namespace_uid,"secret_uid":target.secret_uid,
        "environment_owner":target.environment_owner,"consumer_id":target.consumer_id,
        "issuer_id":target.issuer_id,"encryption_config_revision":target.encryption_config_revision,
        "issued_at":now-chrono::Duration::minutes(1),"expires_at":now+chrono::Duration::minutes(5)
    })).unwrap();
    let signed = json!({"payload":STANDARD_NO_PAD.encode(&payload),"signature":STANDARD_NO_PAD.encode(key.sign(&payload).as_ref())});
    crate::secure_files::write_private(&target.posture_file, &serde_json::to_vec(&signed).unwrap())
        .unwrap();
}

#[tokio::test]
#[ignore = "requires encrypted kind from tests/support/cross_node_fixture.py"]
async fn disposable_kubernetes_signed_delivery_idempotency_and_revocation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let value = fixture();
    let scratch = tempfile::tempdir().unwrap();
    let mut target = KubernetesTarget {
        endpoint: value["endpoint"].as_str().unwrap().into(),
        cluster_id: "fixture-cluster".into(),
        context: "fixture-context".into(),
        environment_id: "fixture-environment".into(),
        environment_owner: "fixture-owner".into(),
        consumer_id: "fixture-consumer".into(),
        issuer_id: "fixture-issuer".into(),
        namespace: "wk-acceptance".into(),
        namespace_uid: value["namespace_uid"].as_str().unwrap().into(),
        secret_name: "selected".into(),
        secret_uid: value["secret_uid"].as_str().unwrap().into(),
        data_key: "selected-value".into(),
        ca_file: PathBuf::from(value["ca_file"].as_str().unwrap()),
        provider_credential_id: uuid::Uuid::new_v4().to_string(),
        posture_file: scratch.path().join("posture.json"),
        posture_public_key: String::new(),
        encryption_config_revision: format!(
            "e-{}",
            &value["encryption_revision"].as_str().unwrap()[..60]
        ),
        action: KubernetesAction::Deliver,
    };
    sign_target(&mut target);
    let token =
        zeroize::Zeroizing::new(std::fs::read(value["token_file"].as_str().unwrap()).unwrap());
    let token_text = std::str::from_utf8(&token).unwrap();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&target.ca_file).unwrap()).unwrap(),
        )
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!(
        "{}/api/v1/namespaces/wk-acceptance/secrets/selected",
        target.endpoint
    );
    let released = AtomicBool::new(false);
    let mut wrong = target.clone();
    wrong.namespace_uid = uuid::Uuid::new_v4().to_string();
    sign_target(&mut wrong);
    let (_sender, cancel) = watch::channel(false);
    assert!(
        execute(
            &wrong,
            "fixture-wrong-uid",
            Instant::now() + Duration::from_secs(20),
            Duration::from_secs(5),
            cancel,
            || Ok(token.to_vec()),
            || {
                released.store(true, Ordering::SeqCst);
                Ok(SECRET.to_vec())
            }
        )
        .await
        .is_err()
    );
    assert!(!released.load(Ordering::SeqCst));
    sign_target(&mut target);
    let (_sender, cancel) = watch::channel(false);
    assert_eq!(
        execute(
            &target,
            "fixture-revision-1",
            Instant::now() + Duration::from_secs(20),
            Duration::from_secs(5),
            cancel,
            || Ok(token.to_vec()),
            || Ok(SECRET.to_vec())
        )
        .await
        .unwrap(),
        KubernetesOutcome::DeliveryAcknowledged
    );
    let delivered: Value = client
        .get(&url)
        .bearer_auth(token_text)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    // Use boolean assertions so even a failed test cannot print the credential.
    assert!(delivered["data"]["selected-value"].as_str() == Some(STANDARD.encode(SECRET).as_str()));
    assert_eq!(delivered["data"]["other"], STANDARD.encode(b"preserved"));
    assert_eq!(delivered["metadata"]["annotations"]["owner"], "preserved");
    let (_sender, cancel) = watch::channel(false);
    assert_eq!(
        execute(
            &target,
            "fixture-revision-1",
            Instant::now() + Duration::from_secs(20),
            Duration::from_secs(5),
            cancel,
            || Ok(token.to_vec()),
            || Ok(SECRET.to_vec())
        )
        .await
        .unwrap(),
        KubernetesOutcome::DeliveryAcknowledged
    );
    let repeated: Value = client
        .get(&url)
        .bearer_auth(token_text)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        repeated["metadata"]["resourceVersion"],
        delivered["metadata"]["resourceVersion"]
    );
    target.action = KubernetesAction::Revoke;
    let (_sender, cancel) = watch::channel(false);
    assert_eq!(
        execute(
            &target,
            "fixture-revision-2",
            Instant::now() + Duration::from_secs(20),
            Duration::from_secs(5),
            cancel,
            || Ok(token.to_vec()),
            || panic!("revocation must not release the selected credential")
        )
        .await
        .unwrap(),
        KubernetesOutcome::RevocationUnverified
    );
    let revoked: Value = client
        .get(&url)
        .bearer_auth(token_text)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(revoked["data"].get("selected-value").is_none());
    assert_eq!(revoked["data"]["other"], STANDARD.encode(b"preserved"));
    assert_eq!(revoked["metadata"]["uid"], target.secret_uid);
}
