//! Authenticated operation execution. Only the owner CLI can issue grants.
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::{Instant, interval};

use super::{catalog, environment, identity, postgres, ssh};
use crate::core::{Vault, operation_grants as grants};
use grants::{AuthenticatedRequester, GrantState, OperationBinding};

type Result<T> = std::result::Result<T, &'static str>;

pub(crate) fn catalog_path() -> PathBuf {
    Vault::vault_dir().join("operations.toml")
}

pub(crate) fn load_operation(
    path: &Path,
    id: &str,
) -> Result<(catalog::Operation, OperationBinding)> {
    let raw = identity::read_private_catalog(path)?;
    let parsed = catalog::parse_catalog(&raw)?;
    if parsed.version != 2 {
        return Err("execution requires a version 2 instance-bound catalog");
    }
    let entry = parsed
        .operations
        .iter()
        .find(|op| op.id == id)
        .ok_or("operation unavailable")?
        .clone();
    let encoded = serde_json::to_vec(&parsed).map_err(|_| "catalog unavailable")?;
    let mut revision = ring::digest::Context::new(&ring::digest::SHA256);
    revision.update(b"wispkey-operation-catalog-v2\0");
    revision.update(&encoded);
    let requester = entry
        .requester_principal
        .strip_prefix("instance:")
        .ok_or("authenticated instance required")?;
    let mut expires_at = entry.expires_at;
    let (provider_credential_id, provider_project_id, old_password_credential_id) =
        match &entry.kind {
            catalog::OperationKind::SshHelper(_) => (None, None, None),
            catalog::OperationKind::KubernetesSecret(target) => {
                let (snapshot, posture_expiry) = target.snapshot_revision()?;
                revision.update(snapshot.as_bytes());
                expires_at = expires_at.min(posture_expiry);
                (
                    Some(target.provider_credential_id.clone()),
                    Some(entry.project_id.clone()),
                    None,
                )
            }
            catalog::OperationKind::PostgresPassword(target) => {
                revision.update(target.snapshot_revision()?.as_bytes());
                (
                    Some(target.provider_credential_id.clone()),
                    Some(entry.project_id.clone()),
                    Some(target.previous_credential_id.clone()),
                )
            }
        };
    let binding = OperationBinding {
        operation: entry.id.clone(),
        target: entry.target_id.clone(),
        environment: entry.environment_id.clone(),
        credential_id: entry.credential_id.clone(),
        project_id: entry.project_id.clone(),
        catalog_revision: revision
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        requester_instance_id: requester.to_owned(),
        expires_at,
        max_runtime_seconds: entry.max_runtime_seconds,
        max_grant_seconds: entry.max_grant_seconds,
        provider_credential_id,
        provider_project_id,
        old_password_credential_id,
    };
    Ok((entry, binding))
}

pub(crate) fn authorize(
    vault: &Vault,
    operation: &str,
    seconds: u32,
    reviewed_revision: Option<&str>,
) -> Result<grants::GrantStatus> {
    let (_, binding) = load_operation(&catalog_path(), operation)?;
    if reviewed_revision.is_some_and(|revision| revision != binding.catalog_revision) {
        return Err("catalog changed during owner approval");
    }
    if seconds == 0 || seconds > binding.max_grant_seconds {
        return Err("invalid grant lifetime");
    }
    let expires = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(i64::from(seconds)))
        .ok_or("invalid grant lifetime")?;
    grants::issue_grant(vault, &binding, expires)
}

fn authenticate(id: &str, secret: &str) -> Result<AuthenticatedRequester> {
    let vault = Vault::open_with_session().map_err(|_| "requester authentication failed")?;
    AuthenticatedRequester::authenticate(&vault, id, secret).inspect_err(|_| {
        let _ = grants::record_denial(&vault, None, None);
    })
}

pub(crate) fn audit_identity_denial() {
    audit_denial(None, None);
}

fn audit_denial(requester: Option<&AuthenticatedRequester>, grant: Option<&str>) {
    if let Ok(vault) = Vault::open_with_session() {
        let _ = grants::record_denial(&vault, requester, grant);
    }
}

fn terminal_unknown(mut attempt: grants::AttemptStatus) -> grants::AttemptStatus {
    attempt.state = GrantState::OutcomeUnknown;
    attempt.exit_code = None;
    attempt
}

async fn execute(
    requester: &AuthenticatedRequester,
    grant_id: &str,
) -> Result<grants::AttemptStatus> {
    // Drop SQLite before awaiting transport; each release/watch reopens the session.
    let (entry, attempt) = {
        let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
        let grant = grants::requester_grant_status(&vault, requester, grant_id)?;
        let (entry, binding) = load_operation(&catalog_path(), &grant.operation)?;
        let attempt = grants::reserve(&vault, requester, grant_id, &binding)?;
        (entry, attempt)
    };
    let remaining = (attempt.hard_deadline - Utc::now())
        .to_std()
        .unwrap_or_default();
    let deadline = Instant::now() + remaining;
    let (cancel, cancellation) = watch::channel(false);
    let release = || {
        let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
        let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
        grants::decrypt_reserved(&vault, requester, &attempt, &binding)
    };
    let mut transport = Box::pin(async {
        match &entry.kind {
            catalog::OperationKind::SshHelper(target) => {
                let observed = ssh::execute(
                    target,
                    &attempt.attempt_id,
                    deadline,
                    Duration::from_secs(u64::from(entry.connect_timeout_seconds)),
                    cancellation,
                    release,
                )
                .await;
                let state = match observed.outcome {
                    ssh::SshOutcome::Succeeded => GrantState::Succeeded,
                    ssh::SshOutcome::FailedChild => GrantState::FailedChild,
                    ssh::SshOutcome::TimedOut => GrantState::TimedOut,
                    ssh::SshOutcome::Canceled => GrantState::Canceled,
                    ssh::SshOutcome::OutcomeUnknown => GrantState::OutcomeUnknown,
                };
                (state, observed.exit_code)
            }
            catalog::OperationKind::KubernetesSecret(target) => {
                let revision = (|| {
                    let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
                    let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
                    grants::delivery_revision(&vault, requester, &attempt, &binding)
                })();
                let Ok(revision) = revision else {
                    return (GrantState::OutcomeUnknown, None);
                };
                let provider = || {
                    let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
                    let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
                    grants::decrypt_provider(&vault, requester, &attempt, &binding)
                };
                let result = environment::execute(
                    target,
                    &revision,
                    deadline,
                    Duration::from_secs(u64::from(entry.connect_timeout_seconds)),
                    cancellation,
                    provider,
                    release,
                )
                .await;
                let state = match result {
                    Ok(environment::KubernetesOutcome::DeliveryAcknowledged) => {
                        GrantState::DeliveryAcknowledged
                    }
                    Ok(environment::KubernetesOutcome::RevocationUnverified) => {
                        GrantState::RevocationUnverified
                    }
                    Ok(environment::KubernetesOutcome::OutcomeUnknown) | Err(_) => {
                        GrantState::OutcomeUnknown
                    }
                };
                (state, None)
            }
            catalog::OperationKind::PostgresPassword(target) => {
                let provider = || {
                    let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
                    let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
                    grants::decrypt_provider(&vault, requester, &attempt, &binding)
                };
                let previous = || {
                    let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
                    let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
                    grants::decrypt_previous(&vault, requester, &attempt, &binding)
                };
                let result = postgres::execute(
                    target,
                    deadline,
                    Duration::from_secs(u64::from(entry.connect_timeout_seconds)),
                    cancellation,
                    provider,
                    previous,
                    release,
                )
                .await;
                let state = match result {
                    Ok(postgres::PostgresOutcome::RotationVerified) => GrantState::Succeeded,
                    Ok(postgres::PostgresOutcome::OutcomeUnknown) | Err(_) => {
                        GrantState::OutcomeUnknown
                    }
                };
                (state, None)
            }
        }
    });
    let mut tick = interval(Duration::from_millis(100));
    let mut observed = loop {
        tokio::select! {
            result = &mut transport => break result,
            _ = tick.tick() => {
                let valid = (|| {
                    let (_, binding) = load_operation(&catalog_path(), &entry.id)?;
                    let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
                    grants::attempt_still_authorized(&vault, requester, &attempt, &binding)
                })();
                if valid.is_err() { let _ = cancel.send(true); }
            }
        }
    };
    let Ok(vault) = Vault::open_with_session() else {
        return Ok(terminal_unknown(attempt.clone()));
    };
    if matches!(
        observed.0,
        GrantState::Succeeded | GrantState::DeliveryAcknowledged
    ) {
        let valid = load_operation(&catalog_path(), &entry.id).and_then(|(_, binding)| {
            grants::attempt_still_authorized(&vault, requester, &attempt, &binding)
        });
        if valid.is_err() {
            observed = (GrantState::OutcomeUnknown, None);
        }
    }
    Ok(grants::finish_attempt(
        &vault,
        requester,
        &attempt.attempt_id,
        observed.0,
        observed.1,
    )
    .unwrap_or_else(|_| terminal_unknown(attempt.clone())))
}

pub(crate) async fn handle_api(
    method: &str,
    path: &str,
    instance_id: &str,
    secret: &str,
) -> (u16, Value) {
    let requester = match authenticate(instance_id, secret) {
        Ok(value) => value,
        Err(_) => return (401, json!({"error":"requester authentication failed"})),
    };
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 4
        || parts.len() > 5
        || parts[0] != "api"
        || parts[1] != "operations"
        || !uuid::Uuid::parse_str(parts[3])
            .is_ok_and(|id| !id.is_nil() && id.to_string() == parts[3])
    {
        audit_denial(Some(&requester), None);
        return (404, json!({"error":"operation route unavailable"}));
    }
    if method == "POST" && parts[2] == "grants" && parts.get(4) == Some(&"execute") {
        return match Box::pin(execute(&requester, parts[3])).await {
            Ok(status) => (200, json!(status)),
            Err(error) => {
                audit_denial(Some(&requester), Some(parts[3]));
                (403, json!({"error":error}))
            }
        };
    }
    let result = (|| -> Result<Value> {
        let vault = Vault::open_with_session().map_err(|_| "session unavailable")?;
        match (method, parts[2], parts.get(4).copied()) {
            ("GET", "grants", None) => Ok(json!(grants::requester_grant_status(
                &vault, &requester, parts[3]
            )?)),
            ("GET", "attempts", None) => Ok(json!(grants::requester_attempt_status(
                &vault, &requester, parts[3]
            )?)),
            ("POST", "grants", Some("cancel")) => {
                grants::requester_grant_status(&vault, &requester, parts[3])?;
                Ok(json!(grants::cancel_grant(&vault, parts[3])?))
            }
            ("POST", "attempts", Some("cancel")) => {
                grants::requester_attempt_status(&vault, &requester, parts[3])?;
                Ok(json!(grants::request_cancel(&vault, parts[3])?))
            }
            _ => Err("operation route unavailable"),
        }
    })();
    match result {
        Ok(value) => (200, value),
        Err(error) => {
            audit_denial(Some(&requester), (parts[2] == "grants").then_some(parts[3]));
            (403, json!({"error":error}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    const CANARY: &str = "synthetic-runtime-credential-canary";

    #[test]
    fn isolated_grant_to_ssh_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operations::runtime::tests::runtime_fixture_child",
                "--ignored",
                "--nocapture",
            ])
            .env("WISPKEY_RUNTIME_FIXTURE", "1")
            .env("WISPKEY_VAULT_PATH", dir.path().canonicalize().unwrap())
            .env("WISPKEY_PROTECTOR", "file")
            .env_remove("WISPKEY_PASSWORD")
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
        assert!(
            output.status.success(),
            "isolated runtime fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "invoked by isolated_grant_to_ssh_roundtrip with a disposable vault"]
    fn runtime_fixture_child() {
        assert_eq!(std::env::var("WISPKEY_RUNTIME_FIXTURE").as_deref(), Ok("1"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut vault = Vault::init("synthetic-test-master-password").unwrap();
            vault.unlock_with_timeout("synthetic-test-master-password", Some(5)).unwrap();
            let credential = vault.add_credential(crate::core::AddCredentialRequest::new(
                "runtime-fixture", crate::core::CredentialType::ApiKey, CANARY)).unwrap();
            let worker = vault.enroll_instance("runtime-worker", "fixture", &[]).unwrap();
            let other = vault.enroll_instance("other-worker", "fixture", &[]).unwrap();
            let server = ssh::tests::spawn_success_fixture(CANARY.as_bytes().to_vec()).await;
            let target = server.target.clone();
            #[cfg(windows)]
            let target = {
                let mut target = target;
                target.identity_file = target.identity_file.trim_start_matches(r"\\?\").replace('\\', "/");
                target
            };
            let raw = toml::to_string(&json!({"version":2, "operation":[{
                "id":"maintenance", "kind":"ssh-helper", "project_id":"default",
                "credential_id":credential.id, "requester_principal":format!("instance:{}",worker.instance.id),
                "environment_id":"test", "target_id":"test-host", "expires_at": "2099-01-01T00:00:00Z",
                "max_grant_seconds":300, "max_runtime_seconds":30,"connect_timeout_seconds":5,"max_concurrency":1,
                "ssh":target
            }]})).unwrap();
            let path = catalog_path();
            std::fs::write(&path, raw).unwrap();
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            #[cfg(windows)] {
                crate::secure_files::harden_existing_file(&path).unwrap();
                let principal = identity::current_principal().unwrap();
                let sid = principal.strip_prefix("windows-sid:").unwrap();
                assert!(std::process::Command::new("icacls").arg(&path).args(["/setowner", &format!("*{sid}")])
                    .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap().success());
            }
            let grant = authorize(&vault, "maintenance", 60, None).unwrap();
            let route = format!("/api/operations/grants/{}/execute", grant.grant_id);
            assert_eq!(handle_api("POST", &route, &other.instance.id, &other.secret).await.0, 403);
            assert_eq!(handle_api("POST", &route, &worker.instance.id, "wrong-secret").await.0, 401);
            assert_eq!(server.received.load(Ordering::SeqCst), 0);
            let (code, status) = handle_api("POST", &route, &worker.instance.id, &worker.secret).await;
            assert_eq!(code, 200);
            assert_eq!(status["state"], "succeeded");
            assert!(server.saw_secret.load(Ordering::SeqCst));
            assert!(!status.to_string().contains(CANARY));
            assert_eq!(handle_api("POST", &route, &worker.instance.id, &worker.secret).await.0, 403);
            let audit = serde_json::to_value(grants::owner_audit(&vault, 100).unwrap()).unwrap();
            assert!(!audit.to_string().contains(CANARY));
            assert!(audit.as_array().unwrap().iter().all(|row| row.as_object().unwrap().len()==8));
            let unused = authorize(&vault, "maintenance", 60, None).unwrap();
            Vault::lock_session().unwrap();
            let locked_route = format!("/api/operations/grants/{}/execute", unused.grant_id);
            assert_eq!(handle_api("POST", &locked_route, &worker.instance.id, &worker.secret).await.0, 401);
            server.server_task.abort();
        });
    }
}
