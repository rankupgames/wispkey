//! Process-isolated disposable vaults. No production authentication or presence.
use super::*;
use crate::core::{
    GenerateWebsiteLoginRequest,
    auth::{AuthRegistration, ProviderExpiry},
};
use chrono::Utc;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::process::{Command as Process, Stdio};
use uuid::Uuid;

const USER: &str = "receiver-synthetic-user-canary";
const ORIGIN: &str = "https://login.synthetic.invalid";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    principal: Principal,
    binding_id: String,
    command: Command,
}
struct SyntheticTransport;
impl AuthenticatedTransport for SyntheticTransport {
    fn verify(&self, bytes: &[u8]) -> Result<VerifiedDelivery> {
        if bytes.len() <= 32 {
            return Err("denied");
        }
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]),
            &bytes[32..],
            &bytes[..32],
        )
        .map_err(|_| "denied")?;
        let w: Wire = serde_json::from_slice(&bytes[32..]).map_err(|_| "denied")?;
        Ok(VerifiedDelivery {
            principal: w.principal,
            binding_id: w.binding_id,
            command: w.command,
        })
    }
}
fn principal() -> Principal {
    Principal {
        issuer: "https://gateway.synthetic.invalid".into(),
        owner: "owner-a".into(),
        tenant: "tenant-a".into(),
        client: "client-a".into(),
        device: "device-a".into(),
    }
}
fn bytes(binding: &Binding, p: Principal, command: Command) -> Vec<u8> {
    let raw = serde_json::to_vec(&Wire {
        principal: p,
        binding_id: binding.id().into(),
        command,
    })
    .unwrap();
    let mut result = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]), &raw)
        .as_ref()
        .to_vec();
    result.extend(raw);
    result
}
fn command(binding: &Binding, job_id: &str) -> Command {
    Command::Request {
        job_id: job_id.into(),
        revision: binding.revision().into(),
        origin: ORIGIN.into(),
        account: "account-a".into(),
        profile: "owner-profile".into(),
        expires_at: binding.expires_at(),
    }
}
fn selected(v: &Vault) -> Binding {
    prepare(
        v,
        principal(),
        Selection {
            project: "default",
            partition: "personal",
            name: "login",
            origin: ORIGIN,
            account: "account-a",
            profile: "owner-profile",
        },
    )
    .unwrap()
}
fn request(v: &Vault, b: &Binding, job_id: &str) -> FillRequest {
    let data = bytes(b, principal(), command(b, job_id));
    assert!(receive(v, b, &SyntheticTransport, &data).is_ok());
    let id: String = v
        .db()
        .query_row(
            "SELECT request_id FROM browser_receiver_jobs WHERE binding_id=?1 AND job_id=?2",
            rusqlite::params![b.id(), job_id],
            |r| r.get(0),
        )
        .unwrap();
    crate::core::browser::status(v, &id).unwrap()
}
fn state(v: &Vault, b: &Binding, id: &str) -> State {
    match receive(
        v,
        b,
        &SyntheticTransport,
        &bytes(b, principal(), Command::Status { job_id: id.into() }),
    )
    .unwrap()
    {
        Receipt::Status(s) => s.state,
        _ => panic!("expected status"),
    }
}
fn no_canary(raw: &[u8]) {
    use base64::Engine;
    let text = String::from_utf8_lossy(raw);
    for s in [USER, "receiver-synthetic-password-canary+/&?"] {
        assert!(!text.contains(s), "plaintext canary leaked");
        assert!(
            !text.contains(&base64::engine::general_purpose::STANDARD.encode(s)),
            "encoded canary leaked"
        );
        assert!(
            !text.contains(&base64::engine::general_purpose::URL_SAFE.encode(s)),
            "URL-safe canary leaked"
        );
        assert!(
            !text.contains(urlencoding::encode(s).as_ref()),
            "percent-encoded canary leaked"
        );
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("", s)
            .finish();
        assert!(!text.contains(&encoded[1..]), "form-encoded canary leaked");
    }
    assert!(!text.contains("wk_"), "capability leaked");
}
fn fixture() -> Vault {
    let v = Vault::init("disposable-receiver-master").unwrap();
    v.generate_website_login(GenerateWebsiteLoginRequest {
        name: "login",
        username: USER,
        url: ORIGIN,
        project: Some("default"),
        partition: Some("personal"),
        review_at: None,
        length: None,
        symbols: true,
    })
    .unwrap();
    // Use the actual typed update path to install a distinctive disposable pair.
    let prepared = v
        .prepare_existing_login(
            "default",
            "personal",
            "login",
            ORIGIN,
            crate::core::ExistingLoginMode::Update,
        )
        .unwrap();
    prepared
        .commit(
            &crate::core::ExistingLoginInput::new(
                USER.into(),
                "receiver-synthetic-password-canary+/&?".into(),
            )
            .unwrap(),
        )
        .unwrap();
    v
}
fn approved(v: &Vault, r: &FillRequest) {
    let value = crate::browser_host::finish_approval(v, r, Ok(true)).unwrap();
    assert!(
        value.username == USER && value.password == "receiver-synthetic-password-canary+/&?",
        "wrong disposable payload"
    );
}
#[test]
fn disposable_process_matrix() {
    for case in [
        "lifecycle",
        "isolation",
        "rename",
        "partition",
        "origin",
        "metadata_aba",
        "delete",
        "race",
        "revocation",
        "restart",
        "atomicity",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let output = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "core::browser_receiver::tests::synthetic_child",
                "--nocapture",
            ])
            .env("WISPKEY_RECEIVER_TEST_CASE", case)
            .env("WISPKEY_VAULT_PATH", dir.path())
            .env("WISPKEY_PROTECTOR", "file")
            .env("WISPKEY_SESSION_TIMEOUT", "30")
            .env_remove("WISPKEY_PASSWORD")
            .env_remove("WISPKEY_SESSION_PLAINTEXT")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        no_canary(&output.stdout);
        no_canary(&output.stderr);
        assert!(
            output.status.success(),
            "receiver case {case} failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
#[test]
fn synthetic_child() {
    let Ok(case) = std::env::var("WISPKEY_RECEIVER_TEST_CASE") else {
        return;
    };
    let v = fixture();
    match case.as_str() {
        "lifecycle" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            let original = v.get_credential_in_project("default", "login").unwrap();
            let details = approval_details(&v, &r).unwrap();
            assert!(details.contains("owner-a"));
            no_canary(details.as_bytes());
            request(&v, &b, &job); // Identical delivery does not enqueue another request.
            let count: i64 = v
                .db()
                .query_row("SELECT COUNT(*) FROM browser_receiver_jobs", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(count, 1);
            approved(&v, &r);
            assert_eq!(state(&v, &b, &job), State::ReleaseCommitted);
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            crate::core::browser::finish(&v, &r.request_id, true).unwrap();
            assert_eq!(state(&v, &b, &job), State::Filled);
            request(&v, &b, &job);
            assert_eq!(state(&v, &b, &job), State::Filled);
            let current = v.get_credential_in_project("default", "login").unwrap();
            assert!(current.id == original.id && current.wisp_token == original.wisp_token);
            let events = outbox(&v, &b).unwrap();
            assert_eq!(events.len(), 3);
            no_canary(&serde_json::to_vec(&events).unwrap());
            let last = events.last().unwrap().sequence;
            receive(
                &v,
                &b,
                &SyntheticTransport,
                &bytes(&b, principal(), Command::Acknowledge { sequence: last }),
            )
            .unwrap();
            assert!(outbox(&v, &b).unwrap().is_empty());
            assert!(
                receive(
                    &v,
                    &b,
                    &SyntheticTransport,
                    &bytes(&b, principal(), Command::Acknowledge { sequence: last + 1 })
                )
                .is_err()
            );
        }
        "isolation" => {
            v.db().execute_batch("INSERT INTO partitions VALUES('other','other','','default','now','now'); INSERT INTO projects VALUES('other','other','','now','now');").unwrap();
            assert!(
                prepare(
                    &v,
                    principal(),
                    Selection {
                        project: "default",
                        partition: "other",
                        name: "login",
                        origin: ORIGIN,
                        account: "account-a",
                        profile: "owner-profile"
                    }
                )
                .is_err()
            );
            assert!(
                prepare(
                    &v,
                    principal(),
                    Selection {
                        project: "other",
                        partition: "personal",
                        name: "login",
                        origin: ORIGIN,
                        account: "account-a",
                        profile: "owner-profile"
                    }
                )
                .is_err()
            );
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            for field in 0..5 {
                let mut p = principal();
                match field {
                    0 => p.owner.push('x'),
                    1 => p.tenant.push('x'),
                    2 => p.client.push('x'),
                    3 => p.device.push('x'),
                    _ => p.issuer = "https://other.invalid".into(),
                };
                assert!(
                    receive(
                        &v,
                        &b,
                        &SyntheticTransport,
                        &bytes(&b, p, command(&b, &job))
                    )
                    .is_err()
                );
            }
            for field in 0..5 {
                let mut c = command(&b, &job);
                if let Command::Request {
                    revision,
                    origin,
                    account,
                    profile,
                    expires_at,
                    ..
                } = &mut c
                {
                    match field {
                        0 => revision.push('x'),
                        1 => origin.push_str(":444"),
                        2 => account.push('x'),
                        3 => profile.push('x'),
                        _ => *expires_at = 0,
                    }
                }
                assert!(receive(&v, &b, &SyntheticTransport, &bytes(&b, principal(), c)).is_err());
            }
            for bad in [vec![], vec![0; 8193], b"invalid".to_vec()] {
                assert!(receive(&v, &b, &SyntheticTransport, &bad).is_err());
            }
            let mut bad = bytes(&b, principal(), command(&b, &job));
            bad[0] ^= 1;
            assert!(receive(&v, &b, &SyntheticTransport, &bad).is_err());
            let other = selected(&v);
            let r = request(&v, &b, &job);
            assert!(
                receive(
                    &v,
                    &other,
                    &SyntheticTransport,
                    &bytes(
                        &other,
                        principal(),
                        Command::Cancel {
                            job_id: job.clone()
                        }
                    )
                )
                .is_err()
            );
            assert_eq!(state(&v, &b, &job), State::Queued);
            let mut replay = command(&b, &job);
            if let Command::Request { expires_at, .. } = &mut replay {
                *expires_at -= 1;
            }
            assert!(receive(&v, &b, &SyntheticTransport, &bytes(&b, principal(), replay)).is_err());
            v.db()
                .execute(
                    "UPDATE browser_fill_requests SET receiver_binding=NULL WHERE request_id=?1",
                    [&r.request_id],
                )
                .unwrap();
            let tampered = crate::core::browser::status(&v, &r.request_id).unwrap();
            assert!(crate::browser_host::finish_approval(&v, &tampered, Ok(true)).is_err());
        }
        "rename" | "partition" | "origin" | "metadata_aba" | "delete" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            let sql = match case.as_str() {
                "rename" => "UPDATE credentials SET name='other' WHERE name='login'",
                "partition" => "UPDATE credentials SET partition_id=NULL WHERE name='login'",
                "origin" => {
                    "UPDATE credentials SET origin='https://other.invalid' WHERE name='login'"
                }
                "metadata_aba" => {
                    "UPDATE credentials SET description='aba'; UPDATE credentials SET description=''"
                }
                _ => "DELETE FROM credentials WHERE name='login'",
            };
            let second = Vault::open_with_session().unwrap();
            second.db().execute_batch(sql).unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            assert_eq!(
                crate::core::browser::status(&v, &r.request_id)
                    .unwrap()
                    .status,
                "pending"
            );
        }
        "race" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let b = b.clone();
                    let job = job.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        let v = Vault::open_with_session().unwrap();
                        barrier.wait();
                        receive(
                            &v,
                            &b,
                            &SyntheticTransport,
                            &bytes(&b, principal(), command(&b, &job)),
                        )
                        .is_ok()
                    })
                })
                .collect();
            let successes = workers
                .into_iter()
                .filter_map(|t| t.join().ok())
                .filter(|ok| *ok)
                .count();
            assert!(successes >= 1);
            let count: i64 = v
                .db()
                .query_row("SELECT COUNT(*) FROM browser_receiver_jobs", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(count, 1);
            let r = request(&v, &b, &job);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let r = r.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        let v = Vault::open_with_session().unwrap();
                        barrier.wait();
                        crate::browser_host::finish_approval(&v, &r, Ok(true)).is_ok()
                    })
                })
                .collect();
            let successes = workers
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|ok| *ok)
                .count();
            assert_eq!(successes, 1);
            assert_eq!(state(&v, &b, &job), State::ReleaseCommitted);
        }
        "revocation" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            receive(
                &v,
                &b,
                &SyntheticTransport,
                &bytes(
                    &b,
                    principal(),
                    Command::Cancel {
                        job_id: job.clone(),
                    },
                ),
            )
            .unwrap();
            assert_eq!(state(&v, &b, &job), State::Cancelled);
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            revoke(&v, &b).unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            v.register_auth(
                "default",
                "login",
                AuthRegistration {
                    provider: "synthetic".into(),
                    account: "account-a".into(),
                    origins: vec![ORIGIN.into()],
                    provider_expiry: ProviderExpiry::NonExpiring,
                    use_until: Some(Utc::now() + chrono::Duration::minutes(10)),
                },
            )
            .unwrap();
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            v.db().execute("UPDATE auth_registry SET metadata_json=json_set(metadata_json,'$.revoked_at',?1)",[Utc::now().to_rfc3339()]).unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            // Reset only synthetic policy; a fresh binding must use the new generation.
            v.db().execute("UPDATE auth_registry SET metadata_json=json_set(metadata_json,'$.revoked_at',NULL)",[]).unwrap();
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            Vault::lock_session().unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
        }
        "restart" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            approved(&v, &r);
            let reopened = Vault::open_with_session().unwrap();
            let restored = restore_local_binding(&reopened, b.id()).unwrap();
            reconcile_after_restart(&reopened, &restored).unwrap();
            assert_eq!(state(&reopened, &restored, &job), State::OutcomeUnknown);
            assert!(crate::browser_host::finish_approval(&reopened, &r, Ok(true)).is_err());
            assert!(crate::core::browser::finish(&reopened, &r.request_id, true).is_err());
            assert!(!outbox(&reopened, &restored).unwrap().is_empty());
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            let r = request(&v, &b, &job);
            approved(&v, &r);
            receive(
                &v,
                &b,
                &SyntheticTransport,
                &bytes(
                    &b,
                    principal(),
                    Command::Cancel {
                        job_id: job.clone(),
                    },
                ),
            )
            .unwrap();
            assert_eq!(state(&v, &b, &job), State::OutcomeUnknown);
            assert!(crate::core::browser::finish(&v, &r.request_id, true).is_err());
        }
        "atomicity" => {
            let b = selected(&v);
            let job = Uuid::new_v4().to_string();
            v.db().execute_batch("CREATE TRIGGER deny_receiver_event BEFORE INSERT ON browser_receiver_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
            assert!(
                receive(
                    &v,
                    &b,
                    &SyntheticTransport,
                    &bytes(&b, principal(), command(&b, &job))
                )
                .is_err()
            );
            let count: i64 = v
                .db()
                .query_row("SELECT COUNT(*) FROM browser_receiver_jobs", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
            let count: i64 = v
                .db()
                .query_row("SELECT COUNT(*) FROM browser_fill_requests", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
            v.db()
                .execute_batch("DROP TRIGGER deny_receiver_event")
                .unwrap();
            let r = request(&v, &b, &job);
            v.db().execute_batch("CREATE TRIGGER deny_receiver_event BEFORE INSERT ON browser_receiver_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            assert_eq!(state(&v, &b, &job), State::Queued);
            assert_eq!(
                crate::core::browser::status(&v, &r.request_id)
                    .unwrap()
                    .status,
                "pending"
            );
            v.db()
                .execute_batch("DROP TRIGGER deny_receiver_event")
                .unwrap();
            v.db().execute_batch("CREATE TRIGGER change_during_release BEFORE INSERT ON browser_receiver_outbox WHEN NEW.state='release-committed' BEGIN UPDATE credentials SET description='changed-during-commit'; END;").unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            assert_eq!(state(&v, &b, &job), State::Queued);
            let description: String = v
                .db()
                .query_row(
                    "SELECT description FROM credentials WHERE name='login'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(description.is_empty());
            v.db()
                .execute_batch("DROP TRIGGER change_during_release")
                .unwrap();
            let now = Utc::now().timestamp();
            v.db()
                .execute(
                    "UPDATE browser_fill_requests SET expires_at=?1 WHERE request_id=?2",
                    rusqlite::params![now, r.request_id],
                )
                .unwrap();
            v.db()
                .execute(
                    "UPDATE browser_receiver_jobs SET expires_at=?1 WHERE request_id=?2",
                    rusqlite::params![now, r.request_id],
                )
                .unwrap();
            assert!(crate::browser_host::finish_approval(&v, &r, Ok(true)).is_err());
            assert_eq!(state(&v, &b, &job), State::Expired);
        }
        _ => panic!("unknown synthetic case"),
    }
    let mut stmt=v.db().prepare("SELECT event_type,COALESCE(credential_name,''),COALESCE(wisp_token,''),COALESCE(deny_reason,'') FROM audit_log").unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "{} {} {} {}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?
            ))
        })
        .unwrap();
    for row in rows {
        no_canary(row.unwrap().as_bytes());
    }
}
