//! Short-lived, metadata-only browser requests. Request IDs never authorize disclosure.
use base64::Engine;
use chrono::Utc;
use rusqlite::{Connection, params};
use serde::Serialize;

use super::{CredentialType, LIFECYCLE_ARCHIVED, Vault, WebsiteLoginPayload, parse_https_origin};
use crate::audit;

const TTL_SECONDS: i64 = 300;
const MAX_PENDING: i64 = 32;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, Serialize)]
pub struct FillRequest {
    pub request_id: String,
    pub name: String,
    pub project: String,
    pub origin: String,
    /// Untrusted, agent-supplied labels; never an authenticated identity.
    pub requester: String,
    pub reason: String,
    pub status: String,
    pub expires_at: i64,
    #[serde(skip)]
    credential_id: String,
    #[serde(skip)]
    revision: String,
}

pub(crate) fn create_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS browser_fill_requests (
        request_id TEXT PRIMARY KEY,
        name TEXT NOT NULL, project TEXT NOT NULL, origin TEXT NOT NULL,
        requester TEXT NOT NULL, reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','completed','failed')),
        expires_at INTEGER NOT NULL, credential_id TEXT NOT NULL, revision TEXT NOT NULL
    );",
    )
}

fn metadata_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty()
        && text.len() <= max
        && !text.chars().any(|c| {
            c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
        })
}

fn revision(vault: &Vault, id: &str) -> Result<String> {
    let encoded: String = vault
        .db()
        .query_row(
            "SELECT encrypted_value || updated_at FROM credentials WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .map_err(|_| "login unavailable")?;
    Ok(base64::engine::general_purpose::STANDARD
        .encode(ring::digest::digest(&ring::digest::SHA256, encoded.as_bytes()).as_ref()))
}

fn log(vault: &Vault, request: &FillRequest, event: &str) -> Result<()> {
    // No arbitrary request text or secret material in audit events.
    audit::try_log_event(
        vault.db(),
        event,
        Some(&request.name),
        None,
        Some(&request.origin),
        None,
        None,
        None,
        event == "BrowserFillDenied",
        None,
        Some(&request.project),
    )
    .map_err(|_| "unable to audit browser request")
}

fn expire(vault: &Vault) -> Result<()> {
    let db = vault.db();
    let tx = db
        .unchecked_transaction()
        .map_err(|_| "browser request store unavailable")?;
    let now = Utc::now().timestamp();
    let expired = read_requests(
        vault,
        "SELECT * FROM browser_fill_requests WHERE status IN ('pending','approved') AND expires_at <= ?1",
        now,
    )?;
    for request in expired {
        log(vault, &request, "BrowserFillFailed")?;
    }
    db.execute("UPDATE browser_fill_requests SET status='failed' WHERE status IN ('pending','approved') AND expires_at <= ?1", [now])
        .map_err(|_| "browser request store unavailable")?;
    // Retain terminal metadata for one day; the audit trail remains in audit_log.
    db.execute(
        "DELETE FROM browser_fill_requests WHERE expires_at < ?1",
        [now - 86400],
    )
    .map_err(|_| "browser request store unavailable")?;
    tx.commit().map_err(|_| "browser request store unavailable")
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FillRequest> {
    Ok(FillRequest {
        request_id: row.get("request_id")?,
        name: row.get("name")?,
        project: row.get("project")?,
        origin: row.get("origin")?,
        requester: row.get("requester")?,
        reason: row.get("reason")?,
        status: row.get("status")?,
        expires_at: row.get("expires_at")?,
        credential_id: row.get("credential_id")?,
        revision: row.get("revision")?,
    })
}

fn read_requests(vault: &Vault, sql: &str, arg: impl rusqlite::ToSql) -> Result<Vec<FillRequest>> {
    let mut statement = vault
        .db()
        .prepare(sql)
        .map_err(|_| "browser request store unavailable")?;
    statement
        .query_map([arg], from_row)
        .map_err(|_| "browser request store unavailable")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| "browser request store unavailable")
}

pub fn request(
    vault: &Vault,
    name: &str,
    project: &str,
    origin: &str,
    requester: &str,
    reason: &str,
) -> Result<FillRequest> {
    vault
        .ensure_unlocked()
        .map_err(|_| "unlock WispKey before requesting browser fill")?;
    if !metadata_text(name, 96)
        || !metadata_text(project, 96)
        || !metadata_text(requester, 64)
        || !metadata_text(reason, 160)
    {
        return Err(
            "name, project, requester and reason must be short, nonempty text without control characters",
        );
    }
    let origin = parse_https_origin(origin).map_err(|_| "an HTTPS origin is required")?;
    if origin.len() > 300 {
        return Err("origin is too long");
    }
    expire(vault)?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "browser request store unavailable")?;
    let credential = vault
        .get_credential_in_project(project, name)
        .map_err(|_| "login unavailable")?;
    if credential.credential_type != CredentialType::WebsiteLogin
        || credential.lifecycle_state == LIFECYCLE_ARCHIVED
        || credential.origin != origin
    {
        return Err("login type, lifecycle or exact HTTPS origin does not match");
    }
    let count: i64 = vault
        .db()
        .query_row(
            "SELECT COUNT(*) FROM browser_fill_requests WHERE status IN ('pending','approved')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "browser request store unavailable")?;
    if count >= MAX_PENDING {
        return Err("too many pending browser requests; deny or wait for expiry");
    }
    let request = FillRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        name: name.into(),
        project: project.into(),
        origin,
        requester: requester.into(),
        reason: reason.into(),
        status: "pending".into(),
        expires_at: Utc::now().timestamp() + TTL_SECONDS,
        revision: revision(vault, &credential.id)?,
        credential_id: credential.id,
    };
    vault
        .db()
        .execute(
            "INSERT INTO browser_fill_requests VALUES (?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9)",
            params![
                request.request_id,
                request.name,
                request.project,
                request.origin,
                request.requester,
                request.reason,
                request.expires_at,
                request.credential_id,
                request.revision
            ],
        )
        .map_err(|_| "browser request store unavailable")?;
    log(vault, &request, "BrowserFillRequested")?;
    tx.commit()
        .map_err(|_| "browser request store unavailable")?;
    Ok(request)
}

pub fn status(vault: &Vault, id: &str) -> Result<FillRequest> {
    expire(vault)?;
    load(vault, id)
}

fn load(vault: &Vault, id: &str) -> Result<FillRequest> {
    vault
        .db()
        .query_row(
            "SELECT * FROM browser_fill_requests WHERE request_id=?1",
            [id],
            from_row,
        )
        .map_err(|_| "browser request not found")
}

pub(crate) fn pending(vault: &Vault, origin: &str) -> Result<Vec<FillRequest>> {
    expire(vault)?;
    read_requests(
        vault,
        "SELECT * FROM browser_fill_requests WHERE origin=?1 AND status='pending' ORDER BY expires_at",
        origin,
    )
}

pub(crate) fn deny(vault: &Vault, id: &str) -> Result<()> {
    expire(vault)?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "browser request store unavailable")?;
    let request = load(vault, id)?;
    transition(vault, &request, "pending", "denied", "BrowserFillDenied")?;
    tx.commit().map_err(|_| "browser request store unavailable")
}

fn transition(
    vault: &Vault,
    request: &FillRequest,
    from: &str,
    to: &str,
    event: &str,
) -> Result<()> {
    let updated = vault.db().execute("UPDATE browser_fill_requests SET status=?1 WHERE request_id=?2 AND status=?3 AND expires_at>?4",
        params![to, request.request_id, from, Utc::now().timestamp()]).map_err(|_| "browser request store unavailable")?;
    if updated != 1 {
        return Err("request expired or already decided");
    }
    log(vault, request, event)
}

/// Only the native host calls this, after OS user verification. Never exposed via MCP/IPC.
/// Reopen the session after the approval prompt, then revalidate within one transaction.
pub(crate) fn release(vault: &Vault, approved: &FillRequest) -> Result<WebsiteLoginPayload> {
    expire(vault)?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "browser request store unavailable")?;
    let current = load(vault, &approved.request_id)?;
    if current.credential_id != approved.credential_id
        || current.revision != approved.revision
        || current.origin != approved.origin
        || current.project != approved.project
        || current.name != approved.name
        || current.requester != approved.requester
        || current.reason != approved.reason
    {
        return Err("request changed after approval");
    }
    let credential = vault
        .get_credential_in_project(&current.project, &current.name)
        .map_err(|_| "login unavailable")?;
    if credential.id != current.credential_id
        || credential.origin != current.origin
        || credential.credential_type != CredentialType::WebsiteLogin
        || credential.lifecycle_state == LIFECYCLE_ARCHIVED
        || revision(vault, &credential.id)? != current.revision
    {
        return Err("login changed; create a new browser request");
    }
    transition(
        vault,
        &current,
        "pending",
        "approved",
        "BrowserFillApproved",
    )?;
    let plaintext = vault
        .decrypt_credential_value_in_project(&current.project, &current.name)
        .map_err(|_| "login unavailable")?;
    let payload = serde_json::from_str(&plaintext).map_err(|_| "invalid website login")?;
    tx.commit()
        .map_err(|_| "browser request store unavailable")?;
    Ok(payload)
}

pub(crate) fn finish(vault: &Vault, id: &str, completed: bool) -> Result<()> {
    expire(vault)?;
    let tx = vault
        .db()
        .unchecked_transaction()
        .map_err(|_| "browser request store unavailable")?;
    let request = load(vault, id)?;
    let (status, event) = if completed {
        ("completed", "BrowserFillCompleted")
    } else {
        ("failed", "BrowserFillFailed")
    };
    transition(vault, &request, "approved", status, event)?;
    tx.commit().map_err(|_| "browser request store unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GenerateWebsiteLoginRequest, LIFECYCLE_ACTIVE};

    fn fixture() -> Vault {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        let now = Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO projects VALUES ('default','default','',?1,?1)",
            [&now],
        )
        .unwrap();
        db.execute(
            "INSERT INTO partitions VALUES ('personal','personal','','default',?1,?1)",
            [&now],
        )
        .unwrap();
        let vault = Vault {
            db,
            master_key: Some([7; 32]),
            session_timeout_override: None,
        };
        create_login(&vault);
        vault
    }

    fn create_login(vault: &Vault) {
        vault
            .generate_website_login(GenerateWebsiteLoginRequest {
                name: "careers",
                username: "test@example.com",
                url: "https://jobs.example.com",
                project: Some("default"),
                partition: None,
                review_at: None,
                length: None,
                symbols: true,
            })
            .unwrap();
    }

    fn enqueue(vault: &Vault) -> FillRequest {
        request(
            vault,
            "careers",
            "default",
            "https://jobs.example.com",
            "test-agent",
            "Apply for a job",
        )
        .unwrap()
    }

    #[test]
    fn browser_request_metadata_and_audit_never_contain_login_payload() {
        let vault = fixture();
        let request = enqueue(&vault);
        let password = release(&vault, &request).unwrap().password;
        let text = serde_json::to_string(&status(&vault, &request.request_id).unwrap()).unwrap();
        assert!(!text.contains(&password));
        assert!(!text.contains("credential_id"));
        assert!(!text.contains("revision"));
        assert!(release(&vault, &request).is_err(), "approval is one use");
        finish(&vault, &request.request_id, true).unwrap();
        assert_eq!(
            status(&vault, &request.request_id).unwrap().status,
            "completed"
        );
        assert!(finish(&vault, &request.request_id, true).is_err());
        let logs: String = vault
            .db()
            .query_row(
                "SELECT group_concat(event_type || coalesce(target_host,'')) FROM audit_log",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(logs.contains("BrowserFillApproved"));
        assert!(logs.contains("BrowserFillCompleted"));
        assert!(!logs.contains(&password));
        assert_eq!(
            vault
                .get_credential_in_project("default", "careers")
                .unwrap()
                .lifecycle_state,
            "pending"
        );
    }

    #[test]
    fn browser_requests_reject_wrong_origins_projects_and_archived_logins() {
        let vault = fixture();
        for origin in [
            "http://jobs.example.com",
            "https://jobs.example.com.evil.test",
            "https://jobs.example.com:444",
        ] {
            assert!(request(&vault, "careers", "default", origin, "agent", "test").is_err());
        }
        assert!(
            request(
                &vault,
                "careers",
                "other",
                "https://jobs.example.com",
                "agent",
                "test"
            )
            .is_err()
        );
        vault
            .set_credential_lifecycle("careers", LIFECYCLE_ARCHIVED, Some("default"))
            .unwrap();
        assert!(
            request(
                &vault,
                "careers",
                "default",
                "https://jobs.example.com",
                "agent",
                "test"
            )
            .is_err()
        );
    }

    #[test]
    fn browser_requests_fail_after_expiry_denial_replacement_or_change() {
        let vault = fixture();
        let expired = enqueue(&vault);
        vault
            .db()
            .execute(
                "UPDATE browser_fill_requests SET expires_at=?1",
                [Utc::now().timestamp() - 1],
            )
            .unwrap();
        assert_eq!(
            status(&vault, &expired.request_id).unwrap().status,
            "failed"
        );
        assert!(release(&vault, &expired).is_err());
        let denied = enqueue(&vault);
        deny(&vault, &denied.request_id).unwrap();
        assert!(release(&vault, &denied).is_err());
        let replaced = enqueue(&vault);
        vault
            .remove_credential_in_project("default", "careers")
            .unwrap();
        create_login(&vault);
        assert!(release(&vault, &replaced).is_err());
        let changed = enqueue(&vault);
        vault
            .set_credential_lifecycle("careers", LIFECYCLE_ACTIVE, Some("default"))
            .unwrap();
        assert!(release(&vault, &changed).is_err());
    }

    #[test]
    fn browser_requests_bound_pending_queue_and_untrusted_labels() {
        let vault = fixture();
        assert!(
            request(
                &vault,
                "careers",
                "default",
                "https://jobs.example.com",
                "agent\nApproved",
                "reason"
            )
            .is_err()
        );
        assert!(
            request(
                &vault,
                "careers",
                "default",
                "https://jobs.example.com",
                "agent",
                &"x".repeat(161)
            )
            .is_err()
        );
        for _ in 0..MAX_PENDING {
            enqueue(&vault);
        }
        assert!(
            request(
                &vault,
                "careers",
                "default",
                "https://jobs.example.com",
                "agent",
                "reason"
            )
            .is_err()
        );
    }

    #[test]
    fn browser_schema_migrates_v11_and_concurrent_release_has_one_winner() {
        let vault = fixture();
        vault
            .db()
            .execute_batch(
                "DROP TABLE browser_fill_requests;
            INSERT INTO vault_meta VALUES ('version','11');",
            )
            .unwrap();
        Vault::migrate_schema(vault.db()).unwrap();
        let version: String = vault
            .db()
            .query_row(
                "SELECT value FROM vault_meta WHERE key='version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, super::super::CURRENT_SCHEMA_VERSION);
        let request = enqueue(&vault);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.db");
        vault
            .db()
            .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let request = request.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    let vault = Vault {
                        db,
                        master_key: Some([7; 32]),
                        session_timeout_override: None,
                    };
                    barrier.wait();
                    release(&vault, &request).is_ok()
                })
            })
            .collect();
        let winners = handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>();
        assert_eq!(winners, 1);
    }

    #[test]
    fn browser_release_rolls_back_if_audit_cannot_be_written() {
        let vault = fixture();
        let request = enqueue(&vault);
        vault.db().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'full'); END;").unwrap();
        assert!(release(&vault, &request).is_err());
        assert_eq!(
            status(&vault, &request.request_id).unwrap().status,
            "pending"
        );
    }
}
