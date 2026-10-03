//! Local metadata bridge. No transport, enrollment, approval bypass or secret API.
use rusqlite::{Connection, OptionalExtension};

use super::Vault;
use super::browser::{FillRequest, Result};

#[cfg(feature = "experimental-browser-receiver")]
mod enabled;
#[cfg(feature = "experimental-browser-receiver")]
pub use enabled::*;
#[cfg(all(test, feature = "experimental-browser-receiver"))]
mod tests;

pub(crate) fn create_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS browser_receiver_generation (
            id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL);
        INSERT OR IGNORE INTO browser_receiver_generation VALUES(1,0);
        CREATE TABLE IF NOT EXISTS browser_receiver_bindings (
            id TEXT PRIMARY KEY, metadata TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS browser_receiver_jobs (
            request_id TEXT PRIMARY KEY, binding_id TEXT NOT NULL, job_id TEXT NOT NULL,
            envelope TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER NOT NULL,
            UNIQUE(binding_id,job_id));
        CREATE TABLE IF NOT EXISTS browser_receiver_outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, binding_id TEXT NOT NULL,
            job_id TEXT NOT NULL, state TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS receiver_binding_immutable BEFORE UPDATE OF id,metadata
            ON browser_receiver_bindings BEGIN SELECT RAISE(ABORT,'receiver binding immutable'); END;
        CREATE TRIGGER IF NOT EXISTS receiver_revocation_monotonic BEFORE UPDATE OF revoked
            ON browser_receiver_bindings WHEN OLD.revoked<>0 AND NEW.revoked<>OLD.revoked
            BEGIN SELECT RAISE(ABORT,'receiver revocation is final'); END;",
    )?;
    // Deliberately conservative: all credential/auth/scope writes invalidate a
    // prepared local binding, including ABA and changes through another process.
    for table in ["credentials", "auth_registry", "partitions", "projects"] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_batch(&format!(
                "CREATE TRIGGER IF NOT EXISTS receiver_{table}_{operation}
                AFTER {operation} ON {table} BEGIN
                UPDATE browser_receiver_generation SET revision=revision+1 WHERE id=1; END;"
            ))?;
        }
    }
    Ok(())
}

fn is_bound(vault: &Vault, request: &FillRequest) -> Result<bool> {
    let linked: Option<String> = vault
        .db()
        .query_row(
            "SELECT binding_id FROM browser_receiver_jobs WHERE request_id=?1",
            [&request.request_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| "receiver store unavailable")?;
    match (&request.receiver_binding, linked) {
        (None, None) => Ok(false),
        (Some(expected), Some(actual)) if expected == &actual => Ok(true),
        _ => Err("receiver binding unavailable"),
    }
}

pub(super) fn release_guard(
    vault: &Vault,
    request: &FillRequest,
) -> Result<Option<super::session_store::SessionGuard>> {
    if !is_bound(vault, request)? {
        return Ok(None);
    }
    #[cfg(feature = "experimental-browser-receiver")]
    return enabled::release_guard(vault, request).map(Some);
    #[cfg(not(feature = "experimental-browser-receiver"))]
    {
        let _ = vault;
        Err("browser receiver is disabled")
    }
}

pub(super) fn released(vault: &Vault, request: &FillRequest) -> Result<()> {
    if !is_bound(vault, request)? {
        return Ok(());
    }
    #[cfg(feature = "experimental-browser-receiver")]
    return enabled::released(vault, request);
    #[cfg(not(feature = "experimental-browser-receiver"))]
    {
        let _ = vault;
        Err("browser receiver is disabled")
    }
}

pub(super) fn finish(vault: &Vault, request: &FillRequest, completed: bool) -> Result<()> {
    if !is_bound(vault, request)? {
        return Ok(());
    }
    #[cfg(feature = "experimental-browser-receiver")]
    return enabled::finished(vault, request, completed);
    #[cfg(not(feature = "experimental-browser-receiver"))]
    {
        let _ = (vault, completed);
        Err("browser receiver is disabled")
    }
}

pub(super) fn expired(vault: &Vault, request: &FillRequest) -> Result<()> {
    if !is_bound(vault, request)? {
        return Ok(());
    }
    #[cfg(feature = "experimental-browser-receiver")]
    return enabled::expired(vault, request);
    #[cfg(not(feature = "experimental-browser-receiver"))]
    {
        let _ = vault;
        Ok(()) // Disabled clients may expire requests, but never release them.
    }
}

/// Metadata for the existing native owner prompt, not remote/provider attestation.
pub(crate) fn approval_details(vault: &Vault, request: &FillRequest) -> Result<String> {
    if !is_bound(vault, request)? {
        return Ok(String::new());
    }
    #[cfg(feature = "experimental-browser-receiver")]
    return enabled::approval_details(vault, request);
    #[cfg(not(feature = "experimental-browser-receiver"))]
    {
        let _ = vault;
        Err("browser receiver is disabled")
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    #[test]
    fn schema_15_migrates_receiver_guard_atomically() {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        db.execute_batch("ALTER TABLE browser_fill_requests DROP COLUMN receiver_binding; INSERT INTO vault_meta VALUES('version','15');").unwrap();
        Vault::migrate_schema(&db).unwrap();
        let version: String = db
            .query_row(
                "SELECT value FROM vault_meta WHERE key='version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, crate::core::CURRENT_SCHEMA_VERSION);
        db.prepare("SELECT receiver_binding FROM browser_fill_requests")
            .unwrap();
        db.execute("UPDATE vault_meta SET value='999' WHERE key='version'", [])
            .unwrap();
        assert!(Vault::migrate_schema(&db).is_err());
    }
    #[cfg(not(feature = "experimental-browser-receiver"))]
    #[test]
    fn default_build_refuses_bound_or_inconsistently_marked_release() {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        let v = Vault {
            db,
            master_key: Some([1; 32]),
            session_timeout_override: None,
        };
        let mut r = FillRequest {
            request_id: "request".into(),
            name: "n".into(),
            project: "p".into(),
            origin: "https://example.com".into(),
            requester: "r".into(),
            reason: "r".into(),
            status: "pending".into(),
            expires_at: i64::MAX,
            credential_id: "credential".into(),
            revision: "revision".into(),
            receiver_binding: Some("binding".into()),
        };
        v.db().execute("INSERT INTO browser_receiver_jobs VALUES('request','binding','job','{}','queued',?1)",[i64::MAX]).unwrap();
        assert!(matches!(
            release_guard(&v, &r),
            Err("browser receiver is disabled")
        ));
        assert!(approval_details(&v, &r).is_err());
        r.receiver_binding = None;
        assert!(release_guard(&v, &r).is_err());
    }
}
