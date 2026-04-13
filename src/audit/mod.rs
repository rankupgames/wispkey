/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Audit log -- records credential usage, denials, and CRUD events
 *              to SQLite. Supports filtered queries by credential, date, and count.
 * Created: 2026-04-07
 * Last Modified: 2026-04-13
 */

use chrono::Utc;
use rusqlite::{Connection, params};
use serde::Serialize;

/// Single row from the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub credential_name: Option<String>,
    pub wisp_token: Option<String>,
    pub target_host: Option<String>,
    pub target_path: Option<String>,
    pub http_method: Option<String>,
    pub response_status: Option<u16>,
    pub denied: bool,
    pub deny_reason: Option<String>,
    pub project_name: Option<String>,
}

/// Writes an audit event to the SQLite audit_log table.
#[allow(clippy::too_many_arguments)]
pub fn log_event(
    db: &Connection,
    event_type: &str,
    credential_name: Option<&str>,
    wisp_token: Option<&str>,
    target_host: Option<&str>,
    target_path: Option<&str>,
    http_method: Option<&str>,
    response_status: Option<u16>,
    denied: bool,
    deny_reason: Option<&str>,
    project_name: Option<&str>,
) {
    let result = db.execute(
		"INSERT INTO audit_log (timestamp, event_type, credential_name, wisp_token, target_host, target_path, http_method, response_status, denied, deny_reason, project_name) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
		params![Utc::now().to_rfc3339(), event_type, credential_name, wisp_token, target_host, target_path, http_method, response_status, denied as i32, deny_reason, project_name],
	);
    if let Err(e) = result {
        tracing::error!("Failed to write audit log: {}", e);
    }
}

/// Queries the audit log with optional filters for credential name, date range, and row limit.
pub fn query_log(
    db: &Connection,
    last: usize,
    credential: Option<&str>,
    since: Option<&str>,
) -> Vec<AuditEntry> {
    let mut query = String::from(
        "SELECT id, timestamp, event_type, credential_name, wisp_token, target_host, target_path, http_method, response_status, denied, deny_reason, project_name FROM audit_log WHERE 1=1",
    );
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::with_capacity(3);

    if let Some(cred) = credential {
        query.push_str(" AND credential_name = ?");
        param_values.push(Box::new(cred.to_string()));
    }

    if let Some(since_date) = since {
        query.push_str(" AND timestamp >= ?");
        param_values.push(Box::new(format!("{}T00:00:00Z", since_date)));
    }

    query.push_str(" ORDER BY id DESC LIMIT ?");
    param_values.push(Box::new(last as i64));

    let params_ref: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let mut stmt = match db.prepare(&query) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            return Vec::new();
        }
    };

    let rows = match stmt.query_map(params_ref.as_slice(), |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            event_type: row.get(2)?,
            credential_name: row.get(3)?,
            wisp_token: row.get(4)?,
            target_host: row.get(5)?,
            target_path: row.get(6)?,
            http_method: row.get(7)?,
            response_status: row.get::<_, Option<i32>>(8)?.map(|v| v as u16),
            denied: row.get::<_, i32>(9)? != 0,
            deny_reason: row.get(10)?,
            project_name: row.get(11)?,
        })
    }) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            return Vec::new();
        }
    };

    rows.filter_map(|r| r.ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn test_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                credential_name TEXT,
                wisp_token TEXT,
                target_host TEXT,
                target_path TEXT,
                http_method TEXT,
                response_status INTEGER,
                denied INTEGER NOT NULL DEFAULT 0,
                deny_reason TEXT,
                project_name TEXT
            );",
        )
        .unwrap();
        db
    }

    #[test]
    fn log_event_inserts_row() {
        let db = test_db();
        log_event(
            &db,
            "credential_accessed",
            Some("my-key"),
            Some("wk_my_key_abc"),
            Some("api.example.com"),
            Some("/v1/data"),
            Some("GET"),
            Some(200),
            false,
            None,
            None,
        );
        let entries = query_log(&db, 10, None, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "credential_accessed");
        assert_eq!(entries[0].credential_name.as_deref(), Some("my-key"));
        assert_eq!(entries[0].response_status, Some(200));
        assert_eq!(entries[0].denied, false);
    }

    #[test]
    fn log_event_denied() {
        let db = test_db();
        log_event(
            &db,
            "proxy_denied",
            Some("secret"),
            Some("wk_secret_xyz"),
            Some("evil.com"),
            Some("/steal"),
            Some("POST"),
            None,
            true,
            Some("host not allowed"),
            None,
        );
        let entries = query_log(&db, 10, None, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].denied, true);
        assert_eq!(entries[0].deny_reason.as_deref(), Some("host not allowed"));
    }

    #[test]
    fn query_log_filters_by_credential() {
        let db = test_db();
        log_event(
            &db,
            "accessed",
            Some("key-a"),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        log_event(
            &db,
            "accessed",
            Some("key-b"),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        let entries = query_log(&db, 10, Some("key-a"), None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].credential_name.as_deref(), Some("key-a"));
    }

    #[test]
    fn query_log_respects_limit() {
        let db = test_db();
        for index in 0..20 {
            log_event(
                &db,
                &format!("event_{index}"),
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
        }
        let entries = query_log(&db, 5, None, None);
        assert_eq!(entries.len(), 5);
    }
}
