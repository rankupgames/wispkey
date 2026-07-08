/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Audit log -- records credential usage, denials, and CRUD events
 *              to SQLite. Supports filtered queries by credential, date, and count.
 * Created: 2026-04-07
 * Last Modified: 2026-04-13
 */

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::core::Vault;
use crate::secure_files;

pub const SIDELOAD_FALLBACK_AUDIT_FILE: &str = "sideload-audit.jsonl";

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
    pub source: String,
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

#[derive(Debug, Serialize)]
struct FallbackAuditEntry<'a> {
    timestamp: String,
    event_type: &'a str,
    credential_name: Option<&'a str>,
    wisp_token: Option<&'a str>,
    target_host: Option<&'a str>,
    target_path: Option<&'a str>,
    http_method: Option<&'a str>,
    response_status: Option<u16>,
    denied: bool,
    deny_reason: Option<&'a str>,
    project_name: Option<&'a str>,
    sink: &'static str,
}

#[derive(Debug, Deserialize)]
struct FallbackAuditLine {
    timestamp: String,
    event_type: String,
    credential_name: Option<String>,
    wisp_token: Option<String>,
    target_host: Option<String>,
    target_path: Option<String>,
    http_method: Option<String>,
    response_status: Option<u16>,
    denied: bool,
    deny_reason: Option<String>,
    project_name: Option<String>,
    sink: Option<String>,
}

/// Writes an audit event when no unlocked vault database is available.
#[allow(clippy::too_many_arguments)]
pub fn log_fallback_event(
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
    let entry = FallbackAuditEntry {
        timestamp: Utc::now().to_rfc3339(),
        event_type,
        credential_name,
        wisp_token,
        target_host,
        target_path,
        http_method,
        response_status,
        denied,
        deny_reason,
        project_name,
        sink: "sideload-fallback-jsonl",
    };

    let mut line = match serde_json::to_vec(&entry) {
        Ok(line) => line,
        Err(e) => {
            tracing::error!("Failed to encode fallback audit log: {}", e);
            return;
        }
    };
    line.push(b'\n');

    let path = Vault::vault_dir().join(SIDELOAD_FALLBACK_AUDIT_FILE);
    if let Err(e) = secure_files::append_private(&path, &line) {
        tracing::error!("Failed to write fallback audit log: {}", e);
    }
}

/// Queries both the vault-backed audit DB and the sideload fallback JSONL sink.
pub fn query_combined_log(
    db: Option<&Connection>,
    last: usize,
    credential: Option<&str>,
    since: Option<&str>,
) -> Vec<AuditEntry> {
    let mut entries = db
        .map(|db| query_log(db, last, credential, since))
        .unwrap_or_default();
    entries.extend(query_fallback_log(last, credential, since));
    sort_and_limit(entries, last)
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
        if let Some(env_key) = sideload_env_key_filter(cred) {
            query.push_str(" AND (credential_name = ? OR credential_name = ?)");
            param_values.push(Box::new(cred.to_string()));
            param_values.push(Box::new(env_key));
        } else {
            query.push_str(" AND credential_name = ?");
            param_values.push(Box::new(cred.to_string()));
        }
    }

    if let Some(since_date) = since {
        query.push_str(" AND timestamp >= ?");
        param_values.push(Box::new(since_lower_bound(since_date)));
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
            response_status: row
                .get::<_, Option<i64>>(8)?
                .map(u16::try_from)
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?,
            denied: row.get::<_, i32>(9)? != 0,
            deny_reason: row.get(10)?,
            project_name: row.get(11)?,
            source: "vault".to_string(),
        })
    }) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for row in rows {
        match row {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                tracing::error!("Failed to read audit log row: {}", e);
                return Vec::new();
            }
        }
    }
    entries
}

/// Queries vault-less env-sideload audit rows from the fallback JSONL sink.
pub fn query_fallback_log(
    last: usize,
    credential: Option<&str>,
    since: Option<&str>,
) -> Vec<AuditEntry> {
    query_fallback_log_from_path(
        &Vault::vault_dir().join(SIDELOAD_FALLBACK_AUDIT_FILE),
        last,
        credential,
        since,
    )
}

fn query_fallback_log_from_path(
    path: &Path,
    last: usize,
    credential: Option<&str>,
    since: Option<&str>,
) -> Vec<AuditEntry> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            tracing::error!("Failed to open fallback audit log: {}", error);
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for (line_index, line) in BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                tracing::error!("Failed to read fallback audit log line: {}", error);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let row = match serde_json::from_str::<FallbackAuditLine>(&line) {
            Ok(row) => row,
            Err(error) => {
                tracing::error!("Failed to parse fallback audit log line: {}", error);
                continue;
            }
        };
        if !matches_credential(row.credential_name.as_deref(), credential)
            || !matches_since(&row.timestamp, since)
        {
            continue;
        }

        entries.push(AuditEntry {
            id: -((line_index as i64) + 1),
            timestamp: row.timestamp,
            event_type: row.event_type,
            credential_name: row.credential_name,
            wisp_token: row.wisp_token,
            target_host: row.target_host,
            target_path: row.target_path,
            http_method: row.http_method,
            response_status: row.response_status,
            denied: row.denied,
            deny_reason: row.deny_reason,
            project_name: row.project_name,
            source: row
                .sink
                .unwrap_or_else(|| "sideload-fallback-jsonl".to_string()),
        });
    }

    sort_and_limit(entries, last)
}

fn sort_and_limit(mut entries: Vec<AuditEntry>, last: usize) -> Vec<AuditEntry> {
    entries.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries.truncate(last);
    entries
}

fn matches_credential(entry_credential: Option<&str>, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let Some(entry_credential) = entry_credential else {
        return false;
    };
    entry_credential == filter
        || sideload_env_key_filter(filter).as_deref() == Some(entry_credential)
}

fn sideload_env_key_filter(credential: &str) -> Option<String> {
    if credential.starts_with("WISPKEY_SIDELOAD_") {
        return None;
    }
    crate::env_sideload::env_key_for_name(credential)
}

fn since_lower_bound(since: &str) -> String {
    format!("{since}T00:00:00+00:00")
}

fn matches_since(timestamp: &str, since: Option<&str>) -> bool {
    let Some(since) = since else {
        return true;
    };
    let threshold = match DateTime::parse_from_rfc3339(&since_lower_bound(since)) {
        Ok(threshold) => threshold.with_timezone(&Utc),
        Err(_) => return false,
    };
    let timestamp = match DateTime::parse_from_rfc3339(timestamp) {
        Ok(timestamp) => timestamp.with_timezone(&Utc),
        Err(_) => return false,
    };
    timestamp >= threshold
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
        assert!(!entries[0].denied);
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
        assert!(entries[0].denied);
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
    fn query_log_matches_sideload_filter_by_user_facing_name() {
        let db = test_db();
        log_event(
            &db,
            "SideloadUsed",
            Some("WISPKEY_SIDELOAD_OPENAI"),
            Some("wk_env_openai"),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );

        let entries = query_log(&db, 10, Some("openai"), None);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].credential_name.as_deref(),
            Some("WISPKEY_SIDELOAD_OPENAI")
        );
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

    #[test]
    fn query_log_since_includes_midnight_utc_rows() {
        let db = test_db();
        db.execute(
            "INSERT INTO audit_log (timestamp, event_type, denied) VALUES ('2026-06-12T00:00:00+00:00', 'midnight', 0)",
            [],
        )
        .unwrap();

        let entries = query_log(&db, 10, None, Some("2026-06-12"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "midnight");
    }

    #[test]
    fn query_log_rejects_invalid_response_status() {
        let db = test_db();
        db.execute(
            "INSERT INTO audit_log (timestamp, event_type, response_status, denied) VALUES (?1, 'bad_status', 70000, 0)",
            params![Utc::now().to_rfc3339()],
        )
        .unwrap();

        assert!(query_log(&db, 10, None, None).is_empty());
    }

    #[test]
    fn query_fallback_log_reads_sideload_jsonl_without_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SIDELOAD_FALLBACK_AUDIT_FILE);
        let line = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event_type": "SideloadUsed",
            "credential_name": "WISPKEY_SIDELOAD_OPENAI",
            "wisp_token": "wk_env_openai",
            "target_host": "api.example.com",
            "target_path": "/v1/test",
            "http_method": "GET",
            "response_status": 200,
            "denied": false,
            "deny_reason": "used env sideload credential without unlocked vault",
            "project_name": null,
            "sink": "sideload-fallback-jsonl"
        });
        std::fs::write(&path, format!("{line}\n")).unwrap();

        let entries = query_fallback_log_from_path(&path, 10, Some("openai"), None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, -1);
        assert_eq!(entries[0].event_type, "SideloadUsed");
        assert_eq!(
            entries[0].credential_name.as_deref(),
            Some("WISPKEY_SIDELOAD_OPENAI")
        );
        assert_eq!(entries[0].wisp_token.as_deref(), Some("wk_env_openai"));
        assert_eq!(entries[0].source, "sideload-fallback-jsonl");

        let serialized = serde_json::to_string(&entries).unwrap();
        assert!(!serialized.contains("sideload-secret"));
    }
}
