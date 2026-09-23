/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Audit log -- records credential usage, denials, and CRUD events
 *              to SQLite. Supports filtered queries by credential, date, and count.
 * Created: 2026-04-07
 * Last Modified: 2026-04-13
 */

use std::fmt::Write as _;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::core::Vault;
use crate::secure_files;

pub const SIDELOAD_FALLBACK_AUDIT_FILE: &str = "sideload-audit.jsonl";
const AUDIT_FINGERPRINT_KEY_FILE: &str = "audit-fingerprint.key";
const AUDIT_FINGERPRINT_KEY_LEN: usize = 32;
const AUDIT_REDACTION_MARKER: &str = "audit_tokens_redacted_v1";

fn redact_capabilities(value: Option<&str>) -> Option<String> {
    static WISP_TOKEN_PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = WISP_TOKEN_PATTERN.get_or_init(|| {
        Regex::new(r"wk_[A-Za-z0-9_-]+").expect("static wisp token regex must compile")
    });
    value.map(|value| pattern.replace_all(value, "[wisp-token]").into_owned())
}

fn redact_required(value: &str) -> String {
    redact_capabilities(Some(value)).unwrap_or_default()
}

fn token_fingerprint(token: &str, key_material: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_material);
    let digest = hmac::sign(&key, token.as_bytes());
    let mut fingerprint = String::with_capacity(12 + digest.as_ref().len() * 2);
    fingerprint.push_str("hmac-sha256:");
    for byte in digest.as_ref() {
        let _ = write!(&mut fingerprint, "{byte:02x}");
    }
    fingerprint
}

fn stored_token_fingerprint(value: Option<String>) -> Option<String> {
    value.filter(|value| value.starts_with("hmac-sha256:"))
}

fn database_fingerprint_key(db: &Connection) -> Option<String> {
    db.query_row(
        "SELECT value FROM vault_meta WHERE key = 'password_hash'",
        [],
        |row| row.get(0),
    )
    .ok()
}

fn fallback_fingerprint_key() -> Option<Vec<u8>> {
    let path = Vault::vault_dir().join(AUDIT_FINGERPRINT_KEY_FILE);
    match fs::read(&path) {
        Ok(key) if key.len() == AUDIT_FINGERPRINT_KEY_LEN => return Some(key),
        Ok(_) => {
            tracing::error!("Invalid audit fingerprint key length");
            return None;
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            tracing::error!("Failed to read audit fingerprint key: {error}");
            return None;
        }
        Err(_) => {}
    }

    let mut key = vec![0u8; AUDIT_FINGERPRINT_KEY_LEN];
    if let Err(error) = SystemRandom::new().fill(&mut key) {
        tracing::error!("Failed to generate audit fingerprint key: {error}");
        return None;
    }
    match secure_files::create_private(&path, &key) {
        Ok(true) => Some(key),
        Ok(false) => match fs::read(&path) {
            Ok(winning_key) if winning_key.len() == AUDIT_FINGERPRINT_KEY_LEN => Some(winning_key),
            Ok(_) => {
                tracing::error!("Invalid concurrently-created audit fingerprint key length");
                None
            }
            Err(error) => {
                tracing::error!(
                    "Failed to read concurrently-created audit fingerprint key: {error}"
                );
                None
            }
        },
        Err(error) => {
            tracing::error!("Failed to store audit fingerprint key: {error}");
            None
        }
    }
}

pub(crate) fn redact_legacy_audit_tokens(db: &Connection) -> rusqlite::Result<()> {
    let already_redacted = db
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            params![AUDIT_REDACTION_MARKER],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some_and(|value| value == "1");
    if already_redacted {
        return Ok(());
    }

    let mut statement = db.prepare(
        "SELECT id, wisp_token, event_type, credential_name, target_host, target_path,
                http_method, deny_reason, project_name
         FROM audit_log
         WHERE wisp_token LIKE 'wk_%'
            OR event_type LIKE '%wk_%'
            OR credential_name LIKE '%wk_%'
            OR target_host LIKE '%wk_%'
            OR target_path LIKE '%wk_%'
            OR http_method LIKE '%wk_%'
            OR deny_reason LIKE '%wk_%'
            OR project_name LIKE '%wk_%'
         ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<String>>(8)?,
        ))
    })?;
    let legacy_tokens = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    let key = database_fingerprint_key(db);
    for (
        id,
        token,
        event_type,
        credential_name,
        target_host,
        target_path,
        http_method,
        deny_reason,
        project_name,
    ) in legacy_tokens
    {
        let fingerprint = token.as_deref().and_then(|token| {
            if token.starts_with("wk_") {
                key.as_deref()
                    .map(|key| token_fingerprint(token, key.as_bytes()))
            } else {
                stored_token_fingerprint(Some(token.to_string()))
            }
        });
        db.execute(
            "UPDATE audit_log
             SET wisp_token = ?1, event_type = ?2, credential_name = ?3, target_host = ?4,
                 target_path = ?5, http_method = ?6, deny_reason = ?7, project_name = ?8
             WHERE id = ?9",
            params![
                fingerprint,
                redact_required(&event_type),
                redact_capabilities(credential_name.as_deref()),
                redact_capabilities(target_host.as_deref()),
                redact_capabilities(target_path.as_deref()),
                redact_capabilities(http_method.as_deref()),
                redact_capabilities(deny_reason.as_deref()),
                redact_capabilities(project_name.as_deref()),
                id
            ],
        )?;
    }
    db.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![AUDIT_REDACTION_MARKER],
    )?;
    Ok(())
}

/// Single row from the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub credential_name: Option<String>,
    pub token_fingerprint: Option<String>,
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
    if let Err(e) = try_log_event(
        db,
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
    ) {
        tracing::error!("Failed to write audit log: {}", e);
    }
}

/// Attempts to write an audit event and returns database failures to the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_log_event(
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
) -> rusqlite::Result<()> {
    let key = database_fingerprint_key(db);
    let token_fingerprint = wisp_token
        .zip(key.as_deref())
        .map(|(token, key)| token_fingerprint(token, key.as_bytes()));
    let event_type = redact_required(event_type);
    let credential_name = redact_capabilities(credential_name);
    let target_host = redact_capabilities(target_host);
    let target_path = redact_capabilities(target_path);
    let http_method = redact_capabilities(http_method);
    let deny_reason = redact_capabilities(deny_reason);
    let project_name = redact_capabilities(project_name);
    db.execute(
		"INSERT INTO audit_log (timestamp, event_type, credential_name, wisp_token, target_host, target_path, http_method, response_status, denied, deny_reason, project_name) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
		params![Utc::now().to_rfc3339(), event_type, credential_name, token_fingerprint, target_host, target_path, http_method, response_status, denied as i32, deny_reason, project_name],
    )?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct FallbackAuditEntry {
    timestamp: String,
    event_type: String,
    credential_name: Option<String>,
    token_fingerprint: Option<String>,
    target_host: Option<String>,
    target_path: Option<String>,
    http_method: Option<String>,
    response_status: Option<u16>,
    denied: bool,
    deny_reason: Option<String>,
    project_name: Option<String>,
    sink: &'static str,
}

#[derive(Debug, Deserialize)]
struct FallbackAuditLine {
    timestamp: String,
    event_type: String,
    credential_name: Option<String>,
    #[serde(default)]
    token_fingerprint: Option<String>,
    #[serde(default)]
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
    if let Err(e) = try_log_fallback_event(
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
    ) {
        tracing::error!("Failed to write fallback audit log: {}", e);
    }
}

/// Attempts to write a fallback audit event and returns sink failures.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_log_fallback_event(
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
) -> std::result::Result<(), String> {
    let key = fallback_fingerprint_key();
    let event_type = redact_required(event_type);
    let credential_name = redact_capabilities(credential_name);
    let target_host = redact_capabilities(target_host);
    let target_path = redact_capabilities(target_path);
    let http_method = redact_capabilities(http_method);
    let deny_reason = redact_capabilities(deny_reason);
    let project_name = redact_capabilities(project_name);
    let entry = FallbackAuditEntry {
        timestamp: Utc::now().to_rfc3339(),
        event_type,
        credential_name,
        token_fingerprint: wisp_token
            .zip(key.as_deref())
            .map(|(token, key)| token_fingerprint(token, key)),
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
        Err(e) => return Err(format!("failed to encode fallback audit log: {e}")),
    };
    line.push(b'\n');

    let path = Vault::vault_dir().join(SIDELOAD_FALLBACK_AUDIT_FILE);
    secure_files::append_private(&path, &line)
        .map_err(|error| format!("failed to write fallback audit log: {error}"))
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

/// Queries both audit sinks without a row limit, ordered oldest to newest.
pub fn query_combined_log_range(
    db: Option<&Connection>,
    credential: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<AuditEntry> {
    let mut entries = db
        .map(|db| query_log_range(db, credential, since, until))
        .unwrap_or_default();
    entries.extend(query_fallback_log_range(credential, since, until));
    sort_oldest_first(entries)
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
            event_type: redact_required(&row.get::<_, String>(2)?),
            credential_name: redact_capabilities(row.get::<_, Option<String>>(3)?.as_deref()),
            token_fingerprint: stored_token_fingerprint(row.get(4)?),
            target_host: redact_capabilities(row.get::<_, Option<String>>(5)?.as_deref()),
            target_path: redact_capabilities(row.get::<_, Option<String>>(6)?.as_deref()),
            http_method: redact_capabilities(row.get::<_, Option<String>>(7)?.as_deref()),
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
            deny_reason: redact_capabilities(row.get::<_, Option<String>>(10)?.as_deref()),
            project_name: redact_capabilities(row.get::<_, Option<String>>(11)?.as_deref()),
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

/// Queries the audit log with optional credential and timestamp range filters, without a row limit.
pub fn query_log_range(
    db: &Connection,
    credential: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<AuditEntry> {
    let mut query = String::from(
        "SELECT id, timestamp, event_type, credential_name, wisp_token, target_host, target_path, http_method, response_status, denied, deny_reason, project_name FROM audit_log WHERE 1=1",
    );
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::with_capacity(4);

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
        param_values.push(Box::new(lower_bound(since_date)));
    }

    if let Some(until_date) = until {
        query.push_str(" AND timestamp <= ?");
        param_values.push(Box::new(upper_bound(until_date)));
    }

    query.push_str(" ORDER BY timestamp ASC, id ASC");

    let params_ref: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let mut stmt = match db.prepare(&query) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            return Vec::new();
        }
    };

    read_audit_rows(&mut stmt, params_ref.as_slice())
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

/// Queries all vault-less env-sideload audit rows in a range.
pub fn query_fallback_log_range(
    credential: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<AuditEntry> {
    query_fallback_log_range_from_path(
        &Vault::vault_dir().join(SIDELOAD_FALLBACK_AUDIT_FILE),
        credential,
        since,
        until,
    )
}

fn query_fallback_log_range_from_path(
    path: &Path,
    credential: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<AuditEntry> {
    let mut entries = query_fallback_log_from_path(path, usize::MAX, credential, since)
        .into_iter()
        .filter(|entry| matches_until(&entry.timestamp, until))
        .collect::<Vec<_>>();
    entries = sort_oldest_first(entries);
    entries
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

        let token_fingerprint = if row.wisp_token.is_some() {
            None
        } else {
            row.token_fingerprint
                .filter(|value| value.starts_with("hmac-sha256:"))
        };
        let event_type = redact_required(&row.event_type);
        let credential_name = redact_capabilities(row.credential_name.as_deref());
        let target_host = redact_capabilities(row.target_host.as_deref());
        let target_path = redact_capabilities(row.target_path.as_deref());
        let http_method = redact_capabilities(row.http_method.as_deref());
        let deny_reason = redact_capabilities(row.deny_reason.as_deref());
        let project_name = redact_capabilities(row.project_name.as_deref());
        let source = redact_required(row.sink.as_deref().unwrap_or("sideload-fallback-jsonl"));
        entries.push(AuditEntry {
            id: -((line_index as i64) + 1),
            timestamp: row.timestamp,
            event_type,
            credential_name,
            token_fingerprint,
            target_host,
            target_path,
            http_method,
            response_status: row.response_status,
            denied: row.denied,
            deny_reason,
            project_name,
            source,
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

fn sort_oldest_first(mut entries: Vec<AuditEntry>) -> Vec<AuditEntry> {
    entries.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.id.cmp(&right.id))
    });
    entries
}

fn read_audit_rows(
    stmt: &mut rusqlite::Statement<'_>,
    params_ref: &[&dyn rusqlite::types::ToSql],
) -> Vec<AuditEntry> {
    let rows = match stmt.query_map(params_ref, |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            event_type: redact_required(&row.get::<_, String>(2)?),
            credential_name: redact_capabilities(row.get::<_, Option<String>>(3)?.as_deref()),
            token_fingerprint: stored_token_fingerprint(row.get(4)?),
            target_host: redact_capabilities(row.get::<_, Option<String>>(5)?.as_deref()),
            target_path: redact_capabilities(row.get::<_, Option<String>>(6)?.as_deref()),
            http_method: redact_capabilities(row.get::<_, Option<String>>(7)?.as_deref()),
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
            deny_reason: redact_capabilities(row.get::<_, Option<String>>(10)?.as_deref()),
            project_name: redact_capabilities(row.get::<_, Option<String>>(11)?.as_deref()),
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
    lower_bound(since)
}

fn lower_bound(value: &str) -> String {
    if value.contains('T') {
        return value.to_string();
    }
    format!("{value}T00:00:00+00:00")
}

fn upper_bound(value: &str) -> String {
    if value.contains('T') {
        return value.to_string();
    }
    format!("{value}T23:59:59.999999999+00:00")
}

fn matches_since(timestamp: &str, since: Option<&str>) -> bool {
    let Some(since) = since else {
        return true;
    };
    let threshold = match DateTime::parse_from_rfc3339(&lower_bound(since)) {
        Ok(threshold) => threshold.with_timezone(&Utc),
        Err(_) => return false,
    };
    let timestamp = match DateTime::parse_from_rfc3339(timestamp) {
        Ok(timestamp) => timestamp.with_timezone(&Utc),
        Err(_) => return false,
    };
    timestamp >= threshold
}

fn matches_until(timestamp: &str, until: Option<&str>) -> bool {
    let Some(until) = until else {
        return true;
    };
    let threshold = match DateTime::parse_from_rfc3339(&upper_bound(until)) {
        Ok(threshold) => threshold.with_timezone(&Utc),
        Err(_) => return false,
    };
    let timestamp = match DateTime::parse_from_rfc3339(timestamp) {
        Ok(timestamp) => timestamp.with_timezone(&Utc),
        Err(_) => return false,
    };
    timestamp <= threshold
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
            );
            CREATE TABLE vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO vault_meta (key, value) VALUES ('password_hash', 'audit-test-key');",
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
        assert!(
            entries[0]
                .token_fingerprint
                .as_deref()
                .is_some_and(|value| value.starts_with("hmac-sha256:"))
        );
        let stored: String = db
            .query_row("SELECT wisp_token FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert!(!stored.contains("wk_my_key_abc"));
        assert_eq!(entries[0].response_status, Some(200));
        assert!(!entries[0].denied);
    }

    #[test]
    fn try_log_event_returns_database_failures() {
        let db = test_db();
        db.execute("DROP TABLE audit_log", []).unwrap();

        let result = try_log_event(
            &db,
            "credential_accessed",
            Some("my-key"),
            Some("wk_my_key_abc"),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );

        assert!(result.is_err());
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
            Some("/steal/foowk_secret_xyz"),
            Some("POST"),
            None,
            true,
            Some("unknown token wk_secret_xyz"),
            None,
        );
        let entries = query_log(&db, 10, None, None);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].denied);
        assert_eq!(
            entries[0].target_path.as_deref(),
            Some("/steal/foo[wisp-token]")
        );
        assert_eq!(
            entries[0].deny_reason.as_deref(),
            Some("unknown token [wisp-token]")
        );
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
            "target_path": "/v1/foowk_env_openai",
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
        assert!(entries[0].token_fingerprint.is_none());
        assert_eq!(
            entries[0].target_path.as_deref(),
            Some("/v1/foo[wisp-token]")
        );
        assert_eq!(entries[0].source, "sideload-fallback-jsonl");

        let serialized = serde_json::to_string(&entries).unwrap();
        assert!(!serialized.contains("wk_env_openai"));
        assert!(!serialized.contains("sideload-secret"));
    }
}
