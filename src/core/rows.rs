use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{Connection, Row};

use super::{Credential, CredentialType, Partition, Project, Result, VaultError};

pub(super) fn partition_from_row(row: &Row<'_>) -> rusqlite::Result<Partition> {
    let project_id: Option<String> = row.get(3)?;
    let created_str: String = row.get(4)?;
    let updated_str: String = row.get(5)?;
    Ok(Partition {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        project_id,
        created_at: parse_datetime_column(4, &created_str)?,
        updated_at: parse_datetime_column(5, &updated_str)?,
    })
}

pub(super) fn project_from_row(row: &Row<'_>) -> rusqlite::Result<Project> {
    let created_str: String = row.get(3)?;
    let updated_str: String = row.get(4)?;
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_at: parse_datetime_column(3, &created_str)?,
        updated_at: parse_datetime_column(4, &updated_str)?,
    })
}

pub(super) fn credential_from_row(row: &Row<'_>) -> rusqlite::Result<Credential> {
    let description: String = row.get(2)?;
    let type_json: String = row.get(3)?;
    let hosts_csv: String = row.get(5)?;
    let tags_csv: String = row.get(6)?;
    let created_str: String = row.get(7)?;
    let updated_str: String = row.get(8)?;
    let last_used_str: Option<String> = row.get(9)?;
    let partition_id: Option<String> = row.get(10)?;
    let origin: String = row.get(11)?;
    let lifecycle_state: String = row.get(12)?;
    let review_at_str: Option<String> = row.get(13)?;

    Ok(Credential {
        id: row.get(0)?,
        name: row.get(1)?,
        description,
        credential_type: parse_credential_type_column(3, &type_json)?,
        wisp_token: row.get(4)?,
        hosts: parse_csv(&hosts_csv),
        tags: parse_csv(&tags_csv),
        created_at: parse_datetime_column(7, &created_str)?,
        updated_at: parse_datetime_column(8, &updated_str)?,
        last_used_at: last_used_str
            .as_deref()
            .map(|value| parse_datetime_column(9, value))
            .transpose()?,
        partition_id,
        origin,
        lifecycle_state,
        review_at: review_at_str
            .as_deref()
            .map(|value| parse_datetime_column(13, value))
            .transpose()?,
    })
}

pub(super) fn table_has_column(db: &Connection, table: &str, column: &str) -> Result<bool> {
    let query = match table {
        "audit_log" => "PRAGMA table_info(audit_log)",
        "credentials" => "PRAGMA table_info(credentials)",
        "partitions" => "PRAGMA table_info(partitions)",
        "instances" => "PRAGMA table_info(instances)",
        "instance_scopes" => "PRAGMA table_info(instance_scopes)",
        "access_requests" => "PRAGMA table_info(access_requests)",
        _ => return Err(VaultError::Database(rusqlite::Error::InvalidQuery)),
    };
    let mut stmt = db.prepare(query)?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|name| name == column))
}

pub(super) fn parse_datetime_column(column: usize, value: &str) -> rusqlite::Result<DateTime<Utc>> {
    parse_flexible_datetime(value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            format!("unrecognized datetime format: {value:?}").into(),
        )
    })
}

/// Parses a stored timestamp. WispKey writes RFC 3339, but rows written through
/// raw SQL or SQLite `CURRENT_TIMESTAMP` use the space-separated
/// `YYYY-MM-DD HH:MM:SS` form (no `T`, no offset); accept both so a single
/// legacy row can never make a whole listing fail.
fn parse_flexible_datetime(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(datetime) = DateTime::parse_from_rfc3339(value) {
        return Some(datetime.with_timezone(&Utc));
    }
    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc());
        }
    }
    None
}

pub(super) fn parse_credential_type_column(
    column: usize,
    value: &str,
) -> rusqlite::Result<CredentialType> {
    if let Ok(credential_type) = serde_json::from_str::<CredentialType>(value) {
        return Ok(credential_type);
    }

    CredentialType::from_str_with_params(value, None, None).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })
}

#[inline]
pub(super) fn parse_csv(csv: &str) -> Vec<String> {
    csv.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_flexible_datetime;

    #[test]
    fn parses_rfc3339_and_sqlite_timestamp_formats() {
        // Canonical form WispKey writes.
        assert!(parse_flexible_datetime("2026-04-09T19:58:57.966708+00:00").is_some());
        // SQLite space-separated form (raw SQL / CURRENT_TIMESTAMP) must not brick a listing.
        let sqlite_form =
            parse_flexible_datetime("2026-05-18 22:14:55").expect("sqlite form parses");
        assert_eq!(sqlite_form.to_rfc3339(), "2026-05-18T22:14:55+00:00");
        // Fractional seconds in the space form.
        assert!(parse_flexible_datetime("2026-07-04 01:33:13.5").is_some());
        // Genuinely malformed input still fails.
        assert!(parse_flexible_datetime("not-a-timestamp").is_none());
    }
}
