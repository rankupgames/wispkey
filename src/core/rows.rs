use chrono::{DateTime, Utc};
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
    })
}

pub(super) fn table_has_column(db: &Connection, table: &str, column: &str) -> Result<bool> {
    let query = match table {
        "audit_log" => "PRAGMA table_info(audit_log)",
        "credentials" => "PRAGMA table_info(credentials)",
        "partitions" => "PRAGMA table_info(partitions)",
        _ => return Err(VaultError::Database(rusqlite::Error::InvalidQuery)),
    };
    let mut stmt = db.prepare(query)?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|name| name == column))
}

pub(super) fn parse_datetime_column(column: usize, value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|datetime| datetime.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
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
