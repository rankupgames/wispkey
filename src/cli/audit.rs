use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crate::audit::{self, AuditEntry};
use crate::core::{Vault, VaultError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditExportFormat {
    Jsonl,
    Json,
}

pub async fn handle_audit_export(
    since: Option<&str>,
    until: Option<&str>,
    credential: Option<&str>,
    format: AuditExportFormat,
    output: Option<&str>,
) {
    let vault = open_optional_vault();
    let entries =
        audit::query_combined_log_range(vault.as_ref().map(Vault::db), credential, since, until);

    let mut writer: Box<dyn Write> = match output {
        Some(path) => match File::create(path) {
            Ok(file) => Box::new(file),
            Err(error) => {
                eprintln!("Error: cannot write {path}: {error}");
                std::process::exit(1);
            }
        },
        None => Box::new(io::stdout()),
    };

    if let Err(error) = write_entries(&mut writer, &entries, format) {
        eprintln!("Error: failed to write audit export: {error}");
        std::process::exit(1);
    }
}

pub async fn handle_audit_tail(follow: bool, credential: Option<&str>) {
    let mut cursors: HashMap<String, AuditCursor> = HashMap::new();
    let mut initial = true;
    loop {
        let vault = open_optional_vault();
        let mut entries = if initial {
            let mut all_entries = audit::query_combined_log_range(
                vault.as_ref().map(Vault::db),
                credential,
                None,
                None,
            );
            sort_forward(&mut all_entries);
            for entry in &all_entries {
                record_cursor(&mut cursors, entry);
            }
            let start = all_entries.len().saturating_sub(50);
            all_entries[start..].to_vec()
        } else {
            audit::query_combined_log_range(vault.as_ref().map(Vault::db), credential, None, None)
                .into_iter()
                .filter(|entry| is_after_cursor(entry, cursors.get(&entry.source)))
                .collect()
        };
        sort_forward(&mut entries);

        for entry in &entries {
            print_jsonl(entry);
            record_cursor(&mut cursors, entry);
        }

        if !follow {
            return;
        }
        initial = false;
        thread::sleep(Duration::from_secs(1));
    }
}

fn open_optional_vault() -> Option<Vault> {
    match Vault::open() {
        Ok(vault) => Some(vault),
        Err(VaultError::NotFound) => None,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

fn write_entries(
    writer: &mut dyn Write,
    entries: &[AuditEntry],
    format: AuditExportFormat,
) -> io::Result<()> {
    match format {
        AuditExportFormat::Jsonl => {
            for entry in entries {
                serde_json::to_writer(&mut *writer, entry)?;
                writer.write_all(b"\n")?;
            }
        }
        AuditExportFormat::Json => {
            serde_json::to_writer_pretty(&mut *writer, entries)?;
            writer.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn print_jsonl(entry: &AuditEntry) {
    match serde_json::to_string(entry) {
        Ok(line) => println!("{line}"),
        Err(error) => {
            eprintln!("Error: failed to encode audit entry: {error}");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Debug)]
struct AuditCursor {
    timestamp: String,
    id: i64,
}

fn record_cursor(cursors: &mut HashMap<String, AuditCursor>, entry: &AuditEntry) {
    let next = AuditCursor {
        timestamp: entry.timestamp.clone(),
        id: entry.id,
    };
    match cursors.get(&entry.source) {
        Some(cursor) if !is_after_cursor(entry, Some(cursor)) => {}
        _ => {
            cursors.insert(entry.source.clone(), next);
        }
    }
}

fn is_after_cursor(entry: &AuditEntry, cursor: Option<&AuditCursor>) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };
    entry.timestamp > cursor.timestamp
        || (entry.timestamp == cursor.timestamp && cursor_id(entry.id) > cursor_id(cursor.id))
}

fn sort_forward(entries: &mut [AuditEntry]) {
    entries.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| cursor_id(left.id).cmp(&cursor_id(right.id)))
            .then_with(|| left.source.cmp(&right.source))
    });
}

fn cursor_id(id: i64) -> i64 {
    id.checked_abs().unwrap_or(i64::MAX)
}
