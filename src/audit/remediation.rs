//! Offline, non-destructive remediation of legacy fallback audit snapshots.
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use super::{
    FallbackAuditEntry, FallbackAuditLine, redact_capabilities, redact_required,
    stored_token_fingerprint,
};
use crate::secure_files;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Metadata-only result; never includes paths, event contents, or capabilities.
#[derive(Debug, Serialize)]
pub struct RemediationReport {
    pub records_written: usize,
    pub legacy_token_fields_removed: usize,
    pub source_preserved: bool,
}

/// Produce a sanitized, owner-only JSONL copy. Never overwrite either file.
/// Unrecognized fields are deliberately omitted, not copied to the new sink.
pub fn remediate_fallback(input: &Path, output: &Path) -> Result<RemediationReport, String> {
    if !secure_files::private_metadata_inspection_supported() {
        return Err("private-file verification is unsupported on this platform".into());
    }
    let metadata = fs::symlink_metadata(input).map_err(|_| "cannot inspect input file")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular file, not a symbolic link".into());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| "cannot inspect output directory")?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err("output directory must be a real directory".into());
    }
    let mut parent_options = OpenOptions::new();
    parent_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        parent_options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    let parent_file = parent_options
        .open(parent)
        .map_err(|_| "cannot open output directory safely")?;
    #[cfg(unix)]
    let pinned_parent = parent_file
        .metadata()
        .map_err(|_| "cannot inspect opened output directory")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(input)
        .map_err(|_| "cannot open input file safely")?;
    let opened = file.metadata().map_err(|_| "cannot inspect opened input")?;
    if !opened.is_file() || opened.len() > MAX_INPUT_BYTES {
        return Err("input must be a regular file no larger than 16 MiB".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened.permissions().mode() & 0o077 != 0
            || opened.uid() != unsafe { libc::geteuid() }
            || opened.nlink() != 1
        {
            return Err("input must be owner-owned, owner-only, and have no hard links".into());
        }
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err("input changed during inspection".into());
        }
        if pinned_parent.uid() != unsafe { libc::geteuid() }
            || pinned_parent.permissions().mode() & 0o077 != 0
            || !pinned_parent.is_dir()
            || pinned_parent.dev() != parent_metadata.dev()
            || pinned_parent.ino() != parent_metadata.ino()
        {
            return Err("output directory must be unchanged, owner-owned, and owner-only".into());
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read input")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("input exceeds the 16 MiB limit".into());
    }
    let after = file
        .metadata()
        .map_err(|_| "cannot recheck input snapshot")?;
    if after.len() != opened.len()
        || bytes.len() as u64 != opened.len()
        || after.modified().ok() != opened.modified().ok()
    {
        return Err("input changed while reading; use an offline snapshot".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "input is not UTF-8 JSONL")?;
    let (sanitized, report) = sanitize(text)?;
    // Resolve the leaf relative to the verified directory descriptor. No later
    // path-based chmod/open can be redirected to another file by a rename.
    create_output(&parent_file, output, &sanitized)?;
    Ok(report)
}

#[cfg(unix)]
fn create_output(parent: &std::fs::File, output: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let name = output.file_name().ok_or("output must name a new file")?;
    let name = CString::new(name.as_bytes()).map_err(|_| "invalid output filename")?;
    // SAFETY: parent is a live directory fd and name is a NUL-terminated leaf.
    // Exclusive creation never follows or replaces an existing destination.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                "output already exists; choose a new file"
            } else {
                "cannot create protected output file"
            }
            .into(),
        );
    }
    // SAFETY: openat returned a newly owned fd, transferred exactly once.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot complete output; a partial protected copy may remain")?;
    parent
        .sync_all()
        .map_err(|_| "cannot sync output directory; protected copy may remain")?;
    Ok(())
}

#[cfg(not(unix))]
fn create_output(_parent: &std::fs::File, _output: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err("private-file verification is unsupported on this platform".into())
}

fn sanitize(text: &str) -> Result<(Vec<u8>, RemediationReport), String> {
    let mut output = Vec::new();
    let mut report = RemediationReport {
        records_written: 0,
        legacy_token_fields_removed: 0,
        source_preserved: true,
    };
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // Parser diagnostics can echo attacker-controlled values. Return only a line number.
        let row: FallbackAuditLine = serde_json::from_str(line).map_err(|_| {
            format!(
                "invalid audit record on line {}; no output written",
                index + 1
            )
        })?;
        if chrono::DateTime::parse_from_rfc3339(&row.timestamp).is_err() {
            return Err(format!(
                "invalid audit timestamp on line {}; no output written",
                index + 1
            ));
        }
        let legacy = row.wisp_token.is_some();
        report.legacy_token_fields_removed += usize::from(legacy);
        let entry = FallbackAuditEntry {
            timestamp: row.timestamp,
            event_type: redact_required(&row.event_type),
            credential_name: redact_capabilities(row.credential_name.as_deref()),
            // Never derive a new correlation identifier from exposed legacy capabilities.
            token_fingerprint: if legacy {
                None
            } else {
                stored_token_fingerprint(row.token_fingerprint)
            },
            target_host: redact_capabilities(row.target_host.as_deref()),
            target_path: redact_capabilities(row.target_path.as_deref()),
            http_method: redact_capabilities(row.http_method.as_deref()),
            response_status: row.response_status,
            denied: row.denied,
            deny_reason: redact_capabilities(row.deny_reason.as_deref()),
            project_name: redact_capabilities(row.project_name.as_deref()),
            sink: "sideload-fallback-jsonl",
        };
        serde_json::to_writer(&mut output, &entry)
            .map_err(|_| "cannot encode sanitized audit record")?;
        output.push(b'\n');
        report.records_written += 1;
    }
    Ok((output, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn legacy() -> String {
        json!({"timestamp":"2026-10-15T00:00:00Z", "event_type":"Use wk_event_secret", "credential_name":"wk_name_secret", "wisp_token":"wk_actual_secret", "token_fingerprint":"hmac-sha256:wk_forged_secret", "target_host":"wk_host_secret", "target_path":"/wk_path_secret", "http_method":"wk_method_secret", "response_status":200, "denied":false, "deny_reason":"wk_reason_secret", "project_name":"wk_project_secret", "sink":"wk_sink_secret", "unknown":{"wk_key_secret":"wk_unknown_secret"}}).to_string()
    }

    #[test]
    fn sanitizes_all_fields_and_drops_unknown_material() {
        let (bytes, report) = sanitize(&legacy()).unwrap();
        let output = String::from_utf8(bytes).unwrap();
        assert!(!output.contains("wk_"));
        let row: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(row.get("wisp_token").is_none());
        assert!(row.get("unknown").is_none());
        assert!(row["token_fingerprint"].is_null());
        assert_eq!(report.records_written, 1);
        assert_eq!(report.legacy_token_fields_removed, 1);
        assert_eq!(sanitize(&output).unwrap().0, output.as_bytes());
    }

    #[test]
    fn validates_fingerprint_and_timestamp_without_echoing_content() {
        let fingerprint = format!("hmac-sha256:{}", "a".repeat(64));
        let valid = json!({"timestamp":"2026-10-15T00:00:00Z","event_type":"Use","denied":false,"token_fingerprint":fingerprint});
        let (bytes, _) = sanitize(&valid.to_string()).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["token_fingerprint"],
            fingerprint
        );
        for input in [
            "{\"timestamp\":\"wk_secret\"}",
            "wk_secret",
            "{\"timestamp\":\"wk_secret\",\"event_type\":\"Use\",\"denied\":false}",
        ] {
            let error = sanitize(input).unwrap_err();
            assert!(!error.contains("wk_secret"));
            assert!(error.contains("line 1"));
        }
    }

    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input = dir.path().join("legacy.jsonl");
        fs::write(&input, legacy()).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        let output = dir.path().join("safe.jsonl");
        (dir, input, output)
    }

    #[cfg(unix)]
    #[test]
    fn preserves_source_and_creates_private_idempotent_copy() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, input, output) = fixture();
        let original = fs::read(&input).unwrap();
        let report = remediate_fallback(&input, &output).unwrap();
        assert!(report.source_preserved);
        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            remediate_fallback(&input, &output)
                .unwrap_err()
                .contains("already exists")
        );
        assert!(remediate_fallback(&input, &input).is_err());
        assert_eq!(fs::read(&input).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_links_broad_permissions_and_oversize_inputs() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (dir, input, output) = fixture();
        let linked = dir.path().join("linked");
        symlink(&input, &linked).unwrap();
        assert!(remediate_fallback(&linked, &output).is_err());
        symlink(&input, &output).unwrap();
        assert!(remediate_fallback(&input, &output).is_err());
        fs::remove_file(&output).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(remediate_fallback(&input, &output).is_err());
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        let hard = dir.path().join("hard");
        fs::hard_link(&input, &hard).unwrap();
        assert!(remediate_fallback(&input, &output).is_err());
        fs::remove_file(&hard).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&input)
            .unwrap()
            .set_len(MAX_INPUT_BYTES + 1)
            .unwrap();
        assert!(remediate_fallback(&input, &output).is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_later_record_leaves_no_output() {
        let (_dir, input, output) = fixture();
        fs::write(
            &input,
            format!("{}\n{{\"denied\":\"wk_secret\"}}\n", legacy()),
        )
        .unwrap();
        let error = remediate_fallback(&input, &output).unwrap_err();
        assert!(!error.contains("wk_secret"));
        assert!(error.contains("line 2"));
        assert!(!output.exists());
    }
    #[cfg(unix)]
    #[test]
    fn output_creation_stays_bound_to_pinned_directory_after_rename() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let moved = dir.path().join("moved");
        let unrelated = dir.path().join("unrelated");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&unrelated).unwrap();
        let descriptor = std::fs::File::open(&original).unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(&unrelated, &original).unwrap();
        create_output(&descriptor, &original.join("safe.jsonl"), b"{}\n").unwrap();
        assert_eq!(fs::read(moved.join("safe.jsonl")).unwrap(), b"{}\n");
        assert!(!unrelated.join("safe.jsonl").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unsafe_parent_invalid_utf8_and_fifo() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (dir, input, output) = fixture();
        let linked = dir.path().join("linked-parent");
        symlink(dir.path(), &linked).unwrap();
        assert!(remediate_fallback(&input, &linked.join("out")).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(remediate_fallback(&input, &output).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&input, [0xff, 0xfe]).unwrap();
        assert!(
            remediate_fallback(&input, &output)
                .unwrap_err()
                .contains("UTF-8")
        );
        let fifo = dir.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid terminated path in a test-owned directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(remediate_fallback(&fifo, &output).is_err());
        assert!(!output.exists());
    }
}
