/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: .env file importer -- parses env files, auto-detects credential types
 *              via regex heuristics, encrypts and stores them, outputs a .env.wispkey
 *              file with wisp tokens.
 * Created: 2026-04-07
 * Last Modified: 2026-04-08
 */

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

use fs2::FileExt;
use regex::Regex;
use serde::Serialize;
use uuid::Uuid;

use crate::audit;
use crate::core::{AddCredentialRequest, CredentialType, Vault, VaultError};
use crate::secure_files;

/// Summary of a `.env` file import operation.
pub struct ImportResults {
    pub imported: usize,
    pub skipped: usize,
    pub errors: usize,
    pub output_path: String,
}

/// One directory that could not be read during `.env` discovery.
#[derive(Debug, Serialize)]
pub struct EnvDiscoveryWarning {
    pub path: String,
    pub error: String,
}

/// Absolute paths and explicit traversal warnings from `.env` discovery.
pub struct EnvDiscoveryResults {
    pub directory: String,
    pub files: Vec<String>,
    pub warnings: Vec<EnvDiscoveryWarning>,
}

/// One environment variable attached to a vault credential.
#[derive(Debug, Serialize)]
pub struct AttachedEnvCredential {
    pub env_key: String,
    pub credential: String,
    pub wisp_token: String,
}

/// Summary of an in-place `.env` attachment.
#[derive(Debug, Serialize)]
pub struct AttachEnvResults {
    pub path: String,
    pub project: String,
    pub environment: String,
    pub partition: String,
    pub imported: usize,
    pub reused: usize,
    pub already_attached: usize,
    pub updated: usize,
    pub project_created: bool,
    pub environment_created: bool,
    pub credentials: Vec<AttachedEnvCredential>,
}

struct EnvEntry {
    key: String,
    value: String,
}

#[derive(Debug)]
struct SelectedEnvEntry {
    key: String,
    value: String,
    value_range: Range<usize>,
}

struct AttachPlan {
    entry: SelectedEnvEntry,
    credential_name: String,
    credential: Option<crate::core::Credential>,
    already_tokenized: bool,
}

const MAX_ATTACH_FILE_BYTES: u64 = 10 * 1024 * 1024;
const RESERVED_ENV_FILES: &[&str] = &[
    ".env.example",
    ".env.keys",
    ".env.me",
    ".env.project",
    ".env.wispkey",
    ".env.x",
];
const SKIPPED_DIRECTORIES: &[&str] = &[".git", ".hg", ".svn", "node_modules", "target"];

/// Recursively finds attachable `.env` files without reading their contents.
pub fn discover_env_files(directory: &str) -> std::io::Result<EnvDiscoveryResults> {
    let root = fs::canonicalize(directory)?;
    if !root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", root.display()),
        ));
    }

    let mut files = Vec::new();
    let mut warnings = Vec::new();
    let mut directories = vec![root.clone()];

    while let Some(current) = directories.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if current == root => return Err(error),
            Err(error) => {
                warnings.push(EnvDiscoveryWarning {
                    path: current.to_string_lossy().into_owned(),
                    error: error.to_string(),
                });
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warnings.push(EnvDiscoveryWarning {
                        path: current.to_string_lossy().into_owned(),
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    warnings.push(EnvDiscoveryWarning {
                        path: path.to_string_lossy().into_owned(),
                        error: error.to_string(),
                    });
                    continue;
                }
            };

            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if !is_skipped_directory(&entry.file_name()) {
                    directories.push(path);
                }
                continue;
            }
            if file_type.is_file() && is_attachable_env_file(&entry.file_name()) {
                files.push(path.to_string_lossy().into_owned());
            }
        }
    }

    files.sort();
    warnings.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(EnvDiscoveryResults {
        directory: root.to_string_lossy().into_owned(),
        files,
        warnings,
    })
}

/// Imports selected `.env` entries into a project/environment and atomically
/// replaces their plaintext values with WispKey tokens in the same file.
pub fn attach_env_file(
    vault: &Vault,
    path: &str,
    keys: &[String],
    project: &str,
    environment_override: Option<&str>,
) -> crate::core::Result<AttachEnvResults> {
    let input_path = Path::new(path);
    if project.trim().is_empty() {
        return Err(VaultError::InvalidEnvFile(
            "project name must not be empty".into(),
        ));
    }
    let input_metadata = fs::symlink_metadata(input_path)?;
    if input_metadata.file_type().is_symlink() || !input_metadata.is_file() {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} must be a regular, non-symlink file",
            input_path.display()
        )));
    }
    if input_metadata.len() > MAX_ATTACH_FILE_BYTES {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} exceeds the {} byte size limit",
            input_path.display(),
            MAX_ATTACH_FILE_BYTES
        )));
    }

    let canonical_path = fs::canonicalize(input_path)?;
    let _attachment_lock = lock_env_file(&canonical_path)?;
    let locked_metadata = fs::symlink_metadata(&canonical_path)?;
    if locked_metadata.file_type().is_symlink() || !locked_metadata.is_file() {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} must remain a regular, non-symlink file",
            canonical_path.display()
        )));
    }
    if locked_metadata.len() > MAX_ATTACH_FILE_BYTES {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} exceeds the {} byte size limit",
            canonical_path.display(),
            MAX_ATTACH_FILE_BYTES
        )));
    }
    let original = fs::read_to_string(&canonical_path)?;
    let entries = selected_env_entries(&original, keys)?;
    let environment = resolve_environment_name(&canonical_path, environment_override)?;

    let mut credential_names = HashSet::new();
    let mut named_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let credential_name = format!("{}-{}", environment, env_key_to_credential_name(&entry.key));
        if !credential_names.insert(credential_name.clone()) {
            return Err(VaultError::InvalidEnvFile(format!(
                "selected keys map to duplicate credential '{credential_name}'"
            )));
        }
        named_entries.push((entry, credential_name));
    }

    let project_created = match vault.get_project(project) {
        Ok(_) => false,
        Err(VaultError::ProjectNotFound(_)) => {
            if let Some((entry, _)) = named_entries
                .iter()
                .find(|(entry, _)| is_wisp_token(&entry.value))
            {
                return Err(VaultError::EnvCredentialConflict(format!(
                    "token for '{}' cannot be attached because project '{project}' does not exist",
                    entry.key
                )));
            }
            vault.create_project(project, "")?;
            true
        }
        Err(error) => return Err(error),
    };
    let (partition, environment_created) = match vault
        .get_partition_in_project(project, &environment)
    {
        Ok(partition) => (partition, false),
        Err(VaultError::PartitionNotFound(_)) => {
            if let Some((entry, _)) = named_entries
                .iter()
                .find(|(entry, _)| is_wisp_token(&entry.value))
            {
                return Err(VaultError::EnvCredentialConflict(format!(
                    "token for '{}' cannot be attached because environment '{environment}' does not exist",
                    entry.key
                )));
            }
            for (_, credential_name) in &named_entries {
                match vault.get_credential_in_project(project, credential_name) {
                    Ok(_) => {
                        return Err(VaultError::EnvCredentialConflict(format!(
                            "credential '{credential_name}' belongs to a different environment"
                        )));
                    }
                    Err(VaultError::CredentialNotFound(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            (
                vault.create_partition(
                    &environment,
                    "Environment attached from a .env file",
                    Some(project),
                )?,
                true,
            )
        }
        Err(error) => return Err(error),
    };

    let mut plans = Vec::with_capacity(named_entries.len());
    for (entry, credential_name) in named_entries {
        let already_tokenized = is_wisp_token(&entry.value);
        let credential = match vault.get_credential_in_project(project, &credential_name) {
            Ok(credential) => {
                if credential.partition_id.as_deref() != Some(partition.id.as_str()) {
                    return Err(VaultError::EnvCredentialConflict(format!(
                        "credential '{credential_name}' belongs to a different environment"
                    )));
                }
                if already_tokenized {
                    if credential.wisp_token != entry.value {
                        return Err(VaultError::EnvCredentialConflict(format!(
                            "token for '{}' does not match credential '{credential_name}'",
                            entry.key
                        )));
                    }
                } else {
                    let existing_value =
                        vault.decrypt_credential_value_in_project(project, &credential_name)?;
                    if !secret_values_match(&existing_value, &entry.value) {
                        return Err(VaultError::EnvCredentialConflict(format!(
                            "credential '{credential_name}' already stores a different value"
                        )));
                    }
                }
                Some(credential)
            }
            Err(VaultError::CredentialNotFound(_)) if already_tokenized => {
                return Err(VaultError::EnvCredentialConflict(format!(
                    "token for '{}' is not attached to credential '{credential_name}'",
                    entry.key
                )));
            }
            Err(VaultError::CredentialNotFound(_)) => None,
            Err(error) => return Err(error),
        };

        plans.push(AttachPlan {
            entry,
            credential_name,
            credential,
            already_tokenized,
        });
    }

    let mut imported = 0;
    let mut reused = 0;
    let mut already_attached = 0;
    let requests: Vec<_> = plans
        .iter()
        .filter(|plan| plan.credential.is_none())
        .map(|plan| AddCredentialRequest {
            name: &plan.credential_name,
            credential_type: detect_credential_type(&plan.entry.value),
            value: &plan.entry.value,
            description: None,
            hosts: None,
            tags: Some("attached"),
            partition: Some(&environment),
            project: Some(project),
            origin: None,
            lifecycle_state: None,
            review_at: None,
        })
        .collect();
    let created = if requests.is_empty() {
        Vec::new()
    } else {
        vault.add_credentials_atomic(&requests)?
    };
    drop(requests);
    let mut created = created.into_iter();
    for plan in &mut plans {
        if plan.credential.is_none() {
            let credential = created
                .next()
                .expect("atomic attachment insert must return one credential per request");
            audit::log_event(
                vault.db(),
                "CredentialAdded",
                Some(&credential.name),
                Some(&credential.wisp_token),
                None,
                None,
                None,
                None,
                false,
                None,
                Some(project),
            );
            plan.credential = Some(credential);
            imported += 1;
        } else if plan.already_tokenized {
            already_attached += 1;
        } else {
            reused += 1;
        }
    }

    let mut replacements = Vec::new();
    let mut credentials = Vec::with_capacity(plans.len());
    for plan in plans {
        let credential = plan
            .credential
            .expect("attach plan must resolve a credential before file replacement");
        if !plan.already_tokenized {
            replacements.push((plan.entry.value_range, credential.wisp_token.clone()));
        }
        credentials.push(AttachedEnvCredential {
            env_key: plan.entry.key,
            credential: credential.name,
            wisp_token: credential.wisp_token,
        });
    }

    let updated = replacements.len();
    if updated > 0 {
        replacements.sort_by(|left, right| right.0.start.cmp(&left.0.start));
        let mut attached = original.clone();
        for (range, token) in replacements {
            attached.replace_range(range, &token);
        }
        replace_env_file(&canonical_path, original.as_bytes(), attached.as_bytes())?;
    }
    secure_files::harden_existing_file(&canonical_path)?;

    Ok(AttachEnvResults {
        path: canonical_path.to_string_lossy().into_owned(),
        project: project.to_string(),
        environment: environment.clone(),
        partition: environment,
        imported,
        reused,
        already_attached,
        updated,
        project_created,
        environment_created,
        credentials,
    })
}

fn is_skipped_directory(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    SKIPPED_DIRECTORIES.contains(&name.as_ref())
}

fn is_attachable_env_file(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    (name == ".env" || name.starts_with(".env."))
        && !name.ends_with(".previous")
        && !name.ends_with(".example")
        && !name.ends_with(".sample")
        && !name.ends_with(".template")
        && !name.ends_with(".wispkey.lock")
        && !RESERVED_ENV_FILES.contains(&name.as_ref())
}

fn resolve_environment_name(
    path: &Path,
    environment_override: Option<&str>,
) -> crate::core::Result<String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| VaultError::InvalidEnvFile("missing file name".into()))?;
    if !is_attachable_env_file(file_name) {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} is not an attachable .env file",
            path.display()
        )));
    }

    let raw_name = if let Some(environment) = environment_override {
        environment.to_string()
    } else {
        let file_name = file_name.to_string_lossy();
        if file_name == ".env" {
            "default".to_string()
        } else {
            file_name
                .strip_prefix(".env.")
                .expect("attachable environment file has .env. prefix")
                .to_string()
        }
    };

    let normalized = normalize_scope_component(&raw_name);
    if normalized.is_empty() {
        return Err(VaultError::InvalidEnvFile(
            "environment name must contain an ASCII letter or number".into(),
        ));
    }
    if normalized != raw_name {
        return Err(VaultError::InvalidEnvFile(format!(
            "environment '{raw_name}' is not canonical; use '{normalized}'"
        )));
    }
    Ok(normalized)
}

fn is_wisp_token(value: &str) -> bool {
    if let Some(slug) = value.strip_prefix("wk_env_") {
        return !slug.is_empty()
            && slug
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_');
    }

    let Some(body) = value.strip_prefix("wk_") else {
        return false;
    };
    let Some((slug, random)) = body.rsplit_once('_') else {
        return false;
    };
    !slug.is_empty()
        && slug
            .chars()
            .all(|character| character.is_alphanumeric() || character == '_')
        && random.len() == 8
        && random
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn lock_env_file(path: &Path) -> crate::core::Result<fs::File> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let lock_path = parent.join(format!("{file_name}.wispkey.lock"));
    let _created = secure_files::create_private_in_existing_directory(&lock_path, b"")?;
    let lock = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    lock.lock_exclusive()?;
    Ok(lock)
}

fn normalize_scope_component(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
        } else if !normalized.is_empty() && !normalized.ends_with('-') {
            normalized.push('-');
        }
    }
    normalized.trim_matches('-').to_string()
}

fn selected_env_entries(
    content: &str,
    keys: &[String],
) -> crate::core::Result<Vec<SelectedEnvEntry>> {
    if keys.is_empty() {
        return Err(VaultError::InvalidEnvFile(
            "select at least one secret key with --key".into(),
        ));
    }

    let mut selected = HashSet::new();
    for key in keys {
        if !is_valid_env_key(key) {
            return Err(VaultError::InvalidEnvFile(format!(
                "'{key}' is not a portable environment variable name"
            )));
        }
        selected.insert(key.as_str());
    }

    let mut entries = Vec::with_capacity(selected.len());
    let mut found = HashSet::new();
    let mut offset = 0;
    for segment in content.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(entry) = parse_selected_assignment(line, offset, &selected)? {
            if !found.insert(entry.key.clone()) {
                return Err(VaultError::InvalidEnvFile(format!(
                    "selected key '{}' is defined more than once",
                    entry.key
                )));
            }
            if entry.value.is_empty() {
                return Err(VaultError::InvalidEnvFile(format!(
                    "selected key '{}' has an empty value",
                    entry.key
                )));
            }
            entries.push(entry);
        }
        offset += segment.len();
    }

    let mut missing: Vec<&str> = selected
        .into_iter()
        .filter(|key| !found.contains(*key))
        .collect();
    if !missing.is_empty() {
        missing.sort_unstable();
        return Err(VaultError::InvalidEnvFile(format!(
            "selected key(s) not found: {}",
            missing.join(", ")
        )));
    }

    Ok(entries)
}

fn parse_selected_assignment(
    line: &str,
    line_offset: usize,
    selected: &HashSet<&str>,
) -> crate::core::Result<Option<SelectedEnvEntry>> {
    let bytes = line.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if cursor == bytes.len() || bytes[cursor] == b'#' {
        return Ok(None);
    }

    if line[cursor..].starts_with("export")
        && bytes
            .get(cursor + "export".len())
            .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += "export".len();
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
    }

    let key_start = cursor;
    if bytes
        .get(cursor)
        .is_none_or(|byte| *byte != b'_' && !byte.is_ascii_alphabetic())
    {
        return Ok(None);
    }
    cursor += 1;
    while cursor < bytes.len() && (bytes[cursor] == b'_' || bytes[cursor].is_ascii_alphanumeric()) {
        cursor += 1;
    }
    let key = &line[key_start..cursor];
    if !selected.contains(key) {
        return Ok(None);
    }

    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'=') {
        return Err(VaultError::InvalidEnvFile(format!(
            "selected key '{key}' is not a KEY=value assignment"
        )));
    }
    cursor += 1;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }

    let (value, range) = if matches!(bytes.get(cursor), Some(b'\'' | b'"')) {
        let quote = bytes[cursor];
        let value_start = cursor + 1;
        let mut value_end = value_start;
        let mut closed = false;
        while value_end < bytes.len() {
            if bytes[value_end] == quote {
                closed = true;
                break;
            }
            if quote == b'"' && bytes[value_end] == b'\\' && value_end + 1 < bytes.len() {
                value_end += 2;
            } else {
                value_end += 1;
            }
        }
        if !closed {
            return Err(VaultError::InvalidEnvFile(format!(
                "selected key '{key}' has an unterminated quoted value"
            )));
        }
        let trailing = line[value_end + 1..].trim_start();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return Err(VaultError::InvalidEnvFile(format!(
                "selected key '{key}' has invalid content after its quoted value"
            )));
        }
        let raw_value = &line[value_start..value_end];
        (
            if quote == b'"' {
                decode_double_quoted_value(raw_value)
            } else {
                raw_value.to_string()
            },
            line_offset + value_start..line_offset + value_end,
        )
    } else {
        let value_start = cursor;
        let mut value_end = bytes.len();
        for index in value_start..bytes.len() {
            if bytes[index] == b'#'
                && (index == value_start || bytes[index - 1].is_ascii_whitespace())
            {
                value_end = index;
                break;
            }
        }
        while value_end > value_start && bytes[value_end - 1].is_ascii_whitespace() {
            value_end -= 1;
        }
        (
            line[value_start..value_end].to_string(),
            line_offset + value_start..line_offset + value_end,
        )
    };

    Ok(Some(SelectedEnvEntry {
        key: key.to_string(),
        value,
        value_range: range,
    }))
}

fn decode_double_quoted_value(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }

        match characters.next() {
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some('"') => decoded.push('"'),
            Some('\\') => decoded.push('\\'),
            Some(other) => {
                decoded.push('\\');
                decoded.push(other);
            }
            None => decoded.push('\\'),
        }
    }
    decoded
}

fn secret_values_match(left: &str, right: &str) -> bool {
    left.as_bytes() == right.as_bytes()
}

fn replace_env_file(path: &Path, original: &[u8], attached: &[u8]) -> crate::core::Result<()> {
    if fs::read(path)? != original {
        return Err(VaultError::InvalidEnvFile(format!(
            "{} changed while it was being attached; retry",
            path.display()
        )));
    }

    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let temp_path = parent.join(format!(".{file_name}.wispkey-{}.tmp", Uuid::new_v4()));
    if !secure_files::create_private_in_existing_directory(&temp_path, attached)? {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "temporary attachment file already exists: {}",
                temp_path.display()
            ),
        )));
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(VaultError::Io(error));
    }
    Ok(())
}

/// Parses a `.env` file, auto-detects credential types, and imports each entry into the vault.
pub fn import_env_file(
    vault: &Vault,
    path: &str,
    prefix: Option<&str>,
    partition: Option<&str>,
    project: Option<&str>,
) -> crate::core::Result<ImportResults> {
    let content = fs::read_to_string(path).map_err(VaultError::Io)?;
    let entries = parse_env(&content);

    if entries.is_empty() {
        return Ok(ImportResults {
            imported: 0,
            skipped: 0,
            errors: 0,
            output_path: String::new(),
        });
    }

    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = 0;
    let mut output_lines: Vec<String> = Vec::with_capacity(entries.len());

    let prefix_str = prefix.unwrap_or("");

    for entry in &entries {
        let base_name = env_key_to_credential_name(&entry.key);
        let cred_name = if prefix_str.is_empty() {
            base_name
        } else {
            format!("{}-{}", prefix_str, base_name)
        };
        let detected_type = detect_credential_type(&entry.value);

        match vault.add_credential(AddCredentialRequest {
            name: &cred_name,
            credential_type: detected_type,
            value: &entry.value,
            description: None,
            hosts: None,
            tags: Some("imported"),
            partition,
            project,
            origin: None,
            lifecycle_state: None,
            review_at: None,
        }) {
            Ok(cred) => {
                audit::log_event(
                    vault.db(),
                    "CredentialAdded",
                    Some(&cred_name),
                    Some(&cred.wisp_token),
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    None,
                );
                output_lines.push(format!("{}={}", entry.key, cred.wisp_token));
                println!(
                    "  + {} -> {} ({})",
                    entry.key,
                    cred.wisp_token,
                    cred.credential_type.display_name()
                );
                imported += 1;
            }
            Err(VaultError::DuplicateCredential(_)) => {
                println!("  ~ {} skipped (already exists)", entry.key);
                skipped += 1;
            }
            Err(e) => {
                eprintln!("  ! {} error: {}", entry.key, e);
                errors += 1;
            }
        }
    }

    let mut output_path = String::new();
    if !output_lines.is_empty() {
        let env_path = Path::new(path);
        let out_name = format!(
            "{}.wispkey",
            env_path.file_name().unwrap_or_default().to_string_lossy()
        );
        let out_path = env_path.parent().unwrap_or(Path::new(".")).join(out_name);
        let header = "# Generated by WispKey -- use these wisp tokens instead of real credentials\n# Set HTTP_PROXY=http://localhost:7700 in your agent environment\n\n";
        secure_files::write_private(
            &out_path,
            format!("{}{}\n", header, output_lines.join("\n")).as_bytes(),
        )?;
        output_path = out_path.to_string_lossy().to_string();
    }

    Ok(ImportResults {
        imported,
        skipped,
        errors,
        output_path,
    })
}

fn parse_env(content: &str) -> Vec<EnvEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let line_content = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        if let Some(eq_pos) = line_content.find('=') {
            let key = line_content[..eq_pos].trim().to_string();
            let mut value = line_content[eq_pos + 1..].trim().to_string();

            if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value = value[1..value.len() - 1].to_string();
            }

            if is_valid_env_key(&key) && !value.is_empty() {
                entries.push(EnvEntry { key, value });
            }
        }
    }

    entries
}

fn is_valid_env_key(key: &str) -> bool {
    let mut characters = key.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

struct CredentialPatterns {
    openai: Regex,
    github_pat: Regex,
    github_app: Regex,
    slack_bot: Regex,
    slack_user: Regex,
    aws_access: Regex,
    bearer: Regex,
}

static CREDENTIAL_PATTERNS: OnceLock<CredentialPatterns> = OnceLock::new();

fn get_patterns() -> &'static CredentialPatterns {
    CREDENTIAL_PATTERNS.get_or_init(|| CredentialPatterns {
        openai: Regex::new(r"^sk-[a-zA-Z0-9]{20,}$").expect("static regex"),
        github_pat: Regex::new(r"^ghp_[a-zA-Z0-9]{36}$").expect("static regex"),
        github_app: Regex::new(r"^ghs_[a-zA-Z0-9]{36}$").expect("static regex"),
        slack_bot: Regex::new(r"^xoxb-[0-9]+-[a-zA-Z0-9]+$").expect("static regex"),
        slack_user: Regex::new(r"^xoxp-[0-9]+-[a-zA-Z0-9]+$").expect("static regex"),
        aws_access: Regex::new(r"^AKIA[A-Z0-9]{16}$").expect("static regex"),
        bearer: Regex::new(r"^Bearer [a-zA-Z0-9._\-]+$").expect("static regex"),
    })
}

fn env_key_to_credential_name(key: &str) -> String {
    let mut result = String::with_capacity(key.len() + 8);
    let chars: Vec<char> = key.chars().collect();

    for (index, &character) in chars.iter().enumerate() {
        if character == '_' {
            if !result.is_empty() && !result.ends_with('-') {
                result.push('-');
            }
            continue;
        }

        if character.is_uppercase() && index > 0 {
            let previous = chars[index - 1];
            if previous.is_lowercase() || previous.is_ascii_digit() {
                if !result.ends_with('-') {
                    result.push('-');
                }
            } else if previous.is_uppercase()
                && let Some(&next) = chars.get(index + 1)
                && next.is_lowercase()
                && !result.ends_with('-')
            {
                result.push('-');
            }
        }

        result.push(character.to_ascii_lowercase());
    }

    result.trim_matches('-').to_string()
}

fn detect_credential_type(value: &str) -> CredentialType {
    let patterns = get_patterns();

    if patterns.openai.is_match(value)
        || patterns.github_pat.is_match(value)
        || patterns.github_app.is_match(value)
        || patterns.slack_bot.is_match(value)
        || patterns.slack_user.is_match(value)
        || patterns.bearer.is_match(value)
    {
        return CredentialType::BearerToken;
    }

    if patterns.aws_access.is_match(value) {
        return CredentialType::ApiKey;
    }

    CredentialType::BearerToken
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naming_screaming_snake() {
        assert_eq!(env_key_to_credential_name("DB_PASSWORD"), "db-password");
        assert_eq!(
            env_key_to_credential_name("AUTH_SERVICE_BASE"),
            "auth-service-base"
        );
        assert_eq!(
            env_key_to_credential_name("REDIS_SSL_HOST"),
            "redis-ssl-host"
        );
    }

    #[test]
    fn naming_camel_case() {
        assert_eq!(env_key_to_credential_name("simpleKey"), "simple-key");
        assert_eq!(
            env_key_to_credential_name("MareSynchronosJwt"),
            "mare-synchronos-jwt"
        );
    }

    #[test]
    fn naming_camel_case_with_acronym() {
        assert_eq!(
            env_key_to_credential_name("MareSynchronosDiscordOAuthClientSecret"),
            "mare-synchronos-discord-o-auth-client-secret"
        );
        assert_eq!(env_key_to_credential_name("HTTPSProxy"), "https-proxy");
    }

    #[test]
    fn naming_single_word() {
        assert_eq!(env_key_to_credential_name("PORT"), "port");
        assert_eq!(env_key_to_credential_name("port"), "port");
    }

    #[test]
    fn naming_mixed_underscores_and_camel() {
        assert_eq!(
            env_key_to_credential_name("MareSynchronos_VanityRoles"),
            "mare-synchronos-vanity-roles"
        );
    }

    #[test]
    fn naming_no_leading_trailing_hyphens() {
        assert_eq!(env_key_to_credential_name("_PRIVATE_KEY_"), "private-key");
    }

    #[test]
    fn detect_openai_key() {
        assert_eq!(
            detect_credential_type("sk-abcdefghijklmnopqrstuvwxyz1234567890abcd").display_name(),
            "bearer_token"
        );
    }

    #[test]
    fn detect_github_pat() {
        assert_eq!(
            detect_credential_type("ghp_abcdefghijklmnopqrstuvwxyz1234567890").display_name(),
            "bearer_token"
        );
    }

    #[test]
    fn encoded_basic_auth_is_not_encoded_again() {
        assert_eq!(
            detect_credential_type("Basic dXNlcjpwYXNz").display_name(),
            "bearer_token"
        );
    }

    #[test]
    fn detect_aws_access_key() {
        assert_eq!(
            detect_credential_type("AKIAIOSFODNN7EXAMPLE").display_name(),
            "api_key"
        );
    }

    #[test]
    fn detect_generic_falls_back_to_bearer() {
        assert_eq!(
            detect_credential_type("some-random-value-123").display_name(),
            "bearer_token"
        );
    }

    #[test]
    fn recognizes_only_complete_wisp_token_shapes() {
        assert!(is_wisp_token("wk_default_api_token_a1B2c3D4"));
        assert!(is_wisp_token("wk_env_openai_api_key"));
        assert!(!is_wisp_token("wk_customer-secret"));
        assert!(!is_wisp_token("wk_default_api_token_short"));
    }

    #[test]
    fn parse_env_basic() {
        let content = "KEY1=value1\nKEY2=value2\n# comment\n\nKEY3=\"quoted\"";
        let entries = parse_env(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");
        assert_eq!(entries[2].value, "quoted");
    }

    #[test]
    fn parse_env_export_prefix() {
        let content = "export MY_KEY=my_value";
        let entries = parse_env(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "MY_KEY");
        assert_eq!(entries[0].value, "my_value");
    }

    #[test]
    fn parse_env_skips_empty_values() {
        let content = "EMPTY=\nVALID=yes";
        let entries = parse_env(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "VALID");
    }

    #[test]
    fn parse_env_rejects_nonportable_keys() {
        let content = "SAFE_KEY=value\ntrue; attacker-command #=value\n1INVALID=value";
        let entries = parse_env(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "SAFE_KEY");
    }

    #[test]
    fn selected_entry_decodes_double_quoted_escapes_and_preserves_byte_range() {
        let content = "PORT=3000\r\nPRIVATE_KEY=\"first\\nsecond\" # comment\r\n";
        let entries = selected_env_entries(content, &["PRIVATE_KEY".to_string()]).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "first\nsecond");
        assert_eq!(&content[entries[0].value_range.clone()], "first\\nsecond");
    }
}
