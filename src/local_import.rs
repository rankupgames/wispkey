//! Bounded, owner-reviewed local import. Only metadata crosses the review boundary.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::core::{Credential, Vault, VaultError};

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * MAX_FILE_BYTES;
const MAX_FILES: usize = 64;
const MAX_ITEMS: usize = 256;
const MAX_PLANS: usize = 4;
const PLAN_LIFETIME: Duration = Duration::from_secs(300);

/// All diagnostic text is fixed. Parser input and provider errors are not echoed.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("import input is invalid or unsupported")]
    InvalidInput,
    #[error("import source is unavailable or changed; scan again")]
    SourceChanged,
    #[error("import exceeds the file, item or byte limit")]
    LimitExceeded,
    #[error("import plan expired or was consumed; scan again")]
    PlanUnavailable,
    #[error("unlock the vault again and scan again")]
    SessionChanged,
    #[error("import destination or selection is invalid")]
    InvalidSelection,
    #[error("review the duplicate credential and choose keep, replace or skip")]
    Conflict,
    #[error("enter a bounded hostname or host pattern for each HTTP credential")]
    HostsRequired,
    #[error("confirm the import destination before saving")]
    ConfirmationRequired,
    #[error("vault changed after review or the import could not be saved; scan again")]
    SaveFailed,
}

impl ImportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::SourceChanged => "source_changed",
            Self::LimitExceeded => "limit_exceeded",
            Self::PlanUnavailable => "plan_unavailable",
            Self::SessionChanged => "locked",
            Self::InvalidSelection => "invalid_selection",
            Self::Conflict => "conflict",
            Self::HostsRequired => "hosts_required",
            Self::ConfirmationRequired => "confirmation_required",
            Self::SaveFailed => "import_failed",
        }
    }
}

type Result<T> = std::result::Result<T, ImportError>;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportSource {
    Files {
        paths: Vec<PathBuf>,
    },
    Directory {
        path: PathBuf,
    },
    Clipboard {
        content: String,
        format: InputFormat,
        #[serde(default)]
        name: Option<String>,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    Env,
    Json,
    Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub source: ImportSource,
    pub project: String,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ImportPreview {
    pub plan_id: String,
    pub expires_at: DateTime<Utc>,
    pub project: String,
    pub items: Vec<ImportItem>,
    pub warnings: Vec<&'static str>,
}

#[derive(Clone, Serialize)]
pub struct ImportItem {
    pub id: String,
    pub key: String,
    pub name: String,
    pub source: String,
    pub environment: String,
    #[serde(rename = "type")]
    pub credential_type: &'static str,
    pub conflict: &'static str,
    pub tokenizable: bool,
    pub hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub plan_id: String,
    pub project: String,
    pub items: Vec<ImportSelection>,
    #[serde(default)]
    pub replace_http_values: bool,
    pub destination_confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSelection {
    pub id: String,
    pub environment: String,
    pub selected: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub conflict_action: ConflictAction,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictAction {
    #[default]
    Unresolved,
    Keep,
    Replace,
    Skip,
}

#[derive(Serialize)]
pub struct ImportOutcome {
    pub stored: usize,
    pub reused: usize,
    pub skipped: usize,
    pub credentials: Vec<ImportedCredential>,
    pub sources: Vec<SourceOutcome>,
    pub source_update_failed: bool,
}

#[derive(Serialize)]
pub struct ImportedCredential {
    pub name: String,
    pub environment: String,
}

#[derive(Serialize)]
pub struct SourceOutcome {
    pub source: String,
    pub status: &'static str,
    pub updated: usize,
}

struct SourceSnapshot {
    path: Option<PathBuf>,
    label: String,
    content: Zeroizing<String>,
}

struct PlannedItem {
    metadata: ImportItem,
    value: Zeroizing<String>,
    source: usize,
    range: Option<Range<usize>>,
}

struct Plan {
    id: String,
    project: String,
    created: Instant,
    expires_at: DateTime<Utc>,
    session_revision: String,
    fingerprint: Vec<u8>,
    sources: Vec<SourceSnapshot>,
    items: Vec<PlannedItem>,
}

/// Session-local secret staging. No persistence, Debug or serialization of plans.
#[derive(Default)]
pub struct ImportSession {
    plans: HashMap<String, Plan>,
}

pub(crate) struct ImportWrite<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub environment: &'a str,
    pub hosts: &'a str,
    pub replace: bool,
}

impl ImportSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.plans.clear();
    }

    /// Owner IPC housekeeping drops expired staged values even without a review.
    pub fn expire(&mut self) {
        let now = Utc::now();
        self.plans
            .retain(|_, plan| plan.created.elapsed() < PLAN_LIFETIME && now < plan.expires_at);
    }

    pub fn cancel(&mut self, plan_id: &str) -> Result<()> {
        self.plans
            .remove(plan_id)
            .map(|_| ())
            .ok_or(ImportError::PlanUnavailable)
    }

    pub fn preview(&mut self, vault: &Vault, request: PreviewRequest) -> Result<ImportPreview> {
        self.expire();
        if self.plans.len() >= MAX_PLANS {
            return Err(ImportError::LimitExceeded);
        }
        validate_scope(&request.project)?;
        if let Some(environment) = request.environment.as_deref() {
            validate_scope(environment)?;
        }
        let binding = vault
            .operation_session_binding()
            .map_err(|_| ImportError::SessionChanged)?;
        let fingerprint = vault
            .local_import_fingerprint(&request.project)
            .map_err(|_| ImportError::SaveFailed)?;
        let mut sources = Vec::new();
        let mut items = Vec::new();
        match request.source {
            ImportSource::Files { paths } => {
                if paths.is_empty() || paths.len() > MAX_FILES {
                    return Err(ImportError::LimitExceeded);
                }
                let mut seen = HashSet::new();
                for path in paths {
                    let path = checked_path(&path)?;
                    if !seen.insert(path.clone()) {
                        return Err(ImportError::InvalidInput);
                    }
                    push_file(
                        &mut sources,
                        &mut items,
                        path,
                        request.environment.as_deref(),
                    )?;
                }
            }
            ImportSource::Directory { path } => {
                if fs::symlink_metadata(&path)
                    .map_err(|_| ImportError::SourceChanged)?
                    .file_type()
                    .is_symlink()
                {
                    return Err(ImportError::InvalidInput);
                }
                let discovery = crate::migrate::discover_env_files(
                    path.to_str().ok_or(ImportError::InvalidInput)?,
                )
                .map_err(|_| ImportError::SourceChanged)?;
                if !discovery.warnings.is_empty() {
                    return Err(ImportError::SourceChanged);
                }
                if discovery.files.is_empty() {
                    return Err(ImportError::InvalidInput);
                }
                if discovery.files.len() > MAX_FILES {
                    return Err(ImportError::LimitExceeded);
                }
                for path in discovery.files {
                    push_file(
                        &mut sources,
                        &mut items,
                        checked_path(Path::new(&path))?,
                        request.environment.as_deref(),
                    )?;
                }
            }
            ImportSource::Clipboard {
                content,
                format,
                name,
            } => {
                let content = Zeroizing::new(content);
                check_content(&content)?;
                let environment = request.environment.as_deref().unwrap_or("default");
                parse_source(
                    &mut items,
                    0,
                    "Clipboard",
                    &content,
                    format,
                    name.as_deref(),
                    environment,
                )?;
                sources.push(SourceSnapshot {
                    path: None,
                    label: "Clipboard".into(),
                    content,
                });
            }
        }
        if items.is_empty() {
            return Err(ImportError::InvalidInput);
        }
        let mut names = HashSet::new();
        for item in &mut items {
            if !names.insert(item.metadata.name.clone()) {
                return Err(ImportError::Conflict);
            }
            item.metadata.conflict =
                match vault.get_credential_in_project(&request.project, &item.metadata.name) {
                    Ok(existing) => {
                        item.metadata.hosts = existing.hosts.clone();
                        item.metadata.tokenizable &= valid_hosts(&existing.hosts);
                        let matching_scope = vault
                            .get_partition_in_project(&request.project, &item.metadata.environment)
                            .is_ok_and(|partition| {
                                existing.partition_id.as_deref() == Some(partition.id.as_str())
                            });
                        if !matching_scope {
                            "scope_conflict"
                        } else {
                            let existing_value = Zeroizing::new(
                                vault
                                    .decrypt_credential_value_in_project(
                                        &request.project,
                                        &item.metadata.name,
                                    )
                                    .map_err(|_| ImportError::Conflict)?,
                            );
                            if existing.wisp_token == *item.value {
                                item.value = existing_value;
                                item.metadata.tokenizable = item.range.is_some()
                                    && http_value(&item.metadata.key, &item.value)
                                    && valid_hosts(&existing.hosts);
                                "same"
                            } else if *existing_value == *item.value {
                                "same"
                            } else {
                                "different"
                            }
                        }
                    }
                    Err(VaultError::CredentialNotFound(_) | VaultError::ProjectNotFound(_)) => {
                        if item.value.starts_with("wk_") {
                            return Err(ImportError::InvalidInput);
                        }
                        "new"
                    }
                    Err(_) => return Err(ImportError::SaveFailed),
                };
        }
        let expires_at = std::cmp::min(
            binding.expires_at,
            Utc::now() + chrono::Duration::seconds(300),
        );
        let plan = Plan {
            id: Uuid::new_v4().to_string(),
            project: request.project,
            created: Instant::now(),
            expires_at,
            session_revision: binding.revision,
            fingerprint,
            sources,
            items,
        };
        let preview = plan.metadata();
        self.plans.insert(plan.id.clone(), plan);
        Ok(preview)
    }

    pub fn review(&mut self, vault: &Vault, plan_id: &str) -> Result<ImportPreview> {
        let plan = self
            .plans
            .get(plan_id)
            .ok_or(ImportError::PlanUnavailable)?;
        if let Err(error) = plan.validate(vault) {
            self.plans.remove(plan_id);
            return Err(error);
        }
        let plan = self
            .plans
            .get(plan_id)
            .ok_or(ImportError::PlanUnavailable)?;
        Ok(plan.metadata())
    }

    pub fn commit(&mut self, vault: &Vault, request: CommitRequest) -> Result<ImportOutcome> {
        if !request.destination_confirmed {
            return Err(ImportError::ConfirmationRequired);
        }
        let plan = self
            .plans
            .remove(&request.plan_id)
            .ok_or(ImportError::PlanUnavailable)?;
        plan.validate(vault)?;
        if request.project != plan.project
            || request.items.is_empty()
            || request.items.len() > MAX_ITEMS
        {
            return Err(ImportError::InvalidSelection);
        }
        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        let mut reused = Vec::new();
        let mut skipped = plan.items.len();
        let mut hosts = Vec::new();
        for selection in &request.items {
            if !seen.insert(selection.id.as_str()) {
                return Err(ImportError::InvalidSelection);
            }
            let item = plan
                .items
                .iter()
                .find(|item| item.metadata.id == selection.id)
                .ok_or(ImportError::InvalidSelection)?;
            // Each destination is explicit and must match its frozen review.
            if selection.environment != item.metadata.environment {
                return Err(ImportError::InvalidSelection);
            }
            if !selection.selected || matches!(selection.conflict_action, ConflictAction::Skip) {
                continue;
            }
            let environment = selection.environment.as_str();
            let existing = match vault.get_credential_in_project(&plan.project, &item.metadata.name)
            {
                Ok(existing) => Some(existing),
                Err(VaultError::CredentialNotFound(_) | VaultError::ProjectNotFound(_)) => None,
                Err(_) => return Err(ImportError::SaveFailed),
            };
            if let Some(existing) = existing {
                let partition = vault
                    .get_partition_in_project(&plan.project, environment)
                    .map_err(|_| ImportError::Conflict)?;
                if existing.partition_id.as_deref() != Some(partition.id.as_str()) {
                    return Err(ImportError::Conflict);
                }
                if request.replace_http_values && !valid_hosts(&existing.hosts) {
                    return Err(ImportError::HostsRequired);
                }
                match selection.conflict_action {
                    ConflictAction::Keep => {
                        let current = Zeroizing::new(
                            vault
                                .decrypt_credential_value_in_project(
                                    &plan.project,
                                    &item.metadata.name,
                                )
                                .map_err(|_| ImportError::Conflict)?,
                        );
                        if request.replace_http_values && *current != *item.value {
                            return Err(ImportError::Conflict);
                        }
                        reused.push((item, existing));
                        skipped -= 1;
                        continue;
                    }
                    ConflictAction::Replace => {}
                    _ => return Err(ImportError::Conflict),
                }
                hosts.push(existing.hosts.join(","));
                selected.push((item, true));
            } else {
                if item.metadata.tokenizable && !valid_hosts(&selection.hosts) {
                    return Err(ImportError::HostsRequired);
                }
                hosts.push(selection.hosts.join(","));
                selected.push((item, false));
            }
            skipped -= 1;
        }
        if selected.is_empty() && reused.is_empty() {
            return Err(ImportError::InvalidSelection);
        }
        if request.replace_http_values {
            for (item, _) in selected
                .iter()
                .copied()
                .chain(reused.iter().map(|(item, _)| (*item, false)))
            {
                if !item.metadata.tokenizable
                    || item.range.is_none()
                    || plan.sources[item.source].path.is_none()
                {
                    return Err(ImportError::InvalidSelection);
                }
            }
        }
        let writes: Vec<_> = selected
            .iter()
            .enumerate()
            .map(|(index, (item, replace))| ImportWrite {
                name: &item.metadata.name,
                value: &item.value,
                environment: &item.metadata.environment,
                hosts: &hosts[index],
                replace: *replace,
            })
            .collect();
        let saved = vault
            .commit_local_import(
                &plan.session_revision,
                &plan.fingerprint,
                &plan.project,
                &writes,
                &reused
                    .iter()
                    .map(|(_, credential)| credential.id.as_str())
                    .collect::<Vec<_>>(),
                || {
                    plan.validate_sources().map_err(|_| {
                        VaultError::AuthRejected("import source changed before commit")
                    })
                },
            )
            .map_err(|_| ImportError::SaveFailed)?;
        let mut resolved: Vec<(&PlannedItem, Credential)> =
            selected.iter().map(|(item, _)| *item).zip(saved).collect();
        let stored = resolved.len();
        let reused_count = reused.len();
        resolved.extend(reused);
        let credentials = resolved
            .iter()
            .map(|(item, _)| ImportedCredential {
                name: item.metadata.name.clone(),
                environment: item.metadata.environment.clone(),
            })
            .collect();
        let mut source_update_failed = false;
        let mut outcomes = Vec::new();
        for (index, source) in plan.sources.iter().enumerate() {
            let mut replacements: Vec<_> = resolved
                .iter()
                .filter(|(item, _)| item.source == index)
                .filter_map(|(item, credential)| {
                    item.range
                        .clone()
                        .map(|range| (range, credential.wisp_token.as_str()))
                })
                .collect();
            let mut status = "unchanged";
            let mut updated = 0;
            if request.replace_http_values && !replacements.is_empty() {
                replacements.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
                let mut rendered = Zeroizing::new(source.content.to_string());
                for (range, token) in &replacements {
                    rendered.replace_range(range.clone(), token);
                }
                if rendered.as_str() == source.content.as_str() {
                    outcomes.push(SourceOutcome {
                        source: source.label.clone(),
                        status,
                        updated,
                    });
                    continue;
                }
                let result = source
                    .path
                    .as_ref()
                    .ok_or(ImportError::InvalidSelection)
                    .and_then(|path| {
                        if read_source(path)?.as_str() != source.content.as_str() {
                            return Err(ImportError::SourceChanged);
                        }
                        crate::migrate::replace_env_file(
                            path,
                            source.content.as_bytes(),
                            rendered.as_bytes(),
                        )
                        .map_err(|_| ImportError::SourceChanged)
                    });
                if result.is_ok() {
                    status = "tokens_written";
                    updated = replacements.len();
                } else {
                    status = "not_changed";
                    source_update_failed = true;
                }
            }
            outcomes.push(SourceOutcome {
                source: source.label.clone(),
                status,
                updated,
            });
        }
        Ok(ImportOutcome {
            stored,
            reused: reused_count,
            skipped,
            credentials,
            sources: outcomes,
            source_update_failed,
        })
    }
}

impl Plan {
    fn metadata(&self) -> ImportPreview {
        ImportPreview {
            plan_id: self.id.clone(),
            expires_at: self.expires_at,
            project: self.project.clone(),
            items: self
                .items
                .iter()
                .map(|item| item.metadata.clone())
                .collect(),
            warnings: Vec::new(),
        }
    }

    fn validate(&self, vault: &Vault) -> Result<()> {
        if self.created.elapsed() >= PLAN_LIFETIME || Utc::now() >= self.expires_at {
            return Err(ImportError::PlanUnavailable);
        }
        let binding = vault
            .operation_session_binding()
            .map_err(|_| ImportError::SessionChanged)?;
        if binding.revision != self.session_revision {
            return Err(ImportError::SessionChanged);
        }
        if vault
            .local_import_fingerprint(&self.project)
            .map_err(|_| ImportError::SaveFailed)?
            != self.fingerprint
        {
            return Err(ImportError::SaveFailed);
        }
        self.validate_sources()
    }

    fn validate_sources(&self) -> Result<()> {
        for source in &self.sources {
            if let Some(path) = source.path.as_ref()
                && read_source(path)?.as_str() != source.content.as_str()
            {
                return Err(ImportError::SourceChanged);
            }
        }
        Ok(())
    }
}

fn validate_scope(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 96 || value.chars().any(char::is_control) {
        return Err(ImportError::InvalidSelection);
    }
    Ok(())
}

fn valid_hosts(hosts: &[String]) -> bool {
    !hosts.is_empty()
        && hosts.iter().all(|host| {
            !host.is_empty()
                && host.len() <= 253
                && host.contains(|ch: char| ch.is_ascii_alphanumeric())
                && !host.contains(['/', ':', ',', '@'])
                && !host.chars().any(char::is_whitespace)
                && host
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '*' | '?'))
        })
}

fn checked_path(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ImportError::SourceChanged)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ImportError::InvalidInput);
    }
    fs::canonicalize(path).map_err(|_| ImportError::SourceChanged)
}

fn read_source(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ImportError::SourceChanged)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_FILE_BYTES as u64
    {
        return Err(ImportError::SourceChanged);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| ImportError::SourceChanged)?;
    if !file
        .metadata()
        .map_err(|_| ImportError::SourceChanged)?
        .is_file()
    {
        return Err(ImportError::InvalidInput);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImportError::SourceChanged)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ImportError::LimitExceeded);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ImportError::InvalidInput)?;
    check_content(text)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn check_content(content: &str) -> Result<()> {
    if content.is_empty() || content.contains('\0') {
        return Err(ImportError::InvalidInput);
    }
    if content.len() > MAX_FILE_BYTES {
        return Err(ImportError::LimitExceeded);
    }
    Ok(())
}

fn push_file(
    sources: &mut Vec<SourceSnapshot>,
    items: &mut Vec<PlannedItem>,
    path: PathBuf,
    environment: Option<&str>,
) -> Result<()> {
    let content = read_source(&path)?;
    if sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>()
        + content.len()
        > MAX_TOTAL_BYTES
    {
        return Err(ImportError::LimitExceeded);
    }
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ImportError::InvalidInput)?;
    let (format, suggested) = if filename == ".env" {
        (InputFormat::Env, "default")
    } else if let Some(environment) = filename.strip_prefix(".env.") {
        (InputFormat::Env, environment)
    } else if path.extension().is_some_and(|value| value == "json") {
        (InputFormat::Json, "default")
    } else if path
        .extension()
        .is_some_and(|value| matches!(value.to_str(), Some("pem" | "key" | "secret")))
    {
        (InputFormat::Secret, "default")
    } else {
        return Err(ImportError::InvalidInput);
    };
    let environment = environment.unwrap_or(suggested);
    validate_scope(environment)?;
    let label = path.to_string_lossy().to_string();
    parse_source(
        items,
        sources.len(),
        &label,
        &content,
        format,
        Some(filename),
        environment,
    )?;
    sources.push(SourceSnapshot {
        path: Some(path),
        label,
        content,
    });
    Ok(())
}

fn parse_source(
    items: &mut Vec<PlannedItem>,
    source: usize,
    label: &str,
    content: &str,
    format: InputFormat,
    name: Option<&str>,
    environment: &str,
) -> Result<()> {
    let entries = match format {
        InputFormat::Env => strict_env(content)?,
        InputFormat::Json => {
            let entries: StrictJson =
                serde_json::from_str(content).map_err(|_| ImportError::InvalidInput)?;
            entries
                .0
                .into_iter()
                .map(|(key, value)| (key, value, None))
                .collect()
        }
        InputFormat::Secret => vec![(
            name.filter(|name| !name.trim().is_empty())
                .ok_or(ImportError::InvalidInput)?
                .to_string(),
            content.to_string(),
            None,
        )],
    };
    for (key, value, range) in entries {
        if key.is_empty()
            || key.len() > 128
            || key.chars().any(char::is_control)
            || value.trim().is_empty()
            || value.contains('\0')
        {
            return Err(ImportError::InvalidInput);
        }
        if items.len() >= MAX_ITEMS {
            return Err(ImportError::LimitExceeded);
        }
        let normalized = normalize_name(&key);
        let name = format!("{}-{normalized}", normalize_name(environment));
        if normalized.is_empty() || name.len() > 192 {
            return Err(ImportError::InvalidInput);
        }
        let tokenizable = !matches!(format, InputFormat::Secret) && http_value(&key, &value);
        items.push(PlannedItem {
            metadata: ImportItem {
                id: Uuid::new_v4().to_string(),
                key,
                name,
                source: label.to_string(),
                environment: environment.to_string(),
                credential_type: "api_key",
                conflict: "new",
                tokenizable,
                hosts: Vec::new(),
            },
            value: Zeroizing::new(value),
            source,
            range,
        });
    }
    Ok(())
}

fn normalize_name(value: &str) -> String {
    let mut name = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_lowercase());
        } else if !name.is_empty() && !name.ends_with('-') {
            name.push('-');
        }
    }
    name.trim_end_matches('-').to_owned()
}

fn http_value(key: &str, value: &str) -> bool {
    let key = key.to_ascii_uppercase();
    let value = value.trim();
    if key.contains("DATABASE")
        || key.contains("PRIVATE_KEY")
        || key.contains("PRIVATEKEY")
        || key.contains("PASSWORD")
        || key.contains("KEYFILE")
        || key.contains("FILEPATH")
        || key
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|part| {
                matches!(
                    part,
                    "DB" | "PORT"
                        | "PORTS"
                        | "SSH"
                        | "SFTP"
                        | "PASSWORD"
                        | "PASSWD"
                        | "PASSPHRASE"
                        | "PWD"
                        | "PATH"
                        | "FILE"
                        | "DIRECTORY"
                        | "DIR"
                        | "SOCKET"
                        | "SOCK"
                        | "CERT"
                        | "CERTIFICATE"
                )
            })
        || value.parse::<f64>().is_ok()
        || ["true", "false", "yes", "no", "on", "off", "null", "none"]
            .iter()
            .any(|setting| value.eq_ignore_ascii_case(setting))
        || value.contains(['\r', '\n'])
        || value.starts_with(['/', '~'])
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('\\')
        || value.starts_with("ssh-")
        || value.starts_with("-----BEGIN")
    {
        return false;
    }
    match url::Url::parse(value) {
        Ok(url) => matches!(url.scheme(), "http" | "https"),
        Err(_) => true,
    }
}

type ParsedEntry = (String, String, Option<Range<usize>>);

fn strict_env(content: &str) -> Result<Vec<ParsedEntry>> {
    let mut keys = Vec::new();
    for line in content.lines() {
        let mut line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export")
            && rest.starts_with(char::is_whitespace)
        {
            line = rest.trim_start();
        }
        let (key, _) = line.split_once('=').ok_or(ImportError::InvalidInput)?;
        let key = key.trim();
        if key.is_empty()
            || !key.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            })
        {
            return Err(ImportError::InvalidInput);
        }
        keys.push(key.to_owned());
    }
    crate::migrate::selected_env_entries(content, &keys)
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| (entry.key, entry.value, Some(entry.value_range)))
                .collect()
        })
        .map_err(|_| ImportError::InvalidInput)
}

struct StrictJson(Vec<(String, String)>);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = StrictJson;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a nonempty object of distinct string fields")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut result = Vec::new();
                let mut names = HashSet::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if result.len() >= MAX_ITEMS || !names.insert(key.clone()) || value.is_empty() {
                        return Err(serde::de::Error::custom("invalid or repeated field"));
                    }
                    result.push((key, value));
                }
                if result.is_empty() {
                    return Err(serde::de::Error::custom("empty object"));
                }
                Ok(StrictJson(result))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
