//! Owner-selected, local repository bindings. Nothing is written to a worktree.
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::core::Vault;
use crate::secure_files;

use super::exec::open_unlocked_vault;
use super::shared::{json_output, print_json};

type Result<T> = std::result::Result<T, &'static str>;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub worktree: WorktreeSettings,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorktreeSettings {
    #[serde(default)]
    overrides: Vec<String>,
    #[serde(default)]
    allow_shared_database: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    repository: String,
    project: String,
    project_id: String,
    environment: String,
    partition_id: String,
    manifest: Manifest,
}

pub(super) struct Selection {
    pub project: String,
    pub manifest: Manifest,
    pub partition_id: Option<String>,
}

struct Repository {
    identity: String,
    root: PathBuf,
}

fn git(args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    // Caller-controlled Git routing/config must not select a different repository.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command
        .args(args)
        .output()
        .map_err(|_| "Git discovery failed")?;
    if !output.status.success() {
        return Err("Git discovery failed");
    }
    String::from_utf8(output.stdout).map_err(|_| "Git paths must be valid UTF-8")
}

fn repository(create_identity: bool) -> Result<Repository> {
    let root = git(&["rev-parse", "--show-toplevel"])?;
    let root = Path::new(root.trim_end_matches('\n'))
        .canonicalize()
        .map_err(|_| "Git worktree is unavailable")?;
    let cwd = std::env::current_dir()
        .and_then(|path| path.canonicalize())
        .map_err(|_| "current directory is unavailable")?;
    if !cwd.starts_with(&root) {
        return Err("Git worktree root does not contain the current directory");
    }
    let common = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"])?;
    let common = Path::new(common.trim_end_matches('\n'))
        .canonicalize()
        .map_err(|_| "Git common directory is unavailable")?;
    // A hand-written .git pointer is not enough: Git must register this root.
    let registered = git(&["worktree", "list", "--porcelain", "-z"])?;
    if !registered
        .split('\0')
        .filter_map(|field| field.strip_prefix("worktree "))
        .any(|path| Path::new(path).canonicalize().ok().as_ref() == Some(&root))
    {
        return Err("current directory is not a registered Git worktree");
    }
    // An untracked common-dir marker prevents a different repository recreated at
    // the same filesystem path from acquiring the old binding. The canonical
    // common path additionally prevents copied markers in independent clones.
    let marker = common.join("wispkey-repository-id");
    if create_identity && !marker.exists() {
        secure_files::create_private_in_existing_directory(
            &marker,
            uuid::Uuid::new_v4().to_string().as_bytes(),
        )
        .map_err(|_| "cannot establish repository identity")?;
    }
    let repository_id = secure_files::read_private_string(&marker, 128)
        .map_err(|_| "repository is not bound; use wispkey env bind or explicit --manifest")?;
    uuid::Uuid::parse_str(&repository_id).map_err(|_| "invalid repository identity")?;
    let mut identity_material = common.as_os_str().as_encoded_bytes().to_vec();
    identity_material.push(0);
    identity_material.extend_from_slice(repository_id.as_bytes());
    let identity = digest(&SHA256, &identity_material)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Repository { identity, root })
}

fn binding_path(identity: &str) -> PathBuf {
    Vault::vault_dir()
        .join("repository-bindings")
        .join(format!("{identity}.json"))
}

fn read_config(path: &Path) -> Result<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not block opening a FIFO substituted for an override file.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "configuration is missing or unreadable")?;
    let metadata = file.metadata().map_err(|_| "configuration is unreadable")?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err("configuration must be a regular file smaller than 64 KiB");
    }
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|_| "configuration is unreadable")?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("configuration exceeds 64 KiB");
    }
    Ok(raw)
}

pub(super) fn read_manifest(path: &Path) -> Result<Manifest> {
    let manifest: Manifest = toml::from_str(&read_config(path)?).map_err(
        |_| "failed to parse manifest: expected [env] strings and optional [worktree] settings",
    )?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.env.is_empty() {
        return Err("manifest must contain a non-empty [env] table");
    }
    for (name, value) in &manifest.env {
        if !valid_name(name) || value.contains('\0') || value == "cred:" {
            return Err("invalid environment name, value, or credential reference");
        }
    }
    for name in &manifest.worktree.overrides {
        if !manifest
            .env
            .get(name)
            .is_some_and(|value| !value.starts_with("cred:"))
        {
            return Err("worktree overrides must name existing non-credential settings");
        }
    }
    Ok(())
}

fn validate_scope(vault: &Vault, binding: &Binding) -> Result<()> {
    if binding.version != 1
        || !matches!(
            binding.environment.as_str(),
            "development" | "dev" | "local" | "test"
        )
    {
        return Err("invalid development environment binding");
    }
    let project = vault
        .get_project(&binding.project)
        .map_err(|_| "bound project is unavailable")?;
    let partition = vault
        .get_partition_in_project(&binding.project, &binding.environment)
        .map_err(|_| "bound environment is unavailable")?;
    if project.id != binding.project_id || partition.id != binding.partition_id {
        return Err("bound project or environment identity changed; bind again explicitly");
    }
    validate_manifest(&binding.manifest)?;
    for value in binding.manifest.env.values() {
        if let Some(name) = value.strip_prefix("cred:") {
            let credential = vault
                .get_credential_in_project(&binding.project, name)
                .map_err(|_| "bound credential is unavailable")?;
            if credential.partition_id.as_deref() != Some(&binding.partition_id) {
                return Err("credential is outside the bound development environment");
            }
        }
    }
    Ok(())
}

fn apply_override(manifest: &mut Manifest, name: &str, value: &str) -> Result<()> {
    if !manifest
        .worktree
        .overrides
        .iter()
        .any(|allowed| allowed == name)
        || value.starts_with("cred:")
        || value.contains('\0')
    {
        return Err("invalid or unauthorized worktree override");
    }
    manifest.env.insert(name.to_string(), value.to_string());
    Ok(())
}

fn validate_database(manifest: &Manifest) -> Result<()> {
    if manifest.worktree.allow_shared_database {
        return Ok(());
    }
    if let Some(value) = manifest.env.get("DATABASE_URL") {
        // SQLite relative URLs stay relative to the child working directory. Reject
        // unknown/credential-backed URLs unless the owner explicitly opts in.
        let path = value
            .strip_prefix("file:")
            .or_else(|| value.strip_prefix("sqlite:"))
            .ok_or(
                "DATABASE_URL requires a relative SQLite URL or explicit allow_shared_database",
            )?;
        if path.is_empty()
            || path.starts_with('/')
            || path.starts_with('\\')
            || path.contains('%')
            || path.contains(':')
            || path.contains('?')
            || path.contains('#')
            || path.split(['/', '\\']).any(|part| part == "..")
        {
            return Err(
                "DATABASE_URL must stay worktree-relative unless allow_shared_database is explicit",
            );
        }
    }
    Ok(())
}

pub(super) fn manual_manifest(
    explicit: Option<&str>,
    overrides: &[String],
) -> Result<Option<Manifest>> {
    let cwd = std::env::current_dir().map_err(|_| "current directory is unavailable")?;
    let path = explicit.map(PathBuf::from).or_else(|| {
        (!cwd.ancestors().any(|path| path.join(".git").exists()))
            .then(|| PathBuf::from("wispkey.toml"))
    });
    if let Some(path) = path {
        if !overrides.is_empty() {
            return Err("--env requires a repository binding; edit the explicit manifest instead");
        }
        return read_manifest(&path).map(Some);
    }
    Ok(None)
}

pub(super) fn select(
    vault: &Vault,
    manual: Option<Manifest>,
    project: Option<&str>,
    overrides: &[String],
) -> Result<Selection> {
    if let Some(manifest) = manual {
        return Ok(Selection {
            project: project
                .map(str::to_owned)
                .unwrap_or_else(crate::core::resolve_active_project),
            manifest,
            partition_id: None,
        });
    }
    let repo = repository(false)?;
    let path = binding_path(&repo.identity);
    let raw = secure_files::read_private_string(&path, MAX_CONFIG_BYTES)
        .map_err(|_| "repository binding is missing or unreadable; use wispkey env bind or explicit --manifest")?;
    let binding: Binding = serde_json::from_str(&raw).map_err(|_| "invalid repository binding")?;
    if binding.repository != repo.identity {
        return Err("repository binding identity mismatch");
    }
    if project.is_some_and(|name| name != binding.project) {
        return Err(
            "project override does not match repository binding; use explicit --manifest for manual selection",
        );
    }
    validate_scope(vault, &binding)?;
    let mut manifest = binding.manifest;
    let local_path = repo.root.join("wispkey.local.toml");
    match fs::symlink_metadata(&local_path) {
        Ok(_) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Overrides {
                env: BTreeMap<String, String>,
            }
            let local: Overrides = toml::from_str(&read_config(&local_path)?)
                .map_err(|_| "invalid worktree override file")?;
            for (name, value) in local.env {
                apply_override(&mut manifest, &name, &value)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("worktree override file is unreadable"),
    }
    for entry in overrides {
        let (name, value) = entry.split_once('=').ok_or("--env expects NAME=VALUE")?;
        apply_override(&mut manifest, name, value)?;
    }
    validate_database(&manifest)?;
    Ok(Selection {
        project: binding.project,
        manifest,
        partition_id: Some(binding.partition_id),
    })
}

pub fn handle_env_bind(project: &str, environment: &str, manifest: &str, replace: bool) {
    if let Err(error) = bind(project, environment, manifest, replace) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
    if json_output() {
        print_json(
            serde_json::json!({"bound": true, "project": project, "environment": environment}),
        );
    } else {
        println!("Bound repository to project '{project}' environment '{environment}'.");
    }
}

fn bind(project: &str, environment: &str, manifest: &str, replace: bool) -> Result<()> {
    let repo = repository(true)?;
    let vault = open_unlocked_vault();
    let binding = Binding {
        version: 1,
        repository: repo.identity.clone(),
        project: project.to_string(),
        project_id: vault
            .get_project(project)
            .map_err(|_| "project is unavailable")?
            .id,
        environment: environment.to_string(),
        partition_id: vault
            .get_partition_in_project(project, environment)
            .map_err(|_| "environment partition is unavailable")?
            .id,
        manifest: read_manifest(Path::new(manifest))?,
    };
    validate_scope(&vault, &binding)?;
    validate_database(&binding.manifest)?;
    // Validate every reference before saving, without persisting resolved values.
    for value in binding.manifest.env.values() {
        if let Some(name) = value.strip_prefix("cred:") {
            vault
                .decrypt_credential_value_in_project(project, name)
                .map_err(|_| "bound credential is unavailable for use")?;
        }
    }
    let bytes = serde_json::to_vec(&binding).map_err(|_| "cannot serialize binding")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("binding exceeds size limit");
    }
    let path = binding_path(&repo.identity);
    if replace {
        // Atomic replacement prevents readers from seeing a partially written snapshot.
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        if !secure_files::create_private(&temporary, &bytes)
            .map_err(|_| "cannot stage repository binding")?
        {
            return Err("cannot stage repository binding");
        }
        if fs::rename(&temporary, &path).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err("cannot replace repository binding");
        }
    } else if !secure_files::create_private(&path, &bytes)
        .map_err(|_| "cannot save repository binding")?
    {
        return Err("repository already bound; use --replace explicitly");
    }
    Ok(())
}
