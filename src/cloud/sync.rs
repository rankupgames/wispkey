//! Conditional, client-encrypted partition synchronization.
use super::*;
use crate::core::{cloud_sync::Snapshot, resolve_active_project};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rusqlite::{OptionalExtension, params};
use serde_json::json;

const MAGIC: &[u8; 4] = b"WKCS";
const MAX_BYTES: usize = 6 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum SyncMode {
    Push,
    Pull,
    Sync,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartitionState {
    pub project: String,
    pub partition: String,
    pub remote_id: String,
    pub revision: Option<String>,
    pub local_hash: Option<String>,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
    pub conflict_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending: Option<PendingUpload>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingUpload {
    expected_revision: Option<String>,
    local_hash: String,
    body: Upload,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Upload {
    partition_name: String,
    encrypted_metadata: String,
    encrypted_payload_base64: String,
    content_hash: String,
    mutation_id: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Clone, Deserialize)]
struct RemotePartition {
    id: String,
    revision: String,
    content_hash: Option<String>,
    size_bytes: usize,
    last_mutation_id: Option<String>,
}

fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn valid_revision(value: &str) -> bool {
    (value.len() == 32 || value.len() == 36)
        && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn invalid(code: &str) -> CloudError {
    CloudError::ApiError(code.to_owned())
}

fn network_error(error: reqwest::Error, interrupted: &str) -> CloudError {
    CloudError::Network(
        if error.is_timeout() {
            "request_timed_out"
        } else {
            interrupted
        }
        .into(),
    )
}

struct SyncLock(std::fs::File);
impl SyncLock {
    fn acquire() -> CloudResult<Self> {
        let path = Vault::vault_dir().join("cloud-sync.lock");
        secure_files::create_private(&path, b"")?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid("unsafe_sync_lock"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("unsafe_sync_lock"));
        }
        secure_files::harden_existing_file(&path)?;
        if secure_files::private_metadata_inspection_supported() {
            secure_files::inspect_private_file(&path).map_err(|_| invalid("unsafe_sync_lock"))?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| invalid("sync_lock_unavailable"))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| invalid("sync_already_running"))?;
        Ok(Self(file))
    }
}
impl Drop for SyncLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// Restore an authenticated recovery snapshot locally, without claiming a sync
/// acknowledgement or requiring a live Cloud session.
pub fn recover_partition(
    vault: &Vault,
    path: &std::path::Path,
    password: &str,
) -> CloudResult<serde_json::Value> {
    let _lock = SyncLock::acquire()?;
    let metadata = std::fs::metadata(path).map_err(|_| invalid("recovery_file_unavailable"))?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return Err(invalid("invalid_recovery_file"));
    }
    let bytes = std::fs::read(path).map_err(|_| invalid("recovery_file_unavailable"))?;
    let snapshot: Snapshot =
        crate::bundle::decrypt_payload_bytes(MAGIC, &bytes, password, MAX_BYTES as u64)
            .map_err(|_| invalid("bundle_authentication_failed"))?;
    if snapshot.project != resolve_active_project() {
        return Err(invalid("recovery_project_mismatch"));
    }
    // An uncertain upload must be reconciled before changing its source. Otherwise
    // the next sync could resend the older journaled snapshot after this recovery.
    let mut statement = vault
        .db()
        .prepare("SELECT value FROM vault_meta WHERE key LIKE 'cloud_sync_v1:%'")
        .map_err(|_| invalid("sync_state_unavailable"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| invalid("sync_state_unavailable"))?;
    for row in rows {
        let state: PartitionState =
            serde_json::from_str(&row.map_err(|_| invalid("sync_state_unavailable"))?)
                .map_err(|_| invalid("invalid_sync_state"))?;
        if state.project == snapshot.project
            && state.partition == snapshot.partition
            && state.pending.is_some()
        {
            return Err(invalid("pending_upload; reconcile it before recovery"));
        }
    }
    drop(statement);
    let current = vault.cloud_snapshot(&snapshot.project, &snapshot.partition)?;
    let hash = current
        .as_ref()
        .map(|snapshot| vault.cloud_snapshot_hash(snapshot))
        .transpose()?;
    let mut recovery_path = None;
    if let Some(current) = current {
        let bytes = crate::bundle::encrypted_payload_bytes(
            MAGIC,
            &current,
            password,
            (MAX_BYTES - 65) as u64,
        )
        .map_err(|_| invalid("recovery_encryption_failed"))?;
        let backup =
            Vault::vault_dir().join(format!("cloud-recovery-{}.wkcs", uuid::Uuid::new_v4()));
        if !secure_files::create_private(&backup, &bytes)? {
            return Err(invalid("recovery_file_exists"));
        }
        recovery_path = Some(backup.to_string_lossy().into_owned());
    }
    vault
        .cloud_apply(&snapshot, hash.as_deref(), None)
        .map_err(|_| invalid("atomic_recovery_failed; local partition unchanged"))?;
    Ok(
        json!({"ok":true,"project":snapshot.project,"partition":snapshot.partition,"recovery_path":recovery_path,"remote_modified":false}),
    )
}

impl CloudClient {
    /// Recheck the saved account and OAuth bindings against the Cloud API.
    pub async fn refresh_account(&mut self) -> CloudResult<()> {
        let response = self
            .request(reqwest::Method::GET, "/api/v1/billing/status")?
            .send()
            .await
            .map_err(|error| network_error(error, "account_verification_failed"))?;
        Self::check_response(&response)?;
        let envelope: serde_json::Value =
            serde_json::from_slice(&Self::response_bytes(response, 65536).await?)
                .map_err(|_| invalid("invalid_account_response"))?;
        if envelope["success"] != true {
            return Err(invalid("invalid_account_response"));
        }
        self.apply_verified_account(&envelope["data"])
    }

    pub(super) fn apply_verified_account(&mut self, data: &serde_json::Value) -> CloudResult<()> {
        let id = data["clerkUserId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("invalid_account_response"))?;
        if let Some(session) = &self.config.oauth_session {
            let binding = &data["oauth"];
            if id != session.account_id
                || binding["issuer"].as_str() != Some(session.issuer.as_str())
                || binding["clientId"].as_str() != Some(session.client_id.as_str())
                || binding["resource"].as_str() != Some(session.resource.as_str())
                || binding["expiresAt"].as_i64() != Some(session.expires_at)
                || binding["issuedAt"].as_i64() != Some(session.issued_at)
                || binding["tokenFormat"].as_str() != Some("opaque")
            {
                return Err(invalid("cloud_account_binding_mismatch; log in again"));
            }
        }
        let claims = &data["sessionClaims"];
        if claims["sub"].as_str() != Some(id) || !claims["org_id"].is_null() {
            return Err(invalid("cloud_account_binding_mismatch; log in again"));
        }
        let metadata = &claims["public_metadata"];
        let plans = [claims["plan"].as_str(), metadata["plan"].as_str()];
        let has_feature = [claims, metadata].iter().any(|value| {
            value["features"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "cloud_sync"))
        });
        self.config.tier = if plans.contains(&Some("enterprise")) {
            CloudTier::Enterprise
        } else if plans.contains(&Some("cloud")) || has_feature {
            CloudTier::Cloud
        } else {
            CloudTier::Personal
        };
        self.config.user_id = Some(id.to_owned());
        Ok(())
    }
    fn base_url(&self) -> CloudResult<String> {
        let url =
            reqwest::Url::parse(&self.config.api_url).map_err(|_| invalid("invalid_api_url"))?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "API requires HTTPS or literal loopback HTTP without userinfo, query or fragment",
            ));
        }
        Ok(url.as_str().trim_end_matches('/').to_owned())
    }

    fn scope_prefix(&self) -> CloudResult<String> {
        let account = self
            .config
            .user_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("missing_account_identity; log in again"))?;
        Ok(format!(
            "cloud_sync_v1:{}:",
            digest(format!("{}\0{}", self.base_url()?, account).as_bytes())
        ))
    }

    fn state_key(&self, id: &str) -> CloudResult<String> {
        Ok(format!("{}{id}", self.scope_prefix()?))
    }

    pub fn partition_states(&self, vault: &Vault) -> CloudResult<Vec<PartitionState>> {
        let prefix = self.scope_prefix()?;
        let mut statement = vault
            .db()
            .prepare("SELECT value FROM vault_meta WHERE key LIKE ?1 ORDER BY key")
            .map_err(|_| invalid("sync_state_unavailable"))?;
        let rows = statement
            .query_map([format!("{prefix}%")], |row| row.get::<_, String>(0))
            .map_err(|_| invalid("sync_state_unavailable"))?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|_| invalid("sync_state_unavailable"))?)
                .map_err(|_| invalid("invalid_sync_state"))
        })
        .collect()
    }

    fn load_state(
        &self,
        vault: &Vault,
        project: &str,
        partition: &str,
    ) -> CloudResult<PartitionState> {
        let scope = self.scope_prefix()?;
        let id =
            digest(format!("wispkey-partition-v1\0{scope}\0{project}\0{partition}").as_bytes());
        let value: Option<String> = vault
            .db()
            .query_row(
                "SELECT value FROM vault_meta WHERE key=?1",
                [self.state_key(&id)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| invalid("sync_state_unavailable"))?;
        match value {
            Some(value) => serde_json::from_str(&value).map_err(|_| invalid("invalid_sync_state")),
            None => Ok(PartitionState {
                project: project.to_owned(),
                partition: partition.to_owned(),
                remote_id: id,
                revision: None,
                local_hash: None,
                last_success: None,
                last_error: None,
                conflict_revision: None,
                pending: None,
            }),
        }
    }

    #[cfg(feature = "experimental-sync")]
    pub(super) fn watch_has_acknowledgement(
        &self,
        vault: &Vault,
        project: &str,
        partition: &str,
    ) -> CloudResult<bool> {
        let state = self.load_state(vault, project, partition)?;
        let scope = self.scope_prefix()?;
        let expected_id =
            digest(format!("wispkey-partition-v1\0{scope}\0{project}\0{partition}").as_bytes());
        Ok(state.project == project
            && state.partition == partition
            && state.remote_id == expected_id
            && state.revision.as_deref().is_some_and(valid_revision)
            && state
                .local_hash
                .as_deref()
                .is_some_and(|hash| BASE64.decode(hash).is_ok_and(|bytes| bytes.len() == 32))
            && state
                .last_success
                .as_deref()
                .is_some_and(|time| chrono::DateTime::parse_from_rfc3339(time).is_ok())
            && state.pending.is_none()
            && state.conflict_revision.is_none())
    }

    fn save_state(&self, vault: &Vault, state: &PartitionState) -> CloudResult<()> {
        let value = serde_json::to_string(state).map_err(|_| invalid("invalid_sync_state"))?;
        vault.db().execute("INSERT INTO vault_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![self.state_key(&state.remote_id)?, value]).map_err(|_| invalid("sync_state_write_failed"))?;
        Ok(())
    }

    fn request(&self, method: reqwest::Method, path: &str) -> CloudResult<reqwest::RequestBuilder> {
        self.ensure_authenticated()?;
        Ok(self
            .http_client
            .request(method, format!("{}{path}", self.base_url()?))
            .bearer_auth(
                self.config
                    .clerk_session_token
                    .as_deref()
                    .unwrap_or_default(),
            ))
    }

    pub(super) async fn response_bytes(
        mut response: reqwest::Response,
        max: usize,
    ) -> CloudResult<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|size| size > max as u64)
        {
            return Err(invalid("response_too_large"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| network_error(error, "response_interrupted"))?
        {
            if bytes.len().saturating_add(chunk.len()) > max {
                return Err(invalid("response_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    fn check_response(response: &reqwest::Response) -> CloudResult<()> {
        match response.status().as_u16() {
            200 | 201 => Ok(()),
            401 => Err(CloudError::NotAuthenticated),
            403 => Err(CloudError::TierLimit(
                "remote plan or permission denied".into(),
            )),
            408 => Err(CloudError::Network("request_timed_out".into())),
            409 | 412 => Err(invalid("revision_conflict")),
            428 => Err(invalid("backend_missing_revision_contract")),
            429 => Err(invalid("rate_limited")),
            500 | 502 | 503 | 504 => Err(CloudError::Network("service_unavailable".into())),
            _ => Err(invalid("remote_request_failed")),
        }
    }

    async fn remote(&self, id: &str) -> CloudResult<Option<RemotePartition>> {
        let response = self
            .request(reqwest::Method::GET, &format!("/api/v1/partitions/{id}"))?
            .send()
            .await
            .map_err(|error| network_error(error, "request_failed"))?;
        if response.status() == 404 {
            return Ok(None);
        }
        Self::check_response(&response)?;
        let remote: Envelope<RemotePartition> =
            serde_json::from_slice(&Self::response_bytes(response, 32768).await?)
                .map_err(|_| invalid("invalid_remote_metadata"))?;
        if remote.data.id != id
            || !valid_revision(&remote.data.revision)
            || remote.data.size_bytes > MAX_BYTES
        {
            return Err(invalid("invalid_remote_metadata"));
        }
        Ok(Some(remote.data))
    }

    async fn download(
        &self,
        remote: &RemotePartition,
        password: &str,
        project: &str,
        partition: &str,
        guard: &dyn Fn() -> crate::core::Result<()>,
    ) -> CloudResult<(Snapshot, Vec<u8>)> {
        guard()?;
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/api/v1/partitions/{}/payload", remote.id),
            )?
            .header(
                reqwest::header::IF_MATCH,
                format!("\"{}\"", remote.revision),
            )
            .send()
            .await
            .map_err(|error| network_error(error, "request_failed"))?;
        Self::check_response(&response)?;
        if response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            != Some(format!("\"{}\"", remote.revision).as_str())
        {
            return Err(invalid("invalid_remote_revision"));
        }
        let bytes = Self::response_bytes(response, MAX_BYTES).await?;
        if remote.content_hash.as_deref() != Some(digest(&bytes).as_str())
            || bytes.len() != remote.size_bytes
        {
            return Err(invalid("ciphertext_hash_mismatch"));
        }
        guard()?;
        let snapshot: Snapshot =
            crate::bundle::decrypt_payload_bytes(MAGIC, &bytes, password, MAX_BYTES as u64)
                .map_err(|_| invalid("bundle_authentication_failed"))?;
        if !matches!(snapshot.version, 1..=3)
            || snapshot.project != project
            || snapshot.partition != partition
        {
            return Err(invalid("bundle_scope_mismatch"));
        }
        Ok((snapshot, bytes))
    }

    async fn send_pending(
        &self,
        vault: &Vault,
        state: &mut PartitionState,
        guard: &dyn Fn() -> crate::core::Result<()>,
    ) -> CloudResult<()> {
        guard()?;
        let pending = state
            .pending
            .as_ref()
            .ok_or_else(|| invalid("missing_pending_upload"))?;
        let mut request = self
            .request(
                reqwest::Method::PUT,
                &format!("/api/v1/partitions/{}", state.remote_id),
            )?
            .json(&pending.body);
        request = match &pending.expected_revision {
            Some(revision) => request.header(reqwest::header::IF_MATCH, format!("\"{revision}\"")),
            None => request.header(reqwest::header::IF_NONE_MATCH, "*"),
        };
        guard()?;
        let response = request
            .send()
            .await
            .map_err(|error| network_error(error, "upload_interrupted; retry the same command"))?;
        Self::check_response(&response)?;
        let receipt: Envelope<RemotePartition> =
            serde_json::from_slice(&Self::response_bytes(response, 32768).await?)
                .map_err(|_| invalid("invalid_upload_receipt"))?;
        if receipt.data.id != state.remote_id
            || receipt.data.content_hash.as_deref() != Some(&pending.body.content_hash)
            || receipt.data.last_mutation_id.as_deref() != Some(&pending.body.mutation_id)
            || !valid_revision(&receipt.data.revision)
        {
            return Err(invalid("invalid_upload_receipt"));
        }
        guard()?;
        state.local_hash = Some(pending.local_hash.clone());
        state.revision = Some(receipt.data.revision);
        state.pending = None;
        state.last_error = None;
        state.conflict_revision = None;
        state.last_success = Some(chrono::Utc::now().to_rfc3339());
        self.save_state(vault, state)
    }

    pub async fn synchronize_partition(
        &self,
        vault: &Vault,
        partition: &str,
        password: &str,
        mode: SyncMode,
        resolution: Option<(&str, &str)>,
    ) -> CloudResult<SyncManifest> {
        self.synchronize_scoped(
            vault,
            &resolve_active_project(),
            partition,
            password,
            mode,
            resolution,
            &|| Ok(()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn synchronize_scoped(
        &self,
        vault: &Vault,
        project: &str,
        partition: &str,
        password: &str,
        mode: SyncMode,
        resolution: Option<(&str, &str)>,
        guard: &dyn Fn() -> crate::core::Result<()>,
    ) -> CloudResult<SyncManifest> {
        guard()?;
        self.ensure_authenticated()?;
        self.check_tier_limit("sync")?;
        if password.chars().count() < 12 {
            return Err(invalid(
                "sync passphrase must contain at least 12 characters",
            ));
        }
        let _lock = SyncLock::acquire()?;
        let mut state = self.load_state(vault, project, partition)?;
        // Keep the network/import state machine off the CLI's bounded native
        // stack (Windows debug builds otherwise overflow even on other commands).
        let result =
            Box::pin(self.sync_locked(vault, &mut state, password, mode, resolution, guard)).await;
        let result = match result {
            Err(CloudError::ApiError(code)) if code == "revision_conflict" => {
                state.conflict_revision = Some("refresh_required".into());
                Err(CloudError::SyncConflict(
                    partition.to_owned(),
                    "remote revision changed during transfer; inspect status again".into(),
                ))
            }
            other => other,
        };
        if let Err(error) = &result {
            // Fixed category only: never persist provider errors, URLs or payloads.
            state.last_error = Some(
                match error {
                    CloudError::NotAuthenticated => "authentication_expired",
                    CloudError::TierLimit(_) => "permission_denied",
                    CloudError::Network(code) if code == "request_timed_out" => "request_timed_out",
                    CloudError::Network(code) if code == "service_unavailable" => {
                        "service_unavailable"
                    }
                    CloudError::Network(_) => "network_interrupted",
                    CloudError::ApiError(code) if code == "rate_limited" => "rate_limited",
                    CloudError::ApiError(code)
                        if matches!(
                            code.as_str(),
                            "backend_missing_revision_contract"
                                | "remote_request_failed"
                                | "invalid_remote_metadata"
                                | "invalid_upload_receipt"
                        ) =>
                    {
                        "protocol_rejected"
                    }
                    CloudError::SyncConflict(_, _) => "conflict",
                    _ => "sync_failed",
                }
                .into(),
            );
            self.save_state(vault, &state)?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync_locked(
        &self,
        vault: &Vault,
        state: &mut PartitionState,
        password: &str,
        mode: SyncMode,
        resolution: Option<(&str, &str)>,
        guard: &dyn Fn() -> crate::core::Result<()>,
    ) -> CloudResult<SyncManifest> {
        guard()?;
        let local = vault.cloud_snapshot(&state.project, &state.partition)?;
        let local_hash = local
            .as_ref()
            .map(|value| vault.cloud_snapshot_hash(value))
            .transpose()?;
        let mut outcome = "unchanged";
        let mut recovery_path = None;
        if state.pending.is_some() && resolution.is_none() {
            self.send_pending(vault, state, guard).await?;
            outcome = "uploaded";
        } else {
            guard()?;
            let remote = self.remote(&state.remote_id).await?;
            guard()?;
            if state.revision.is_none()
                && self.config.tier == CloudTier::Cloud
                && self
                    .partition_states(vault)?
                    .iter()
                    .filter(|state| state.revision.is_some())
                    .count()
                    >= 10
            {
                return Err(CloudError::TierLimit("Cloud tier tracks at most 10 partitions; existing partitions can still synchronize".into()));
            }

            let revision = remote.as_ref().map(|remote| remote.revision.as_str());
            let local_changed = local_hash != state.local_hash;
            let remote_changed = revision != state.revision.as_deref();
            let fresh_empty = state.revision.is_none()
                && local.as_ref().is_none_or(|value| {
                    value.credentials.is_empty() && value.signup_profiles.is_none()
                });
            let mut action = match mode {
                SyncMode::Push => "push",
                SyncMode::Pull => "pull",
                SyncMode::Sync => {
                    if remote_changed {
                        "pull"
                    } else {
                        "push"
                    }
                }
            };
            let conflict = if action == "push" {
                remote_changed
            } else {
                local_changed && !fresh_empty
            };
            if let Some((keep, expected)) = resolution {
                if expected != revision.unwrap_or("absent") || !["local", "remote"].contains(&keep)
                {
                    return Err(invalid("resolution_revision_changed; inspect status again"));
                }
                action = if keep == "local" { "push" } else { "pull" };
                let recovery = if keep == "local" {
                    if let Some(remote) = &remote {
                        Some(
                            self.download(
                                remote,
                                password,
                                &state.project,
                                &state.partition,
                                guard,
                            )
                            .await?
                            .1,
                        )
                    } else {
                        None
                    }
                } else {
                    local
                        .as_ref()
                        .map(|value| {
                            crate::bundle::encrypted_payload_bytes(
                                MAGIC,
                                value,
                                password,
                                (MAX_BYTES - 65) as u64,
                            )
                        })
                        .transpose()
                        .map_err(|_| invalid("recovery_encryption_failed"))?
                };
                if let Some(bytes) = recovery {
                    let path = Vault::vault_dir()
                        .join(format!("cloud-recovery-{}.wkcs", uuid::Uuid::new_v4()));
                    if !secure_files::create_private(&path, &bytes)? {
                        return Err(invalid("recovery_file_exists"));
                    }
                    recovery_path = Some(path.to_string_lossy().into_owned());
                }
                // A failed explicit resolution must not erase an uncertain prior upload.
            } else if conflict {
                state.conflict_revision = Some(revision.unwrap_or("absent").to_owned());
                return Err(CloudError::SyncConflict(
                    state.partition.clone(),
                    "inspect cloud status --remote; resolve explicitly with the observed revision"
                        .into(),
                ));
            }
            if action == "push" {
                let local = local
                    .as_ref()
                    .ok_or_else(|| invalid("local_partition_missing"))?;
                if local_changed || remote.is_none() || resolution.is_some() {
                    let bytes = crate::bundle::encrypted_payload_bytes(
                        MAGIC,
                        local,
                        password,
                        (MAX_BYTES - 65) as u64,
                    )
                    .map_err(|_| invalid("bundle_encryption_failed"))?;
                    let pending = PendingUpload {
                        expected_revision: revision.map(str::to_owned),
                        local_hash: local_hash
                            .clone()
                            .ok_or_else(|| invalid("local_partition_missing"))?,
                        body: Upload {
                            partition_name: state.partition.clone(),
                            encrypted_metadata: String::new(),
                            encrypted_payload_base64: BASE64.encode(&bytes),
                            content_hash: digest(&bytes),
                            mutation_id: uuid::Uuid::new_v4().to_string(),
                        },
                    };
                    guard()?;
                    state.pending = Some(pending);
                    self.save_state(vault, state)?;
                    self.send_pending(vault, state, guard).await?;
                    outcome = "uploaded";
                }
            } else {
                let remote = remote.ok_or_else(|| invalid("remote_partition_missing"))?;
                if remote_changed || resolution.is_some() || state.last_success.is_none() {
                    let (snapshot, _) = self
                        .download(&remote, password, &state.project, &state.partition, guard)
                        .await?;
                    let mut committed = state.clone();
                    committed.revision = Some(remote.revision);
                    committed.last_success = Some(chrono::Utc::now().to_rfc3339());
                    committed.last_error = None;
                    committed.conflict_revision = None;
                    committed.pending = None;
                    let hash = vault
                        .cloud_apply_guarded(
                            &snapshot,
                            local_hash.as_deref(),
                            Some((
                                &self.state_key(&state.remote_id)?,
                                serde_json::to_value(&committed)
                                    .map_err(|_| invalid("invalid_sync_state"))?,
                            )),
                            guard,
                        )
                        .map_err(|error| match error {
                            VaultError::WatchDurationElapsed => CloudError::Vault(error),
                            _ => invalid("atomic_import_failed; local partition unchanged"),
                        })?;
                    committed.local_hash = Some(hash);
                    *state = committed;
                    outcome = "downloaded";
                }
            }
        }
        guard()?;
        let current = vault.cloud_snapshot(&state.project, &state.partition)?;
        if outcome == "unchanged"
            && (state.last_error.is_some() || state.conflict_revision.is_some())
        {
            state.last_error = None;
            state.conflict_revision = None;
            self.save_state(vault, state)?;
        }
        let current_hash = current
            .as_ref()
            .map(|value| vault.cloud_snapshot_hash(value))
            .transpose()?;
        Ok(SyncManifest {
            partition_id: state.remote_id.clone(),
            partition_name: state.partition.clone(),
            last_synced_at: state.last_success.clone().unwrap_or_default(),
            local_hash: state.local_hash.clone().unwrap_or_default(),
            remote_hash: state.revision.clone(),
            sync_direction: match mode {
                SyncMode::Push => SyncDirection::Push,
                SyncMode::Pull => SyncDirection::Pull,
                SyncMode::Sync => SyncDirection::Bidirectional,
            },
            project: state.project.clone(),
            remote_revision: state.revision.clone(),
            outcome: outcome.into(),
            local_changes_pending: current_hash != state.local_hash,
            recovery_path,
        })
    }

    pub async fn sync_status(&self, vault: &Vault, remote: bool) -> CloudResult<serde_json::Value> {
        let remote_rows = if remote {
            let response = self
                .request(reqwest::Method::GET, "/api/v1/partitions")?
                .send()
                .await
                .map_err(|error| network_error(error, "request_failed"))?;
            Self::check_response(&response)?;
            let rows: Envelope<Vec<RemotePartition>> =
                serde_json::from_slice(&Self::response_bytes(response, 1024 * 1024).await?)
                    .map_err(|_| invalid("invalid_remote_metadata"))?;
            rows.data
        } else {
            Vec::new()
        };
        let mut partitions = Vec::new();
        for state in self.partition_states(vault)? {
            let local_changed = if vault.is_unlocked() {
                let local = vault.cloud_snapshot(&state.project, &state.partition)?;
                let hash = local
                    .as_ref()
                    .map(|value| vault.cloud_snapshot_hash(value))
                    .transpose()?;
                Some(hash != state.local_hash)
            } else {
                None
            };
            let remote_revision = if remote {
                remote_rows
                    .iter()
                    .find(|row| row.id == state.remote_id)
                    .map(|row| row.revision.clone())
            } else {
                state.revision.clone()
            };
            let remote_changed = remote_revision != state.revision;
            partitions.push(json!({"project":state.project,"partition":state.partition,"last_success":state.last_success,
                "last_error":state.last_error,"local_changes_pending":local_changed,"remote_changes_pending":if remote { Some(remote_changed) } else { None },
                "upload_pending":state.pending.is_some(),"conflict":state.conflict_revision.is_some() || local_changed == Some(true) && remote_changed,
                "remote_revision":remote_revision.unwrap_or_else(|| "absent".into()),"acknowledged_revision":state.revision}));
        }
        Ok(
            json!({"authenticated": self.ensure_authenticated().is_ok(),"source":if remote { "remote" } else { "local" },
            "remote_verified":remote,"sync_available":true,"tracked_partitions":partitions.len(),"partitions":partitions}),
        )
    }
}
