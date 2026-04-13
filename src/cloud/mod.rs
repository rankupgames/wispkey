/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Cloud sync client -- config persistence, tier limits, and API stubs for WispKey Cloud.
 * Created: 2026-04-08
 * Last Modified: 2026-04-08
 */

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{Vault, VaultError};

const COMING_SOON: &str = "WispKey Cloud is coming soon. Pro $1.99/mo | Team $9.99/user/mo";

// INTEGRATION NOTE: Login flow will use Clerk browser-based auth.
// 1. Start localhost callback server on random port
// 2. Open browser to Clerk sign-in page with redirect_url to localhost
// 3. Receive Clerk session token via callback
// 4. Store token as clerk_session_token in cloud.json
// See wispkey-cloud/docs/clerk-integration-plan.md

pub type CloudResult<T> = std::result::Result<T, CloudError>;

#[derive(Error, Debug)]
pub enum CloudError {
    #[error("not authenticated -- run `wispkey cloud login` first")]
    NotAuthenticated,
    #[error("cloud API error: {0}")]
    ApiError(String),
    #[error("tier limit reached: {0}")]
    TierLimit(String),
    #[allow(dead_code)]
    #[error("sync conflict on partition '{0}': {1}")]
    SyncConflict(String, String),
    #[allow(dead_code)]
    #[error("network error: {0}")]
    Network(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum CloudTier {
    Free,
    Pro,
    Team,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudConfig {
    pub api_url: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub tier: CloudTier,
    pub last_sync: Option<String>,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            access_token: None,
            refresh_token: None,
            user_id: None,
            org_id: None,
            tier: CloudTier::Free,
            last_sync: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SyncDirection {
    Push,
    Pull,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub partition_id: String,
    pub partition_name: String,
    pub last_synced_at: String,
    pub local_hash: String,
    pub remote_hash: Option<String>,
    pub sync_direction: SyncDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStatus {
    pub authenticated: bool,
    pub tier: CloudTier,
    pub email: Option<String>,
    pub org_name: Option<String>,
    pub synced_partitions: usize,
    pub storage_used_bytes: u64,
    pub storage_limit_bytes: u64,
}

pub struct CloudClient {
    config: CloudConfig,
    #[allow(dead_code)]
    http_client: reqwest::Client,
}

impl CloudClient {
    pub fn new(config: CloudConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            config,
            http_client,
        }
    }

    #[allow(dead_code)]
    pub fn config(&self) -> &CloudConfig {
        &self.config
    }

    #[allow(dead_code)]
    pub fn config_mut(&mut self) -> &mut CloudConfig {
        &mut self.config
    }

    pub async fn login(&self, email: &str, password: &str) -> CloudResult<CloudConfig> {
        let _ = (&self.http_client, email, password);
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    pub fn logout(&mut self) -> CloudResult<()> {
        self.config.access_token = None;
        self.config.refresh_token = None;
        self.config.user_id = None;
        self.config.org_id = None;
        self.config.last_sync = None;
        self.config.tier = CloudTier::Free;
        save_config(&self.config)
    }

    pub async fn push_partition(
        &self,
        vault: &Vault,
        partition_name: &str,
    ) -> CloudResult<SyncManifest> {
        self.ensure_authenticated()?;
        self.check_tier_limit("push_partition")?;
        let _ = (vault, partition_name);
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    pub async fn pull_partition(
        &self,
        vault: &Vault,
        partition_name: &str,
    ) -> CloudResult<SyncManifest> {
        self.ensure_authenticated()?;
        self.check_tier_limit("pull_partition")?;
        let _ = (vault, partition_name);
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    pub async fn sync_all(&self, vault: &Vault) -> CloudResult<Vec<SyncManifest>> {
        self.ensure_authenticated()?;
        self.check_tier_limit("sync_all")?;
        let _ = vault;
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    #[allow(dead_code)]
    pub async fn get_status(&self) -> CloudResult<CloudStatus> {
        self.ensure_authenticated()?;
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    pub fn check_tier_limit(&self, operation: &str) -> CloudResult<()> {
        if self.config.tier == CloudTier::Free {
            return Err(CloudError::TierLimit(format!(
                "{operation}: free tier allows 0 cloud partitions; upgrade to Pro ($1.99/mo) or Team ($9.99/user/mo)"
            )));
        }
        if self.config.tier == CloudTier::Team {
            return Ok(());
        }
        if operation == "push_partition" {
            let manifests = load_sync_manifests()?;
            if manifests.len() >= 10 {
                return Err(CloudError::TierLimit(format!(
                    "{operation}: Pro tier allows up to 10 cloud partitions; upgrade to Team for unlimited"
                )));
            }
        }
        Ok(())
    }

    fn ensure_authenticated(&self) -> CloudResult<()> {
        if self
            .config
            .access_token
            .as_ref()
            .is_some_and(|token| !token.is_empty())
        {
            return Ok(());
        }
        Err(CloudError::NotAuthenticated)
    }
}

pub fn default_api_url() -> String {
    "https://api.wispkey.com".to_string()
}

pub fn config_path() -> PathBuf {
    Vault::vault_dir().join("cloud.json")
}

pub fn sync_manifests_path() -> PathBuf {
    Vault::vault_dir().join("cloud-manifests.json")
}

pub fn load_config() -> CloudResult<CloudConfig> {
    let path = config_path();
    if !path.exists() {
        return Ok(CloudConfig::default());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|error| CloudError::ApiError(format!("config read failed: {error}")))?;
    let parsed: CloudConfig = serde_json::from_str(&raw)
        .map_err(|error| CloudError::ApiError(format!("config parse failed: {error}")))?;
    Ok(parsed)
}

pub fn save_config(config: &CloudConfig) -> CloudResult<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| CloudError::ApiError(format!("config directory failed: {error}")))?;
    }
    let data = serde_json::to_string_pretty(config)
        .map_err(|error| CloudError::ApiError(format!("config serialize failed: {error}")))?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, &data)
        .map_err(|error| CloudError::ApiError(format!("config write failed: {error}")))?;
    fs::rename(&temp_path, &path)
        .map_err(|error| CloudError::ApiError(format!("config finalize failed: {error}")))?;
    Ok(())
}

pub fn load_sync_manifests() -> CloudResult<Vec<SyncManifest>> {
    let path = sync_manifests_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|error| CloudError::ApiError(format!("manifest read failed: {error}")))?;
    let parsed: Vec<SyncManifest> = serde_json::from_str(&raw)
        .map_err(|error| CloudError::ApiError(format!("manifest parse failed: {error}")))?;
    Ok(parsed)
}

pub fn storage_limit_bytes_for_tier(tier: &CloudTier) -> u64 {
    match tier {
        CloudTier::Free => 0,
        CloudTier::Pro => 100 * 1024 * 1024,
        CloudTier::Team => 1024 * 1024 * 1024 * 1024,
    }
}

pub fn summarize_local_cloud_status(config: &CloudConfig) -> CloudResult<CloudStatus> {
    let manifests = load_sync_manifests()?;
    let authenticated = config
        .access_token
        .as_ref()
        .is_some_and(|token| !token.is_empty());
    Ok(CloudStatus {
        authenticated,
        tier: config.tier.clone(),
        email: None,
        org_name: None,
        synced_partitions: manifests.len(),
        storage_used_bytes: 0,
        storage_limit_bytes: storage_limit_bytes_for_tier(&config.tier),
    })
}
