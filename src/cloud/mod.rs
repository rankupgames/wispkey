/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Cloud sync client -- config persistence, tier limits, and API stubs for WispKey Cloud.
 * Created: 2026-04-08
 * Last Modified: 2026-04-13
 */

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{Vault, VaultError};

const COMING_SOON: &str = "WispKey Cloud is coming soon. Cloud $1.99/mo | Enterprise: contact us";

// INTEGRATION NOTE: Login flow will use Clerk browser-based auth.
// 1. Start localhost callback server on random port
// 2. Open browser to Clerk sign-in page with redirect_url to localhost
// 3. Receive Clerk session token via callback
// 4. Store token as clerk_session_token in cloud.json
// See wispkey-cloud/docs/clerk-integration-plan.md

/// Result alias for cloud operations.
pub type CloudResult<T> = std::result::Result<T, CloudError>;

/// Errors from cloud sync operations.
#[derive(Error, Debug)]
#[non_exhaustive]
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

/// Subscription tier for WispKey Cloud.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub enum CloudTier {
    Personal,
    Cloud,
    Enterprise,
}

/// Persisted cloud configuration (stored in `.wispkey/cloud.json`).
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
            tier: CloudTier::Personal,
            last_sync: None,
        }
    }
}

/// Direction of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub enum SyncDirection {
    Push,
    Pull,
    Bidirectional,
}

/// Tracks the sync state of a single partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub partition_id: String,
    pub partition_name: String,
    pub last_synced_at: String,
    pub local_hash: String,
    pub remote_hash: Option<String>,
    pub sync_direction: SyncDirection,
}

/// Snapshot of cloud sync status for display.
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

/// HTTP client for WispKey Cloud API operations.
pub struct CloudClient {
    config: CloudConfig,
    #[allow(dead_code)]
    http_client: reqwest::Client,
}

impl CloudClient {
    /// Creates a new cloud client with the given config.
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

    /// Returns a reference to the cloud configuration.
    #[allow(dead_code)]
    pub fn config(&self) -> &CloudConfig {
        &self.config
    }

    /// Returns a mutable reference to the cloud configuration.
    #[allow(dead_code)]
    pub fn config_mut(&mut self) -> &mut CloudConfig {
        &mut self.config
    }

    /// Opens the browser to the Clerk sign-in page and waits for the session token
    /// to arrive via a localhost callback. Returns the updated config with the token stored.
    pub async fn login(&mut self) -> CloudResult<CloudConfig> {
        let (token, user_email) = browser_login_flow(&self.config.api_url).await?;
        self.config.access_token = Some(token);
        self.config.user_id = user_email.clone();
        save_config(&self.config)?;
        Ok(self.config.clone())
    }

    /// Clears cloud credentials and resets to Personal tier.
    pub fn logout(&mut self) -> CloudResult<()> {
        self.config.access_token = None;
        self.config.refresh_token = None;
        self.config.user_id = None;
        self.config.org_id = None;
        self.config.last_sync = None;
        self.config.tier = CloudTier::Personal;
        save_config(&self.config)
    }

    /// Pushes a local partition to WispKey Cloud (stub).
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

    /// Pulls a partition from WispKey Cloud (stub).
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

    /// Syncs all cloud-enabled partitions (stub).
    pub async fn sync_all(&self, vault: &Vault) -> CloudResult<Vec<SyncManifest>> {
        self.ensure_authenticated()?;
        self.check_tier_limit("sync_all")?;
        let _ = vault;
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    /// Retrieves remote cloud status (stub).
    #[allow(dead_code)]
    pub async fn get_status(&self) -> CloudResult<CloudStatus> {
        self.ensure_authenticated()?;
        Err(CloudError::ApiError(COMING_SOON.into()))
    }

    /// Validates that the current tier allows the requested operation.
    pub fn check_tier_limit(&self, operation: &str) -> CloudResult<()> {
        if self.config.tier == CloudTier::Personal {
            return Err(CloudError::TierLimit(format!(
                "{operation}: personal tier is local-only; upgrade to Cloud ($1.99/mo) for sync"
            )));
        }
        if self.config.tier == CloudTier::Enterprise {
            return Ok(());
        }
        if operation == "push_partition" {
            let manifests = load_sync_manifests()?;
            if manifests.len() >= 10 {
                return Err(CloudError::TierLimit(format!(
                    "{operation}: Cloud tier allows up to 10 partitions; contact us for Enterprise"
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

/// Starts a localhost HTTP server, opens the browser to the Clerk sign-in page,
/// and waits for the callback with a session token. Returns (token, optional email).
async fn browser_login_flow(api_url: &str) -> CloudResult<(String, Option<String>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| CloudError::ApiError(format!("failed to bind localhost listener: {e}")))?;
    let callback_port = listener.local_addr()
        .map_err(|e| CloudError::ApiError(format!("failed to get listener address: {e}")))?
        .port();

    let callback_url = format!("http://127.0.0.1:{callback_port}/callback");
    let sign_in_url = format!("{api_url}/auth/cli-login?callback={}", urlencoding::encode(&callback_url));

    eprintln!("Opening browser for WispKey Cloud sign-in...");
    eprintln!("If the browser doesn't open, visit: {sign_in_url}");

    if let Err(e) = open::that(&sign_in_url) {
        tracing::warn!("Could not open browser: {e}");
    }

    eprintln!("Waiting for authentication...");

    let (token, email) = tokio::task::spawn_blocking(move || -> CloudResult<(String, Option<String>)> {
        let (stream, _) = listener.accept()
            .map_err(|e| CloudError::ApiError(format!("callback accept failed: {e}")))?;

        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)
            .map_err(|e| CloudError::ApiError(format!("callback read failed: {e}")))?;

        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        let query = path.split('?').nth(1).unwrap_or("");

        let mut token: Option<String> = None;
        let mut email: Option<String> = None;
        for param in query.split('&') {
            let mut parts = param.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("token"), Some(value)) => token = Some(urlencoding::decode(value).unwrap_or_default().into_owned()),
                (Some("email"), Some(value)) => email = Some(urlencoding::decode(value).unwrap_or_default().into_owned()),
                _ => {}
            }
        }

        let html_body = if token.is_some() {
            "<html><body><h2>WispKey Cloud</h2><p>Authentication successful! You can close this tab.</p></body></html>"
        } else {
            "<html><body><h2>WispKey Cloud</h2><p>Authentication failed. Please try again.</p></body></html>"
        };

        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{html_body}");
        let mut writer = stream;
        let _ = writer.write_all(response.as_bytes());
        let _ = writer.flush();

        match token {
            Some(t) => Ok((t, email)),
            None => Err(CloudError::ApiError("no token received in callback".into())),
        }
    })
    .await
    .map_err(|e| CloudError::ApiError(format!("callback task panicked: {e}")))??;

    Ok((token, email))
}

/// Returns the default WispKey Cloud API URL.
pub fn default_api_url() -> String {
    "https://api.wispkey.com".to_string()
}

/// Path to the persisted cloud config file.
pub fn config_path() -> PathBuf {
    Vault::vault_dir().join("cloud.json")
}

/// Path to the sync manifests file.
pub fn sync_manifests_path() -> PathBuf {
    Vault::vault_dir().join("cloud-manifests.json")
}

/// Loads cloud config from disk, returning defaults if the file doesn't exist.
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

/// Atomically writes cloud config to disk (write-to-temp then rename).
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

/// Loads sync manifests from disk, returning an empty list if the file doesn't exist.
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

/// Returns the storage limit in bytes for the given cloud tier.
pub fn storage_limit_bytes_for_tier(tier: &CloudTier) -> u64 {
    match tier {
        CloudTier::Personal => 0,
        CloudTier::Cloud => 100 * 1024 * 1024,
        CloudTier::Enterprise => 1024 * 1024 * 1024 * 1024,
    }
}

/// Builds a `CloudStatus` from local config and manifests (no network call).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_personal_tier() {
        let config = CloudConfig::default();
        assert_eq!(config.tier, CloudTier::Personal);
        assert!(config.access_token.is_none());
        assert_eq!(config.api_url, "https://api.wispkey.com");
    }

    #[test]
    fn storage_limits_match_tiers() {
        assert_eq!(storage_limit_bytes_for_tier(&CloudTier::Personal), 0);
        assert_eq!(storage_limit_bytes_for_tier(&CloudTier::Cloud), 100 * 1024 * 1024);
        assert_eq!(storage_limit_bytes_for_tier(&CloudTier::Enterprise), 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn personal_tier_blocks_sync() {
        let client = CloudClient::new(CloudConfig::default());
        let result = client.check_tier_limit("push_partition");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("personal tier is local-only"));
    }

    #[test]
    fn enterprise_tier_allows_all() {
        let config = CloudConfig {
            tier: CloudTier::Enterprise,
            access_token: Some("token".into()),
            ..CloudConfig::default()
        };
        let client = CloudClient::new(config);
        assert!(client.check_tier_limit("push_partition").is_ok());
        assert!(client.check_tier_limit("sync_all").is_ok());
    }

    #[test]
    fn config_roundtrip_serialization() {
        let config = CloudConfig {
            api_url: "https://custom.example.com".into(),
            access_token: Some("tok_abc".into()),
            refresh_token: None,
            user_id: Some("user_123".into()),
            org_id: None,
            tier: CloudTier::Cloud,
            last_sync: Some("2026-04-13T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CloudConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tier, CloudTier::Cloud);
        assert_eq!(parsed.access_token.as_deref(), Some("tok_abc"));
        assert_eq!(parsed.user_id.as_deref(), Some("user_123"));
    }

    #[test]
    fn logout_clears_credentials() {
        let config = CloudConfig {
            access_token: Some("tok".into()),
            refresh_token: Some("ref".into()),
            user_id: Some("uid".into()),
            tier: CloudTier::Cloud,
            ..CloudConfig::default()
        };
        let mut client = CloudClient::new(config);
        let _ = client.logout();
        assert!(client.config.access_token.is_none());
        assert!(client.config.refresh_token.is_none());
        assert!(client.config.user_id.is_none());
        assert_eq!(client.config.tier, CloudTier::Personal);
    }
}
