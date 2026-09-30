//! Bounded foreground polling under the existing manual owner/passphrase model.
//! This is not device enrollment or ring authorization and creates no grants.
use super::coordinator::{Admission, Binding, Coordinator, Reconciliation};
use super::{CloudClient, CloudError, CloudResult, SyncManifest, SyncMode, load_config};
use crate::core::{Vault, VaultError, resolve_active_project};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct WatchReport {
    pub stopped: &'static str,
    pub successful_attempts: u64,
    /// A deadline/cancel can leave an uncertain upload; this is not an all-device
    /// acknowledgement and the next manual sync must reconcile its journal.
    pub reconciliation_required: bool,
    pub last: Option<SyncManifest>,
}

fn stopped(code: &'static str) -> VaultError {
    VaultError::InvalidBundle(code.into())
}

pub async fn watch_partition(
    partition: &str,
    passphrase: &str,
    seconds: u64,
) -> CloudResult<WatchReport> {
    if !(1..=3600).contains(&seconds) {
        return Err(CloudError::ApiError(
            "watch_duration_must_be_1_to_3600_seconds".into(),
        ));
    }
    let vault = Vault::open_with_session()?; // Never unlock or renew from environment/protector.
    let session = vault.operation_session_binding()?;
    let project = resolve_active_project();
    let project_id = vault.get_project(&project)?.id;
    let partition_id = vault.get_partition_in_project(&project, partition)?.id;
    let config = load_config()?;
    let account = config
        .user_id
        .clone()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CloudError::ApiError("watch_missing_account".into()))?;
    let remaining = (session.expires_at - chrono::Utc::now())
        .to_std()
        .map_err(|_| stopped("watch_session_expired"))?;
    let duration = Duration::from_secs(seconds).min(remaining);
    let started = Instant::now();
    let deadline = started + duration;
    let guard = || -> crate::core::Result<()> {
        if Instant::now() >= deadline {
            return Err(stopped("watch_deadline"));
        }
        if vault.operation_session_binding()? != session {
            return Err(stopped("watch_session_changed"));
        }
        if load_config().ok().as_ref() != Some(&config) {
            return Err(stopped("watch_cloud_config_changed"));
        }
        if resolve_active_project() != project
            || vault.get_project(&project)?.id != project_id
            || vault.get_partition_in_project(&project, partition)?.id != partition_id
        {
            return Err(stopped("watch_scope_changed"));
        }
        Ok(())
    };
    guard()?;
    let mut client = CloudClient::new(config.clone());
    // Account labels in cloud.json are not proof of who owns the bearer token.
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        client.refresh_account(),
    )
    .await
    .map_err(|_| stopped("watch_deadline"))??;
    guard()?;
    if client.config().user_id.as_deref() != Some(&account) {
        return Err(stopped("watch_account_mismatch").into());
    }
    if !client.watch_has_acknowledgement(&vault, &project, partition)? {
        return Err(stopped(
            "watch_requires_acknowledged_partition; complete manual push/pull first",
        )
        .into());
    }
    let binding = Binding {
        endpoint: config.api_url.clone(),
        account,
        // An owner-session binding, explicitly not a cryptographically enrolled device.
        device: "manual-owner-session".into(),
        project: project.clone(),
        partition: partition.into(),
    };
    let mut coordinator =
        Coordinator::restore(binding, None).map_err(|_| stopped("watch_invalid_coordinator"))?;
    coordinator.set_admission(Admission::Ready);
    let mut report = WatchReport {
        stopped: "duration",
        successful_attempts: 0,
        reconciliation_required: true,
        last: None,
    };
    loop {
        if Instant::now() >= deadline {
            return Ok(report);
        }
        guard()?;
        coordinator.request_reconciliation();
        if let Some(attempt) = coordinator.begin(started.elapsed().as_secs()) {
            let transfer = client.synchronize_scoped(
                &vault,
                &project,
                partition,
                passphrase,
                SyncMode::Sync,
                None,
                &guard,
            );
            let result = tokio::select! {
                result = transfer => result,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return Ok(report),
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|_| stopped("watch_signal_unavailable"))?;
                    report.stopped = "cancelled";
                    return Ok(report);
                }
            };
            match result {
                Ok(manifest) => {
                    guard()?;
                    let outcome = if manifest.local_changes_pending {
                        Reconciliation::Pending
                    } else {
                        Reconciliation::Complete
                    };
                    attempt
                        .acknowledge(started.elapsed().as_secs(), Admission::Ready, outcome)
                        .map_err(|_| stopped("watch_admission_changed"))?;
                    report.successful_attempts += 1;
                    report.last = Some(manifest);
                }
                Err(CloudError::Network(_)) => {
                    attempt.fail(started.elapsed().as_secs(), false);
                }
                Err(error) => return Err(error), // No retries for auth, policy, scope or conflict.
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return Ok(report),
            result = tokio::signal::ctrl_c() => {
                result.map_err(|_| stopped("watch_signal_unavailable"))?;
                report.stopped = "cancelled";
                return Ok(report);
            }
        }
    }
}
