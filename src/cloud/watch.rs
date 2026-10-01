//! Bounded foreground polling under the existing manual owner/passphrase model.
//! This is not device enrollment or ring authorization and creates no grants.
use super::coordinator::{Admission, Attempt, Binding, Coordinator, Reconciliation};
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

struct WatchDeadline {
    at: Instant,
    session_limited: bool,
}

impl WatchDeadline {
    fn error(&self) -> VaultError {
        if self.session_limited {
            VaultError::SessionExpired
        } else {
            VaultError::WatchDurationElapsed
        }
    }

    fn check(&self, now: Instant) -> crate::core::Result<()> {
        if now >= self.at {
            Err(self.error())
        } else {
            Ok(())
        }
    }
}

fn record_transfer(
    result: CloudResult<SyncManifest>,
    attempt: Attempt<'_>,
    elapsed: u64,
    guard: &dyn Fn() -> crate::core::Result<()>,
    report: &mut WatchReport,
) -> CloudResult<()> {
    match result {
        Ok(manifest) => {
            guard()?;
            let outcome = if manifest.local_changes_pending {
                Reconciliation::Pending
            } else {
                Reconciliation::Complete
            };
            attempt
                .acknowledge(elapsed, Admission::Ready, outcome)
                .map_err(|_| stopped("watch_admission_changed"))?;
            report.successful_attempts += 1;
            report.last = Some(manifest);
            Ok(())
        }
        Err(CloudError::Network(_)) => {
            attempt.fail(elapsed, false);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub async fn watch_partition(
    partition: &str,
    passphrase: &str,
    seconds: u64,
) -> CloudResult<WatchReport> {
    let mut report = WatchReport {
        stopped: "duration",
        successful_attempts: 0,
        reconciliation_required: true,
        last: None,
    };
    finish_watch(
        watch_partition_inner(partition, passphrase, seconds, &mut report).await,
        report,
    )
}

fn finish_watch(result: CloudResult<()>, report: WatchReport) -> CloudResult<WatchReport> {
    match result {
        Ok(()) | Err(CloudError::Vault(VaultError::WatchDurationElapsed)) => Ok(report),
        Err(error) => Err(error),
    }
}

async fn watch_partition_inner(
    partition: &str,
    passphrase: &str,
    seconds: u64,
    report: &mut WatchReport,
) -> CloudResult<()> {
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
    let requested = Duration::from_secs(seconds);
    let duration = requested.min(remaining);
    let started = Instant::now();
    let deadline = WatchDeadline {
        at: started + duration,
        session_limited: remaining <= requested,
    };
    let guard = || -> crate::core::Result<()> {
        deadline.check(Instant::now())?;
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
        tokio::time::Instant::from_std(deadline.at),
        client.refresh_account(),
    )
    .await
    .map_err(|_| deadline.error())??;
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
    loop {
        if Instant::now() >= deadline.at {
            return Err(deadline.error().into());
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
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.at)) => return Err(deadline.error().into()),
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|_| stopped("watch_signal_unavailable"))?;
                    report.stopped = "cancelled";
                    return Ok(());
                }
            };
            record_transfer(result, attempt, started.elapsed().as_secs(), &guard, report)?;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.at)) => return Err(deadline.error().into()),
            result = tokio::signal::ctrl_c() => {
                result.map_err(|_| stopped("watch_signal_unavailable"))?;
                report.stopped = "cancelled";
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> WatchReport {
        WatchReport {
            stopped: "duration",
            successful_attempts: 3,
            reconciliation_required: true,
            last: None,
        }
    }

    #[test]
    fn duration_guard_exit_preserves_prior_progress_without_acknowledging_attempt() {
        // The same typed result is returned when a synchronous guard wins against
        // the async timer, including the guard after a transfer finishes.
        let result = finish_watch(Err(VaultError::WatchDurationElapsed.into()), report()).unwrap();
        assert_eq!(result.stopped, "duration");
        assert_eq!(result.successful_attempts, 3);
        assert!(result.reconciliation_required);
        assert!(result.last.is_none());
    }

    #[test]
    fn duration_does_not_mask_session_auth_scope_conflict_or_transport_errors() {
        for error in [
            CloudError::Vault(VaultError::SessionExpired),
            CloudError::Vault(VaultError::Locked),
            CloudError::Vault(stopped("watch_scope_changed")),
            CloudError::NotAuthenticated,
            CloudError::SyncConflict("partition".into(), "conflict".into()),
            CloudError::Network("unavailable".into()),
            CloudError::Vault(stopped("watch_deadline")),
        ] {
            assert!(finish_watch(Err(error), report()).is_err());
        }
    }
    #[test]
    fn duration_expiry_before_transfer_and_before_acknowledgement_never_advances_cursor() {
        let at = Instant::now();
        for session_limited in [false, true] {
            for before_transfer in [false, true] {
                let deadline = WatchDeadline {
                    at,
                    session_limited,
                };
                assert!(deadline.check(at - Duration::from_nanos(1)).is_ok());
                let mut coordinator = Coordinator::restore(
                    Binding {
                        endpoint: "https://synthetic.invalid".into(),
                        account: "account".into(),
                        device: "device".into(),
                        project: "project".into(),
                        partition: "partition".into(),
                    },
                    None,
                )
                .unwrap();
                coordinator.set_admission(Admission::Ready);
                let binding = coordinator.checkpoint().binding.clone();
                coordinator
                    .hint(&binding, "unacknowledged-revision")
                    .unwrap();
                let prior = coordinator.checkpoint().clone();
                let attempt = coordinator.begin(0).unwrap();
                let mut progress = report();
                let transfer = if before_transfer {
                    deadline
                        .check(at)
                        .map(|_| unreachable!())
                        .map_err(CloudError::from)
                } else {
                    Ok(serde_json::from_value(serde_json::json!({
                        "partition_id":"partition", "partition_name":"partition",
                        "last_synced_at":"", "local_hash":"", "remote_hash":null,
                        "sync_direction":"Bidirectional"
                    }))
                    .unwrap())
                };
                let result =
                    record_transfer(transfer, attempt, 1, &|| deadline.check(at), &mut progress);
                assert_eq!(coordinator.checkpoint(), &prior);
                assert_eq!(progress.successful_attempts, 3);
                assert!(progress.last.is_none());
                assert!(progress.reconciliation_required);
                let finished = finish_watch(result, progress);
                if session_limited {
                    assert!(matches!(
                        finished,
                        Err(CloudError::Vault(VaultError::SessionExpired))
                    ));
                } else {
                    assert_eq!(finished.unwrap().stopped, "duration");
                }
            }
        }
    }

    #[test]
    fn network_failure_keeps_reconciliation_pending_without_acknowledgement() {
        let mut coordinator = Coordinator::restore(
            Binding {
                endpoint: "https://synthetic.invalid".into(),
                account: "account".into(),
                device: "device".into(),
                project: "project".into(),
                partition: "partition".into(),
            },
            None,
        )
        .unwrap();
        coordinator.set_admission(Admission::Ready);
        coordinator.request_reconciliation();
        let prior = coordinator.checkpoint().clone();
        let attempt = coordinator.begin(0).unwrap();
        let mut progress = report();
        record_transfer(
            Err(CloudError::Network("unavailable".into())),
            attempt,
            0,
            &|| panic!("failed transfer must not be acknowledged"),
            &mut progress,
        )
        .unwrap();
        assert_eq!(coordinator.checkpoint(), &prior);
        assert!(coordinator.begin(0).is_none()); // Bounded retry backoff remains active.
        assert_eq!(progress.successful_attempts, 3);
        assert!(progress.reconciliation_required);
    }
}
