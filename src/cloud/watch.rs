//! Owner-started foreground sync for manually paired encrypted partitions.
//! This is not device enrollment or ring authorization and creates no grants.
use super::coordinator::{Admission, Attempt, Binding, Coordinator, Reconciliation};
use super::{CloudClient, CloudError, CloudResult, SyncManifest, SyncMode, load_config, oauth};
use crate::core::{Vault, VaultError, resolve_active_project};
use serde::Serialize;
use std::time::{Duration, Instant};

const REMOTE_POLL_INTERVAL: Duration = Duration::from_secs(5);

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
    end: WatchEnd,
}

#[derive(Clone, Copy)]
enum WatchEnd {
    Requested,
    VaultSession,
    CloudSession,
}

impl WatchDeadline {
    fn error(&self) -> VaultError {
        match self.end {
            WatchEnd::Requested => VaultError::WatchDurationElapsed,
            WatchEnd::VaultSession => VaultError::SessionExpired,
            WatchEnd::CloudSession => {
                VaultError::AuthRejected("cloud session expired; run wispkey cloud login")
            }
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

/// Watch a single paired partition for a bounded duration.
pub async fn watch_partition(
    partition: &str,
    passphrase: &str,
    seconds: u64,
) -> CloudResult<WatchReport> {
    watch_partitions(&[partition.to_owned()], passphrase, Some(seconds)).await
}

pub async fn watch_partitions(
    partitions: &[String],
    passphrase: &str,
    seconds: Option<u64>,
) -> CloudResult<WatchReport> {
    let mut report = WatchReport {
        stopped: "duration",
        successful_attempts: 0,
        reconciliation_required: true,
        last: None,
    };
    finish_watch(
        watch_partitions_inner(partitions, passphrase, seconds, &mut report).await,
        report,
    )
}

fn finish_watch(result: CloudResult<()>, report: WatchReport) -> CloudResult<WatchReport> {
    match result {
        Ok(()) | Err(CloudError::Vault(VaultError::WatchDurationElapsed)) => Ok(report),
        Err(error) => Err(error),
    }
}

async fn watch_partitions_inner(
    partitions: &[String],
    passphrase: &str,
    seconds: Option<u64>,
    report: &mut WatchReport,
) -> CloudResult<()> {
    if seconds.is_some_and(|seconds| !(1..=3600).contains(&seconds)) {
        return Err(CloudError::ApiError(
            "watch_duration_must_be_1_to_3600_seconds".into(),
        ));
    }
    if !(1..=10).contains(&partitions.len()) {
        return Err(stopped("watch_requires_1_to_10_partitions").into());
    }
    let vault = Vault::open_with_session()?; // Never unlock or renew from environment/protector.
    let session = vault.operation_session_binding()?;
    let project = resolve_active_project();
    let project_id = vault.get_project(&project)?.id;
    let mut scope = Vec::with_capacity(partitions.len());
    for name in partitions {
        let id = vault.get_partition_in_project(&project, name)?.id;
        if scope.iter().any(|(_, selected_id)| selected_id == &id) {
            return Err(stopped("watch_duplicate_partition").into());
        }
        scope.push((name, id));
    }
    let config = load_config()?;
    oauth::ensure_session(&config)?;
    let account = config
        .user_id
        .clone()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CloudError::ApiError("watch_missing_account".into()))?;
    let now = chrono::Utc::now();
    let vault_remaining = (session.expires_at - now)
        .to_std()
        .map_err(|_| stopped("watch_session_expired"))?;
    let cloud_expiry = config
        .oauth_session
        .as_ref()
        .and_then(|session| chrono::DateTime::from_timestamp(session.expires_at, 0))
        .ok_or_else(|| stopped("watch_missing_cloud_expiry"))?;
    let cloud_remaining = (cloud_expiry - now)
        .to_std()
        .map_err(|_| stopped("watch_cloud_session_expired"))?;
    let (duration, end) = if vault_remaining <= cloud_remaining {
        (vault_remaining, WatchEnd::VaultSession)
    } else {
        (cloud_remaining, WatchEnd::CloudSession)
    };
    let (duration, end) = match seconds.map(Duration::from_secs) {
        Some(requested) if requested < duration => (requested, WatchEnd::Requested),
        _ => (duration, end),
    };
    let started = Instant::now();
    let deadline = WatchDeadline {
        at: started + duration,
        end,
    };
    let guard = || -> crate::core::Result<()> {
        deadline.check(Instant::now())?;
        if vault.operation_session_binding()? != session {
            return Err(stopped("watch_session_changed"));
        }
        if load_config().ok().as_ref() != Some(&config) {
            return Err(stopped("watch_cloud_config_changed"));
        }
        if resolve_active_project() != project || vault.get_project(&project)?.id != project_id {
            return Err(stopped("watch_scope_changed"));
        }
        for (name, id) in &scope {
            if vault.get_partition_in_project(&project, name)?.id != *id {
                return Err(stopped("watch_scope_changed"));
            }
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
    let mut coordinators = Vec::with_capacity(scope.len());
    for (name, _) in &scope {
        if !client.watch_has_acknowledgement(&vault, &project, name)? {
            return Err(stopped(
                "watch_requires_acknowledged_partition; complete manual push/pull first",
            )
            .into());
        }
        let binding = Binding {
            endpoint: config.api_url.clone(),
            account: account.clone(),
            // An owner-session binding, explicitly not a cryptographically enrolled device.
            device: "manual-owner-session".into(),
            project: project.clone(),
            partition: (*name).clone(),
        };
        let mut coordinator = Coordinator::restore(binding, None)
            .map_err(|_| stopped("watch_invalid_coordinator"))?;
        coordinator.set_admission(Admission::Ready);
        coordinators.push(coordinator);
    }
    let mut observed_version = None;
    let mut next_remote_check = started;
    loop {
        guard()?;
        // The same SQLite connection sees other processes' saves without decrypting
        // every selected partition or querying Cloud on each local poll.
        let data_version: i64 = vault
            .db()
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(VaultError::from)?;
        let now = Instant::now();
        let remote_due = now >= next_remote_check;
        let local_changed = observed_version.replace(data_version) != Some(data_version);
        if remote_due {
            next_remote_check = now + REMOTE_POLL_INTERVAL;
        }
        for ((partition, _), coordinator) in scope.iter().zip(&mut coordinators) {
            if remote_due || local_changed {
                coordinator.request_reconciliation();
            }
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
                    end: if session_limited {
                        WatchEnd::VaultSession
                    } else {
                        WatchEnd::Requested
                    },
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
    fn failure_policy_keeps_reconciliation_pending_without_acknowledgement() {
        for (error, retryable) in [
            (CloudError::Network("unavailable".into()), true),
            (CloudError::Network("request_timed_out".into()), true),
            (CloudError::Network("service_unavailable".into()), true),
            (CloudError::NotAuthenticated, false),
            (CloudError::TierLimit("denied".into()), false),
            (CloudError::ApiError("rate_limited".into()), false),
            (
                CloudError::ApiError("backend_missing_revision_contract".into()),
                false,
            ),
            (
                CloudError::SyncConflict("partition".into(), "conflict".into()),
                false,
            ),
        ] {
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
            let result = record_transfer(
                Err(error),
                attempt,
                0,
                &|| panic!("failed transfer must not be acknowledged"),
                &mut progress,
            );
            assert_eq!(result.is_ok(), retryable);
            assert_eq!(coordinator.checkpoint(), &prior);
            if retryable {
                assert!(coordinator.begin(0).is_none()); // Bounded retry backoff remains active.
            }
            assert_eq!(progress.successful_attempts, 3);
            assert!(progress.reconciliation_required);
        }
    }
}
