//! Experimental scheduling only: hints never authorize sync, decryption, or release.
//!
//! No production caller uses this module. A future adapter must authenticate the
//! feed, verify device enrollment and policy, obtain owner-approved local key
//! access, and use the existing conditional encrypted sync transaction.
use serde::{Deserialize, Serialize};

const MAX_CURSOR_BYTES: usize = 256;
const RECONCILE_SECONDS: u64 = 60;
const MAX_BACKOFF_SECONDS: u64 = 300;

/// Exact trusted binding, selected locally rather than supplied by a notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub endpoint: String,
    pub account: String,
    pub device: String,
    pub project: String,
    pub partition: String,
}

/// Metadata checkpoint only. It contains no key, ciphertext or authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u8,
    pub binding: Binding,
    pub cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    Disabled,
    NotEnrolled,
    Locked,
    Offline,
    StalePolicy,
    Conflict,
}

/// A trusted adapter must recompute admission at dispatch and before applying a
/// result. `Ready` is a scheduling input, never a substitute for authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Ready,
    Blocked(Blocked),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Blocked(Blocked),
    Pending,
    Waiting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCheckpoint,
    WrongBinding,
    InvalidCursor,
    Blocked,
}

/// A successful transaction can still have local edits or an uncertain upload to
/// reconcile. Only a full authenticated current-revision reconciliation is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    Complete,
    Pending,
}

/// Opaque single-use attempt, tied to a specific coordinator instance.
/// Keeping it borrowed prevents hints, account switches or another dispatch while
/// the adapter reconciles. Drop without completion leaves reconciliation pending.
pub struct Attempt<'a> {
    coordinator: &'a mut Coordinator,
}

/// One bounded slot per explicitly opted-in partition. No notification queue,
/// notification-controlled URLs, revision selection or automatic conflict retry.
pub struct Coordinator {
    checkpoint: Checkpoint,
    pending_cursor: Option<String>,
    dirty: bool,
    admission: Admission,
    next_due: u64,
    retry_after: u64,
    failures: u8,
    conflict: bool,
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_CURSOR_BYTES
        && cursor.bytes().all(|b| b.is_ascii_graphic())
}

impl Coordinator {
    /// Restore only an exact locally chosen scope. Always reconcile on restart:
    /// a saved cursor is a resume hint, not proof the current snapshot is fresh.
    pub fn restore(binding: Binding, saved: Option<Checkpoint>) -> Result<Self, Error> {
        let checkpoint = saved.unwrap_or(Checkpoint {
            version: 1,
            binding: binding.clone(),
            cursor: None,
        });
        if checkpoint.version != 1 {
            return Err(Error::InvalidCheckpoint);
        }
        if checkpoint.binding != binding {
            return Err(Error::WrongBinding);
        }
        if checkpoint
            .cursor
            .as_deref()
            .is_some_and(|v| !valid_cursor(v))
        {
            return Err(Error::InvalidCursor);
        }
        Ok(Self {
            checkpoint,
            pending_cursor: None,
            dirty: true,
            admission: Admission::Blocked(Blocked::Disabled),
            next_due: 0,
            retry_after: 0,
            failures: 0,
            conflict: false,
        })
    }

    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The caller supplies fresh trusted policy evaluation, never a wire label.
    pub fn set_admission(&mut self, admission: Admission) {
        if admission == Admission::Blocked(Blocked::Conflict) {
            self.conflict = true;
        }
        if self.admission != admission {
            self.dirty = true;
        }
        self.admission = admission;
    }

    /// Call only after the existing explicit owner conflict-resolution workflow
    /// has completed. Routine admission refresh cannot clear this latch.
    pub fn conflict_resolved(&mut self) {
        self.conflict = false;
        self.dirty = true;
    }

    /// Cursors are opaque: an older/reordered hint can only cause extra fetches.
    /// Coalesce to one cursor; only a successful authenticated reconciliation can
    /// acknowledge it. Reject unrelated scopes before storing anything.
    pub fn hint(&mut self, binding: &Binding, cursor: &str) -> Result<(), Error> {
        if binding != &self.checkpoint.binding {
            return Err(Error::WrongBinding);
        }
        if !valid_cursor(cursor) {
            return Err(Error::InvalidCursor);
        }
        if self.pending_cursor.as_deref() == Some(cursor)
            || self.checkpoint.cursor.as_deref() == Some(cursor)
        {
            return Ok(());
        }
        self.pending_cursor = Some(cursor.to_owned());
        self.dirty = true;
        Ok(())
    }

    /// `now` is monotonic seconds from the adapter's process clock. Hints cannot
    /// bypass failure backoff. Periodic reconciliation repairs missed hints.
    pub fn status(&self, now: u64) -> Status {
        match self.admission {
            Admission::Blocked(reason) => Status::Blocked(reason),
            Admission::Ready if self.conflict => Status::Blocked(Blocked::Conflict),
            Admission::Ready if now < self.retry_after => Status::Waiting,
            Admission::Ready if self.dirty || now >= self.next_due => Status::Pending,
            Admission::Ready => Status::Waiting,
        }
    }

    pub fn begin(&mut self, now: u64) -> Option<Attempt<'_>> {
        if self.status(now) != Status::Pending {
            return None;
        }
        Some(Attempt { coordinator: self })
    }
}

impl Attempt<'_> {
    /// Use Complete only after full authenticated current-revision reconciliation,
    /// not merely a successful upload retry or a result with local changes pending.
    /// Call only after the existing authenticated sync transaction succeeds and
    /// admission is rechecked. Persist the returned checkpoint atomically through
    /// the future adapter; a failed save safely causes reconciliation on restart.
    pub fn acknowledge(
        self,
        now: u64,
        admission: Admission,
        outcome: Reconciliation,
    ) -> Result<Checkpoint, Error> {
        let coordinator = self.coordinator;
        coordinator.set_admission(admission);
        if admission != Admission::Ready || coordinator.conflict {
            return Err(Error::Blocked);
        }
        if outcome == Reconciliation::Pending {
            coordinator.dirty = true;
            coordinator.retry_after = now.saturating_add(1);
            return Ok(coordinator.checkpoint.clone());
        }
        if let Some(cursor) = coordinator.pending_cursor.take() {
            coordinator.checkpoint.cursor = Some(cursor);
        }
        coordinator.dirty = false;
        coordinator.failures = 0;
        coordinator.next_due = now.saturating_add(RECONCILE_SECONDS);
        coordinator.retry_after = now.saturating_add(1);
        Ok(coordinator.checkpoint.clone())
    }

    /// Network failure has bounded exponential backoff; it never advances a
    /// cursor. Conflict is sticky until explicit resolution by the owner
    /// workflow, not cleared by routine admission refresh.
    pub fn fail(self, now: u64, conflict: bool) {
        let coordinator = self.coordinator;
        coordinator.dirty = true;
        if conflict {
            coordinator.conflict = true;
        }
        coordinator.failures = coordinator.failures.saturating_add(1).min(9);
        let delay = (1_u64 << coordinator.failures).min(MAX_BACKOFF_SECONDS);
        coordinator.retry_after = now.saturating_add(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            endpoint: "https://sync.example.test".into(),
            account: "synthetic-account".into(),
            device: "synthetic-enrolled-device".into(),
            project: "work".into(),
            partition: "production".into(),
        }
    }

    fn ready() -> Coordinator {
        let mut coordinator = Coordinator::restore(binding(), None).unwrap();
        coordinator.set_admission(Admission::Ready);
        coordinator
    }

    #[test]
    fn disabled_by_default_and_all_denials_block_dispatch() {
        let mut coordinator = Coordinator::restore(binding(), None).unwrap();
        assert_eq!(coordinator.status(0), Status::Blocked(Blocked::Disabled));
        for reason in [
            Blocked::Disabled,
            Blocked::NotEnrolled,
            Blocked::Locked,
            Blocked::Offline,
            Blocked::StalePolicy,
            Blocked::Conflict,
        ] {
            coordinator.set_admission(Admission::Blocked(reason));
            assert!(coordinator.begin(u64::MAX).is_none());
        }
    }

    #[test]
    fn every_scope_component_is_bound() {
        let mut coordinator = ready();
        for field in 0..5 {
            let mut other = binding();
            match field {
                0 => other.endpoint.push_str("/other"),
                1 => other.account.push_str("other"),
                2 => other.device.push_str("other"),
                3 => other.project.push_str("other"),
                _ => other.partition.push_str("other"),
            }
            assert_eq!(coordinator.hint(&other, "cursor"), Err(Error::WrongBinding));
            let saved = coordinator.checkpoint().clone();
            assert!(matches!(
                Coordinator::restore(other, Some(saved)),
                Err(Error::WrongBinding)
            ));
        }
        assert!(coordinator.pending_cursor.is_none());
    }

    #[test]
    fn cursor_input_is_bounded_and_unknown_checkpoint_versions_fail_closed() {
        let mut coordinator = ready();
        for invalid in ["".to_owned(), "a".repeat(257), "x\ny".into(), "☃".into()] {
            assert_eq!(
                coordinator.hint(&binding(), &invalid),
                Err(Error::InvalidCursor)
            );
        }
        coordinator.hint(&binding(), &"x".repeat(256)).unwrap();
        let mut checkpoint = coordinator.checkpoint().clone();
        checkpoint.version = 2;
        assert!(matches!(
            Coordinator::restore(binding(), Some(checkpoint)),
            Err(Error::InvalidCheckpoint)
        ));
        let mut checkpoint = coordinator.checkpoint().clone();
        checkpoint.cursor = Some("a".repeat(257));
        assert!(matches!(
            Coordinator::restore(binding(), Some(checkpoint)),
            Err(Error::InvalidCursor)
        ));
        let mut value = serde_json::to_value(coordinator.checkpoint()).unwrap();
        value["enabled"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Checkpoint>(value).is_err());
    }

    #[test]
    fn hints_coalesce_and_only_reconciliation_advances_checkpoint() {
        let mut coordinator = ready();
        for n in 0..10_000 {
            coordinator
                .hint(&binding(), &format!("cursor-{n}"))
                .unwrap();
        }
        assert_eq!(coordinator.pending_cursor.as_deref(), Some("cursor-9999"));
        assert!(coordinator.checkpoint().cursor.is_none());
        let checkpoint = coordinator
            .begin(0)
            .unwrap()
            .acknowledge(0, Admission::Ready, Reconciliation::Complete)
            .unwrap();
        assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-9999"));
        coordinator.hint(&binding(), "cursor-9999").unwrap();
        assert_eq!(coordinator.status(1), Status::Waiting);
        // Reordered events only prompt reconciliation; never select a snapshot.
        coordinator.hint(&binding(), "cursor-1").unwrap();
        assert_eq!(coordinator.status(1), Status::Pending);
        assert_eq!(
            coordinator.checkpoint().cursor.as_deref(),
            Some("cursor-9999")
        );
    }

    #[test]
    fn missed_events_restart_and_dropped_attempts_reconcile() {
        let mut coordinator = ready();
        {
            let _attempt = coordinator.begin(0).unwrap();
        }
        assert_eq!(coordinator.status(0), Status::Pending);
        let saved = coordinator
            .begin(0)
            .unwrap()
            .acknowledge(0, Admission::Ready, Reconciliation::Complete)
            .unwrap();
        assert_eq!(coordinator.status(59), Status::Waiting);
        assert_eq!(coordinator.status(60), Status::Pending);
        let mut restarted = Coordinator::restore(binding(), Some(saved)).unwrap();
        assert_eq!(restarted.status(0), Status::Blocked(Blocked::Disabled));
        restarted.set_admission(Admission::Ready);
        assert_eq!(restarted.status(0), Status::Pending);
    }

    #[test]
    fn network_failure_backoff_survives_hint_flood_and_caps() {
        let mut coordinator = ready();
        let mut now = 0;
        for failures in 1..=20 {
            coordinator.begin(now).unwrap().fail(now, false);
            coordinator
                .hint(&binding(), &format!("cursor-{failures}"))
                .unwrap();
            let delay = (1_u64 << failures.min(9)).min(300);
            assert_eq!(coordinator.status(now + delay - 1), Status::Waiting);
            now += delay;
            assert_eq!(coordinator.status(now), Status::Pending);
            assert!(coordinator.checkpoint().cursor.is_none());
        }
    }

    #[test]
    fn every_completion_denial_preserves_checkpoint() {
        for reason in [
            Blocked::Disabled,
            Blocked::NotEnrolled,
            Blocked::Locked,
            Blocked::Offline,
            Blocked::StalePolicy,
            Blocked::Conflict,
        ] {
            let mut coordinator = ready();
            coordinator.hint(&binding(), "pending").unwrap();
            assert_eq!(
                coordinator.begin(0).unwrap().acknowledge(
                    0,
                    Admission::Blocked(reason),
                    Reconciliation::Complete
                ),
                Err(Error::Blocked)
            );
            assert!(coordinator.checkpoint().cursor.is_none());
            assert_eq!(coordinator.status(100), Status::Blocked(reason));
            if reason == Blocked::Conflict {
                coordinator.set_admission(Admission::Ready);
                assert_eq!(coordinator.status(100), Status::Blocked(Blocked::Conflict));
            }
        }
    }

    #[test]
    fn reordered_cursor_checkpoint_is_only_a_resume_hint_after_restart() {
        let mut coordinator = ready();
        for (now, cursor) in [(0, "newer"), (1, "older")] {
            coordinator.hint(&binding(), cursor).unwrap();
            coordinator
                .begin(now)
                .unwrap()
                .acknowledge(now, Admission::Ready, Reconciliation::Complete)
                .unwrap();
        }
        let saved = coordinator.checkpoint().clone();
        assert_eq!(saved.cursor.as_deref(), Some("older"));
        let mut restarted = Coordinator::restore(binding(), Some(saved)).unwrap();
        assert!(restarted.begin(0).is_none());
        restarted.set_admission(Admission::Ready);
        assert!(restarted.begin(0).is_some());
    }

    #[test]
    fn conflict_and_revocation_do_not_acknowledge_or_retry() {
        let mut coordinator = ready();
        coordinator.hint(&binding(), "pending").unwrap();
        coordinator.begin(0).unwrap().fail(0, true);
        assert_eq!(coordinator.status(1000), Status::Blocked(Blocked::Conflict));
        assert!(coordinator.checkpoint().cursor.is_none());
        coordinator.set_admission(Admission::Ready);
        assert_eq!(coordinator.status(1000), Status::Blocked(Blocked::Conflict));
        coordinator.conflict_resolved();
        assert_eq!(
            coordinator.begin(1000).unwrap().acknowledge(
                1000,
                Admission::Blocked(Blocked::NotEnrolled),
                Reconciliation::Complete
            ),
            Err(Error::Blocked)
        );
        assert!(coordinator.checkpoint().cursor.is_none());
        assert_eq!(
            coordinator.status(2000),
            Status::Blocked(Blocked::NotEnrolled)
        );
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;
    #[test]
    fn partial_success_keeps_hint_unacknowledged_and_work_pending() {
        let binding = Binding {
            endpoint: "e".into(),
            account: "a".into(),
            device: "d".into(),
            project: "p".into(),
            partition: "q".into(),
        };
        let mut coordinator = Coordinator::restore(binding.clone(), None).unwrap();
        coordinator.set_admission(Admission::Ready);
        coordinator.hint(&binding, "cursor").unwrap();
        let checkpoint = coordinator
            .begin(0)
            .unwrap()
            .acknowledge(0, Admission::Ready, Reconciliation::Pending)
            .unwrap();
        assert!(checkpoint.cursor.is_none());
        assert_eq!(coordinator.status(0), Status::Waiting);
        assert_eq!(coordinator.status(1), Status::Pending);
        assert_eq!(coordinator.pending_cursor.as_deref(), Some("cursor"));
    }
}
