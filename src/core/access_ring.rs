//! Local access rings: an owner classification that limits which release paths
//! may decrypt a credential. Rings are orthogonal to project, instance, host,
//! auth registry and policy checks. They never establish identity.
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::{Result, Vault, VaultError};

pub(crate) const ACCESS_RING_POLICY_KEY: &str = "access_ring_policy";
pub(crate) const ACCESS_RING_POLICY_VERSION: &str = "1";

/// Records the ring policy for a new or migrated vault. An existing row is kept,
/// so an unsupported stored policy still fails closed.
pub(crate) fn insert_access_ring_policy(db: &Connection) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES (?1, ?2)",
        params![ACCESS_RING_POLICY_KEY, ACCESS_RING_POLICY_VERSION],
    )?;
    Ok(())
}

fn rejected(reason: &'static str) -> VaultError {
    VaultError::AuthRejected(reason)
}

/// Ordered from broadest to narrowest release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRing {
    Routine,
    Restricted,
    Critical,
}

impl AccessRing {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Restricted => "restricted",
            Self::Critical => "critical",
        }
    }

    /// Strict parse for owner input and transport formats.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "routine" => Some(Self::Routine),
            "restricted" => Some(Self::Restricted),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Stored values: a missing or unknown classification is restricted.
    pub(crate) fn from_stored(value: Option<&str>) -> Self {
        value.and_then(Self::parse).unwrap_or(Self::Restricted)
    }
}

fn ring_label(ring: Option<AccessRing>) -> &'static str {
    ring.map_or("unclassified", AccessRing::as_str)
}

/// The approval a delegated release path holds. Critical execution and fill
/// remain denied; explicit owner recovery and transfer use a separate boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RingRelease {
    /// Proxy, MCP, webhook signing, auth resolution and owner egress.
    /// A cached unlock is not step-up.
    Unattended,
    /// Browser fill after OS verification, or a one-use operation grant after
    /// a fresh interactive owner password. Both bind identity and revision.
    /// The default-off browser receiver uses the same native approval.
    OwnerApproved,
}

impl RingRelease {
    fn permits(self, ring: AccessRing) -> bool {
        match self {
            Self::Unattended => ring == AccessRing::Routine,
            Self::OwnerApproved => ring <= AccessRing::Restricted,
        }
    }
}

impl Vault {
    fn ensure_access_ring_policy(&self) -> Result<()> {
        let policy: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM vault_meta WHERE key=?1",
                [ACCESS_RING_POLICY_KEY],
                |row| row.get(0),
            )
            .optional()?;
        if policy.as_deref() != Some(ACCESS_RING_POLICY_VERSION) {
            return Err(rejected("access ring policy unsupported"));
        }
        Ok(())
    }

    fn stored_access_ring(&self, credential_id: &str) -> Result<AccessRing> {
        Ok(self
            .explicit_access_ring(credential_id)?
            .unwrap_or(AccessRing::Restricted))
    }

    /// Transport the effective restriction, including the restricted default.
    /// Omitting an unclassified ring would let older readers ignore it.
    pub(crate) fn transport_access_ring(&self, credential_id: &str) -> Result<AccessRing> {
        self.ensure_access_ring_policy()?;
        self.stored_access_ring(credential_id)
    }

    pub(crate) fn ensure_access_ring(
        &self,
        credential_id: &str,
        release: RingRelease,
    ) -> Result<()> {
        self.ensure_access_ring_policy()?;
        match self.stored_access_ring(credential_id)? {
            ring if release.permits(ring) => Ok(()),
            AccessRing::Critical => Err(rejected(
                "access ring critical denies release without trusted-device presence",
            )),
            _ => Err(rejected("access ring restricted requires owner approval")),
        }
    }

    pub fn access_ring_in_project(&self, project: &str, name: &str) -> Result<AccessRing> {
        let credential = self.get_credential_in_project(project, name)?;
        self.stored_access_ring(&credential.id)
    }

    /// Owner classification. Broadening release needs a fresh interactive owner
    /// password; narrowing does not. The change bumps `updated_at`, so earlier
    /// browser and operation approvals for this revision become stale.
    /// Setting the stored ring again is a no-op. Returns the previous ring.
    /// The audit records metadata only.
    pub fn set_access_ring(
        &self,
        project: &str,
        name: &str,
        ring: AccessRing,
        owner_password: Option<&str>,
    ) -> Result<AccessRing> {
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.ensure_access_ring_policy()?;
        let credential = self.get_credential_in_project(project, name)?;
        let previous = self.stored_access_ring(&credential.id)?;
        if self.explicit_access_ring(&credential.id)? == Some(ring) {
            return Ok(previous);
        }
        if ring < previous {
            let password = owner_password
                .ok_or(rejected("broadening an access ring requires owner password"))?;
            self.verify_operation_owner_password(password)
                .map_err(rejected)?;
        }
        self.db.execute(
            "UPDATE credentials SET access_ring=?1, updated_at=?2 WHERE id=?3",
            params![ring.as_str(), Utc::now().to_rfc3339(), credential.id],
        )?;
        self.log_access_ring_change(&credential.name, previous.as_str(), ring.as_str(), project)?;
        tx.commit()?;
        Ok(previous)
    }

    /// Classifies a row inserted earlier in the caller's transaction. A new row
    /// needs no step-up: the owner supplied its value in the same call.
    pub(crate) fn classify_new_credential(
        &self,
        credential: &super::Credential,
        ring: AccessRing,
        project: &str,
    ) -> Result<()> {
        if self.db.is_autocommit() {
            return Err(rejected("access ring classification requires a transaction"));
        }
        self.ensure_access_ring_policy()?;
        let changed = self.db.execute(
            "UPDATE credentials SET access_ring=?1 WHERE id=?2 AND access_ring IS NULL",
            params![ring.as_str(), credential.id],
        )?;
        if changed != 1 {
            return Err(rejected("access ring classification requires a new credential"));
        }
        self.log_access_ring_change(&credential.name, "unclassified", ring.as_str(), project)
    }

    /// Applies a transported classification to an existing row inside the
    /// caller's transport transaction. A snapshot may keep or narrow a ring,
    /// but never broaden it: only the local owner control can broaden.
    pub(crate) fn replace_transport_access_ring(
        &self,
        credential_id: &str,
        name: &str,
        project: &str,
        ring: Option<AccessRing>,
    ) -> Result<()> {
        if self.db.is_autocommit() {
            return Err(VaultError::InvalidBundle(
                "transport transaction required".into(),
            ));
        }
        let previous = self.explicit_access_ring(credential_id)?;
        if previous == ring {
            return Ok(());
        }
        self.ensure_access_ring_policy()?;
        if ring.unwrap_or(AccessRing::Restricted) < previous.unwrap_or(AccessRing::Restricted) {
            return Err(VaultError::InvalidBundle(
                "snapshot cannot broaden an access ring".into(),
            ));
        }
        self.db.execute(
            "UPDATE credentials SET access_ring=?1 WHERE id=?2",
            params![ring.map(AccessRing::as_str), credential_id],
        )?;
        self.log_access_ring_change(name, ring_label(previous), ring_label(ring), project)
    }

    fn log_access_ring_change(
        &self,
        name: &str,
        previous: &str,
        next: &str,
        project: &str,
    ) -> Result<()> {
        let detail = format!("{previous}->{next}");
        crate::audit::try_log_event(
            &self.db,
            "AccessRingChanged",
            Some(name),
            None,
            None,
            Some(&detail),
            None,
            None,
            false,
            None,
            Some(project),
        )?;
        Ok(())
    }

    /// The explicit classification, or none when the owner never classified
    /// the credential (restricted by default).
    pub(crate) fn explicit_access_ring(&self, credential_id: &str) -> Result<Option<AccessRing>> {
        let stored: Option<String> = self.db.query_row(
            "SELECT access_ring FROM credentials WHERE id=?1",
            [credential_id],
            |row| row.get(0),
        )?;
        Ok(stored.map(|value| AccessRing::from_stored(Some(&value))))
    }
}
