//! Authenticated cloud snapshots and atomic partition replacement.
use super::auth::AuthPartitionData;
use super::*;
use ring::hmac;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub version: u8,
    pub project: String,
    pub partition: String,
    pub description: String,
    pub credentials: Vec<SnapshotCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<AuthPartitionData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signup_profiles: Option<Vec<signup::PortableProfile>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotCredential {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_id: Option<String>,
    description: String,
    credential_type: CredentialType,
    value: String,
    wisp_token: String,
    hosts: Vec<String>,
    tags: Vec<String>,
    origin: String,
    lifecycle_state: String,
    review_at: Option<String>,
}

impl Drop for SnapshotCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Secret-bearing rows explicitly bind to their portable metadata. A v2
/// document may contain both generic and registered credentials, but removing
/// one registry row must never convert its registered secret into a generic one.
pub(crate) fn validate_transport_auth_bindings<'a>(
    credentials: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    auth_data: Option<&AuthPartitionData>,
) -> Result<()> {
    let mut records = std::collections::HashMap::new();
    if let Some(auth_data) = auth_data {
        for record in &auth_data.records {
            if records
                .insert(record.credential_name.as_str(), record.metadata.id.as_str())
                .is_some()
            {
                return Err(VaultError::InvalidBundle("duplicate auth reference".into()));
            }
        }
    }
    for (name, auth_id) in credentials {
        if records.remove(name) != auth_id {
            return Err(VaultError::InvalidBundle(
                "credential auth metadata binding mismatch".into(),
            ));
        }
    }
    if !records.is_empty() {
        return Err(VaultError::InvalidBundle(
            "auth record is missing its credential".into(),
        ));
    }
    Ok(())
}

impl Vault {
    /// Keep transport scope creation, secrets, and auth restrictions atomic.
    pub(crate) fn with_transport_transaction<T>(
        &self,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let transaction = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let result = action()?;
        transaction.commit()?;
        Ok(result)
    }

    /// Keep registry metadata and plaintext export values in one read snapshot.
    pub(crate) fn with_transport_snapshot<T>(
        &self,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let transaction = if self.db.is_autocommit() {
            Some(self.db.unchecked_transaction()?)
        } else {
            None
        };
        let result = action()?;
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok(result)
    }

    /// Only transport callers holding a transaction may bypass add's own transaction.
    pub(crate) fn insert_transport_credential(
        &self,
        request: AddCredentialRequest<'_>,
    ) -> Result<Credential> {
        if self.db.is_autocommit() {
            return Err(VaultError::InvalidBundle(
                "transport transaction required".into(),
            ));
        }
        validate_add_request(&request)?;
        self.insert_credential_row(self.ensure_unlocked()?, &request)
    }

    pub(crate) fn cloud_snapshot(
        &self,
        project: &str,
        partition: &str,
    ) -> Result<Option<Snapshot>> {
        // Metadata and encrypted values must come from the same SQLite read
        // snapshot, even if a local credential writer runs during encryption.
        let transaction = if self.db.is_autocommit() {
            Some(self.db.unchecked_transaction()?)
        } else {
            None
        };
        let partition = match self.get_partition_in_project(project, partition) {
            Ok(partition) => partition,
            Err(VaultError::PartitionNotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut credentials =
            self.list_credentials_in_partition_for_project(project, &partition.name)?;
        credentials.sort_by(|a, b| a.name.cmp(&b.name));
        let credentials = credentials
            .into_iter()
            .map(|credential| {
                let value = self.decrypt_credential_for_transfer(project, &credential.name)?;
                let auth_id = self
                    .auth_metadata_for_id(&credential.id)?
                    .map(|metadata| metadata.id);
                Ok(SnapshotCredential {
                    name: credential.name,
                    auth_id,
                    description: credential.description,
                    credential_type: credential.credential_type,
                    value,
                    wisp_token: credential.wisp_token,
                    hosts: credential.hosts,
                    tags: credential.tags,
                    origin: credential.origin,
                    lifecycle_state: credential.lifecycle_state,
                    review_at: credential.review_at.map(|date| date.to_rfc3339()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let auth_data = self.export_auth_partition(project, &partition.name)?;
        let managed = self.auth_partition_managed(project, &partition.name)?;
        let auth_data = (managed || !auth_data.records.is_empty() || !auth_data.bundles.is_empty())
            .then_some(auth_data);
        let signup_profiles = self.export_signup_profiles(project, &partition.name)?;
        let snapshot = Snapshot {
            version: if signup_profiles.is_some() {
                3
            } else if auth_data.is_some() {
                2
            } else {
                1
            },
            project: project.to_owned(),
            partition: partition.name,
            description: partition.description,
            credentials,
            auth_data,
            signup_profiles,
        };
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok(Some(snapshot))
    }

    pub(crate) fn cloud_snapshot_hash(&self, snapshot: &Snapshot) -> Result<String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(snapshot)
                .map_err(|_| VaultError::InvalidBundle("invalid snapshot".into()))?,
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.ensure_unlocked()?);
        Ok(BASE64.encode(hmac::sign(&key, &bytes).as_ref()))
    }

    /// The caller holds the cloud process lock. Local credential writers are
    /// checked again under SQLite's write lock immediately before replacement.
    pub(crate) fn cloud_apply(
        &self,
        snapshot: &Snapshot,
        expected_hash: Option<&str>,
        state_update: Option<(&str, serde_json::Value)>,
    ) -> Result<String> {
        self.cloud_apply_guarded(snapshot, expected_hash, state_update, &|| Ok(()))
    }

    pub(crate) fn cloud_apply_guarded(
        &self,
        snapshot: &Snapshot,
        expected_hash: Option<&str>,
        state_update: Option<(&str, serde_json::Value)>,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<String> {
        guard()?;
        let key = self.ensure_unlocked()?;
        if !matches!(
            (
                snapshot.version,
                snapshot.auth_data.is_some(),
                snapshot.signup_profiles.is_some()
            ),
            (1, false, false) | (2, true, false) | (3, _, true)
        ) || snapshot.project.is_empty()
            || snapshot.partition.is_empty()
        {
            return Err(VaultError::InvalidBundle("invalid snapshot scope".into()));
        }
        let mut names = HashSet::new();
        let mut tokens = HashSet::new();
        for credential in &snapshot.credentials {
            if credential.name.trim().is_empty()
                || credential.value.trim().is_empty()
                || !names.insert(&credential.name)
                || !tokens.insert(&credential.wisp_token)
                || !credential.wisp_token.starts_with("wk_")
                || credential.wisp_token.len() > 256
                || !credential
                    .wisp_token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(VaultError::InvalidBundle(
                    "invalid snapshot credential".into(),
                ));
            }
            validate_lifecycle_state(&credential.lifecycle_state)?;
            if let Some(review) = &credential.review_at {
                DateTime::parse_from_rfc3339(review)
                    .map_err(|_| VaultError::InvalidBundle("invalid review date".into()))?;
            }
            if credential.credential_type == CredentialType::WebsiteLogin {
                if parse_https_origin(&credential.origin)? != credential.origin {
                    return Err(VaultError::InvalidBundle("invalid login origin".into()));
                }
                let login: WebsiteLoginPayload = serde_json::from_str(&credential.value)
                    .map_err(|_| VaultError::InvalidBundle("invalid login payload".into()))?;
                if login.username.trim().is_empty() || login.password.is_empty() {
                    return Err(VaultError::InvalidBundle("invalid login payload".into()));
                }
            }
        }
        validate_transport_auth_bindings(
            snapshot
                .credentials
                .iter()
                .map(|credential| (credential.name.as_str(), credential.auth_id.as_deref())),
            snapshot.auth_data.as_ref(),
        )?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let current = self.cloud_snapshot(&snapshot.project, &snapshot.partition)?;
        let hash = current
            .as_ref()
            .map(|value| self.cloud_snapshot_hash(value))
            .transpose()?;
        if hash.as_deref() != expected_hash {
            return Err(VaultError::InvalidBundle(
                "local partition changed during sync".into(),
            ));
        }
        if current
            .as_ref()
            .is_some_and(|s| s.signup_profiles.is_some())
            && snapshot.signup_profiles.is_none()
        {
            return Err(VaultError::InvalidBundle(
                "legacy snapshot cannot replace signup profiles".into(),
            ));
        }
        // Registration binds an identity to immutable secret material and its
        // credential-level restrictions. Match the local update API: changing
        // this material requires a new credential and a new auth identity.
        // Metadata revisions, lifecycle changes, and token rotation do not
        // authorize substituting a different underlying secret.
        let registered_values: std::collections::HashMap<_, _> = current
            .iter()
            .flat_map(|snapshot| snapshot.credentials.iter())
            .filter_map(|credential| credential.auth_id.as_deref().map(|id| (id, credential)))
            .collect();
        for incoming in &snapshot.credentials {
            if let Some(previous) = incoming
                .auth_id
                .as_deref()
                .and_then(|id| registered_values.get(id))
                && (incoming.value != previous.value
                    || incoming.credential_type != previous.credential_type
                    || incoming.hosts != previous.hosts
                    || incoming.origin != previous.origin)
            {
                return Err(VaultError::InvalidBundle(
                    "registered auth material cannot be replaced".into(),
                ));
            }
        }
        // Resolve incoming portable IDs against the pre-apply registry, before
        // deleting any credentials. A rename must not erase the old row first
        // and thereby launder its identity or revocation into a fresh record.
        if let Some(auth_data) = &snapshot.auth_data {
            for record in &auth_data.records {
                let existing: Option<(String, String, String, String)> = self.db.query_row(
                    "SELECT c.id,c.name,pr.name,p.name FROM auth_registry a JOIN credentials c ON c.id=a.credential_id JOIN partitions p ON p.id=c.partition_id JOIN projects pr ON pr.id=p.project_id WHERE a.auth_id=?1",
                    [&record.metadata.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                ).optional()?;
                if let Some((id, name, project, partition)) = existing {
                    let previous = self.auth_metadata_for_id(&id)?.ok_or_else(|| {
                        VaultError::InvalidBundle("auth identity unavailable".into())
                    })?;
                    if name != record.credential_name
                        || project != snapshot.project
                        || partition != snapshot.partition
                        || previous.provider != record.metadata.provider
                        || previous.account != record.metadata.account
                        || (previous.revoked_at.is_some() && record.metadata.revoked_at.is_none())
                    {
                        return Err(VaultError::InvalidBundle(
                            "auth identity or revocation conflict".into(),
                        ));
                    }
                }
            }
        }
        // A legacy snapshot must never turn a registered auth credential into
        // an unrestricted generic secret. Deletions are allowed only in v2.
        if let Some(current_auth) = current.as_ref().and_then(|value| value.auth_data.as_ref()) {
            let incoming_auth = snapshot.auth_data.as_ref().ok_or_else(|| {
                VaultError::InvalidBundle("legacy snapshot cannot replace registered auth".into())
            })?;
            if current_auth.records.iter().any(|record| {
                names.contains(&record.credential_name)
                    && !incoming_auth
                        .records
                        .iter()
                        .any(|incoming| incoming.credential_name == record.credential_name)
            }) {
                return Err(VaultError::InvalidBundle(
                    "snapshot drops registered auth metadata".into(),
                ));
            }
        }
        if let Some(auth_data) = &snapshot.auth_data
            && auth_data
                .records
                .iter()
                .any(|record| !names.contains(&record.credential_name))
        {
            return Err(VaultError::InvalidBundle(
                "auth record is missing its credential".into(),
            ));
        }
        let partition = match self.get_partition_in_project(&snapshot.project, &snapshot.partition)
        {
            Ok(partition) => partition,
            Err(VaultError::PartitionNotFound(_)) => self.create_partition(
                &snapshot.partition,
                &snapshot.description,
                Some(&snapshot.project),
            )?,
            Err(error) => return Err(error),
        };
        if snapshot.auth_data.is_some() {
            // The complete incoming bundle graph replaces the old graph. Clear
            // old edges before credential deletion under the same transaction;
            // invalid incoming references roll back this deletion too.
            self.db.execute(
                "DELETE FROM auth_bundles WHERE partition_id=?1",
                [&partition.id],
            )?;
        }
        if let Some(profiles) = &snapshot.signup_profiles {
            self.import_signup_profiles(&snapshot.project, &snapshot.partition, profiles, true)?;
        }
        if let Some(current) = current {
            for credential in &current.credentials {
                if !names.contains(&credential.name) {
                    self.remove_credential_in_project(&snapshot.project, &credential.name)?;
                }
            }
        }
        for credential in &snapshot.credentials {
            let hosts = credential.hosts.join(",");
            let tags = credential.tags.join(",");
            let existing: Option<(String, String)> = self.db.query_row(
                "SELECT c.id,c.partition_id FROM credentials c JOIN partitions p ON p.id=c.partition_id JOIN projects pr ON pr.id=p.project_id WHERE pr.name=?1 AND c.name=?2",
                params![snapshot.project, credential.name], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            let id = if let Some((id, partition_id)) = existing {
                if partition_id != partition.id {
                    return Err(VaultError::InvalidBundle(
                        "credential belongs to another partition".into(),
                    ));
                }
                id
            } else {
                self.insert_credential_row(
                    key,
                    &AddCredentialRequest {
                        name: &credential.name,
                        credential_type: credential.credential_type.clone(),
                        value: &credential.value,
                        description: Some(&credential.description),
                        hosts: Some(&hosts),
                        tags: Some(&tags),
                        partition: Some(&snapshot.partition),
                        project: Some(&snapshot.project),
                        origin: Some(&credential.origin),
                        lifecycle_state: Some(&credential.lifecycle_state),
                        review_at: credential.review_at.as_deref(),
                    },
                )?
                .id
            };
            let encrypted = self.encrypt_bytes(key, credential.value.as_bytes())?;
            self.db.execute("UPDATE credentials SET description=?1,credential_type=?2,encrypted_value=?3,wisp_token=?4,hosts=?5,tags=?6,origin=?7,lifecycle_state=?8,review_at=?9,updated_at=?10 WHERE id=?11",
                params![credential.description, serde_json::to_string(&credential.credential_type).map_err(|_| VaultError::InvalidBundle("invalid type".into()))?, BASE64.encode(encrypted), credential.wisp_token,
                    hosts,tags,credential.origin,credential.lifecycle_state,credential.review_at,Utc::now().to_rfc3339(),id])?;
        }
        if let Some(auth_data) = &snapshot.auth_data {
            self.import_auth_partition(&snapshot.project, &snapshot.partition, auth_data)?;
        }
        self.db.execute(
            "UPDATE partitions SET description=?1,updated_at=?2 WHERE id=?3",
            params![snapshot.description, Utc::now().to_rfc3339(), partition.id],
        )?;
        let applied = self
            .cloud_snapshot(&snapshot.project, &snapshot.partition)?
            .ok_or_else(|| VaultError::InvalidBundle("partition missing".into()))?;
        let hash = self.cloud_snapshot_hash(&applied)?;
        if let Some((state_key, mut state)) = state_update {
            state["local_hash"] = serde_json::json!(hash);
            self.db.execute("INSERT INTO vault_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![state_key,state.to_string()])?;
        }
        guard()?;
        tx.commit()?;
        Ok(hash)
    }
}

#[cfg(test)]
mod auth_transport_tests {
    use super::*;
    use crate::core::auth::{
        AuthAlternative, AuthBundle, AuthReference, AuthRegistration, ProviderExpiry,
    };

    const PASSPHRASE: &str = "synthetic-transport-passphrase";
    const SECRET: &str = "synthetic-auth-transport-canary";

    fn vault() -> Vault {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        let vault = Vault {
            db,
            master_key: Some([7; 32]),
            session_timeout_override: None,
        };
        vault.create_project("default", "").unwrap();
        vault
    }

    fn add(vault: &Vault, name: &str, registered: bool) {
        vault
            .add_credential(
                AddCredentialRequest::new(name, CredentialType::ApiKey, SECRET)
                    .hosts(Some("api.example.test"))
                    .project(Some("default")),
            )
            .unwrap();
        if registered {
            vault
                .register_auth(
                    "default",
                    name,
                    AuthRegistration {
                        provider: "synthetic-provider".into(),
                        account: "synthetic-account".into(),
                        origins: vec!["https://api.example.test".into()],
                        provider_expiry: ProviderExpiry::NonExpiring,
                        use_until: Some(Utc::now() + chrono::Duration::days(1)),
                    },
                )
                .unwrap();
        }
    }

    fn paired(vault: &Vault) {
        add(vault, "a-key", true);
        add(vault, "b-key", true);
        let data = vault.export_auth_partition("default", "personal").unwrap();
        vault
            .set_auth_bundle(&AuthBundle {
                name: "synthetic-pair".into(),
                project: "default".into(),
                partition: "personal".into(),
                account: "synthetic-account".into(),
                alternatives: vec![AuthAlternative {
                    name: "pair".into(),
                    members: data
                        .records
                        .iter()
                        .map(|record| AuthReference {
                            auth_id: record.metadata.id.clone(),
                            revision: record.metadata.revision.clone(),
                            role: record.credential_name.clone(),
                        })
                        .collect(),
                }],
            })
            .unwrap();
    }

    fn current_hash(vault: &Vault) -> String {
        vault
            .cloud_snapshot_hash(
                &vault
                    .cloud_snapshot("default", "personal")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn cloud_apply_guard_denial_at_commit_rolls_back_credentials_and_journal() {
        let source = vault();
        add(&source, "incoming", true);
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let target = vault();
        add(&target, "existing", false);
        let before = current_hash(&target);
        let calls = std::cell::Cell::new(0);
        let guard = || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(VaultError::Locked)
            } else {
                Ok(())
            }
        };
        assert!(
            target
                .cloud_apply_guarded(
                    &snapshot,
                    Some(&before),
                    Some(("synthetic-watch-journal", serde_json::json!({}))),
                    &guard
                )
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert_eq!(current_hash(&target), before);
        let auth_rows: i64 = target
            .db
            .query_row("SELECT count(*) FROM auth_registry", [], |r| r.get(0))
            .unwrap();
        assert_eq!(auth_rows, 0);
        let rows: i64 = target
            .db
            .query_row(
                "SELECT count(*) FROM vault_meta WHERE key='synthetic-watch-journal'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn cloud_apply_duration_deadline_at_commit_rolls_back_credentials_and_journal() {
        let source = vault();
        add(&source, "incoming", true);
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let target = vault();
        add(&target, "existing", false);
        let before = current_hash(&target);
        let calls = std::cell::Cell::new(0);
        let guard = || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(VaultError::WatchDurationElapsed)
            } else {
                Ok(())
            }
        };
        assert!(
            target
                .cloud_apply_guarded(
                    &snapshot,
                    Some(&before),
                    Some(("synthetic-watch-journal", serde_json::json!({}))),
                    &guard
                )
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert_eq!(current_hash(&target), before);
        let auth_rows: i64 = target
            .db
            .query_row("SELECT count(*) FROM auth_registry", [], |r| r.get(0))
            .unwrap();
        assert_eq!(auth_rows, 0);
        let rows: i64 = target
            .db
            .query_row(
                "SELECT count(*) FROM vault_meta WHERE key='synthetic-watch-journal'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn auth_transport_cloud_preserves_identity_bundle_and_deadlines() {
        let source = vault();
        paired(&source);
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, 2);
        let destination = vault();
        let expected = current_hash(&destination);
        destination
            .cloud_apply(&snapshot, Some(&expected), None)
            .unwrap();
        assert_eq!(
            source.export_auth_partition("default", "personal").unwrap(),
            destination
                .export_auth_partition("default", "personal")
                .unwrap()
        );
        assert_eq!(
            destination
                .resolve_auth_bundle(
                    "default",
                    "personal",
                    "synthetic-pair",
                    "synthetic-account",
                    "pair",
                    "https://api.example.test"
                )
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn auth_transport_cloud_rejects_legacy_overwrite_and_invalid_references_atomically() {
        let source = vault();
        paired(&source);
        let mut snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let destination = vault();
        let expected = current_hash(&destination);
        snapshot.auth_data.as_mut().unwrap().records[0].credential_name = "missing-key".into();
        assert!(
            destination
                .cloud_apply(&snapshot, Some(&expected), None)
                .is_err()
        );
        assert_eq!(destination.credential_count().unwrap(), 0);
        assert_eq!(current_hash(&destination), expected);

        let mut legacy = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        legacy.version = 1;
        legacy.auth_data = None;
        let before = current_hash(&source);
        assert!(source.cloud_apply(&legacy, Some(&before), None).is_err());
        assert_eq!(current_hash(&source), before);
    }

    #[test]
    fn auth_transport_cloud_rejects_cross_account_bundle_without_partial_credentials() {
        let source = vault();
        paired(&source);
        let mut snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        snapshot.auth_data.as_mut().unwrap().bundles[0].account = "different-account".into();
        let destination = vault();
        let expected = current_hash(&destination);
        assert!(
            destination
                .cloud_apply(&snapshot, Some(&expected), None)
                .is_err()
        );
        assert_eq!(destination.credential_count().unwrap(), 0);
        assert_eq!(current_hash(&destination), expected);
    }

    #[test]
    fn auth_transport_revoked_stale_bundle_recovers_but_cannot_resolve() {
        let source = vault();
        paired(&source);
        source.revoke_auth("default", "a-key").unwrap();
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let destination = vault();
        let expected = current_hash(&destination);
        destination
            .cloud_apply(&snapshot, Some(&expected), None)
            .unwrap();
        assert_eq!(
            source.export_auth_partition("default", "personal").unwrap(),
            destination
                .export_auth_partition("default", "personal")
                .unwrap()
        );
        assert!(
            destination
                .resolve_auth_bundle(
                    "default",
                    "personal",
                    "synthetic-pair",
                    "synthetic-account",
                    "pair",
                    "https://api.example.test"
                )
                .is_err()
        );
        assert!(
            destination
                .decrypt_credential_value_in_project("default", "a-key")
                .is_err()
        );
    }

    #[test]
    fn auth_transport_cloud_replaces_removed_bundle_graph_and_rolls_back_invalid_graph() {
        let target = vault();
        paired(&target);
        let original = target.export_auth_partition("default", "personal").unwrap();
        let mut snapshot = target
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let before = current_hash(&target);
        snapshot
            .credentials
            .retain(|credential| credential.name != "a-key");
        snapshot
            .auth_data
            .as_mut()
            .unwrap()
            .records
            .retain(|record| record.credential_name != "a-key");
        assert!(target.cloud_apply(&snapshot, Some(&before), None).is_err());
        assert_eq!(target.credential_count().unwrap(), 2);
        assert_eq!(
            target.export_auth_partition("default", "personal").unwrap(),
            original
        );
        snapshot.auth_data.as_mut().unwrap().bundles.clear();
        target.cloud_apply(&snapshot, Some(&before), None).unwrap();
        assert_eq!(target.credential_count().unwrap(), 1);
        assert!(
            target
                .list_auth_bundles("default", "personal")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            target
                .decrypt_credential_value_in_project("default", "b-key")
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn auth_transport_cloud_final_auth_deletion_retains_v2_tombstone() {
        let source = vault();
        paired(&source);
        let mut deletion = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let before = current_hash(&source);
        deletion.credentials.clear();
        deletion.auth_data = Some(AuthPartitionData::default());
        source.cloud_apply(&deletion, Some(&before), None).unwrap();
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.auth_data, Some(AuthPartitionData::default()));
        let destination = vault();
        paired(&destination);
        let before = current_hash(&destination);
        destination
            .cloud_apply(&snapshot, Some(&before), None)
            .unwrap();
        assert_eq!(destination.credential_count().unwrap(), 0);
        assert_eq!(
            destination
                .cloud_snapshot("default", "personal")
                .unwrap()
                .unwrap()
                .version,
            2
        );
    }

    #[test]
    fn auth_transport_cloud_missing_metadata_cannot_downgrade_unbundled_credentials() {
        let source = vault();
        paired(&source);
        let mut snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        snapshot.auth_data.as_mut().unwrap().bundles.clear();
        snapshot.auth_data.as_mut().unwrap().records.pop();
        let destination = vault();
        let before = current_hash(&destination);
        assert!(
            destination
                .cloud_apply(&snapshot, Some(&before), None)
                .is_err()
        );
        snapshot.auth_data.as_mut().unwrap().records.clear();
        assert!(
            destination
                .cloud_apply(&snapshot, Some(&before), None)
                .is_err()
        );
        assert_eq!(destination.credential_count().unwrap(), 0);
        assert_eq!(current_hash(&destination), before);
    }

    #[test]
    fn auth_transport_cloud_cannot_launder_revoked_identity_by_renaming() {
        let target = vault();
        paired(&target);
        target.revoke_auth("default", "a-key").unwrap();
        let mut snapshot = target
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let before = current_hash(&target);
        snapshot
            .credentials
            .iter_mut()
            .find(|credential| credential.name == "a-key")
            .unwrap()
            .name = "renamed-key".into();
        let auth_data = snapshot.auth_data.as_mut().unwrap();
        auth_data.bundles.clear();
        let record = auth_data
            .records
            .iter_mut()
            .find(|record| record.credential_name == "a-key")
            .unwrap();
        record.credential_name = "renamed-key".into();
        record.metadata.revoked_at = None;
        record.metadata.account = "replacement-account".into();
        assert!(target.cloud_apply(&snapshot, Some(&before), None).is_err());
        assert_eq!(current_hash(&target), before);
        assert!(
            target
                .get_credential_in_project("default", "renamed-key")
                .is_err()
        );
        assert!(
            target
                .decrypt_credential_value_in_project("default", "a-key")
                .is_err()
        );
    }

    #[test]
    fn auth_transport_project_missing_metadata_cannot_downgrade_unbundled_credentials() {
        let source = vault();
        paired(&source);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unbundled.wkbundle");
        let path = path.to_str().unwrap();
        crate::sharing::export_project(&source, "default", PASSPHRASE, path).unwrap();
        let mut payload: serde_json::Value =
            crate::bundle::read_encrypted_payload(b"WKPJ", path, PASSPHRASE).unwrap();
        let partition = &mut payload["payload"]["partitions"][0];
        partition["auth_data"]["bundles"] = serde_json::json!([]);
        partition["auth_data"]["records"]
            .as_array_mut()
            .unwrap()
            .pop();
        crate::bundle::write_encrypted_payload(b"WKPJ", &payload, PASSPHRASE, path).unwrap();
        let destination = vault();
        assert!(crate::sharing::import_project(&destination, path, PASSPHRASE).is_err());
        payload["payload"]["partitions"][0]["auth_data"]["records"] = serde_json::json!([]);
        crate::bundle::write_encrypted_payload(b"WKPJ", &payload, PASSPHRASE, path).unwrap();
        assert!(crate::sharing::import_project(&destination, path, PASSPHRASE).is_err());
        assert_eq!(destination.credential_count().unwrap(), 0);
    }

    #[test]
    fn auth_transport_cloud_rejects_material_replacement_under_retained_identity() {
        let target = vault();
        paired(&target);
        let before = current_hash(&target);
        let replacement = "synthetic-replacement-secret-canary";
        for change in 0..5 {
            let mut snapshot = target
                .cloud_snapshot("default", "personal")
                .unwrap()
                .unwrap();
            let incoming = snapshot
                .credentials
                .iter_mut()
                .find(|credential| credential.name == "a-key")
                .unwrap();
            match change {
                0 | 4 => incoming.value = replacement.into(),
                1 => incoming.credential_type = CredentialType::BearerToken,
                2 => incoming.hosts.push("different.example.test".into()),
                3 => incoming.origin = "https://different.example.test".into(),
                _ => unreachable!(),
            }
            if change == 4 {
                snapshot
                    .auth_data
                    .as_mut()
                    .unwrap()
                    .records
                    .iter_mut()
                    .find(|record| record.credential_name == "a-key")
                    .unwrap()
                    .metadata
                    .revision = Uuid::new_v4().to_string();
            }
            let error = target
                .cloud_apply(&snapshot, Some(&before), None)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("registered auth material cannot be replaced")
            );
            assert!(!error.to_string().contains(SECRET));
            assert!(!error.to_string().contains(replacement));
            assert_eq!(current_hash(&target), before);
            assert_eq!(
                target
                    .decrypt_credential_for_transfer("default", "a-key")
                    .unwrap(),
                SECRET
            );
        }
    }

    #[test]
    fn auth_transport_cloud_allows_token_and_policy_revision_without_material_change() {
        let target = vault();
        paired(&target);
        let mut snapshot = target
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        let before = current_hash(&target);
        snapshot
            .credentials
            .iter_mut()
            .find(|credential| credential.name == "a-key")
            .unwrap()
            .wisp_token = "wk_synthetic_rotated_auth".into();
        let metadata = &mut snapshot
            .auth_data
            .as_mut()
            .unwrap()
            .records
            .iter_mut()
            .find(|record| record.credential_name == "a-key")
            .unwrap()
            .metadata;
        metadata.revision = Uuid::new_v4().to_string();
        metadata.use_until = Some(Utc::now() + chrono::Duration::hours(1));
        target.cloud_apply(&snapshot, Some(&before), None).unwrap();
        assert_eq!(
            target
                .get_credential_in_project("default", "a-key")
                .unwrap()
                .wisp_token,
            "wk_synthetic_rotated_auth"
        );
        assert_eq!(
            target
                .decrypt_credential_for_transfer("default", "a-key")
                .unwrap(),
            SECRET
        );
        assert_eq!(
            target.export_auth_partition("default", "personal").unwrap(),
            snapshot.auth_data.unwrap()
        );
    }

    #[test]
    fn auth_transport_legacy_cloud_snapshot_remains_v1() {
        let source = vault();
        add(&source, "legacy-key", false);
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, 1);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert!(value.get("auth_data").is_none());
        let destination = vault();
        let expected = current_hash(&destination);
        destination
            .cloud_apply(&snapshot, Some(&expected), None)
            .unwrap();
        assert_eq!(
            destination
                .decrypt_credential_value_in_project("default", "legacy-key")
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn auth_transport_project_envelope_preserves_bundle_and_rejects_legacy_reader() {
        let source = vault();
        paired(&source);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("project.wkbundle");
        let path = path.to_str().unwrap();
        assert_eq!(
            crate::sharing::export_project(&source, "default", PASSPHRASE, path).unwrap(),
            2
        );
        assert!(
            !std::fs::read(path)
                .unwrap()
                .windows(SECRET.len())
                .any(|part| part == SECRET.as_bytes())
        );
        #[derive(Deserialize)]
        struct LegacyProject {
            #[serde(rename = "project")]
            _project: String,
        }
        assert!(
            crate::bundle::read_encrypted_payload::<LegacyProject>(b"WKPJ", path, PASSPHRASE)
                .is_err()
        );
        let destination = vault();
        let result = crate::sharing::import_project(&destination, path, PASSPHRASE).unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(
            source.export_auth_partition("default", "personal").unwrap(),
            destination
                .export_auth_partition("default", "personal")
                .unwrap()
        );
        let duplicate = vault();
        add(&duplicate, "b-key", false);
        assert!(crate::sharing::import_project(&duplicate, path, PASSPHRASE).is_err());
        assert_eq!(duplicate.credential_count().unwrap(), 1);
        assert!(
            duplicate
                .get_credential_in_project("default", "a-key")
                .is_err()
        );
    }

    #[test]
    fn auth_transport_single_revoked_preserves_metadata_omits_bundles_and_forbids_rebinding() {
        let source = vault();
        paired(&source);
        source.revoke_auth("default", "a-key").unwrap();
        let mut original = source.export_auth_partition("default", "personal").unwrap();
        original
            .records
            .retain(|record| record.credential_name == "a-key");
        original.bundles.clear();
        assert!(
            source
                .decrypt_credential_value_in_project("default", "a-key")
                .is_err()
        );
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("single.wkcred");
        let path = path.to_str().unwrap();
        crate::sharing::export_credential(&source, "a-key", PASSPHRASE, path).unwrap();
        #[derive(Deserialize)]
        struct LegacyCredential {
            #[serde(rename = "credential")]
            _credential: serde_json::Value,
        }
        assert!(
            crate::bundle::read_encrypted_payload::<LegacyCredential>(b"WKCR", path, PASSPHRASE)
                .is_err()
        );
        let destination = vault();
        assert!(
            crate::sharing::import_credential(&destination, path, PASSPHRASE, Some("other"), None)
                .is_err()
        );
        assert!(destination.get_project("other").is_err());
        assert!(
            crate::sharing::import_credential(&destination, path, PASSPHRASE, None, Some("other"))
                .is_err()
        );
        let result =
            crate::sharing::import_credential(&destination, path, PASSPHRASE, None, None).unwrap();
        assert_eq!(result.imported, 1);
        assert_eq!(
            original,
            destination
                .export_auth_partition("default", "personal")
                .unwrap()
        );
        assert!(
            destination
                .decrypt_credential_value_in_project("default", "a-key")
                .is_err()
        );
        assert_eq!(
            destination
                .decrypt_credential_for_transfer("default", "a-key")
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn auth_transport_partition_preserves_bundle_and_expired_credentials() {
        let source = vault();
        paired(&source);
        // Expiry is metadata, so recovery must still export and restore it.
        source.db.execute("UPDATE auth_registry SET metadata_json=json_set(metadata_json,'$.use_until','2000-01-01T00:00:00Z')", []).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("partition.wkbundle");
        let path = path.to_str().unwrap();
        crate::partition::export_partition(&source, "personal", PASSPHRASE, path).unwrap();
        #[derive(Deserialize)]
        struct LegacyPartition {
            #[serde(rename = "partition")]
            _partition: String,
        }
        assert!(
            crate::bundle::read_encrypted_payload::<LegacyPartition>(b"WKBX", path, PASSPHRASE)
                .is_err()
        );
        let destination = vault();
        assert_eq!(
            crate::partition::import_partition(&destination, path, PASSPHRASE)
                .unwrap()
                .imported,
            2
        );
        assert_eq!(
            source.export_auth_partition("default", "personal").unwrap(),
            destination
                .export_auth_partition("default", "personal")
                .unwrap()
        );
        assert!(
            destination
                .decrypt_credential_value_in_project("default", "a-key")
                .is_err()
        );
        assert!(
            destination
                .resolve_auth_bundle(
                    "default",
                    "personal",
                    "synthetic-pair",
                    "synthetic-account",
                    "pair",
                    "https://api.example.test"
                )
                .is_err()
        );
    }

    #[test]
    fn auth_transport_malformed_project_rolls_back_scope_and_credentials() {
        let source = vault();
        paired(&source);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("project.wkbundle");
        let path = path.to_str().unwrap();
        crate::sharing::export_project(&source, "default", PASSPHRASE, path).unwrap();
        let mut payload: serde_json::Value =
            crate::bundle::read_encrypted_payload(b"WKPJ", path, PASSPHRASE).unwrap();
        payload["payload"]["project"] = serde_json::json!("new-project");
        payload["payload"]["partitions"][0]["auth_data"]["records"][0]["credential_name"] =
            serde_json::json!("missing-key");
        crate::bundle::write_encrypted_payload(b"WKPJ", &payload, PASSPHRASE, path).unwrap();
        let destination = vault();
        assert!(crate::sharing::import_project(&destination, path, PASSPHRASE).is_err());
        assert!(destination.get_project("new-project").is_err());
        assert_eq!(destination.credential_count().unwrap(), 0);
    }
}
