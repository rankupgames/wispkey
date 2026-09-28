//! Authenticated cloud snapshots and atomic partition replacement.
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotCredential {
    pub name: String,
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

impl Vault {
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
                let value = self.decrypt_credential_value_in_project(project, &credential.name)?;
                Ok(SnapshotCredential {
                    name: credential.name,
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
        let snapshot = Snapshot {
            version: 1,
            project: project.to_owned(),
            partition: partition.name,
            description: partition.description,
            credentials,
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
        let key = self.ensure_unlocked()?;
        if snapshot.version != 1 || snapshot.project.is_empty() || snapshot.partition.is_empty() {
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
        tx.commit()?;
        Ok(hash)
    }
}
