//! Atomic owner-reviewed local import. Secret values never leave this boundary.

use super::*;
use ring::hmac;

/// Private keyed revision of the selected project's encrypted rows and scope.
/// This is never serialized or exposed as a low-entropy secret fingerprint.
impl Vault {
    pub(crate) fn local_import_fingerprint(&self, project: &str) -> Result<Vec<u8>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.ensure_unlocked()?);
        let mut hash = hmac::Context::with_key(&key);
        hash.update(b"wispkey-local-import-v1\0");
        hash.update(project.as_bytes());
        for sql in [
            "SELECT id,name,description,created_at,updated_at FROM projects WHERE name=?1 ORDER BY id",
            "SELECT p.id,p.name,p.description,p.created_at,p.updated_at FROM partitions p JOIN projects pr ON p.project_id=pr.id WHERE pr.name=?1 ORDER BY p.id",
            "SELECT c.id,c.name,c.credential_type,c.encrypted_value,c.wisp_token,c.hosts,c.tags,c.partition_id,c.origin,c.lifecycle_state,c.review_at,c.updated_at FROM credentials c JOIN partitions p ON c.partition_id=p.id JOIN projects pr ON p.project_id=pr.id WHERE pr.name=?1 ORDER BY c.id",
        ] {
            let mut statement = self.db.prepare(sql)?;
            let columns = statement.column_count();
            let mut rows = statement.query([project])?;
            while let Some(row) = rows.next()? {
                for column in 0..columns {
                    let value: Option<String> = row.get(column)?;
                    match value {
                        Some(value) => {
                            hash.update(&[1]);
                            hash.update(&(value.len() as u64).to_be_bytes());
                            hash.update(value.as_bytes());
                        }
                        None => hash.update(&[0]),
                    }
                }
            }
        }
        Ok(hash.sign().as_ref().to_vec())
    }

    pub(crate) fn commit_local_import(
        &self,
        session_revision: &str,
        fingerprint: &[u8],
        project: &str,
        writes: &[crate::local_import::ImportWrite<'_>],
        kept_ids: &[&str],
        check_sources: impl Fn() -> Result<()>,
    ) -> Result<Vec<Credential>> {
        self.with_current_operation_session(session_revision, || {
            if self.local_import_fingerprint(project)? != fingerprint {
                return Err(VaultError::AuthRejected(
                    "vault changed after import review",
                ));
            }
            check_sources()?;
            for id in kept_ids {
                self.ensure_auth_usable(id, false, None)?;
                let state: String = self.db.query_row(
                    "SELECT lifecycle_state FROM credentials WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )?;
                if state != LIFECYCLE_ACTIVE {
                    return Err(VaultError::AuthRejected(
                        "kept import credential is not usable",
                    ));
                }
            }
            if writes.is_empty() {
                return Ok(Vec::new());
            }
            match self.get_project(project) {
                Ok(_) => {}
                Err(VaultError::ProjectNotFound(_)) => {
                    self.create_project(project, "")?;
                }
                Err(error) => return Err(error),
            }
            let mut names = HashSet::new();
            let mut saved = Vec::with_capacity(writes.len());
            for write in writes {
                if !names.insert(write.name) {
                    return Err(VaultError::AuthRejected("duplicate import credential name"));
                }
                match self.get_partition_in_project(project, write.environment) {
                    Ok(_) => {}
                    Err(VaultError::PartitionNotFound(_)) => {
                        self.create_partition(write.environment, "", Some(project))?;
                    }
                    Err(error) => return Err(error),
                }
                let credential = if write.replace {
                    let credential = self.get_credential_in_project(project, write.name)?;
                    let partition = self.get_partition_in_project(project, write.environment)?;
                    if credential.partition_id.as_deref() != Some(partition.id.as_str())
                        || credential.lifecycle_state != LIFECYCLE_ACTIVE
                    {
                        return Err(VaultError::AuthRejected(
                            "import replacement scope is not usable",
                        ));
                    }
                    self.ensure_auth_usable(&credential.id, false, None)?;
                    value_update::validate_value(&credential.credential_type, write.value)?;
                    let ciphertext =
                        self.encrypt_bytes(self.ensure_unlocked()?, write.value.as_bytes())?;
                    let prefix = if self.auth_metadata_for_id(&credential.id)?.is_some() {
                        auth::CIPHERTEXT_PREFIX
                    } else {
                        ""
                    };
                    self.db.execute(
                        "UPDATE credentials SET encrypted_value=?1,updated_at=?2 WHERE id=?3",
                        params![
                            format!("{prefix}{}", BASE64.encode(ciphertext)),
                            Utc::now().to_rfc3339(),
                            credential.id
                        ],
                    )?;
                    self.ensure_auth_usable(&credential.id, false, None)?;
                    self.get_credential_in_project(project, write.name)?
                } else {
                    self.insert_transport_credential(AddCredentialRequest {
                        name: write.name,
                        credential_type: CredentialType::ApiKey,
                        value: write.value,
                        description: None,
                        hosts: Some(write.hosts),
                        tags: Some("imported"),
                        partition: Some(write.environment),
                        project: Some(project),
                        origin: None,
                        lifecycle_state: None,
                        review_at: None,
                    })?
                };
                crate::audit::try_log_event(
                    &self.db,
                    if write.replace {
                        "CredentialValueReplaced"
                    } else {
                        "CredentialAdded"
                    },
                    Some(write.name),
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    Some(project),
                )?;
                saved.push(credential);
            }
            for credential in &saved {
                self.ensure_auth_usable(&credential.id, false, None)?;
            }
            for id in kept_ids {
                self.ensure_auth_usable(id, false, None)?;
            }
            check_sources()?;
            Ok(saved)
        })
    }
}
