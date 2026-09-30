//! Opt-in authentication metadata and explicit, partition-local credential bundles.
//!
//! Labels describe owner-declared identity; they are not provider verification.
//! A bundle is a selector, never an authorization grant.
use super::*;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};

pub(crate) const CIPHERTEXT_PREFIX: &str = "wka1:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderExpiry {
    Unknown,
    NonExpiring,
    ExpiresAt { at: DateTime<Utc> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRegistration {
    pub provider: String,
    pub account: String,
    pub origins: Vec<String>,
    pub provider_expiry: ProviderExpiry,
    pub use_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthMetadata {
    pub id: String,
    pub revision: String,
    pub provider: String,
    pub account: String,
    pub origins: Vec<String>,
    pub provider_expiry: ProviderExpiry,
    pub use_until: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthInventoryItem {
    pub name: String,
    pub project: String,
    pub partition: String,
    pub credential_type: String,
    /// None explicitly means legacy/unregistered, not non-expiring.
    pub auth: Option<AuthMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthReference {
    pub auth_id: String,
    pub revision: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthAlternative {
    pub name: String,
    /// Every member is required together. No member is optional.
    pub members: Vec<AuthReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthBundle {
    pub name: String,
    pub project: String,
    pub partition: String,
    pub account: String,
    pub alternatives: Vec<AuthAlternative>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedAuthMember {
    pub role: String,
    pub credential_name: String,
    pub wisp_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableAuthRecord {
    pub credential_name: String,
    pub metadata: AuthMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthPartitionData {
    pub records: Vec<PortableAuthRecord>,
    pub bundles: Vec<AuthBundle>,
}

fn rejected(reason: &'static str) -> VaultError {
    VaultError::AuthRejected(reason)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// Canonical HTTPS origin, with no userinfo, path, query, or fragment.
pub fn normalize_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| rejected("invalid auth origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(rejected("invalid auth origin"));
    }
    Ok(url.origin().ascii_serialization())
}

impl AuthMetadata {
    /// Validates stored/transport metadata without requiring it to be usable now.
    pub fn validate(&self) -> Result<()> {
        if !canonical_uuid(&self.id)
            || !canonical_uuid(&self.revision)
            || !valid_label(&self.provider)
            || !valid_label(&self.account)
            || self.origins.is_empty()
            || self.origins.len() > 64
            || (self.provider_expiry == ProviderExpiry::Unknown && self.use_until.is_none())
        {
            return Err(rejected("invalid auth metadata"));
        }
        let mut seen = HashSet::new();
        for origin in &self.origins {
            if normalize_origin(origin)? != *origin || !seen.insert(origin) {
                return Err(rejected("invalid auth origin"));
            }
        }
        Ok(())
    }

    /// Time is injected so exact boundary behavior is testable. Deadlines are exclusive.
    pub fn ensure_usable_at(&self, now: DateTime<Utc>, delegated: bool) -> Result<()> {
        self.validate()?;
        if self.revoked_at.is_some() {
            return Err(rejected("auth locally revoked"));
        }
        if self.use_until.is_some_and(|at| now >= at)
            || matches!(self.provider_expiry, ProviderExpiry::ExpiresAt { at } if now >= at)
        {
            return Err(rejected("auth expired"));
        }
        if delegated && self.use_until.is_none() {
            return Err(rejected("delegated auth requires a local deadline"));
        }
        Ok(())
    }
}

impl AuthBundle {
    pub fn validate(&self) -> Result<()> {
        if !valid_label(&self.name)
            || !valid_label(&self.project)
            || !valid_label(&self.partition)
            || !valid_label(&self.account)
            || self.alternatives.is_empty()
            || self.alternatives.len() > 64
        {
            return Err(rejected("invalid auth bundle"));
        }
        let mut alternatives = HashSet::new();
        for alternative in &self.alternatives {
            if !valid_label(&alternative.name)
                || !alternatives.insert(&alternative.name)
                || alternative.members.is_empty()
                || alternative.members.len() > 64
            {
                return Err(rejected("invalid auth alternative"));
            }
            let mut ids = HashSet::new();
            let mut roles = HashSet::new();
            for member in &alternative.members {
                if !canonical_uuid(&member.auth_id)
                    || !canonical_uuid(&member.revision)
                    || !valid_label(&member.role)
                    || !ids.insert(&member.auth_id)
                    || !roles.insert(&member.role)
                {
                    return Err(rejected("invalid auth member"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn create_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth_registry (
            credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
            auth_id TEXT UNIQUE NOT NULL,
            metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_bundles (
            partition_id TEXT NOT NULL REFERENCES partitions(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            bundle_json TEXT NOT NULL,
            PRIMARY KEY(partition_id, name)
        );",
    )?;
    Ok(())
}

impl Vault {
    pub fn register_auth(
        &self,
        project: &str,
        name: &str,
        request: AuthRegistration,
    ) -> Result<AuthMetadata> {
        self.ensure_unlocked()?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let credential = self.get_credential_in_project(project, name)?;
        let previous = self.auth_metadata_for_id(&credential.id)?;
        if previous.as_ref().is_some_and(|value| {
            value.provider != request.provider || value.account != request.account
        }) {
            return Err(rejected("registered auth identity cannot change"));
        }

        let mut origins = request
            .origins
            .iter()
            .map(|value| normalize_origin(value))
            .collect::<Result<Vec<_>>>()?;
        origins.sort();
        origins.dedup();
        let metadata = AuthMetadata {
            id: previous
                .as_ref()
                .map(|value| value.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            revision: Uuid::new_v4().to_string(),
            provider: request.provider,
            account: request.account,
            origins,
            provider_expiry: request.provider_expiry,
            use_until: request.use_until,
            revoked_at: previous.and_then(|value| value.revoked_at),
        };
        metadata.validate()?;
        self.validate_auth_credential(&credential, &metadata)?;
        self.write_auth_metadata(&credential.id, &metadata)?;
        crate::audit::try_log_event(
            &self.db,
            "AuthRegistered",
            Some(name),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(project),
        )?;
        tx.commit()?;
        Ok(metadata)
    }

    pub fn revoke_auth(&self, project: &str, name: &str) -> Result<()> {
        self.ensure_unlocked()?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let credential = self.get_credential_in_project(project, name)?;
        let mut metadata = self
            .auth_metadata_for_id(&credential.id)?
            .ok_or_else(|| rejected("auth is not registered"))?;
        if metadata.revoked_at.is_none() {
            metadata.revoked_at = Some(Utc::now());
            metadata.revision = Uuid::new_v4().to_string();
            self.write_auth_metadata(&credential.id, &metadata)?;
            crate::audit::try_log_event(
                &self.db,
                "AuthRevoked",
                Some(name),
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                Some(project),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_auth_inventory(&self, project: &str) -> Result<Vec<AuthInventoryItem>> {
        self.ensure_unlocked()?;
        self.list_credentials_in_project(project)?
            .into_iter()
            .map(|credential| {
                let partition = self.get_partition_by_id(
                    credential
                        .partition_id
                        .as_deref()
                        .ok_or_else(|| rejected("auth placement unavailable"))?,
                )?;
                Ok(AuthInventoryItem {
                    auth: self.auth_metadata_for_id(&credential.id)?,
                    name: credential.name,
                    project: project.to_owned(),
                    partition: partition.name,
                    credential_type: credential.credential_type.display_name().to_owned(),
                })
            })
            .collect()
    }

    pub(crate) fn auth_metadata_for_id(&self, id: &str) -> Result<Option<AuthMetadata>> {
        let row: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT auth_id,metadata_json FROM auth_registry WHERE credential_id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(id, json)| {
            let metadata: AuthMetadata =
                serde_json::from_str(&json).map_err(|_| rejected("invalid auth metadata"))?;
            metadata.validate()?;
            if metadata.id != id {
                return Err(rejected("invalid auth reference"));
            }
            Ok(metadata)
        })
        .transpose()
    }

    fn write_auth_metadata(&self, credential_id: &str, metadata: &AuthMetadata) -> Result<()> {
        let json =
            serde_json::to_string(metadata).map_err(|_| rejected("invalid auth metadata"))?;
        self.db.execute("INSERT INTO auth_registry(credential_id,auth_id,metadata_json) VALUES(?1,?2,?3) ON CONFLICT(credential_id) DO UPDATE SET auth_id=excluded.auth_id,metadata_json=excluded.metadata_json", params![credential_id,metadata.id,json])?;
        self.db.execute("UPDATE credentials SET encrypted_value=?1 || encrypted_value WHERE id=?2 AND substr(encrypted_value,1,5)!=?1", params![CIPHERTEXT_PREFIX,credential_id])?;
        self.db.execute("INSERT OR IGNORE INTO vault_meta(key,value) SELECT 'auth_partition_v1:' || partition_id,'1' FROM credentials WHERE id=?1", [credential_id])?;
        Ok(())
    }

    fn validate_auth_credential(
        &self,
        credential: &Credential,
        metadata: &AuthMetadata,
    ) -> Result<()> {
        // Registry origins narrow existing host restrictions. They never replace them.
        for origin in &metadata.origins {
            let url = url::Url::parse(origin).map_err(|_| rejected("invalid auth origin"))?;
            let host = url
                .host_str()
                .ok_or_else(|| rejected("invalid auth origin"))?;
            if !credential.hosts.is_empty()
                && !credential.hosts.iter().any(|pattern| {
                    if credential.credential_type == CredentialType::WebsiteLogin {
                        // Generated logins store the exact authority, including any
                        // non-default port, rather than a generic hostname glob.
                        pattern == &origin_host(origin)
                    } else {
                        glob_match::glob_match(
                            &pattern.to_ascii_lowercase(),
                            &host.to_ascii_lowercase(),
                        )
                    }
                })
            {
                return Err(rejected("auth origin exceeds credential scope"));
            }
            if credential.credential_type == CredentialType::WebsiteLogin
                && credential.origin != *origin
            {
                return Err(rejected("auth origin exceeds login scope"));
            }
        }
        Ok(())
    }

    pub(crate) fn ensure_auth_usable(
        &self,
        credential_id: &str,
        delegated: bool,
        origin: Option<&str>,
    ) -> Result<()> {
        let metadata = self.auth_metadata_for_id(credential_id)?;
        let encoded: String = self.db.query_row(
            "SELECT encrypted_value FROM credentials WHERE id=?1",
            [credential_id],
            |row| row.get(0),
        )?;
        if encoded.starts_with(CIPHERTEXT_PREFIX) != metadata.is_some() {
            return Err(rejected("auth metadata unavailable"));
        }
        if let Some(metadata) = metadata {
            metadata.ensure_usable_at(Utc::now(), delegated)?;
            if let Some(origin) = origin {
                let origin = normalize_origin(origin)?;
                if !metadata.origins.contains(&origin) {
                    return Err(rejected("auth origin denied"));
                }
            }
        }
        Ok(())
    }

    /// Metadata-only last-moment release check; does not consume policy rate limits.
    pub(crate) fn recheck_auth_token(
        &self,
        credential_id: &str,
        token: &str,
        origin: &str,
    ) -> Result<()> {
        let current: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=?1 AND wisp_token=?2)",
            params![credential_id, token],
            |row| row.get(0),
        )?;
        if !current {
            return Err(rejected("credential changed before release"));
        }
        self.ensure_auth_usable(credential_id, true, Some(origin))
    }

    /// Decode a storage marker only when its policy is present and valid.
    pub(crate) fn decode_auth_ciphertext(
        &self,
        credential_id: &str,
        encoded: &str,
    ) -> Result<Vec<u8>> {
        let metadata = self.auth_metadata_for_id(credential_id)?;
        if encoded.starts_with(CIPHERTEXT_PREFIX) != metadata.is_some() {
            return Err(rejected("auth metadata unavailable"));
        }
        BASE64
            .decode(encoded.strip_prefix(CIPHERTEXT_PREFIX).unwrap_or(encoded))
            .map_err(|_| rejected("credential ciphertext invalid"))
    }

    pub fn set_auth_bundle(&self, bundle: &AuthBundle) -> Result<()> {
        self.ensure_unlocked()?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.store_auth_bundle(bundle, false)?;
        crate::audit::try_log_event(
            &self.db,
            "AuthBundleSet",
            None,
            None,
            None,
            Some(&bundle.name),
            None,
            None,
            false,
            None,
            Some(&bundle.project),
        )?;
        tx.commit()?;
        Ok(())
    }

    fn store_auth_bundle(&self, bundle: &AuthBundle, allow_stale: bool) -> Result<()> {
        bundle.validate()?;
        let partition = self.get_partition_in_project(&bundle.project, &bundle.partition)?;
        for alternative in &bundle.alternatives {
            for member in &alternative.members {
                self.resolve_auth_reference(bundle, member, allow_stale)?;
            }
        }
        let json = serde_json::to_string(bundle).map_err(|_| rejected("invalid auth bundle"))?;
        self.db.execute("INSERT INTO auth_bundles(partition_id,name,bundle_json) VALUES(?1,?2,?3) ON CONFLICT(partition_id,name) DO UPDATE SET bundle_json=excluded.bundle_json",params![partition.id,bundle.name,json])?;
        Ok(())
    }

    pub fn list_auth_bundles(&self, project: &str, partition: &str) -> Result<Vec<AuthBundle>> {
        self.ensure_unlocked()?;
        let scope = self.get_partition_in_project(project, partition)?;
        let mut stmt = self.db.prepare(
            "SELECT name,bundle_json FROM auth_bundles WHERE partition_id=?1 ORDER BY name",
        )?;
        stmt.query_map([scope.id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (name, json) = row?;
            let bundle: AuthBundle =
                serde_json::from_str(&json).map_err(|_| rejected("invalid auth bundle"))?;
            bundle.validate()?;
            if bundle.project != project || bundle.partition != partition || bundle.name != name {
                return Err(rejected("auth bundle scope mismatch"));
            }
            Ok(bundle)
        })
        .collect()
    }

    fn resolve_auth_reference(
        &self,
        bundle: &AuthBundle,
        member: &AuthReference,
        allow_stale: bool,
    ) -> Result<(Credential, AuthMetadata)> {
        let found:Option<(String,String,String)>=self.db.query_row("SELECT c.name,pr.name,p.name FROM auth_registry a JOIN credentials c ON c.id=a.credential_id JOIN partitions p ON p.id=c.partition_id JOIN projects pr ON pr.id=p.project_id WHERE a.auth_id=?1",[&member.auth_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let (name, project, partition) =
            found.ok_or_else(|| rejected("auth member unavailable"))?;
        if project != bundle.project || partition != bundle.partition {
            return Err(rejected("auth member scope mismatch"));
        }
        let credential = self.get_credential_in_project(&project, &name)?;
        let metadata = self
            .auth_metadata_for_id(&credential.id)?
            .ok_or_else(|| rejected("auth member unavailable"))?;
        if (!allow_stale && metadata.revision != member.revision)
            || metadata.account != bundle.account
        {
            return Err(rejected("auth member changed or account mismatch"));
        }
        self.validate_auth_credential(&credential, &metadata)?;
        Ok((credential, metadata))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_auth_bundle(
        &self,
        project: &str,
        partition: &str,
        name: &str,
        account: &str,
        alternative: &str,
        origin: &str,
    ) -> Result<Vec<ResolvedAuthMember>> {
        self.ensure_unlocked()?;
        let tx = self.db.unchecked_transaction()?;
        let bundle = self
            .list_auth_bundles(project, partition)?
            .into_iter()
            .find(|bundle| bundle.name == name)
            .ok_or_else(|| rejected("auth bundle unavailable"))?;
        if bundle.account != account {
            return Err(rejected("auth account mismatch"));
        }
        let choice = bundle
            .alternatives
            .iter()
            .find(|choice| choice.name == alternative)
            .ok_or_else(|| rejected("explicit auth alternative required"))?;
        let origin = normalize_origin(origin)?;
        let mut result = Vec::new();
        for member in &choice.members {
            let (credential, metadata) = self.resolve_auth_reference(&bundle, member, false)?;
            metadata.ensure_usable_at(Utc::now(), true)?;
            self.ensure_auth_usable(&credential.id, true, Some(&origin))?;
            if credential.lifecycle_state == LIFECYCLE_ARCHIVED {
                return Err(rejected("auth credential archived"));
            }
            result.push(ResolvedAuthMember {
                role: member.role.clone(),
                credential_name: credential.name,
                wisp_token: credential.wisp_token,
            });
        }
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn ensure_auth_unreferenced(
        &self,
        project: &str,
        credential: &Credential,
    ) -> Result<()> {
        if let Some(metadata) = self.auth_metadata_for_id(&credential.id)? {
            let partition = self.get_partition_by_id(
                credential
                    .partition_id
                    .as_deref()
                    .ok_or_else(|| rejected("auth placement unavailable"))?,
            )?;
            for bundle in self.list_auth_bundles(project, &partition.name)? {
                if bundle
                    .alternatives
                    .iter()
                    .flat_map(|alternative| &alternative.members)
                    .any(|member| member.auth_id == metadata.id)
                {
                    return Err(rejected("credential is referenced by an auth bundle"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn auth_partition_managed(&self, project: &str, partition: &str) -> Result<bool> {
        let scope = self.get_partition_in_project(project, partition)?;
        let exists = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_meta WHERE key=?1)",
            [format!("auth_partition_v1:{}", scope.id)],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub(crate) fn export_auth_partition(
        &self,
        project: &str,
        partition: &str,
    ) -> Result<AuthPartitionData> {
        let credentials = self.list_credentials_in_partition_for_project(project, partition)?;
        let mut records = Vec::new();
        for credential in credentials {
            if let Some(metadata) = self.auth_metadata_for_id(&credential.id)? {
                records.push(PortableAuthRecord {
                    credential_name: credential.name,
                    metadata,
                });
            }
        }
        Ok(AuthPartitionData {
            records,
            bundles: self.list_auth_bundles(project, partition)?,
        })
    }

    /// Replaces metadata only under the caller's transaction after credential import.
    /// Missing members and changed identities abort the whole import. Stale revisions
    /// are preserved for recovery and remain unusable until explicitly rebound.
    pub(crate) fn import_auth_partition(
        &self,
        project: &str,
        partition: &str,
        data: &AuthPartitionData,
    ) -> Result<()> {
        self.ensure_unlocked()?;
        if self.db.is_autocommit() {
            return Err(rejected("auth import requires transaction"));
        }
        let scope = self.get_partition_in_project(project, partition)?;
        self.db.execute(
            "INSERT OR IGNORE INTO vault_meta(key,value) VALUES(?1,'1')",
            [format!("auth_partition_v1:{}", scope.id)],
        )?;
        let mut names = HashSet::new();
        let mut ids = HashSet::new();
        for record in &data.records {
            record.metadata.validate()?;
            if !names.insert(&record.credential_name) || !ids.insert(&record.metadata.id) {
                return Err(rejected("duplicate auth reference"));
            }
            let credential = self.get_credential_in_project(project, &record.credential_name)?;
            if credential.partition_id.as_deref() != Some(&scope.id) {
                return Err(rejected("auth member scope mismatch"));
            }
            self.validate_auth_credential(&credential, &record.metadata)?;
            if let Some(previous) = self.auth_metadata_for_id(&credential.id)? {
                if previous.id != record.metadata.id
                    || previous.account != record.metadata.account
                    || previous.provider != record.metadata.provider
                {
                    return Err(rejected("registered auth identity cannot change"));
                }
                if previous.revoked_at.is_some() && record.metadata.revoked_at.is_none() {
                    return Err(rejected("auth revocation cannot be cleared"));
                }
            }

            let existing: Option<String> = self
                .db
                .query_row(
                    "SELECT credential_id FROM auth_registry WHERE auth_id=?1",
                    [&record.metadata.id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some_and(|id| id != credential.id) {
                return Err(rejected("auth identity conflict"));
            }
        }
        // Never turn a registered credential back into an unregistered one.
        for existing in self.export_auth_partition(project, partition)?.records {
            if !names.contains(&existing.credential_name) {
                return Err(rejected("auth metadata cannot be removed"));
            }
        }
        self.db.execute(
            "DELETE FROM auth_bundles WHERE partition_id=?1",
            [&scope.id],
        )?;
        for record in &data.records {
            let credential = self.get_credential_in_project(project, &record.credential_name)?;
            self.write_auth_metadata(&credential.id, &record.metadata)?;
        }
        let mut bundle_names = HashSet::new();
        for bundle in &data.bundles {
            if bundle.project != project
                || bundle.partition != partition
                || !bundle_names.insert(&bundle.name)
            {
                return Err(rejected("auth bundle scope mismatch"));
            }
            self.store_auth_bundle(bundle, true)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn vault() -> Vault {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        let now = Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO projects VALUES('default','default','',?1,?1)",
            [&now],
        )
        .unwrap();
        db.execute(
            "INSERT INTO partitions VALUES('personal','personal','','default',?1,?1)",
            [&now],
        )
        .unwrap();
        Vault {
            db,
            master_key: Some([42; 32]),
            session_timeout_override: None,
        }
    }
    fn add(vault: &Vault, name: &str) -> Credential {
        vault
            .add_credential(
                AddCredentialRequest::new(name, CredentialType::ApiKey, "synthetic-auth-canary")
                    .hosts(Some("api.example.com"))
                    .project(Some("default")),
            )
            .unwrap()
    }
    fn registration() -> AuthRegistration {
        AuthRegistration {
            provider: "example".into(),
            account: "work".into(),
            origins: vec!["https://api.example.com".into()],
            provider_expiry: ProviderExpiry::Unknown,
            use_until: Some(Utc::now() + Duration::hours(1)),
        }
    }
    fn bundle(metadata: &AuthMetadata) -> AuthBundle {
        AuthBundle {
            name: "service".into(),
            project: "default".into(),
            partition: "personal".into(),
            account: "work".into(),
            alternatives: vec![AuthAlternative {
                name: "api".into(),
                members: vec![AuthReference {
                    auth_id: metadata.id.clone(),
                    revision: metadata.revision.clone(),
                    role: "api-token".into(),
                }],
            }],
        }
    }

    #[test]
    fn malformed_matching_token_is_not_reported_as_missing() {
        let vault = vault();
        let credential = add(&vault, "key");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        vault
            .db
            .execute(
                "UPDATE credentials SET credential_type='malformed' WHERE id=?1",
                [&credential.id],
            )
            .unwrap();
        assert!(matches!(
            vault.lookup_by_wisp_token(&credential.wisp_token),
            Err(VaultError::Database(_))
        ));
        assert!(matches!(
            vault.lookup_by_wisp_token("wk_absent_synthetic"),
            Err(VaultError::CredentialNotFound(_))
        ));
    }

    #[test]
    fn final_token_release_rechecks_expiry_revocation_and_rotation() {
        let vault = vault();
        let credential = add(&vault, "key");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        assert!(
            vault
                .recheck_auth_token(
                    &credential.id,
                    &credential.wisp_token,
                    "https://api.example.com"
                )
                .is_ok()
        );
        vault
            .rotate_wisp_token_in_project("default", "key")
            .unwrap();
        assert!(
            vault
                .recheck_auth_token(
                    &credential.id,
                    &credential.wisp_token,
                    "https://api.example.com"
                )
                .is_err()
        );
        let token = vault
            .get_credential_in_project("default", "key")
            .unwrap()
            .wisp_token;
        vault.revoke_auth("default", "key").unwrap();
        assert!(
            vault
                .recheck_auth_token(&credential.id, &token, "https://api.example.com")
                .is_err()
        );
    }

    #[test]
    fn alternate_uuid_spellings_cannot_alias_auth_identities() {
        let vault = vault();
        add(&vault, "key");
        let mut metadata = vault
            .register_auth("default", "key", registration())
            .unwrap();
        metadata.id = format!("urn:uuid:{}", metadata.id);
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn deadlines_are_exclusive_and_earliest_wins_without_wall_clock_sleep() {
        let vault = vault();
        add(&vault, "key");
        let now = Utc::now();
        let mut metadata = vault
            .register_auth("default", "key", registration())
            .unwrap();
        metadata.provider_expiry = ProviderExpiry::ExpiresAt { at: now };
        metadata.use_until = Some(now + Duration::seconds(1));
        assert!(
            metadata
                .ensure_usable_at(now - Duration::nanoseconds(1), true)
                .is_ok()
        );
        assert!(metadata.ensure_usable_at(now, true).is_err());
        assert!(
            metadata
                .ensure_usable_at(now + Duration::nanoseconds(1), true)
                .is_err()
        );
        metadata.provider_expiry = ProviderExpiry::NonExpiring;
        metadata.use_until = Some(now);
        assert!(
            metadata
                .ensure_usable_at(now - Duration::nanoseconds(1), true)
                .is_ok()
        );
        assert!(metadata.ensure_usable_at(now, true).is_err());
        metadata.use_until = None;
        assert!(metadata.ensure_usable_at(now, false).is_ok());
        assert!(metadata.ensure_usable_at(now, true).is_err());
        metadata.provider_expiry = ProviderExpiry::Unknown;
        assert!(metadata.ensure_usable_at(now, false).is_err());
    }

    #[test]
    fn expiry_and_revocation_guard_plaintext_and_token_release_but_allow_encrypted_recovery() {
        let vault = vault();
        let credential = add(&vault, "key");
        let mut request = registration();
        request.use_until = Some(Utc::now() - Duration::seconds(1));
        vault.register_auth("default", "key", request).unwrap();
        for error in [
            vault
                .decrypt_credential_value_in_project("default", "key")
                .unwrap_err(),
            vault
                .lookup_by_wisp_token(&credential.wisp_token)
                .unwrap_err(),
        ] {
            assert_eq!(error.to_string(), "auth expired");
            assert!(!error.to_string().contains("synthetic-auth-canary"));
            assert!(!error.to_string().contains(&credential.wisp_token));
        }
        assert_eq!(
            vault
                .decrypt_credential_for_transfer("default", "key")
                .unwrap(),
            "synthetic-auth-canary"
        );
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        assert!(
            vault
                .lookup_auth_token(
                    &credential.wisp_token,
                    true,
                    Some("https://api.example.com")
                )
                .is_ok()
        );
        vault.revoke_auth("default", "key").unwrap();
        assert!(
            vault
                .decrypt_credential_value_in_project("default", "key")
                .is_err()
        );
        assert!(vault.lookup_by_wisp_token(&credential.wisp_token).is_err());
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        assert!(
            vault.lookup_by_wisp_token(&credential.wisp_token).is_err(),
            "re-registration must not clear revocation"
        );
    }

    #[test]
    fn website_login_registration_keeps_canonical_authority() {
        for input in [
            "https://Jobs.Example.com:443",
            "https://127.0.0.1:8443",
            "https://[::1]:8443",
        ] {
            let vault = vault();
            let credential = vault
                .generate_website_login(GenerateWebsiteLoginRequest {
                    name: "login",
                    username: "synthetic-user",
                    url: input,
                    project: Some("default"),
                    partition: None,
                    review_at: None,
                    length: None,
                    symbols: true,
                })
                .unwrap();
            let mut request = registration();
            request.origins = vec![input.into()];
            let auth = vault.register_auth("default", "login", request).unwrap();
            assert_eq!(auth.origins, vec![credential.origin.clone()]);
            assert_eq!(credential.hosts, vec![origin_host(&credential.origin)]);
        }
    }

    #[test]
    fn website_login_registration_preserves_exact_nondefault_port() {
        let vault = vault();
        let origin = "https://jobs.example.com:8443";
        let credential = vault
            .generate_website_login(GenerateWebsiteLoginRequest {
                name: "login",
                username: "synthetic-user",
                url: origin,
                project: Some("default"),
                partition: None,
                review_at: None,
                length: None,
                symbols: true,
            })
            .unwrap();
        assert_eq!(credential.hosts, vec!["jobs.example.com:8443"]);
        let mut request = registration();
        request.origins = vec![origin.into()];
        let metadata = vault
            .register_auth("default", "login", request.clone())
            .unwrap();
        assert_eq!(metadata.origins, vec![origin]);
        assert!(
            vault
                .lookup_auth_token(&credential.wisp_token, true, Some(origin))
                .is_ok()
        );
        for denied in [
            "https://jobs.example.com",
            "https://jobs.example.com:443",
            "https://jobs.example.com:8444",
            "https://other.example.com:8443",
            "http://jobs.example.com:8443",
            "https://user:pass@jobs.example.com:8443",
            "https://jobs.example.com:65536",
            "https://jobs.example.com:-1",
            "https://jobs.example.com:8443/path",
            "https://jobs.example.com:8443?x=1",
            "https://jobs.example.com:8443#fragment",
        ] {
            request.origins = vec![denied.into()];
            assert!(
                vault
                    .register_auth("default", "login", request.clone())
                    .is_err(),
                "{denied}"
            );
            assert!(
                vault
                    .lookup_auth_token(&credential.wisp_token, true, Some(denied))
                    .is_err(),
                "{denied}"
            );
        }
        assert_eq!(
            vault.auth_metadata_for_id(&credential.id).unwrap().unwrap(),
            metadata
        );
        // A matching login origin cannot override a narrower/corrupt stored host scope.
        vault
            .db
            .execute(
                "UPDATE credentials SET hosts='other.example.com:8443' WHERE id=?1",
                [&credential.id],
            )
            .unwrap();
        request.origins = vec![origin.into()];
        assert!(vault.register_auth("default", "login", request).is_err());
    }

    #[test]
    fn destination_origin_checks_scheme_port_and_host_without_widening_member_hosts() {
        let vault = vault();
        let credential = add(&vault, "key");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        for origin in [
            "http://api.example.com",
            "https://api.example.com:444",
            "https://evil.example.com",
            "https://api.example.com@evil.example.com",
            "https://api.example.com/path",
            "https://api.example.com?canary=secret",
        ] {
            assert!(
                vault
                    .lookup_auth_token(&credential.wisp_token, true, Some(origin))
                    .is_err(),
                "{origin}"
            );
        }
        let mut request = registration();
        request.origins = vec!["https://evil.example.com".into()];
        assert!(vault.register_auth("default", "key", request).is_err());
        assert!(
            vault
                .lookup_auth_token(
                    &credential.wisp_token,
                    true,
                    Some("https://api.example.com:443")
                )
                .is_ok()
        );
    }

    #[test]
    fn missing_registry_never_downgrades_marked_ciphertext_and_legacy_decoder_fails() {
        let vault = vault();
        let credential = add(&vault, "key");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        let encoded: String = vault
            .db
            .query_row(
                "SELECT encrypted_value FROM credentials WHERE id=?1",
                [&credential.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(encoded.starts_with(CIPHERTEXT_PREFIX));
        assert!(
            BASE64.decode(&encoded).is_err(),
            "old release binaries cannot decode registered material"
        );
        vault.db.execute("DELETE FROM auth_registry", []).unwrap();
        assert!(vault.lookup_by_wisp_token(&credential.wisp_token).is_err());
        assert!(
            vault
                .decrypt_credential_value_in_project("default", "key")
                .is_err()
        );
        assert!(
            vault
                .decrypt_credential_for_transfer("default", "key")
                .is_err()
        );
    }

    #[test]
    fn bundle_account_scope_revision_and_all_required_members_fail_closed() {
        let vault = vault();
        add(&vault, "key");
        add(&vault, "second");
        let metadata = vault
            .register_auth("default", "key", registration())
            .unwrap();
        let second = vault
            .register_auth("default", "second", registration())
            .unwrap();
        let mut bundle = bundle(&metadata);
        bundle.alternatives[0].members.push(AuthReference {
            auth_id: second.id,
            revision: second.revision,
            role: "required".into(),
        });
        vault.set_auth_bundle(&bundle).unwrap();
        let resolve = |account: &str, alternative: &str| {
            vault.resolve_auth_bundle(
                "default",
                "personal",
                "service",
                account,
                alternative,
                "https://api.example.com",
            )
        };
        assert_eq!(resolve("work", "api").unwrap().len(), 2);
        assert!(resolve("personal", "api").is_err());
        assert!(resolve("work", "").is_err());
        assert!(
            vault
                .remove_credential_in_project("default", "key")
                .is_err()
        );
        vault.revoke_auth("default", "second").unwrap();
        assert!(resolve("work", "api").is_err());
        let data = vault.export_auth_partition("default", "personal").unwrap();
        let tx = vault.db.unchecked_transaction().unwrap();
        vault
            .import_auth_partition("default", "personal", &data)
            .unwrap();
        tx.commit().unwrap();
        assert!(
            resolve("work", "api").is_err(),
            "stale reference remains unusable after recovery"
        );
        bundle.alternatives[0].members[0].auth_id = Uuid::new_v4().to_string();
        assert!(vault.set_auth_bundle(&bundle).is_err());
    }

    #[test]
    fn metadata_inventory_does_not_contain_secrets_or_capability_tokens() {
        let vault = vault();
        let credential = add(&vault, "key");
        add(&vault, "legacy");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        let inventory = vault.list_auth_inventory("default").unwrap();
        assert!(
            inventory
                .iter()
                .any(|item| item.name == "legacy" && item.auth.is_none())
        );
        let json = serde_json::to_string(&inventory).unwrap();
        assert!(!json.contains("synthetic-auth-canary"));
        assert!(!json.contains(&credential.wisp_token));
        assert!(!json.contains("encrypted_value"));
    }

    #[test]
    fn registration_and_import_identity_changes_or_revocation_downgrades_are_rejected() {
        let vault = vault();
        add(&vault, "key");
        vault
            .register_auth("default", "key", registration())
            .unwrap();
        let mut request = registration();
        request.account = "another-account".into();
        assert!(vault.register_auth("default", "key", request).is_err());
        let mut data = vault.export_auth_partition("default", "personal").unwrap();
        vault.revoke_auth("default", "key").unwrap();
        let tx = vault.db.unchecked_transaction().unwrap();
        assert!(
            vault
                .import_auth_partition("default", "personal", &data)
                .is_err()
        );
        data.records[0].metadata.id = Uuid::new_v4().to_string();
        assert!(
            vault
                .import_auth_partition("default", "personal", &data)
                .is_err()
        );
        drop(tx);
        assert!(
            vault.list_auth_inventory("default").unwrap()[0]
                .auth
                .as_ref()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn migration_adds_registry_without_reclassifying_legacy_credentials() {
        let vault = vault();
        add(&vault, "legacy");
        vault.db.execute_batch("DROP TABLE auth_registry; DROP TABLE auth_bundles; INSERT INTO vault_meta VALUES('version','13');").unwrap();
        Vault::migrate_schema(&vault.db).unwrap();
        assert_eq!(vault.list_auth_inventory("default").unwrap()[0].auth, None);
        assert!(
            vault
                .decrypt_credential_value_in_project("default", "legacy")
                .is_ok()
        );
        let version: String = vault
            .db
            .query_row(
                "SELECT value FROM vault_meta WHERE key='version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }
}
