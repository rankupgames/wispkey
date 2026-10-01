//! Reusable identities. Profiles are never credentials or proxy capabilities.
use super::*;
use rusqlite::OptionalExtension;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignupProfile {
    pub id: String,
    pub name: String,
    pub revision: String,
    pub project: String,
    pub partition: String,
}

/// Owner input only. Deliberately has no Debug implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupIdentity {
    pub email: String,
    pub username: Option<String>,
}
impl Drop for SignupIdentity {
    fn drop(&mut self) {
        self.email.zeroize();
        if let Some(username) = &mut self.username {
            username.zeroize();
        }
    }
}
impl SignupIdentity {
    fn validate(&self) -> Result<()> {
        let valid =
            |s: &str| !s.trim().is_empty() && s.len() <= 320 && !s.chars().any(char::is_control);
        if !valid(&self.email)
            || !self.email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && !domain.is_empty() && !domain.contains('@')
            })
            || self.email.chars().any(char::is_whitespace)
            || self.username.as_deref().is_some_and(|s| !valid(s))
        {
            return Err(rejected("invalid signup identity"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortableProfile {
    metadata: SignupProfile,
    identity: SignupIdentity,
}

/// Both the scope and revision must be selected explicitly. The identity field
/// determines the single identity slot supported by the existing native fill.
#[derive(Debug, Clone, Copy)]
pub struct ProfileSelection<'a> {
    pub id: &'a str,
    pub revision: &'a str,
    pub project: &'a str,
    pub partition: &'a str,
    pub use_username: bool,
}

fn rejected(reason: &'static str) -> VaultError {
    VaultError::AuthRejected(reason)
}

pub(crate) fn create_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS signup_profiles (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, revision TEXT NOT NULL,
        partition_id TEXT NOT NULL REFERENCES partitions(id), encrypted_value TEXT NOT NULL,
        UNIQUE(partition_id,name));",
    )?;
    Ok(())
}

impl Vault {
    /// Inventory is metadata only; no decrypt operation is used here.
    pub fn list_signup_profiles(
        &self,
        project: &str,
        partition: &str,
    ) -> Result<Vec<SignupProfile>> {
        let partition_id = self.get_partition_in_project(project, partition)?.id;
        let mut stmt = self.db.prepare(
            "SELECT id,name,revision FROM signup_profiles WHERE partition_id=?1 ORDER BY name",
        )?;
        Ok(stmt
            .query_map([partition_id], |row| {
                Ok(SignupProfile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    revision: row.get(2)?,
                    project: project.into(),
                    partition: partition.into(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn create_signup_profile(
        &self,
        project: &str,
        partition: &str,
        name: &str,
        identity: SignupIdentity,
    ) -> Result<SignupProfile> {
        self.with_transport_transaction(|| {
            let profile = PortableProfile {
                metadata: SignupProfile {
                    id: Uuid::new_v4().to_string(),
                    revision: Uuid::new_v4().to_string(),
                    project: project.into(),
                    partition: partition.into(),
                    name: name.into(),
                },
                identity,
            };
            self.insert_signup_profile(&profile)?;
            Ok(profile.metadata.clone())
        })
    }

    pub fn update_signup_profile(
        &self,
        selection: ProfileSelection<'_>,
        identity: SignupIdentity,
    ) -> Result<SignupProfile> {
        self.with_transport_transaction(|| {
            let mut profile = self.resolve_signup_profile(selection)?;
            identity.validate()?;
            profile.identity = identity;
            profile.metadata.revision = Uuid::new_v4().to_string();
            self.db.execute(
                "DELETE FROM signup_profiles WHERE id=?1",
                [&profile.metadata.id],
            )?;
            self.insert_signup_profile(&profile)?;
            Ok(profile.metadata)
        })
    }

    pub fn remove_signup_profile(&self, selection: ProfileSelection<'_>) -> Result<()> {
        self.with_transport_transaction(|| {
            let profile = self.resolve_signup_profile(selection)?;
            self.db.execute(
                "DELETE FROM signup_profiles WHERE id=?1",
                [&profile.metadata.id],
            )?;
            Ok(())
        })
    }

    fn resolve_signup_profile(&self, selection: ProfileSelection<'_>) -> Result<PortableProfile> {
        let metadata = self
            .list_signup_profiles(selection.project, selection.partition)?
            .into_iter()
            .find(|p| p.id == selection.id && p.revision == selection.revision)
            .ok_or_else(|| rejected("signup profile missing, stale, or outside selected scope"))?;
        self.decrypt_signup_profile(metadata)
    }

    fn decrypt_signup_profile(&self, metadata: SignupProfile) -> Result<PortableProfile> {
        let encrypted: String = self.db.query_row(
            "SELECT encrypted_value FROM signup_profiles WHERE id=?1",
            [&metadata.id],
            |row| row.get(0),
        )?;
        let bytes = BASE64
            .decode(encrypted)
            .map_err(|_| rejected("invalid encrypted signup profile"))?;
        let clear = Zeroizing::new(self.decrypt_bytes(self.ensure_unlocked()?, &bytes)?);
        let profile: PortableProfile = serde_json::from_slice(&clear)
            .map_err(|_| rejected("invalid encrypted signup profile"))?;
        if profile.metadata != metadata {
            return Err(rejected("signup profile binding mismatch"));
        }
        profile.identity.validate()?;
        Ok(profile)
    }

    fn insert_signup_profile(&self, profile: &PortableProfile) -> Result<()> {
        if self.db.is_autocommit() {
            return Err(rejected("signup transaction required"));
        }
        let m = &profile.metadata;
        profile.identity.validate()?;
        if m.name.trim().is_empty()
            || m.name.len() > 128
            || m.name.chars().any(char::is_control)
            || Uuid::parse_str(&m.id).is_err()
            || Uuid::parse_str(&m.revision).is_err()
        {
            return Err(rejected("invalid signup profile metadata"));
        }
        let partition = self.get_partition_in_project(&m.project, &m.partition)?;
        let exists: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM signup_profiles WHERE id=?1 OR (partition_id=?2 AND name=?3))",
            params![m.id,partition.id,m.name], |row| row.get(0))?;
        if exists {
            return Err(rejected("signup profile already exists"));
        }
        let clear = Zeroizing::new(
            serde_json::to_vec(profile).map_err(|_| rejected("invalid signup profile"))?,
        );
        let encrypted = BASE64.encode(self.encrypt_bytes(self.ensure_unlocked()?, &clear)?);
        self.db.execute(
            "INSERT INTO signup_profiles VALUES (?1,?2,?3,?4,?5)",
            params![m.id, m.name, m.revision, partition.id, encrypted],
        )?;
        self.db.execute(
            "INSERT OR REPLACE INTO vault_meta(key,value) VALUES (?1,'1')",
            [format!("signup_partition_v1:{}", partition.id)],
        )?;
        Ok(())
    }

    /// Profile resolution and fresh-password insertion share one write transaction.
    /// Only the committed credential metadata is returned. No fill is queued here.
    pub fn generate_signup_login(
        &self,
        selection: ProfileSelection<'_>,
        request: GenerateWebsiteLoginRequest<'_>,
    ) -> Result<Credential> {
        if request.project != Some(selection.project)
            || request.partition != Some(selection.partition)
            || !request.username.is_empty()
        {
            return Err(rejected(
                "signup login requires matching explicit scope and no inline identity",
            ));
        }
        self.with_transport_transaction(|| {
            let profile = self.resolve_signup_profile(selection)?;
            let username = if selection.use_username {
                profile
                    .identity
                    .username
                    .as_deref()
                    .ok_or_else(|| rejected("selected profile has no username"))?
            } else {
                &profile.identity.email
            };
            // Build a new borrow so no identity can escape the transaction.
            self.insert_website_login(GenerateWebsiteLoginRequest {
                username,
                ..request
            })
        })
    }

    pub(crate) fn export_signup_profiles(
        &self,
        project: &str,
        partition: &str,
    ) -> Result<Option<Vec<PortableProfile>>> {
        let id = self.get_partition_in_project(project, partition)?.id;
        let managed: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM vault_meta WHERE key=?1",
                [format!("signup_partition_v1:{id}")],
                |row| row.get(0),
            )
            .optional()?;
        let profiles = self
            .list_signup_profiles(project, partition)?
            .into_iter()
            .map(|m| self.decrypt_signup_profile(m))
            .collect::<Result<Vec<_>>>()?;
        Ok((managed.is_some() || !profiles.is_empty()).then_some(profiles))
    }

    pub(crate) fn import_signup_profiles(
        &self,
        project: &str,
        partition: &str,
        profiles: &[PortableProfile],
        replace: bool,
    ) -> Result<()> {
        if self.db.is_autocommit() {
            return Err(rejected("signup transaction required"));
        }
        let id = self.get_partition_in_project(project, partition)?.id;
        for profile in profiles {
            if profile.metadata.project != project || profile.metadata.partition != partition {
                return Err(rejected("signup profile scope mismatch"));
            }
            let existing: Option<String> = self
                .db
                .query_row(
                    "SELECT partition_id FROM signup_profiles WHERE id=?1",
                    [&profile.metadata.id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.as_deref().is_some_and(|p| p != id) {
                return Err(rejected("signup profile scope mismatch"));
            }
        }
        if replace {
            self.db
                .execute("DELETE FROM signup_profiles WHERE partition_id=?1", [&id])?;
        }
        for profile in profiles {
            self.insert_signup_profile(profile)?;
        }
        self.db.execute(
            "INSERT OR REPLACE INTO vault_meta(key,value) VALUES (?1,'1')",
            [format!("signup_partition_v1:{id}")],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EMAIL: &str = "synthetic-email-canary@example.test";
    const USERNAME: &str = "synthetic-username-canary";
    const PASSPHRASE: &str = "synthetic-transfer-passphrase";
    fn vault() -> Vault {
        let db = Connection::open_in_memory().unwrap();
        Vault::create_schema(&db).unwrap();
        db.execute("INSERT INTO projects VALUES ('default','default','','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')", []).unwrap();
        db.execute("INSERT INTO partitions VALUES ('personal','personal','','default','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')", []).unwrap();
        Vault {
            db,
            master_key: Some([9; 32]),
            session_timeout_override: None,
        }
    }
    fn identity() -> SignupIdentity {
        SignupIdentity {
            email: EMAIL.into(),
            username: Some(USERNAME.into()),
        }
    }
    fn create(v: &Vault) -> SignupProfile {
        v.create_signup_profile("default", "personal", "work", identity())
            .unwrap()
    }
    fn selection(p: &SignupProfile) -> ProfileSelection<'_> {
        ProfileSelection {
            id: &p.id,
            revision: &p.revision,
            project: &p.project,
            partition: &p.partition,
            use_username: false,
        }
    }
    fn request<'a>(name: &'a str) -> GenerateWebsiteLoginRequest<'a> {
        GenerateWebsiteLoginRequest {
            name,
            username: "",
            url: "https://signup.example.test/path",
            project: Some("default"),
            partition: Some("personal"),
            review_at: None,
            length: None,
            symbols: true,
        }
    }
    fn payload(v: &Vault, name: &str) -> WebsiteLoginPayload {
        serde_json::from_str(
            &v.decrypt_credential_value_in_project("default", name)
                .unwrap(),
        )
        .unwrap()
    }
    fn hash(v: &Vault) -> String {
        v.cloud_snapshot_hash(&v.cloud_snapshot("default", "personal").unwrap().unwrap())
            .unwrap()
    }

    #[test]
    fn signup_identity_encrypted_bound_and_absent_from_inventory() {
        let v = vault();
        let p = create(&v);
        let stored: String =
            v.db.query_row("SELECT encrypted_value FROM signup_profiles", [], |r| {
                r.get(0)
            })
            .unwrap();
        for text in [
            stored,
            serde_json::to_string(&p).unwrap(),
            format!(
                "{:?}",
                v.list_signup_profiles("default", "personal").unwrap()
            ),
        ] {
            assert!(!text.contains(EMAIL));
            assert!(!text.contains(USERNAME));
        }
        assert!(v.list_credentials().unwrap().is_empty());
        assert!(
            v.decrypt_credential_value_in_project("default", "work")
                .is_err()
        );
        v.db.execute("UPDATE signup_profiles SET name='tampered'", [])
            .unwrap();
        assert!(
            v.generate_signup_login(selection(&p), request("one"))
                .is_err()
        );
        assert_eq!(v.credential_count().unwrap(), 0);
    }

    #[test]
    fn signup_edits_stale_refs_removal_and_recreation_do_not_change_saved_login() {
        let v = vault();
        let p = create(&v);
        v.generate_signup_login(selection(&p), request("saved"))
            .unwrap();
        let before = payload(&v, "saved");
        let new = v
            .update_signup_profile(
                selection(&p),
                SignupIdentity {
                    email: "edited@example.test".into(),
                    username: None,
                },
            )
            .unwrap();
        assert_ne!(p.revision, new.revision);
        assert!(v.update_signup_profile(selection(&p), identity()).is_err());
        assert!(v.remove_signup_profile(selection(&p)).is_err());
        assert!(
            v.generate_signup_login(selection(&p), request("stale"))
                .is_err()
        );
        v.generate_signup_login(selection(&new), request("edited"))
            .unwrap();
        assert_eq!(payload(&v, "edited").username, "edited@example.test");
        v.remove_signup_profile(selection(&new)).unwrap();
        let recreated = create(&v);
        assert_ne!(p.id, recreated.id);
        assert!(
            v.generate_signup_login(selection(&new), request("deleted"))
                .is_err()
        );
        assert_eq!(before, payload(&v, "saved"));
    }

    #[test]
    fn signup_scope_isolation_same_names_and_explicit_identity_choice() {
        let v = vault();
        let p = create(&v);
        v.create_project("other", "").unwrap();
        v.create_partition("work", "", Some("default")).unwrap();
        let other = v
            .create_signup_profile("other", "personal", "work", identity())
            .unwrap();
        let partition = v
            .create_signup_profile("default", "work", "work", identity())
            .unwrap();
        for s in [
            ProfileSelection {
                project: "other",
                ..selection(&p)
            },
            ProfileSelection {
                partition: "work",
                ..selection(&p)
            },
            selection(&other),
            selection(&partition),
        ] {
            assert!(v.generate_signup_login(s, request("wrong")).is_err());
        }
        let mut req = request("inline");
        req.username = EMAIL;
        assert!(v.generate_signup_login(selection(&p), req).is_err());
        let mut req = request("implicit");
        req.partition = None;
        assert!(v.generate_signup_login(selection(&p), req).is_err());
        v.generate_signup_login(selection(&p), request("email"))
            .unwrap();
        v.generate_signup_login(
            ProfileSelection {
                use_username: true,
                ..selection(&p)
            },
            request("username"),
        )
        .unwrap();
        assert_eq!(payload(&v, "email").username, EMAIL);
        assert_eq!(payload(&v, "username").username, USERNAME);
        assert_ne!(
            payload(&v, "email").password,
            payload(&v, "username").password
        );
        assert!(v.delete_project("other").is_err());
        assert!(v.delete_partition_in_project("default", "work").is_err());
        let new = v
            .update_signup_profile(
                selection(&p),
                SignupIdentity {
                    email: EMAIL.into(),
                    username: None,
                },
            )
            .unwrap();
        assert!(
            v.generate_signup_login(
                ProfileSelection {
                    use_username: true,
                    ..selection(&new)
                },
                request("missing")
            )
            .is_err()
        );
    }

    #[test]
    fn signup_duplicates_write_failures_and_invalid_identity_roll_back() {
        let v = vault();
        let p = create(&v);
        assert!(
            v.create_signup_profile("default", "personal", "work", identity())
                .is_err()
        );
        v.generate_signup_login(selection(&p), request("one"))
            .unwrap();
        let before = payload(&v, "one");
        assert!(
            v.generate_signup_login(selection(&p), request("one"))
                .is_err()
        );
        assert_eq!(before, payload(&v, "one"));
        v.db.execute_batch("CREATE TRIGGER reject_login BEFORE INSERT ON credentials BEGIN SELECT RAISE(ABORT,'synthetic write failure'); END;").unwrap();
        assert!(
            v.generate_signup_login(selection(&p), request("fail"))
                .is_err()
        );
        assert_eq!(v.credential_count().unwrap(), 1);
        v.db.execute_batch("CREATE TRIGGER reject_profile BEFORE INSERT ON signup_profiles BEGIN SELECT RAISE(ABORT,'synthetic write failure'); END;").unwrap();
        assert!(
            v.update_signup_profile(
                selection(&p),
                SignupIdentity {
                    email: "edit@example.test".into(),
                    username: None
                }
            )
            .is_err()
        );
        assert_eq!(
            v.resolve_signup_profile(selection(&p))
                .unwrap()
                .identity
                .email,
            EMAIL
        );
        let error = v
            .update_signup_profile(
                selection(&p),
                SignupIdentity {
                    email: "private-invalid-canary".into(),
                    username: None,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(!error.contains("private-invalid-canary"));
        v.db.execute_batch("PRAGMA query_only=ON").unwrap();
        assert!(
            v.generate_signup_login(selection(&p), request("readonly"))
                .is_err()
        );
    }

    #[test]
    fn signup_pending_login_survives_denial_and_profile_edit_during_approval() {
        let v = vault();
        let p = create(&v);
        v.generate_signup_login(selection(&p), request("saved"))
            .unwrap();
        let before = payload(&v, "saved");
        let req = browser::request(
            &v,
            "saved",
            "default",
            "https://signup.example.test",
            "test-agent",
            "synthetic approval",
        )
        .unwrap();
        v.update_signup_profile(
            selection(&p),
            SignupIdentity {
                email: "edited@example.test".into(),
                username: None,
            },
        )
        .unwrap();
        browser::deny(&v, &req.request_id).unwrap();
        assert!(browser::release(&v, &req).is_err());
        assert_eq!(before, payload(&v, "saved"));
        assert_eq!(
            v.get_credential_in_project("default", "saved")
                .unwrap()
                .lifecycle_state,
            LIFECYCLE_PENDING
        );
        let retry = browser::request(
            &v,
            "saved",
            "default",
            "https://signup.example.test",
            "test-agent",
            "retry",
        )
        .unwrap();
        assert_ne!(req.request_id, retry.request_id);
        assert_eq!(before, payload(&v, "saved"));
    }

    #[test]
    fn signup_sync_roundtrip_edits_deletion_and_legacy_replacement_rejection() {
        let source = vault();
        let p = create(&source);
        let destination = vault();
        source
            .generate_signup_login(selection(&p), request("saved"))
            .unwrap();
        let snapshot = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version, 3);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sync");
        let path = path.to_str().unwrap();
        crate::bundle::write_encrypted_payload(b"WKCS", &snapshot, PASSPHRASE, path).unwrap();
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.windows(EMAIL.len()).any(|b| b == EMAIL.as_bytes()));
        let decoded = crate::bundle::read_encrypted_payload(b"WKCS", path, PASSPHRASE).unwrap();
        destination
            .cloud_apply(&decoded, Some(&hash(&destination)), None)
            .unwrap();
        assert_eq!(
            destination
                .list_signup_profiles("default", "personal")
                .unwrap(),
            vec![p.clone()]
        );
        assert_eq!(payload(&source, "saved"), payload(&destination, "saved"));
        let old_hash = hash(&destination);
        let changed = destination
            .update_signup_profile(
                selection(&p),
                SignupIdentity {
                    email: "local-edit@example.test".into(),
                    username: None,
                },
            )
            .unwrap();
        assert!(
            destination
                .cloud_apply(&snapshot, Some(&old_hash), None)
                .is_err()
        );
        let legacy = vault()
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert!(
            destination
                .cloud_apply(&legacy, Some(&hash(&destination)), None)
                .is_err()
        );
        source.remove_signup_profile(selection(&p)).unwrap();
        let deletion = source
            .cloud_snapshot("default", "personal")
            .unwrap()
            .unwrap();
        assert_eq!(deletion.version, 3);
        destination
            .cloud_apply(&deletion, Some(&hash(&destination)), None)
            .unwrap();
        assert!(
            destination
                .list_signup_profiles("default", "personal")
                .unwrap()
                .is_empty()
        );
        assert!(
            destination
                .generate_signup_login(selection(&changed), request("gone"))
                .is_err()
        );
        assert_eq!(destination.credential_count().unwrap(), 1);
    }

    #[test]
    fn signup_sync_malformed_duplicate_scope_and_downgrade_roll_back() {
        let source = vault();
        create(&source);
        let destination = vault();
        let before = hash(&destination);
        let original = serde_json::to_value(
            source
                .cloud_snapshot("default", "personal")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        for change in 0..5 {
            let mut value = original.clone();
            match change {
                0 => value["version"] = serde_json::json!(2),
                1 => {
                    value["signup_profiles"][0]["metadata"]["project"] = serde_json::json!("other")
                }
                2 => {
                    let copy = value["signup_profiles"][0].clone();
                    value["signup_profiles"].as_array_mut().unwrap().push(copy);
                }
                3 => {
                    value["signup_profiles"][0]["identity"]["email"] =
                        serde_json::json!("invalid-canary")
                }
                _ => value["signup_profiles"][0]["metadata"]["revision"] = serde_json::json!("bad"),
            }
            let snapshot = serde_json::from_value(value).unwrap();
            let error = destination
                .cloud_apply(&snapshot, Some(&before), None)
                .unwrap_err();
            assert!(!error.to_string().contains(EMAIL));
            assert_eq!(hash(&destination), before);
        }
    }

    #[test]
    fn signup_project_and_partition_exports_roundtrip_and_reject_old_formats() {
        let source = vault();
        let p = create(&source);
        source
            .generate_signup_login(selection(&p), request("saved"))
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bundle");
        let path = path.to_str().unwrap();
        for partition in [false, true] {
            let magic = if partition { b"WKBX" } else { b"WKPJ" };
            if partition {
                crate::partition::export_partition(&source, "personal", PASSPHRASE, path).unwrap();
            } else {
                crate::sharing::export_project(&source, "default", PASSPHRASE, path).unwrap();
            }
            let mut document: serde_json::Value =
                crate::bundle::read_encrypted_payload(magic, path, PASSPHRASE).unwrap();
            assert_eq!(document["version"], 3);
            let destination = vault();
            let import = |v: &Vault| {
                if partition {
                    crate::partition::import_partition(v, path, PASSPHRASE)
                } else {
                    crate::sharing::import_project(v, path, PASSPHRASE)
                }
            };
            assert_eq!(import(&destination).unwrap().imported, 1);
            assert_eq!(
                destination
                    .resolve_signup_profile(selection(&p))
                    .unwrap()
                    .identity
                    .email,
                EMAIL
            );
            assert_eq!(payload(&source, "saved"), payload(&destination, "saved"));
            let before = hash(&destination);
            assert!(import(&destination).is_err());
            assert_eq!(hash(&destination), before);
            document["version"] = serde_json::json!(2);
            crate::bundle::write_encrypted_payload(magic, &document, PASSPHRASE, path).unwrap();
            assert!(import(&vault()).is_err());
            crate::bundle::write_encrypted_payload(magic, &document["payload"], PASSPHRASE, path)
                .unwrap();
            assert!(import(&vault()).is_err());
        }
    }

    #[test]
    fn signup_locked_vault_and_invalid_owner_identity_reject_without_writes() {
        let mut v = vault();
        for email in [
            "@",
            "@example.test",
            "local@",
            "a@b@c",
            "line\n@example.test",
        ] {
            assert!(
                v.create_signup_profile(
                    "default",
                    "personal",
                    "bad",
                    SignupIdentity {
                        email: email.into(),
                        username: None
                    }
                )
                .is_err()
            );
        }
        let p = create(&v);
        v.master_key = None;
        assert!(
            v.create_signup_profile("default", "personal", "locked", identity())
                .is_err()
        );
        assert!(v.update_signup_profile(selection(&p), identity()).is_err());
        assert!(v.remove_signup_profile(selection(&p)).is_err());
        assert!(
            v.generate_signup_login(selection(&p), request("locked"))
                .is_err()
        );
        assert_eq!(v.credential_count().unwrap(), 0);
        assert!(v.list_signup_profiles("default", "personal").is_err());
        v.master_key = Some([9; 32]);
        assert_eq!(
            v.list_signup_profiles("default", "personal").unwrap(),
            vec![p]
        );
    }

    #[test]
    fn signup_schema_migrates_14_and_legacy_login_remains_compatible() {
        let v = vault();
        v.db.execute("DROP TABLE signup_profiles", []).unwrap();
        v.db.execute("INSERT INTO vault_meta VALUES ('version','14')", [])
            .unwrap();
        Vault::migrate_schema(&v.db).unwrap();
        create(&v);
        let mut req = request("legacy");
        req.username = "legacy@example.test";
        req.partition = None;
        v.generate_website_login(req).unwrap();
        assert_eq!(payload(&v, "legacy").username, "legacy@example.test");
    }
}
