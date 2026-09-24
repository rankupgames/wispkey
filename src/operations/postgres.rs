//! Scoped PostgreSQL password issuer. The owner installs and reviews the
//! SECURITY DEFINER function separately; this code never creates database roles.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ring::digest;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::config::{ChannelBinding, SslMode};
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, Config};
use tokio_postgres_rustls::MakeRustlsConnect;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::identity;

type Result<T> = std::result::Result<T, &'static str>;
const INVALID_TARGET: &str = "database issuer target is invalid";
const ISSUER_UNVERIFIED: &str = "database issuer is unverified";
const DATABASE_UNAVAILABLE: &str = "database issuer is unavailable";
const MAX_PASSWORD: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostgresTarget {
    pub endpoint: String,
    pub environment_id: String,
    pub environment_owner: String,
    pub database: String,
    pub issuer_username: String,
    pub app_username: String,
    pub provider_credential_id: String,
    pub previous_credential_id: String,
    pub ca_file: PathBuf,
    pub function_schema: String,
    pub function_name: String,
    pub function_oid: u32,
    pub function_owner: String,
    pub function_definition_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostgresOutcome {
    RotationVerified,
    OutcomeUnknown,
}

impl PostgresTarget {
    pub(crate) fn validate(&self) -> Result<()> {
        let _ = self.verified_ca()?;
        Ok(())
    }

    /// Binds a grant to the exact reviewed target and owner-private CA bytes.
    pub(crate) fn snapshot_revision(&self) -> Result<String> {
        let ca = self.verified_ca()?;
        let encoded = serde_json::to_vec(self).map_err(|_| INVALID_TARGET)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"wispkey-postgres-target-v1\0");
        hash.update(&encoded);
        hash.update(ca.as_bytes());
        Ok(STANDARD_NO_PAD.encode(hash.finish().as_ref()))
    }

    fn verified_ca(&self) -> Result<String> {
        let (host, _) = self.host_port()?;
        if !valid_scope(&self.environment_id)
            || !valid_scope(&self.environment_owner)
            || !valid_name(&self.database)
            || !valid_name(&self.issuer_username)
            || !valid_name(&self.app_username)
            || self.issuer_username == self.app_username
            || !valid_name(&self.function_schema)
            || !valid_name(&self.function_name)
            || !valid_name(&self.function_owner)
            || self.issuer_username == self.function_owner
            || self.function_oid == 0
            || host.is_empty()
            || !canonical_uuid(&self.provider_credential_id)
            || !canonical_uuid(&self.previous_credential_id)
            || self.provider_credential_id == self.previous_credential_id
            || self.ca_file.as_os_str().is_empty()
            || !self.ca_file.is_absolute()
        {
            return Err(INVALID_TARGET);
        }
        let hash = STANDARD_NO_PAD
            .decode(&self.function_definition_sha256)
            .map_err(|_| INVALID_TARGET)?;
        if hash.len() != 32 || STANDARD_NO_PAD.encode(hash) != self.function_definition_sha256 {
            return Err(INVALID_TARGET);
        }
        let ca = identity::read_private_catalog(&self.ca_file).map_err(|_| INVALID_TARGET)?;
        let certs: Vec<_> = CertificateDer::pem_slice_iter(ca.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| INVALID_TARGET)?;
        if certs.len() != 1 {
            return Err(INVALID_TARGET);
        }
        Ok(ca)
    }

    fn host_port(&self) -> Result<(String, u16)> {
        let url = url::Url::parse(&self.endpoint).map_err(|_| INVALID_TARGET)?;
        if url.scheme() != "postgresql"
            || url.host().is_none()
            || url.port().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || self.endpoint
                != format!(
                    "postgresql://{}:{}",
                    url.host_str().ok_or(INVALID_TARGET)?,
                    url.port().ok_or(INVALID_TARGET)?
                )
        {
            return Err(INVALID_TARGET);
        }
        Ok((
            url.host_str().ok_or(INVALID_TARGET)?.to_owned(),
            url.port().ok_or(INVALID_TARGET)?,
        ))
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn password(bytes: Vec<u8>) -> Result<Zeroizing<String>> {
    if bytes.is_empty() || bytes.len() > MAX_PASSWORD || bytes.contains(&0) {
        return Err(DATABASE_UNAVAILABLE);
    }
    let text = String::from_utf8(bytes).map_err(|_| DATABASE_UNAVAILABLE)?;
    Ok(Zeroizing::new(text))
}

/// The selected password is released only after the issuer, function and old
/// application login have been verified. An uncertain function call is never
/// retried automatically. Existing PostgreSQL sessions are not revoked.
pub(crate) async fn execute<Provider, Previous, Selected>(
    target: &PostgresTarget,
    deadline: Instant,
    connect_timeout: Duration,
    mut cancellation: watch::Receiver<bool>,
    provider_password: Provider,
    previous_password: Previous,
    selected_password: Selected,
) -> Result<PostgresOutcome>
where
    Provider: FnOnce() -> Result<Vec<u8>>,
    Previous: FnOnce() -> Result<Vec<u8>>,
    Selected: FnOnce() -> Result<Vec<u8>>,
{
    if connect_timeout.is_zero() || connect_timeout > Duration::from_secs(30) {
        return Err(INVALID_TARGET);
    }
    let write_started = AtomicBool::new(false);
    tokio::select! {
        result = timeout_at(deadline, execute_inner(target, connect_timeout, provider_password, previous_password, selected_password, &write_started)) => {
            match result {
                Ok(result) => result,
                Err(_) if write_started.load(Ordering::SeqCst) => Ok(PostgresOutcome::OutcomeUnknown),
                Err(_) => Err(DATABASE_UNAVAILABLE),
            }
        }
        _ = async {
            if cancellation.wait_for(|cancelled| *cancelled).await.is_err() {
                std::future::pending::<()>().await;
            }
        } => {
            if write_started.load(Ordering::SeqCst) {
                Ok(PostgresOutcome::OutcomeUnknown)
            } else {
                Err(DATABASE_UNAVAILABLE)
            }
        }
    }
}

async fn execute_inner<Provider, Previous, Selected>(
    target: &PostgresTarget,
    connect_timeout: Duration,
    provider_password: Provider,
    previous_password: Previous,
    selected_password: Selected,
    write_started: &AtomicBool,
) -> Result<PostgresOutcome>
where
    Provider: FnOnce() -> Result<Vec<u8>>,
    Previous: FnOnce() -> Result<Vec<u8>>,
    Selected: FnOnce() -> Result<Vec<u8>>,
{
    let ca = target.verified_ca()?;
    let tls = pinned_tls(&ca)?;
    let provider = password(provider_password()?)?;
    let previous = password(previous_password()?)?;
    let admin = connect(
        target,
        &target.issuer_username,
        &provider,
        tls.clone(),
        connect_timeout,
    )
    .await
    .map_err(|_| DATABASE_UNAVAILABLE)?;
    verify_issuer(&admin.client, target).await?;
    let old = connect(
        target,
        &target.app_username,
        &previous,
        tls.clone(),
        connect_timeout,
    )
    .await
    .map_err(|_| ISSUER_UNVERIFIED)?;
    verify_database(&old.client, target).await?;
    drop(old);
    // The digest, OID and role privileges are checked immediately before use.
    verify_issuer(&admin.client, target).await?;
    let selected = password(selected_password()?)?;
    if *selected == *previous {
        return Err(INVALID_TARGET);
    }
    let call = format!(
        "SELECT {}.{}($1::text)",
        target.function_schema, target.function_name
    );
    write_started.store(true, Ordering::SeqCst);
    if admin
        .client
        .query_one(&call, &[&selected.as_str()])
        .await
        .is_err()
    {
        return Ok(PostgresOutcome::OutcomeUnknown);
    }
    drop(admin);
    let new = match connect(
        target,
        &target.app_username,
        &selected,
        tls.clone(),
        connect_timeout,
    )
    .await
    {
        Ok(connected) => connected,
        Err(_) => return Ok(PostgresOutcome::OutcomeUnknown),
    };
    if verify_database(&new.client, target).await.is_err() {
        return Ok(PostgresOutcome::OutcomeUnknown);
    }
    drop(new);
    match connect(
        target,
        &target.app_username,
        &previous,
        tls,
        connect_timeout,
    )
    .await
    {
        Err(ConnectionFailure::InvalidPassword) => Ok(PostgresOutcome::RotationVerified),
        Ok(session) => {
            drop(session);
            Ok(PostgresOutcome::OutcomeUnknown)
        }
        Err(_) => Ok(PostgresOutcome::OutcomeUnknown),
    }
}

#[derive(Clone, Copy, Debug)]
enum ConnectionFailure {
    InvalidPassword,
    Other,
}

struct PgSession {
    client: Client,
    task: JoinHandle<()>,
}

impl Drop for PgSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connect(
    target: &PostgresTarget,
    username: &str,
    password: &str,
    tls: MakeRustlsConnect,
    connect_timeout: Duration,
) -> std::result::Result<PgSession, ConnectionFailure> {
    let (host, port) = target.host_port().map_err(|_| ConnectionFailure::Other)?;
    let mut config = Config::new();
    config
        .host(&host)
        .port(port)
        .user(username)
        .password(password)
        .dbname(&target.database)
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require)
        .connect_timeout(connect_timeout);
    let (client, connection) = config.connect(tls).await.map_err(|error| {
        if error
            .as_db_error()
            .is_some_and(|db| db.code() == &SqlState::INVALID_PASSWORD)
        {
            ConnectionFailure::InvalidPassword
        } else {
            ConnectionFailure::Other
        }
    })?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(PgSession { client, task })
}

fn pinned_tls(ca: &str) -> Result<MakeRustlsConnect> {
    let certificate = CertificateDer::from_pem_slice(ca.as_bytes()).map_err(|_| INVALID_TARGET)?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate).map_err(|_| INVALID_TARGET)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| INVALID_TARGET)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

async fn verify_database(client: &Client, target: &PostgresTarget) -> Result<()> {
    let row = client
        .query_one("SELECT current_user, current_database()", &[])
        .await
        .map_err(|_| DATABASE_UNAVAILABLE)?;
    let user: String = row.get(0);
    let database: String = row.get(1);
    if user != target.app_username || database != target.database {
        return Err(ISSUER_UNVERIFIED);
    }
    Ok(())
}

async fn verify_issuer(client: &Client, target: &PostgresTarget) -> Result<()> {
    let row = client.query_one(
        "SELECT current_user, current_database(), r.rolcanlogin, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, (SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid), current_setting('log_statement'), current_setting('log_parameter_max_length'), current_setting('log_parameter_max_length_on_error'), current_setting('log_min_duration_statement'), current_setting('log_min_duration_sample'), current_setting('log_transaction_sample_rate'), current_setting('log_duration') FROM pg_roles r WHERE r.rolname = current_user",
        &[],
    ).await.map_err(|_| ISSUER_UNVERIFIED)?;
    let user: String = row.get(0);
    let database: String = row.get(1);
    let can_login: bool = row.get(2);
    let superuser: bool = row.get(3);
    let create_role: bool = row.get(4);
    let create_db: bool = row.get(5);
    let replication: bool = row.get(6);
    let bypass_rls: bool = row.get(7);
    let memberships: i64 = row.get(8);
    let log_statement: String = row.get(9);
    let log_parameters: String = row.get(10);
    let log_error_parameters: String = row.get(11);
    let log_duration_statement: String = row.get(12);
    let log_duration_sample: String = row.get(13);
    let transaction_sample_rate: String = row.get(14);
    let log_duration: String = row.get(15);
    if user != target.issuer_username
        || database != target.database
        || !can_login
        || superuser
        || create_role
        || create_db
        || replication
        || bypass_rls
        || memberships != 0
        || log_statement != "none"
        || log_parameters != "0"
        || log_error_parameters != "0"
        || log_duration_statement != "-1"
        || log_duration_sample != "-1"
        || transaction_sample_rate != "0"
        || log_duration != "off"
    {
        return Err(ISSUER_UNVERIFIED);
    }
    let oid = i64::from(target.function_oid);
    let row = client.query_opt(
        "SELECT n.nspname, p.proname, p.prosecdef, p.pronargs, p.prorettype = 'void'::regtype, p.proargtypes[0] = 'text'::regtype, pg_get_userbyid(p.proowner), pg_get_functiondef(p.oid), has_function_privilege(current_user, p.oid, 'EXECUTE'), NOT EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee NOT IN (p.proowner, (SELECT oid FROM pg_roles WHERE rolname = current_user))) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.oid = $1::int8::oid AND p.prokind = 'f'",
        &[&oid],
    ).await.map_err(|_| ISSUER_UNVERIFIED)?.ok_or(ISSUER_UNVERIFIED)?;
    let schema: String = row.get(0);
    let name: String = row.get(1);
    let security_definer: bool = row.get(2);
    let arg_count: i16 = row.get(3);
    let returns_void: bool = row.get(4);
    let takes_text: bool = row.get(5);
    let owner: String = row.get(6);
    let definition: String = row.get(7);
    let can_execute: bool = row.get(8);
    let narrow_acl: bool = row.get(9);
    let digest =
        STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256, definition.as_bytes()).as_ref());
    if schema != target.function_schema
        || name != target.function_name
        || !security_definer
        || arg_count != 1
        || !returns_void
        || !takes_text
        || owner != target.function_owner
        || digest != target.function_definition_sha256
        || !can_execute
        || !narrow_acl
    {
        return Err(ISSUER_UNVERIFIED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(endpoint: &str) -> PostgresTarget {
        PostgresTarget {
            endpoint: endpoint.to_owned(),
            environment_id: "production".into(),
            environment_owner: "owner".into(),
            database: "appdb".into(),
            issuer_username: "issuer".into(),
            app_username: "appuser".into(),
            provider_credential_id: "10000000-0000-4000-8000-000000000001".into(),
            previous_credential_id: "20000000-0000-4000-8000-000000000001".into(),
            ca_file: PathBuf::from("C:/synthetic-ca.pem"),
            function_schema: "wispkey_admin".into(),
            function_name: "rotate_app_password".into(),
            function_oid: 42,
            function_owner: "vault_owner".into(),
            function_definition_sha256: STANDARD_NO_PAD.encode([0u8; 32]),
        }
    }

    #[test]
    fn exact_postgres_endpoint_rejects_embedded_credentials_or_queries() {
        assert_eq!(
            target("postgresql://127.0.0.1:5432").host_port().unwrap(),
            ("127.0.0.1".into(), 5432)
        );
        for endpoint in [
            "postgresql://issuer@127.0.0.1:5432",
            "postgresql://127.0.0.1:5432/appdb",
            "postgresql://127.0.0.1:5432?sslmode=disable",
            "postgresql://127.0.0.1:5432/#fragment",
            "postgresql://127.0.0.1:5432/../other",
        ] {
            assert!(target(endpoint).host_port().is_err(), "{endpoint}");
        }
    }

    /// Run only through `tests/support/postgres_operation_fixture.sh`, which
    /// creates and removes an isolated loopback-only PostgreSQL container.
    #[tokio::test]
    #[ignore]
    async fn disposable_postgres_tls_rotation() {
        assert_eq!(
            std::env::var("WISPKEY_TEST_PG_FIXTURE_MARKER").unwrap(),
            "wispkey-synthetic-postgres-v1"
        );
        let endpoint = std::env::var("WISPKEY_TEST_PG_ENDPOINT").unwrap();
        assert!(endpoint.starts_with("postgresql://127.0.0.1:"));
        let ca_source = std::env::var("WISPKEY_TEST_PG_CA").unwrap();
        let ca = std::fs::read(ca_source).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().canonicalize().unwrap().join("ca.pem");
        crate::secure_files::write_private(&ca_file, &ca).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use std::ptr::null_mut;
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            };
            use windows_sys::Win32::Security::{
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
            };
            let principal = identity::current_principal().unwrap();
            let sid = principal.strip_prefix("windows-sid:").unwrap();
            let sddl: Vec<u16> = format!("O:{sid}").encode_utf16().chain(Some(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        null_mut(),
                    )
                },
                0
            );
            let wide: Vec<u16> = ca_file.as_os_str().encode_wide().chain(Some(0)).collect();
            let applied =
                unsafe { SetFileSecurityW(wide.as_ptr(), OWNER_SECURITY_INFORMATION, descriptor) };
            unsafe { LocalFree(descriptor.cast()) };
            assert_ne!(applied, 0);
        }
        let mut target = target(&endpoint);
        target.ca_file = ca_file;
        target.function_oid = std::env::var("WISPKEY_TEST_PG_FUNCTION_OID")
            .unwrap()
            .parse()
            .unwrap();
        target.function_owner = "postgres".into();
        target.function_definition_sha256 = std::env::var("WISPKEY_TEST_PG_FUNCTION_HASH").unwrap();
        target.validate().unwrap();
        let mut drifted = target.clone();
        drifted.function_definition_sha256 = STANDARD_NO_PAD.encode([1u8; 32]);
        let (_, cancelled) = watch::channel(false);
        let rejected = execute(
            &drifted,
            Instant::now() + Duration::from_secs(25),
            Duration::from_secs(5),
            cancelled,
            || Ok(b"synthetic_issuer_password_9214".to_vec()),
            || Ok(b"synthetic_old_password_9214".to_vec()),
            || panic!("selected password released despite function drift"),
        )
        .await;
        assert_eq!(rejected, Err(ISSUER_UNVERIFIED));
        let (_, cancellation) = watch::channel(false);
        let outcome = execute(
            &target,
            Instant::now() + Duration::from_secs(25),
            Duration::from_secs(5),
            cancellation,
            || Ok(b"synthetic_issuer_password_9214".to_vec()),
            || Ok(b"synthetic_old_password_9214".to_vec()),
            || Ok(b"synthetic_new_password_9214".to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(outcome, PostgresOutcome::RotationVerified);
        let tls = pinned_tls(std::str::from_utf8(&ca).unwrap()).unwrap();
        let session = connect(
            &target,
            &target.app_username,
            "synthetic_new_password_9214",
            tls,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let row = session
            .client
            .query_one("SELECT marker FROM public.fixture_marker", &[])
            .await
            .unwrap();
        let marker: String = row.get(0);
        assert_eq!(marker, "preserved-row");
        drop(session);
        let issuer = connect(
            &target,
            &target.issuer_username,
            "synthetic_issuer_password_9214",
            pinned_tls(std::str::from_utf8(&ca).unwrap()).unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let failure_canary = "fail_synthetic_canary_9214";
        assert!(
            issuer
                .client
                .query_one(
                    "SELECT wispkey_admin.rotate_app_password($1::text)",
                    &[&failure_canary],
                )
                .await
                .is_err()
        );
    }
}
