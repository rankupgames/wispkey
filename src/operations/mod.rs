//! Read-only preflight for owner-controlled cross-node operation catalogs.
//! These checks neither create grants nor prove a remote identity.
mod catalog;
mod identity;

use std::path::Path;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Serialize;

pub(crate) use identity::current_principal;

#[derive(Serialize)]
pub(crate) struct CheckReport {
    pub configuration_valid: bool,
    pub checked_operations: usize,
    pub catalog_revision: String,
    pub credential_verified: bool,
    pub live_target_verified: bool,
    pub execution_available: bool,
}

pub(crate) fn check(path: &Path, operation: Option<&str>) -> Result<CheckReport, &'static str> {
    let principal = current_principal()?;
    let raw = identity::read_private_catalog(path)?;
    let catalog = catalog::parse_catalog(&raw)?;
    check_catalog(&catalog, &principal, operation, Utc::now())
}

fn check_catalog(
    catalog: &catalog::Catalog,
    principal: &str,
    selected: Option<&str>,
    now: DateTime<Utc>,
) -> Result<CheckReport, &'static str> {
    let mut checked_operations = 0;
    for entry in &catalog.operations {
        if selected.is_some_and(|id| entry.id != id) {
            continue;
        }
        if entry.requester_principal != principal {
            return Err("requester does not match current OS account");
        }
        if entry.expires_at <= now {
            return Err("operation authorization window expired");
        }
        checked_operations += 1;
    }
    if checked_operations == 0 {
        return Err("operation not found");
    }
    // Hash the validated, canonical metadata rather than raw TOML. Comments,
    // formatting and field order do not change this review reference. This
    // reference is not a grant, a signature, or proof of destination identity.
    let snapshot = serde_json::to_vec(catalog).map_err(|_| "cannot encode catalog metadata")?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &snapshot);
    let catalog_revision = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest.as_ref());
    Ok(CheckReport {
        configuration_valid: true,
        checked_operations,
        catalog_revision,
        credential_verified: false,
        live_target_verified: false,
        execution_available: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use catalog::{Catalog, Operation, OperationKind, SshTarget};

    fn fixture() -> Catalog {
        Catalog {
            operations: vec![Operation {
                id: "maintenance".into(),
                project_id: "default".into(),
                credential_id: "5af05c13-1c0a-4394-a7a3-7f457ff74a40".into(),
                requester_principal: "unix-uid:1000".into(),
                environment_id: "preview".into(),
                target_id: "worker".into(),
                expires_at: "2030-01-01T00:00:00Z".parse().unwrap(),
                max_grant_seconds: 300,
                max_runtime_seconds: 60,
                connect_timeout_seconds: 10,
                max_concurrency: 1,
                kind: OperationKind::SshHelper(SshTarget {
                    address: "192.0.2.1".parse().unwrap(),
                    port: 22,
                    account: "maintenance".into(),
                    host_key_algorithm: "ssh-ed25519".into(),
                    host_key_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    helper_path: "/usr/local/libexec/maintenance".into(),
                    identity_file: "/private/restricted-key".into(),
                }),
            }],
        }
    }

    #[test]
    fn checks_principal_selection_and_exact_expiry_without_claiming_authorization() {
        let catalog = fixture();
        let now = "2029-12-31T23:59:59Z".parse().unwrap();
        let report = check_catalog(&catalog, "unix-uid:1000", None, now).unwrap();
        assert_eq!(report.checked_operations, 1);
        assert!(!report.credential_verified);
        assert!(!report.live_target_verified);
        assert!(!report.execution_available);
        assert!(check_catalog(&catalog, "unix-uid:1001", None, now).is_err());
        assert!(check_catalog(&catalog, "unix-uid:1000", Some("missing"), now).is_err());
        assert!(
            check_catalog(
                &catalog,
                "unix-uid:1000",
                None,
                catalog.operations[0].expires_at
            )
            .is_err()
        );
    }

    #[test]
    fn revision_binds_validated_target_metadata() {
        let mut catalog = fixture();
        let now = "2029-01-01T00:00:00Z".parse().unwrap();
        let before = check_catalog(&catalog, "unix-uid:1000", None, now).unwrap();
        let OperationKind::SshHelper(target) = &mut catalog.operations[0].kind;
        target.port = 2222;
        let after = check_catalog(&catalog, "unix-uid:1000", None, now).unwrap();
        assert_ne!(before.catalog_revision, after.catalog_revision);
    }
}
