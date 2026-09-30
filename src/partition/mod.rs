/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Encrypted partition sharing with portable auth restrictions.
 * Created: 2026-04-08
 * Last Modified: 2026-09-30
 */

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::auth::AuthPartitionData;
use crate::core::{self, Vault};
use crate::sharing::{
    BundleCredential, ensure_partition, ensure_project, export_bundle_credentials,
    import_bundle_credentials, merge_auth_data, optional_auth_data, read_transport_payload,
    validate_bundle_auth_bindings, validate_transport_format, write_transport_payload,
};

const BUNDLE_MAGIC: &[u8; 4] = b"WKBX";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundlePayload {
    partition: String,
    description: String,
    #[serde(default)]
    project: String,
    exported_at: String,
    credentials: Vec<BundleCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_data: Option<AuthPartitionData>,
}

pub use crate::sharing::ImportResults;

/// Encrypts a partition with all registered auth metadata and named bundles.
pub fn export_partition(
    vault: &Vault,
    partition_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<usize> {
    let active_project = core::resolve_active_project();
    let payload = vault.with_transport_snapshot(|| {
        let partition = vault.get_partition_in_project(&active_project, partition_name)?;
        let credentials = export_bundle_credentials(vault, &active_project, partition_name)?;
        let auth_data =
            optional_auth_data(vault.export_auth_partition(&active_project, partition_name)?);
        Ok(BundlePayload {
            partition: partition.name,
            description: partition.description,
            project: active_project.clone(),
            exported_at: Utc::now().to_rfc3339(),
            credentials,
            auth_data,
        })
    })?;
    write_transport_payload(
        BUNDLE_MAGIC,
        &payload,
        payload.auth_data.is_some(),
        passphrase,
        output_path,
    )?;
    Ok(payload.credentials.len())
}

/// Imports legacy payloads additively and policy-bearing payloads atomically.
pub fn import_partition(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<ImportResults> {
    let (payload, registered): (BundlePayload, _) =
        read_transport_payload(BUNDLE_MAGIC, bundle_path, passphrase)?;
    validate_transport_format(registered, payload.auth_data.is_some())?;
    validate_bundle_auth_bindings(&payload.credentials, payload.auth_data.as_ref())?;
    let project_name = if payload.project.is_empty() {
        core::resolve_active_project()
    } else {
        payload.project.clone()
    };
    let import = || {
        ensure_project(vault, &project_name, "")?;
        ensure_partition(
            vault,
            &project_name,
            &payload.partition,
            &payload.description,
        )?;
        let mut results = ImportResults::default();
        import_bundle_credentials(
            vault,
            &project_name,
            &payload.partition,
            &payload.credentials,
            registered,
            &mut results,
        )?;
        if let Some(auth_data) = &payload.auth_data {
            merge_auth_data(
                vault,
                &project_name,
                &payload.partition,
                &payload.credentials,
                auth_data,
            )?;
        }
        Ok(results)
    };
    if registered {
        vault.with_transport_transaction(import)
    } else {
        import()
    }
}
