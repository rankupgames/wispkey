/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Partition management -- key grouping, encrypted .wkbundle export/import
 *              for sharing credential sets between team members.
 * Created: 2026-04-08
 * Last Modified: 2026-05-16
 */

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::bundle;
use crate::core::{self, AddCredentialRequest, CredentialType, Vault, VaultError};

const BUNDLE_MAGIC: &[u8; 4] = b"WKBX";

#[derive(Serialize, Deserialize)]
struct BundleCredential {
    name: String,
    #[serde(default)]
    description: String,
    credential_type: CredentialType,
    value: String,
    hosts: String,
    tags: String,
}

#[derive(Serialize, Deserialize)]
struct BundlePayload {
    partition: String,
    description: String,
    #[serde(default)]
    project: String,
    exported_at: String,
    credentials: Vec<BundleCredential>,
}

/// Summary of a `.wkbundle` partition import operation.
#[derive(Debug, Clone)]
pub struct ImportResults {
    /// Number of credentials successfully inserted.
    pub imported: usize,
    /// Number of credentials skipped because the destination already had them.
    pub skipped: usize,
    /// Number of credentials that failed for reasons other than duplication.
    pub errors: usize,
}

/// Encrypts and exports a partition's credentials to a `.wkbundle` file.
pub fn export_partition(
    vault: &Vault,
    partition_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<usize> {
    let active_project = core::resolve_active_project();
    let partition = vault.get_partition_in_project(&active_project, partition_name)?;
    let credentials =
        vault.list_credentials_in_partition_for_project(&active_project, partition_name)?;
    let mut bundle_credentials = Vec::with_capacity(credentials.len());

    for credential in &credentials {
        let value = vault.decrypt_credential_value(&credential.name)?;
        let hosts = credential.hosts.join(",");
        let tags = credential.tags.join(",");
        bundle_credentials.push(BundleCredential {
            name: credential.name.clone(),
            description: credential.description.clone(),
            credential_type: credential.credential_type.clone(),
            value,
            hosts,
            tags,
        });
    }

    let project_name = vault
        .get_partition_project_name(&partition.id)?
        .unwrap_or_else(core::resolve_active_project);

    let payload = BundlePayload {
        partition: partition.name.clone(),
        description: partition.description.clone(),
        project: project_name,
        exported_at: Utc::now().to_rfc3339(),
        credentials: bundle_credentials,
    };

    bundle::write_encrypted_payload(BUNDLE_MAGIC, &payload, passphrase, output_path)?;
    Ok(credentials.len())
}

/// Decrypts and imports credentials from a `.wkbundle` file into the vault.
pub fn import_partition(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<ImportResults> {
    let payload: BundlePayload =
        bundle::read_encrypted_payload(BUNDLE_MAGIC, bundle_path, passphrase)?;

    let project_name = if payload.project.is_empty() {
        core::resolve_active_project()
    } else {
        payload.project.clone()
    };

    match vault.get_project(&project_name) {
        Ok(_) => {}
        Err(VaultError::ProjectNotFound(_)) => {
            vault.create_project(&project_name, "")?;
        }
        Err(error) => return Err(error),
    }

    match vault.get_partition_in_project(&project_name, &payload.partition) {
        Ok(_) => {}
        Err(VaultError::PartitionNotFound(_)) => {
            vault.create_partition(
                &payload.partition,
                &payload.description,
                Some(&project_name),
            )?;
        }
        Err(error) => return Err(error),
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for bundle_credential in payload.credentials {
        let description = optional_non_empty(&bundle_credential.description);
        let hosts = optional_non_empty(&bundle_credential.hosts);
        let tags = optional_non_empty(&bundle_credential.tags);
        match vault.add_credential(AddCredentialRequest {
            name: &bundle_credential.name,
            credential_type: bundle_credential.credential_type,
            value: &bundle_credential.value,
            description,
            hosts,
            tags,
            partition: Some(&payload.partition),
            project: Some(&project_name),
        }) {
            Ok(_) => imported += 1,
            Err(VaultError::DuplicateCredential(_)) => skipped += 1,
            Err(_) => errors += 1,
        }
    }

    Ok(ImportResults {
        imported,
        skipped,
        errors,
    })
}

fn optional_non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}
