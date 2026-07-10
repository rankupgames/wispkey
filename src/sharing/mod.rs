/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Encrypted project and single-credential bundle sharing.
 * Created: 2026-05-16
 * Last Modified: 2026-05-16
 */

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::bundle;
use crate::core::{
    AddCredentialRequest, CredentialType, DEFAULT_PARTITION_NAME, DEFAULT_PROJECT_NAME, Vault,
    VaultError,
};

const PROJECT_BUNDLE_MAGIC: &[u8; 4] = b"WKPJ";
const CREDENTIAL_BUNDLE_MAGIC: &[u8; 4] = b"WKCR";

/// Summary of an encrypted project or credential bundle import operation.
#[derive(Debug, Clone)]
pub struct ImportResults {
    /// Number of credentials successfully inserted.
    pub imported: usize,
    /// Number of credentials skipped because the destination already had them.
    pub skipped: usize,
    /// Number of credentials that failed for reasons other than duplication.
    pub errors: usize,
}

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
struct BundlePartition {
    name: String,
    #[serde(default)]
    description: String,
    credentials: Vec<BundleCredential>,
}

#[derive(Serialize, Deserialize)]
struct ProjectBundlePayload {
    project: String,
    #[serde(default)]
    description: String,
    exported_at: String,
    partitions: Vec<BundlePartition>,
}

#[derive(Serialize, Deserialize)]
struct CredentialBundlePayload {
    project: String,
    partition: String,
    exported_at: String,
    credential: BundleCredential,
}

/// Exports every partition and credential in a project into one encrypted
/// bundle while keeping the plaintext secrets only in memory.
pub fn export_project(
    vault: &Vault,
    project_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<usize> {
    let project = vault.get_project(project_name)?;
    let partitions = vault.list_partitions_in_project(project_name)?;
    let mut exported_credentials = 0usize;
    let mut bundle_partitions = Vec::with_capacity(partitions.len());

    for partition in partitions {
        let credentials =
            vault.list_credentials_in_partition_for_project(project_name, &partition.name)?;
        let mut bundle_credentials = Vec::with_capacity(credentials.len());

        for credential in credentials {
            let value =
                vault.decrypt_credential_value_in_project(project_name, &credential.name)?;
            bundle_credentials.push(BundleCredential {
                name: credential.name,
                description: credential.description,
                credential_type: credential.credential_type,
                value,
                hosts: credential.hosts.join(","),
                tags: credential.tags.join(","),
            });
            exported_credentials += 1;
        }

        bundle_partitions.push(BundlePartition {
            name: partition.name,
            description: partition.description,
            credentials: bundle_credentials,
        });
    }

    let payload = ProjectBundlePayload {
        project: project.name,
        description: project.description,
        exported_at: Utc::now().to_rfc3339(),
        partitions: bundle_partitions,
    };
    bundle::write_encrypted_payload(PROJECT_BUNDLE_MAGIC, &payload, passphrase, output_path)?;
    Ok(exported_credentials)
}

/// Imports an encrypted project bundle, creating the project and partitions
/// that are missing while leaving duplicate credentials untouched.
pub fn import_project(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<ImportResults> {
    let payload: ProjectBundlePayload =
        bundle::read_encrypted_payload(PROJECT_BUNDLE_MAGIC, bundle_path, passphrase)?;

    ensure_project(vault, &payload.project, &payload.description)?;

    let mut results = ImportResults {
        imported: 0,
        skipped: 0,
        errors: 0,
    };

    for partition in payload.partitions {
        ensure_partition(
            vault,
            &payload.project,
            &partition.name,
            &partition.description,
        )?;
        import_credentials(
            vault,
            &payload.project,
            &partition.name,
            partition.credentials,
            &mut results,
        );
    }

    Ok(results)
}

/// Exports one credential and its current project/partition placement into an
/// encrypted bundle that can be imported into the same or a different project.
pub fn export_credential(
    vault: &Vault,
    credential_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<()> {
    let credential = vault.get_credential(credential_name)?;
    let partition = credential
        .partition_id
        .as_ref()
        .and_then(|id| vault.get_partition_by_id(id).ok())
        .ok_or_else(|| VaultError::PartitionNotFound(DEFAULT_PARTITION_NAME.to_string()))?;
    let project_name = vault
        .get_partition_project_name(&partition.id)?
        .unwrap_or_else(|| DEFAULT_PROJECT_NAME.to_string());

    let value = vault.decrypt_credential_value_in_project(&project_name, &credential.name)?;
    let payload = CredentialBundlePayload {
        project: project_name,
        partition: partition.name,
        exported_at: Utc::now().to_rfc3339(),
        credential: BundleCredential {
            name: credential.name,
            description: credential.description,
            credential_type: credential.credential_type,
            value,
            hosts: credential.hosts.join(","),
            tags: credential.tags.join(","),
        },
    };

    bundle::write_encrypted_payload(CREDENTIAL_BUNDLE_MAGIC, &payload, passphrase, output_path)
}

/// Imports one encrypted credential bundle, optionally overriding the project
/// and partition encoded in the source bundle.
pub fn import_credential(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
    project_override: Option<&str>,
    partition_override: Option<&str>,
) -> crate::core::Result<ImportResults> {
    let payload: CredentialBundlePayload =
        bundle::read_encrypted_payload(CREDENTIAL_BUNDLE_MAGIC, bundle_path, passphrase)?;

    let project_name = project_override.unwrap_or(&payload.project);
    let partition_name = partition_override.unwrap_or(&payload.partition);

    ensure_project(vault, project_name, "")?;
    ensure_partition(vault, project_name, partition_name, "")?;

    let mut results = ImportResults {
        imported: 0,
        skipped: 0,
        errors: 0,
    };
    import_credentials(
        vault,
        project_name,
        partition_name,
        vec![payload.credential],
        &mut results,
    );
    Ok(results)
}

fn ensure_project(vault: &Vault, project_name: &str, description: &str) -> crate::core::Result<()> {
    match vault.get_project(project_name) {
        Ok(_) => Ok(()),
        Err(VaultError::ProjectNotFound(_)) => {
            vault.create_project(project_name, description).map(|_| ())
        }
        Err(error) => Err(error),
    }
}

fn ensure_partition(
    vault: &Vault,
    project_name: &str,
    partition_name: &str,
    description: &str,
) -> crate::core::Result<()> {
    match vault.get_partition_in_project(project_name, partition_name) {
        Ok(_) => Ok(()),
        Err(VaultError::PartitionNotFound(_)) => vault
            .create_partition(partition_name, description, Some(project_name))
            .map(|_| ()),
        Err(error) => Err(error),
    }
}

fn import_credentials(
    vault: &Vault,
    project_name: &str,
    partition_name: &str,
    credentials: Vec<BundleCredential>,
    results: &mut ImportResults,
) {
    for credential in credentials {
        let description = optional_non_empty(&credential.description);
        let hosts = optional_non_empty(&credential.hosts);
        let tags = optional_non_empty(&credential.tags);

        match vault.add_credential(AddCredentialRequest {
            name: &credential.name,
            credential_type: credential.credential_type,
            value: &credential.value,
            description,
            hosts,
            tags,
            partition: Some(partition_name),
            project: Some(project_name),
        }) {
            Ok(_) => results.imported += 1,
            Err(VaultError::DuplicateCredential(_)) => results.skipped += 1,
            Err(_) => results.errors += 1,
        }
    }
}

fn optional_non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}
