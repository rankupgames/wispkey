/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Encrypted project and single-credential bundle sharing.
 * Created: 2026-05-16
 * Last Modified: 2026-09-30
 */

use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use crate::bundle;
use crate::core::auth::AuthPartitionData;
use crate::core::cloud_sync::validate_transport_auth_bindings;
use crate::core::{
    AddCredentialRequest, CredentialType, DEFAULT_PARTITION_NAME, DEFAULT_PROJECT_NAME, Vault,
    VaultError,
};

const PROJECT_BUNDLE_MAGIC: &[u8; 4] = b"WKPJ";
const CREDENTIAL_BUNDLE_MAGIC: &[u8; 4] = b"WKCR";

/// Summary of an encrypted project or credential bundle import operation.
#[derive(Debug, Clone, Default)]
pub struct ImportResults {
    /// Number of credentials successfully inserted.
    pub imported: usize,
    /// Number of legacy credentials skipped because the destination already had them.
    pub skipped: usize,
    /// Number of legacy credentials that failed for reasons other than duplication.
    pub errors: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleCredential {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_id: Option<String>,
    #[serde(default)]
    description: String,
    credential_type: CredentialType,
    value: String,
    hosts: String,
    tags: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    lifecycle_state: Option<String>,
    #[serde(default)]
    review_at: Option<String>,
}

impl Drop for BundleCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundlePartition {
    name: String,
    #[serde(default)]
    description: String,
    credentials: Vec<BundleCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_data: Option<AuthPartitionData>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectBundlePayload {
    project: String,
    #[serde(default)]
    description: String,
    exported_at: String,
    partitions: Vec<BundlePartition>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialBundlePayload {
    project: String,
    partition: String,
    exported_at: String,
    credential: BundleCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_data: Option<AuthPartitionData>,
}

/// Policy-bearing payloads are nested, rather than adding ignorable fields to
/// legacy payloads. Older readers cannot locate their required top-level fields,
/// even if somebody rewrites the unauthenticated outer framing bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthEnvelope<T> {
    version: u8,
    payload: T,
}

pub(crate) fn write_transport_payload<T: Serialize>(
    magic: &[u8; 4],
    payload: &T,
    registered: bool,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<()> {
    if registered {
        bundle::write_encrypted_payload(
            magic,
            &AuthEnvelope {
                version: 2,
                payload,
            },
            passphrase,
            output_path,
        )
    } else {
        bundle::write_encrypted_payload(magic, payload, passphrase, output_path)
    }
}

pub(crate) fn read_transport_payload<T: DeserializeOwned>(
    magic: &[u8; 4],
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<(T, bool)> {
    // Parse the authenticated document before choosing a format. Never retry a
    // failed v2 decode as legacy: malformed policy must not be silently ignored.
    let value: serde_json::Value = bundle::read_encrypted_payload(magic, bundle_path, passphrase)?;
    if value.get("version").is_some() || value.get("payload").is_some() {
        let envelope: AuthEnvelope<T> = serde_json::from_value(value)
            .map_err(|_| VaultError::InvalidBundle("invalid auth bundle envelope".into()))?;
        if envelope.version != 2 {
            return Err(VaultError::InvalidBundle(
                "unsupported auth bundle version".into(),
            ));
        }
        Ok((envelope.payload, true))
    } else {
        serde_json::from_value(value)
            .map(|payload| (payload, false))
            .map_err(|_| VaultError::InvalidBundle("invalid legacy bundle payload".into()))
    }
}

pub(crate) fn optional_auth_data(data: AuthPartitionData) -> Option<AuthPartitionData> {
    (!data.records.is_empty() || !data.bundles.is_empty()).then_some(data)
}

/// Exports a whole project, retaining registered auth identity and restrictions.
pub fn export_project(
    vault: &Vault,
    project_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<usize> {
    let payload = vault.with_transport_snapshot(|| {
        let project = vault.get_project(project_name)?;
        let mut bundle_partitions = Vec::new();
        for partition in vault.list_partitions_in_project(project_name)? {
            let credentials = export_bundle_credentials(vault, project_name, &partition.name)?;
            let auth_data =
                optional_auth_data(vault.export_auth_partition(project_name, &partition.name)?);
            bundle_partitions.push(BundlePartition {
                name: partition.name,
                description: partition.description,
                credentials,
                auth_data,
            });
        }
        Ok(ProjectBundlePayload {
            project: project.name,
            description: project.description,
            exported_at: Utc::now().to_rfc3339(),
            partitions: bundle_partitions,
        })
    })?;
    let registered = payload
        .partitions
        .iter()
        .any(|partition| partition.auth_data.is_some());
    let count = payload
        .partitions
        .iter()
        .map(|partition| partition.credentials.len())
        .sum();
    write_transport_payload(
        PROJECT_BUNDLE_MAGIC,
        &payload,
        registered,
        passphrase,
        output_path,
    )?;
    Ok(count)
}

/// Imports an encrypted project. Registered payloads commit every credential,
/// reference and restriction together, or roll back the entire import.
pub fn import_project(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<ImportResults> {
    let (payload, registered): (ProjectBundlePayload, _) =
        read_transport_payload(PROJECT_BUNDLE_MAGIC, bundle_path, passphrase)?;
    validate_transport_format(
        registered,
        payload
            .partitions
            .iter()
            .any(|partition| partition.auth_data.is_some()),
    )?;
    for partition in &payload.partitions {
        validate_bundle_auth_bindings(&partition.credentials, partition.auth_data.as_ref())?;
    }
    let import = || {
        ensure_project(vault, &payload.project, &payload.description)?;
        let mut results = ImportResults::default();
        let mut names = std::collections::HashSet::new();
        for partition in &payload.partitions {
            if !names.insert(&partition.name) {
                return Err(VaultError::InvalidBundle(
                    "duplicate bundle partition".into(),
                ));
            }
            ensure_partition(
                vault,
                &payload.project,
                &partition.name,
                &partition.description,
            )?;
            import_bundle_credentials(
                vault,
                &payload.project,
                &partition.name,
                &partition.credentials,
                registered,
                &mut results,
            )?;
            if let Some(auth_data) = &partition.auth_data {
                merge_auth_data(
                    vault,
                    &payload.project,
                    &partition.name,
                    &partition.credentials,
                    auth_data,
                )?;
            }
        }
        Ok(results)
    };
    if registered {
        vault.with_transport_transaction(import)
    } else {
        import()
    }
}

/// Exports one credential with its auth metadata; named bundles are omitted.
pub fn export_credential(
    vault: &Vault,
    credential_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<()> {
    let payload = vault.with_transport_snapshot(|| {
        let credential = vault.get_credential(credential_name)?;
        let partition = credential
            .partition_id
            .as_ref()
            .and_then(|id| vault.get_partition_by_id(id).ok())
            .ok_or_else(|| VaultError::PartitionNotFound(DEFAULT_PARTITION_NAME.to_string()))?;
        let project_name = vault
            .get_partition_project_name(&partition.id)?
            .unwrap_or_else(|| DEFAULT_PROJECT_NAME.to_string());
        let mut auth_data = vault.export_auth_partition(&project_name, &partition.name)?;
        auth_data
            .records
            .retain(|record| record.credential_name == credential.name);
        auth_data.bundles.clear();
        let bundle_credential = export_bundle_credential(vault, &project_name, credential)?;
        Ok(CredentialBundlePayload {
            project: project_name,
            partition: partition.name,
            exported_at: Utc::now().to_rfc3339(),
            credential: bundle_credential,
            auth_data: optional_auth_data(auth_data),
        })
    })?;
    write_transport_payload(
        CREDENTIAL_BUNDLE_MAGIC,
        &payload,
        payload.auth_data.is_some(),
        passphrase,
        output_path,
    )
}

/// Imports a single credential. Registered auth cannot be rebound to another
/// project or partition by a transport override.
pub fn import_credential(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
    project_override: Option<&str>,
    partition_override: Option<&str>,
) -> crate::core::Result<ImportResults> {
    let (payload, registered): (CredentialBundlePayload, _) =
        read_transport_payload(CREDENTIAL_BUNDLE_MAGIC, bundle_path, passphrase)?;
    validate_transport_format(registered, payload.auth_data.is_some())?;
    validate_bundle_auth_bindings(
        std::slice::from_ref(&payload.credential),
        payload.auth_data.as_ref(),
    )?;
    let project_name = project_override.unwrap_or(&payload.project);
    let partition_name = partition_override.unwrap_or(&payload.partition);
    if registered && (project_name != payload.project || partition_name != payload.partition) {
        return Err(VaultError::InvalidBundle(
            "registered auth scope cannot be overridden".into(),
        ));
    }
    if payload
        .auth_data
        .as_ref()
        .is_some_and(|data| !data.bundles.is_empty() || data.records.len() != 1)
    {
        return Err(VaultError::InvalidBundle(
            "single credential auth metadata is invalid".into(),
        ));
    }
    let import = || {
        ensure_project(vault, project_name, "")?;
        ensure_partition(vault, project_name, partition_name, "")?;
        let mut results = ImportResults::default();
        let credentials = std::slice::from_ref(&payload.credential);
        import_bundle_credentials(
            vault,
            project_name,
            partition_name,
            credentials,
            registered,
            &mut results,
        )?;
        if let Some(auth_data) = &payload.auth_data {
            merge_auth_data(vault, project_name, partition_name, credentials, auth_data)?;
        }
        Ok(results)
    };
    if registered {
        vault.with_transport_transaction(import)
    } else {
        import()
    }
}

pub(crate) fn validate_transport_format(
    registered: bool,
    has_auth: bool,
) -> crate::core::Result<()> {
    if registered != has_auth {
        return Err(VaultError::InvalidBundle(
            "auth metadata requires the v2 envelope".into(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_project(
    vault: &Vault,
    project_name: &str,
    description: &str,
) -> crate::core::Result<()> {
    match vault.get_project(project_name) {
        Ok(_) => Ok(()),
        Err(VaultError::ProjectNotFound(_)) => {
            vault.create_project(project_name, description).map(|_| ())
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_partition(
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

pub(crate) fn export_bundle_credentials(
    vault: &Vault,
    project: &str,
    partition: &str,
) -> crate::core::Result<Vec<BundleCredential>> {
    vault
        .list_credentials_in_partition_for_project(project, partition)?
        .into_iter()
        .map(|credential| export_bundle_credential(vault, project, credential))
        .collect()
}

fn export_bundle_credential(
    vault: &Vault,
    project: &str,
    credential: crate::core::Credential,
) -> crate::core::Result<BundleCredential> {
    let value = vault.decrypt_credential_for_transfer(project, &credential.name)?;
    let auth_id = vault
        .auth_metadata_for_id(&credential.id)?
        .map(|metadata| metadata.id);
    Ok(BundleCredential {
        name: credential.name,
        auth_id,
        description: credential.description,
        credential_type: credential.credential_type,
        value,
        hosts: credential.hosts.join(","),
        tags: credential.tags.join(","),
        origin: credential.origin,
        lifecycle_state: Some(credential.lifecycle_state),
        review_at: credential.review_at.map(|date| date.to_rfc3339()),
    })
}

pub(crate) fn import_bundle_credentials(
    vault: &Vault,
    project: &str,
    partition: &str,
    credentials: &[BundleCredential],
    strict: bool,
    results: &mut ImportResults,
) -> crate::core::Result<()> {
    for credential in credentials {
        let request = AddCredentialRequest {
            name: &credential.name,
            credential_type: credential.credential_type.clone(),
            value: &credential.value,
            description: optional_non_empty(&credential.description),
            hosts: optional_non_empty(&credential.hosts),
            tags: optional_non_empty(&credential.tags),
            partition: Some(partition),
            project: Some(project),
            origin: optional_non_empty(&credential.origin),
            lifecycle_state: credential.lifecycle_state.as_deref(),
            review_at: credential.review_at.as_deref(),
        };
        let result = if strict {
            vault.insert_transport_credential(request)
        } else {
            vault.add_credential(request)
        };
        match result {
            Ok(_) => results.imported += 1,
            Err(error) if strict => return Err(error),
            Err(VaultError::DuplicateCredential(_)) => results.skipped += 1,
            Err(_) => results.errors += 1,
        }
    }
    Ok(())
}

pub(crate) fn validate_bundle_auth_bindings(
    credentials: &[BundleCredential],
    auth_data: Option<&AuthPartitionData>,
) -> crate::core::Result<()> {
    validate_transport_auth_bindings(
        credentials
            .iter()
            .map(|credential| (credential.name.as_str(), credential.auth_id.as_deref())),
        auth_data,
    )
}

pub(crate) fn merge_auth_data(
    vault: &Vault,
    project: &str,
    partition: &str,
    credentials: &[BundleCredential],
    auth_data: &AuthPartitionData,
) -> crate::core::Result<()> {
    if auth_data.records.iter().any(|record| {
        !credentials
            .iter()
            .any(|credential| credential.name == record.credential_name)
    }) {
        return Err(VaultError::InvalidBundle(
            "auth record is missing its credential".into(),
        ));
    }
    let mut combined = vault.export_auth_partition(project, partition)?;
    combined.records.extend(auth_data.records.iter().cloned());
    combined.bundles.extend(auth_data.bundles.iter().cloned());
    vault.import_auth_partition(project, partition, &combined)
}

fn optional_non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}
