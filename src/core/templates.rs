use super::{AddCredentialRequest, CredentialType, Result, VaultError};

/// Stable identifier for the initial compound OVH API template.
pub const OVH_API_TEMPLATE: &str = "ovh_api";

/// Owner-provided fields for the OVH API compound credential template.
#[derive(Debug, Clone)]
pub struct OvhApiTemplate<'a> {
    pub name_prefix: &'a str,
    pub application_key: &'a str,
    pub application_secret: &'a str,
    pub consumer_key: &'a str,
    pub description: Option<&'a str>,
    pub hosts: Option<&'a str>,
    pub tags: Option<&'a str>,
    pub partition: Option<&'a str>,
    pub project: Option<&'a str>,
}

/// Owned credential-create payload produced by a compound template.
#[derive(Debug, Clone)]
pub struct OwnedAddCredentialRequest {
    pub name: String,
    pub credential_type: CredentialType,
    pub value: String,
    pub description: Option<String>,
    pub hosts: Option<String>,
    pub tags: Option<String>,
    pub partition: Option<String>,
    pub project: Option<String>,
}

impl OwnedAddCredentialRequest {
    /// Borrows this owned request as an [`AddCredentialRequest`].
    #[must_use]
    pub fn as_request(&self) -> AddCredentialRequest<'_> {
        AddCredentialRequest {
            name: &self.name,
            credential_type: self.credential_type.clone(),
            value: &self.value,
            description: self.description.as_deref(),
            hosts: self.hosts.as_deref(),
            tags: self.tags.as_deref(),
            partition: self.partition.as_deref(),
            project: self.project.as_deref(),
        }
    }
}

/// Expands a named compound template into discrete credential create requests.
pub fn expand_credential_template(
    template: &str,
    ovh: OvhApiTemplate<'_>,
) -> Result<Vec<OwnedAddCredentialRequest>> {
    match template {
        OVH_API_TEMPLATE => expand_ovh_api(ovh),
        other => Err(VaultError::InvalidCredentialTemplate(other.to_string())),
    }
}

fn expand_ovh_api(ovh: OvhApiTemplate<'_>) -> Result<Vec<OwnedAddCredentialRequest>> {
    let prefix = ovh.name_prefix.trim();
    if prefix.is_empty() {
        return Err(VaultError::EmptyCredentialName);
    }

    let fields = [
        (
            format!("{prefix}-application-key"),
            ovh.application_key,
            "OVH Application Key",
        ),
        (
            format!("{prefix}-application-secret"),
            ovh.application_secret,
            "OVH Application Secret",
        ),
        (
            format!("{prefix}-consumer-key"),
            ovh.consumer_key,
            "OVH Consumer Key",
        ),
    ];

    fields
        .into_iter()
        .map(|(name, value, default_description)| {
            if value.trim().is_empty() {
                return Err(VaultError::EmptyCredentialValue);
            }
            Ok(OwnedAddCredentialRequest {
                name,
                credential_type: CredentialType::ApiKey,
                value: value.to_string(),
                description: Some(
                    ovh.description
                        .map(str::trim)
                        .filter(|description| !description.is_empty())
                        .unwrap_or(default_description)
                        .to_string(),
                ),
                hosts: ovh.hosts.map(str::to_string),
                tags: Some(ovh.tags.unwrap_or("ovh").to_string()),
                partition: ovh.partition.map(str::to_string),
                project: ovh.project.map(str::to_string),
            })
        })
        .collect()
}
