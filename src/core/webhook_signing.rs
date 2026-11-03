/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Exact-ID webhook signing-key use for instance-authenticated verification.
 * Created: 2026-11-03
 * Last Modified: 2026-11-03
 */

use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use super::instances::INSTANCE_STATUS_ACTIVE;
use super::rows::credential_from_row;
use super::{Credential, CredentialType, LIFECYCLE_ACTIVE, Vault, VaultError};
use crate::webhooks::{SignedWebhook, VERIFY_PATH, WebhookDenial, WebhookResult};

/// Proof that the caller presented a valid instance secret in this request.
pub(crate) struct WebhookInstance {
    id: String,
}

/// Stored credential state that a valid result must still match before release.
struct SigningCredential {
    credential: Credential,
    encrypted_value: String,
    updated_at: String,
}

impl Vault {
    /// Authenticates the requesting instance by its existing ID-and-secret pair.
    pub(crate) fn authenticate_webhook_instance(
        &self,
        instance_identifier: &str,
        instance_secret: &str,
    ) -> Result<WebhookInstance, WebhookDenial> {
        self.ensure_unlocked()
            .map_err(|_| WebhookDenial::Unavailable)?;
        let authenticated = self
            .get_instance(instance_identifier)
            .ok()
            .filter(|instance| {
                self.verify_instance_secret(&instance.id, instance_secret)
                    .unwrap_or(false)
            });
        match authenticated {
            Some(instance) => Ok(WebhookInstance { id: instance.id }),
            None => {
                self.audit_webhook_denial(WebhookDenial::Unauthenticated, None);
                Err(WebhookDenial::Unauthenticated)
            }
        }
    }

    /// Verifies one signed webhook with the exact in-scope signing credential.
    ///
    /// The decrypted key stays inside this call. A valid result requires a
    /// recheck of the instance, scope, credential state and auth registry, and a
    /// committed audit row.
    pub(crate) fn verify_webhook(
        &self,
        instance: &WebhookInstance,
        credential_id: &str,
        project_scope: Option<&str>,
        webhook: &SignedWebhook,
        now_unix_seconds: i64,
    ) -> Result<WebhookResult, WebhookDenial> {
        let outcome = self.verify_webhook_in_transaction(
            instance,
            credential_id,
            project_scope,
            webhook,
            now_unix_seconds,
        );
        if let Err(denial) = outcome {
            self.audit_webhook_denial(denial, Some(instance));
        }
        outcome
    }

    fn verify_webhook_in_transaction(
        &self,
        instance: &WebhookInstance,
        credential_id: &str,
        project_scope: Option<&str>,
        webhook: &SignedWebhook,
        now_unix_seconds: i64,
    ) -> Result<WebhookResult, WebhookDenial> {
        let master_key = self
            .ensure_unlocked()
            .map_err(|_| WebhookDenial::Unavailable)?;
        let transaction = self
            .db
            .unchecked_transaction()
            .map_err(|_| WebhookDenial::Unavailable)?;
        let signing = self.authorized_signing_credential(instance, credential_id, project_scope)?;

        let result = if !webhook.is_fresh_at(now_unix_seconds) {
            WebhookResult::Stale
        } else {
            let encrypted = self
                .decode_auth_ciphertext(&signing.credential.id, &signing.encrypted_value)
                .map_err(auth_denial)?;
            let plaintext = Zeroizing::new(
                self.decrypt_bytes(master_key, &encrypted)
                    .map_err(|_| WebhookDenial::Unavailable)?,
            );
            let signature_matches = webhook
                .matches_signing_secret(&plaintext)
                .map_err(|_| WebhookDenial::Forbidden)?;
            if signature_matches {
                self.recheck_signing_release(instance, &signing, project_scope)?;
                WebhookResult::Valid
            } else {
                WebhookResult::Invalid
            }
        };

        let audit_reason = match result {
            WebhookResult::Valid => None,
            WebhookResult::Invalid => Some("signature_mismatch"),
            WebhookResult::Stale => Some("timestamp_outside_tolerance"),
        };
        let instance_principal = format!("instance:{}", instance.id);
        crate::audit::try_log_event(
            &self.db,
            if result == WebhookResult::Valid {
                "WebhookVerified"
            } else {
                "WebhookRejected"
            },
            Some(&signing.credential.id),
            None,
            Some(&instance_principal),
            Some(VERIFY_PATH),
            Some("POST"),
            Some(200),
            audit_reason.is_some(),
            audit_reason,
            None,
        )
        .map_err(|_| WebhookDenial::Unavailable)?;
        transaction.commit().map_err(|_| WebhookDenial::Unavailable)?;
        Ok(result)
    }

    /// Resolves the exact credential only when the instance may use it as a webhook key.
    /// Absent and out-of-scope credentials return the same denial.
    fn authorized_signing_credential(
        &self,
        instance: &WebhookInstance,
        credential_id: &str,
        project_scope: Option<&str>,
    ) -> Result<SigningCredential, WebhookDenial> {
        self.ensure_signing_scope(instance, credential_id, project_scope)?;
        let signing = self
            .db
            .query_row(
                "SELECT id, name, description, credential_type, wisp_token, hosts, tags, created_at, updated_at, last_used_at, partition_id, origin, lifecycle_state, review_at, encrypted_value FROM credentials WHERE id = ?1",
                params![credential_id],
                |row| {
                    Ok(SigningCredential {
                        credential: credential_from_row(row)?,
                        encrypted_value: row.get(14)?,
                        updated_at: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(|_| WebhookDenial::Unavailable)?
            .ok_or(WebhookDenial::Forbidden)?;
        if signing.credential.credential_type != CredentialType::ApiKey
            || signing.credential.lifecycle_state != LIFECYCLE_ACTIVE
        {
            return Err(WebhookDenial::Forbidden);
        }
        self.ensure_auth_usable(&signing.credential.id, true, None)
            .map_err(auth_denial)?;
        Ok(signing)
    }

    fn ensure_signing_scope(
        &self,
        instance: &WebhookInstance,
        credential_id: &str,
        project_scope: Option<&str>,
    ) -> Result<(), WebhookDenial> {
        let instance_active = self
            .db
            .query_row(
                "SELECT status FROM instances WHERE id = ?1",
                params![instance.id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| WebhookDenial::Unavailable)?
            .is_some_and(|status| status == INSTANCE_STATUS_ACTIVE);
        if !instance_active {
            return Err(WebhookDenial::Unauthenticated);
        }
        if !self
            .credential_in_scope(&instance.id, credential_id)
            .map_err(|_| WebhookDenial::Unavailable)?
        {
            return Err(WebhookDenial::Forbidden);
        }
        if let Some(project_scope) = project_scope {
            let credential_project: Option<String> = self
                .db
                .query_row(
                    "SELECT p.name FROM credentials c JOIN partitions pt ON pt.id = c.partition_id JOIN projects p ON p.id = pt.project_id WHERE c.id = ?1",
                    params![credential_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| WebhookDenial::Unavailable)?;
            if credential_project.as_deref() != Some(project_scope) {
                return Err(WebhookDenial::Forbidden);
            }
        }
        Ok(())
    }

    /// Last check before a valid result: identity, scope, stored value and auth deadlines.
    fn recheck_signing_release(
        &self,
        instance: &WebhookInstance,
        signing: &SigningCredential,
        project_scope: Option<&str>,
    ) -> Result<(), WebhookDenial> {
        self.ensure_signing_scope(instance, &signing.credential.id, project_scope)?;
        let unchanged: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id = ?1 AND encrypted_value = ?2 AND updated_at = ?3 AND lifecycle_state = ?4)",
                params![
                    signing.credential.id,
                    signing.encrypted_value,
                    signing.updated_at,
                    LIFECYCLE_ACTIVE
                ],
                |row| row.get(0),
            )
            .map_err(|_| WebhookDenial::Unavailable)?;
        if !unchanged {
            return Err(WebhookDenial::Forbidden);
        }
        self.ensure_auth_usable(&signing.credential.id, true, None)
            .map_err(auth_denial)
    }

    /// Records a metadata-only denial. Only the authenticated instance ID is trusted.
    pub(crate) fn audit_webhook_denial(
        &self,
        denial: WebhookDenial,
        instance: Option<&WebhookInstance>,
    ) {
        let instance_principal = instance.map(|instance| format!("instance:{}", instance.id));
        crate::audit::log_event(
            &self.db,
            "WebhookDenied",
            None,
            None,
            instance_principal.as_deref(),
            Some(VERIFY_PATH),
            Some("POST"),
            Some(denial.status().as_u16()),
            true,
            Some(denial.audit_reason()),
            None,
        );
    }
}

fn auth_denial(error: VaultError) -> WebhookDenial {
    match error {
        VaultError::Database(_) => WebhookDenial::Unavailable,
        _ => WebhookDenial::Forbidden,
    }
}
