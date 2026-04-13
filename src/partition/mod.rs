/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Partition management -- key grouping, encrypted .wkbundle export/import
 *              for sharing credential sets between team members.
 * Created: 2026-04-08
 * Last Modified: 2026-04-08
 */

use std::fs;
use std::path::Path;

use argon2::Argon2;
use chrono::Utc;
use rand::Rng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::core::{CredentialType, Vault, VaultError};

const BUNDLE_MAGIC: &[u8; 4] = b"WKBX";
const BUNDLE_VERSION: u8 = 1;

const BUNDLE_HEADER_LEN: usize = 4 + 1 + 32 + 12;

#[derive(Serialize, Deserialize)]
struct BundleCredential {
    name: String,
    credential_type: CredentialType,
    value: String,
    hosts: String,
    tags: String,
}

#[derive(Serialize, Deserialize)]
struct BundlePayload {
    partition: String,
    description: String,
    exported_at: String,
    credentials: Vec<BundleCredential>,
}

#[derive(Debug, Clone)]
pub struct ImportResults {
    pub imported: usize,
    pub skipped: usize,
    pub errors: usize,
}

pub fn export_partition(
    vault: &Vault,
    partition_name: &str,
    passphrase: &str,
    output_path: &str,
) -> crate::core::Result<usize> {
    let partition = vault.get_partition(partition_name)?;
    let credentials = vault.list_credentials_in_partition(partition_name)?;
    let mut bundle_credentials = Vec::with_capacity(credentials.len());

    for credential in &credentials {
        let value = vault.decrypt_credential_value(&credential.name)?;
        let hosts = credential.hosts.join(",");
        let tags = credential.tags.join(",");
        bundle_credentials.push(BundleCredential {
            name: credential.name.clone(),
            credential_type: credential.credential_type.clone(),
            value,
            hosts,
            tags,
        });
    }

    let payload = BundlePayload {
        partition: partition.name.clone(),
        description: partition.description.clone(),
        exported_at: Utc::now().to_rfc3339(),
        credentials: bundle_credentials,
    };

    let json =
        serde_json::to_vec(&payload).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;

    let mut salt = [0u8; 32];
    rand::rng().fill(&mut salt);

    let mut derived_key = [0u8; 32];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
    );
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| VaultError::InvalidBundle(e.to_string()))?;

    let encrypted_payload = aes_gcm_encrypt(&derived_key, &json)?;

    let mut file_bytes =
        Vec::with_capacity(BUNDLE_MAGIC.len() + 1 + salt.len() + encrypted_payload.len());
    file_bytes.extend_from_slice(BUNDLE_MAGIC);
    file_bytes.push(BUNDLE_VERSION);
    file_bytes.extend_from_slice(&salt);
    file_bytes.extend_from_slice(&encrypted_payload);

    fs::write(Path::new(output_path), &file_bytes)?;

    Ok(credentials.len())
}

pub fn import_partition(
    vault: &Vault,
    bundle_path: &str,
    passphrase: &str,
) -> crate::core::Result<ImportResults> {
    let data =
        fs::read(Path::new(bundle_path)).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;
    if data.len() < BUNDLE_HEADER_LEN {
        return Err(VaultError::InvalidBundle("file too short".into()));
    }
    if data.get(0..4) != Some(BUNDLE_MAGIC.as_slice()) {
        return Err(VaultError::InvalidBundle("bad magic".into()));
    }
    if data.get(4).copied() != Some(BUNDLE_VERSION) {
        return Err(VaultError::InvalidBundle(
            "unsupported bundle version".into(),
        ));
    }

    let salt = &data[5..37];
    let nonce_and_ciphertext = &data[37..];
    if nonce_and_ciphertext.len() < 12 {
        return Err(VaultError::InvalidBundle("truncated ciphertext".into()));
    }

    let mut derived_key = [0u8; 32];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
    );
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_key)
        .map_err(|e| VaultError::InvalidBundle(e.to_string()))?;

    let plaintext = aes_gcm_decrypt(&derived_key, nonce_and_ciphertext).map_err(|e| match e {
        VaultError::Encryption(message) => VaultError::InvalidBundle(message),
        other => other,
    })?;

    let payload: BundlePayload =
        serde_json::from_slice(&plaintext).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;

    match vault.get_partition(&payload.partition) {
        Ok(_) => {}
        Err(VaultError::PartitionNotFound(_)) => {
            vault.create_partition(&payload.partition, &payload.description)?;
        }
        Err(error) => return Err(error),
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for bundle_credential in payload.credentials {
        let hosts = if bundle_credential.hosts.is_empty() {
            None
        } else {
            Some(bundle_credential.hosts.as_str())
        };
        let tags = if bundle_credential.tags.is_empty() {
            None
        } else {
            Some(bundle_credential.tags.as_str())
        };
        match vault.add_credential(
            &bundle_credential.name,
            bundle_credential.credential_type,
            &bundle_credential.value,
            hosts,
            tags,
            Some(&payload.partition),
        ) {
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

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> crate::core::Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| VaultError::Encryption("RNG failure".into()))?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Encryption("invalid key".into()))?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::Encryption("seal failed".into()))?;

    let mut result = Vec::with_capacity(12 + in_out.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);
    Ok(result)
}

fn aes_gcm_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> crate::core::Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(VaultError::Encryption("ciphertext too short".into()));
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::Encryption("invalid nonce".into()))?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Encryption("invalid key".into()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut in_out = encrypted.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::Encryption("decryption failed -- wrong password?".into()))?;
    Ok(plaintext.to_vec())
}
