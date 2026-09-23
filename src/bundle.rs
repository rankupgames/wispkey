/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Shared encrypted bundle framing for partition, project, and
 *              credential exports.
 * Created: 2026-05-16
 * Last Modified: 2026-08-26
 */

use std::path::Path;

use argon2::Argon2;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::core::{Result, VaultError};
use crate::secure_files;

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_HEADER_LEN: usize = 4 + 1 + 32 + 12;
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Serializes, encrypts, and writes a typed bundle payload using the shared
/// WispKey bundle frame: four-byte magic, version, salt, nonce, and ciphertext.
pub(crate) fn write_encrypted_payload<T: Serialize>(
    magic: &[u8; 4],
    payload: &T,
    passphrase: &str,
    output_path: &str,
) -> Result<()> {
    write_encrypted_payload_with_limit(magic, payload, passphrase, output_path, MAX_BUNDLE_BYTES)
}

/// Same as [`write_encrypted_payload`] with an explicit plaintext size cap.
pub(crate) fn write_encrypted_payload_with_limit<T: Serialize>(
    magic: &[u8; 4],
    payload: &T,
    passphrase: &str,
    output_path: &str,
    max_bytes: u64,
) -> Result<()> {
    let file_bytes = encrypted_payload_bytes(magic, payload, passphrase, max_bytes)?;

    secure_files::write_private(Path::new(output_path), &file_bytes)?;
    Ok(())
}

/// Same as [`write_encrypted_payload_with_limit`] but refuses to replace an
/// existing output file. This is reserved for destructive-recovery artifacts;
/// sharing bundles retain their historical overwrite behavior.
pub(crate) fn write_encrypted_payload_with_limit_no_clobber<T: Serialize>(
    magic: &[u8; 4],
    payload: &T,
    passphrase: &str,
    output_path: &str,
    max_bytes: u64,
) -> Result<()> {
    let file_bytes = encrypted_payload_bytes(magic, payload, passphrase, max_bytes)?;
    let output = Path::new(output_path);
    if !secure_files::create_private(output, &file_bytes)? {
        return Err(VaultError::AlreadyExists(output.to_path_buf()));
    }
    Ok(())
}

fn encrypted_payload_bytes<T: Serialize>(
    magic: &[u8; 4],
    payload: &T,
    passphrase: &str,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;
    if json.len() as u64 > max_bytes {
        return Err(VaultError::InvalidBundle(
            "bundle exceeds size limit".into(),
        ));
    }
    let salt = random_bytes::<32>()?;
    let derived_key = derive_bundle_key(passphrase, &salt)?;
    let encrypted_payload = aes_gcm_encrypt(&derived_key, &json)?;

    let mut file_bytes = Vec::with_capacity(magic.len() + 1 + salt.len() + encrypted_payload.len());
    file_bytes.extend_from_slice(magic);
    file_bytes.push(BUNDLE_VERSION);
    file_bytes.extend_from_slice(&salt);
    file_bytes.extend_from_slice(&encrypted_payload);
    Ok(file_bytes)
}

/// Reads and decrypts a typed bundle payload after validating the expected
/// magic/version and applying a size cap before loading the file into memory.
pub(crate) fn read_encrypted_payload<T: for<'de> Deserialize<'de>>(
    magic: &[u8; 4],
    bundle_path: &str,
    passphrase: &str,
) -> Result<T> {
    read_encrypted_payload_with_limit(magic, bundle_path, passphrase, MAX_BUNDLE_BYTES)
}

/// Same as [`read_encrypted_payload`] with an explicit on-disk size cap.
pub(crate) fn read_encrypted_payload_with_limit<T: for<'de> Deserialize<'de>>(
    magic: &[u8; 4],
    bundle_path: &str,
    passphrase: &str,
    max_bytes: u64,
) -> Result<T> {
    let path = Path::new(bundle_path);
    let metadata = std::fs::metadata(path).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;
    if metadata.len() > max_bytes {
        return Err(VaultError::InvalidBundle(
            "bundle exceeds size limit".into(),
        ));
    }

    let data = std::fs::read(path).map_err(|e| VaultError::InvalidBundle(e.to_string()))?;
    if data.len() < BUNDLE_HEADER_LEN {
        return Err(VaultError::InvalidBundle("file too short".into()));
    }
    if data.get(0..4) != Some(magic.as_slice()) {
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

    let derived_key = derive_bundle_key(passphrase, salt)?;
    let plaintext = aes_gcm_decrypt(&derived_key, nonce_and_ciphertext).map_err(|e| match e {
        VaultError::Encryption(message) => VaultError::InvalidBundle(message),
        other => other,
    })?;

    serde_json::from_slice(&plaintext).map_err(|e| VaultError::InvalidBundle(e.to_string()))
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; N];
    rng.fill(&mut bytes)
        .map_err(|_| VaultError::Encryption("RNG failure".into()))?;
    Ok(bytes)
}

fn derive_bundle_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut derived_key = [0u8; 32];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params"),
    );
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_key)
        .map_err(|e| VaultError::InvalidBundle(e.to_string()))?;
    Ok(derived_key)
}

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = random_bytes::<12>()?;
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

fn aes_gcm_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(VaultError::Encryption("ciphertext too short".into()));
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::Encryption("invalid nonce".into()))?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Encryption("invalid key".into()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = encrypted.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::Encryption("decryption failed -- wrong password?".into()))?;
    Ok(plaintext.to_vec())
}
