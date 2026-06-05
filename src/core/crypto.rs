use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::Connection;

use super::{Result, Vault, VaultError};

impl Vault {
    pub(crate) fn encrypt_bytes(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
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

    pub(crate) fn decrypt_bytes(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
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

    /// Borrow the underlying SQLite connection (read-only use recommended when locked).
    #[must_use]
    pub fn db(&self) -> &Connection {
        &self.db
    }
}
