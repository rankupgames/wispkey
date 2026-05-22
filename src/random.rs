/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Shared secure random token helpers.
 * Created: 2026-05-16
 * Last Modified: 2026-05-16
 */

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::{Result, VaultError};

const LOWER_ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const MIXED_ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generates an alphanumeric token using rejection sampling so management and
/// wisp-token entropy comes from the same CSPRNG-backed helper.
pub(crate) fn alphanumeric(length: usize, lowercase_only: bool) -> Result<String> {
    let alphabet = if lowercase_only {
        LOWER_ALPHANUMERIC
    } else {
        MIXED_ALPHANUMERIC
    };
    let threshold = (256 / alphabet.len()) * alphabet.len();
    let rng = SystemRandom::new();
    let mut token = String::with_capacity(length);

    while token.len() < length {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| VaultError::Encryption("RNG failure".into()))?;

        for byte in bytes {
            if token.len() == length {
                break;
            }
            let value = byte as usize;
            if value < threshold {
                token.push(alphabet[value % alphabet.len()] as char);
            }
        }
    }

    Ok(token)
}
