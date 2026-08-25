/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Shared secure random token helpers.
 * Created: 2026-05-16
 * Last Modified: 2026-08-25
 */

use ring::rand::{SecureRandom, SystemRandom};

use crate::core::{Result, VaultError};

const LOWER_ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const MIXED_ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";
const DEFAULT_PASSWORD_LENGTH: usize = 24;
const TARGET_PASSWORD_ENTROPY_BITS: f64 = 128.0;

/// Password generation policy for website logins. The default is at least 128
/// bits of entropy from the OS CSPRNG, with mixed case, digits, and symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswordPolicy {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl PasswordPolicy {
    #[must_use]
    pub(crate) fn default_strong() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }

    pub(crate) fn charset(&self) -> Result<Vec<u8>> {
        let mut charset = Vec::new();
        if self.uppercase {
            charset.extend_from_slice(UPPERCASE);
        }
        if self.lowercase {
            charset.extend_from_slice(LOWERCASE);
        }
        if self.digits {
            charset.extend_from_slice(DIGITS);
        }
        if self.symbols {
            charset.extend_from_slice(SYMBOLS);
        }
        if charset.len() < 2 {
            return Err(VaultError::Encryption(
                "password policy must enable at least two character classes".into(),
            ));
        }
        Ok(charset)
    }

    pub(crate) fn required_classes(&self) -> Result<Vec<&'static [u8]>> {
        let mut classes = Vec::new();
        if self.uppercase {
            classes.push(UPPERCASE);
        }
        if self.lowercase {
            classes.push(LOWERCASE);
        }
        if self.digits {
            classes.push(DIGITS);
        }
        if self.symbols {
            classes.push(SYMBOLS);
        }
        if classes.is_empty() {
            return Err(VaultError::Encryption(
                "password policy must enable at least one character class".into(),
            ));
        }
        Ok(classes)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let charset = self.charset()?;
        let classes = self.required_classes()?;
        if self.length < classes.len() {
            return Err(VaultError::Encryption(
                "password length is shorter than the number of required character classes".into(),
            ));
        }
        let bits_per_char = (charset.len() as f64).log2();
        let min_length = (TARGET_PASSWORD_ENTROPY_BITS / bits_per_char).ceil() as usize;
        if self.length < min_length {
            return Err(VaultError::Encryption(format!(
                "password length {} is below the 128-bit minimum of {} for this charset",
                self.length, min_length
            )));
        }
        Ok(())
    }
}

/// Generates a fresh password from the OS CSPRNG using rejection sampling.
pub(crate) fn generate_password(policy: &PasswordPolicy) -> Result<String> {
    policy.validate()?;
    let charset = policy.charset()?;
    let classes = policy.required_classes()?;
    let rng = SystemRandom::new();
    let mut password = sample_bytes(&rng, &charset, policy.length)?;
    for (index, class) in classes.iter().enumerate() {
        let chosen = sample_bytes(&rng, class, 1)?;
        password[index] = chosen[0];
    }
    shuffle_bytes(&rng, &mut password)?;
    String::from_utf8(password).map_err(|error| VaultError::Encryption(error.to_string()))
}

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

fn sample_bytes(rng: &SystemRandom, alphabet: &[u8], count: usize) -> Result<Vec<u8>> {
    let threshold = (256 / alphabet.len()) * alphabet.len();
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| VaultError::Encryption("RNG failure".into()))?;
        for byte in bytes {
            if out.len() == count {
                break;
            }
            let value = byte as usize;
            if value < threshold {
                out.push(alphabet[value % alphabet.len()]);
            }
        }
    }
    Ok(out)
}

fn shuffle_bytes(rng: &SystemRandom, values: &mut [u8]) -> Result<()> {
    for i in (1..values.len()).rev() {
        let j = sample_index(rng, i + 1)?;
        values.swap(i, j);
    }
    Ok(())
}

fn sample_index(rng: &SystemRandom, len: usize) -> Result<usize> {
    if len == 0 {
        return Err(VaultError::Encryption("cannot sample empty range".into()));
    }
    let threshold = (256 / len) * len;
    loop {
        let mut bytes = [0u8; 1];
        rng.fill(&mut bytes)
            .map_err(|_| VaultError::Encryption("RNG failure".into()))?;
        let value = bytes[0] as usize;
        if value < threshold {
            return Ok(value % len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_meets_128_bit_minimum() {
        PasswordPolicy::default_strong()
            .validate()
            .expect("default policy should be at least 128 bits");
    }

    #[test]
    fn short_policy_is_rejected() {
        let policy = PasswordPolicy {
            length: 8,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn generated_password_matches_policy_and_is_fresh() {
        let policy = PasswordPolicy::default_strong();
        let first = generate_password(&policy).expect("first password");
        let second = generate_password(&policy).expect("second password");
        assert_eq!(first.len(), 24);
        assert_eq!(second.len(), 24);
        assert_ne!(first, second);
        for password in [&first, &second] {
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| SYMBOLS.contains(&(c as u8))));
        }
    }
}
