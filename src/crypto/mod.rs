//! Cryptographic building blocks of suite 1, wrapped so the rest of the core
//! never touches the libraries directly.

pub mod aead;
pub mod kdf;
pub mod pwhash;

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::Result;
use crate::rand::Rng;

pub const KEY_LEN: usize = 32;

/// A 256-bit secret key. It lives on the heap, so moving it doesn't leave
/// copies on the stack, and it is wiped when dropped.
pub struct SecretKey(Box<[u8; KEY_LEN]>);

impl SecretKey {
    pub(crate) fn random(rng: &mut dyn Rng) -> Result<Self> {
        let mut key = Self::zero();
        rng.fill(&mut key.0[..])?;
        Ok(key)
    }

    /// Copies a key out of a slice; `None` unless it is exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut key = Self::zero();
        key.0.copy_from_slice(bytes);
        Some(key)
    }

    pub(crate) fn zero() -> Self {
        Self(Box::new([0u8; KEY_LEN]))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }

    /// An explicit copy; keys aren't `Clone`, so copies stay visible in the code.
    pub fn duplicate(&self) -> Self {
        let mut key = Self::zero();
        key.0.copy_from_slice(&self.0[..]);
        key
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// Compares secrets in constant time.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_key() {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey(..)");
    }

    #[test]
    fn from_slice_needs_exactly_32_bytes() {
        assert!(SecretKey::from_slice(&[0u8; 31]).is_none());
        assert!(SecretKey::from_slice(&[0u8; 33]).is_none());
        assert_eq!(
            SecretKey::from_slice(&[1u8; 32]).unwrap().as_bytes(),
            &[1u8; 32]
        );
    }

    #[test]
    fn equal_compares_length_and_content() {
        assert!(equal(b"abc", b"abc"));
        assert!(!equal(b"abc", b"abd"));
        assert!(!equal(b"abc", b"abcd"));
    }
}
