//! Cipher suites (crypto agility). Every file header names the suite its data
//! was made with, so new algorithms can be added later while old data stays
//! readable.

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Used for new data.
    Active,
    /// Only read, never written (being retired).
    DecryptOnly,
    /// Only for tests and experiments, never for user data.
    Experimental,
}

#[derive(Debug)]
pub struct Suite {
    pub id: u16,
    pub name: &'static str,
    pub status: Status,
}

/// Suite 1: XChaCha20-Poly1305, HKDF-SHA-256 and Argon2id (D45).
pub const SUITE_1: Suite = Suite {
    id: 1,
    name: "XChaCha20-Poly1305 + HKDF-SHA-256 + Argon2id",
    status: Status::Active,
};

const SUITES: [&Suite; 1] = [&SUITE_1];

/// The suite used for new data.
pub fn current() -> &'static Suite {
    &SUITE_1
}

/// The suite with this ID, if this version of the core can read it.
pub fn lookup(id: u16) -> Result<&'static Suite> {
    SUITES
        .iter()
        .copied()
        .find(|s| s.id == id && s.status != Status::Experimental)
        .ok_or(Error::Unsupported("cipher suite"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_suite_is_active_and_readable() {
        assert_eq!(current().status, Status::Active);
        assert_eq!(lookup(current().id).unwrap().id, 1);
    }

    #[test]
    fn unknown_suites_are_unsupported() {
        assert_eq!(lookup(0).unwrap_err(), Error::Unsupported("cipher suite"));
        assert!(lookup(2).is_err());
        assert!(lookup(u16::MAX).is_err());
    }
}
