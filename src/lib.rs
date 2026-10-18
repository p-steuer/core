//! The security core: cryptography, keys, file and sync formats, sync merging,
//! sharing and permissions (D26). It knows nothing about the app's name; that
//! lives only in the Flutter app's `branding.json`.
//!
//! The design is described in `docs/crypto-design.tex`.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
mod fsio;
pub mod keys;
mod rand;
pub mod suite;
pub mod vault;

pub use error::{Error, Result};

/// The core's version, for the app's "About" screen and compatibility checks.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_the_manifest() {
        assert_eq!(version(), "0.1.0");
    }
}
