//! Argon2id (RFC 9106) for passphrases (P60).

use argon2::{Algorithm, Argon2, Block, Version};
use zeroize::Zeroize;

use super::SecretKey;
use crate::{Error, Result};

pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters, as stored in the keyring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes over the memory.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes.
pub const DEFAULT: Params = Params {
    m_kib: 64 * 1024,
    t: 3,
    p: 4,
};

/// Parameters a keyring may contain. Anything else is refused before any work,
/// so a damaged or hostile file can't make the app hash with no cost or
/// allocate unbounded memory.
const M_KIB_RANGE: std::ops::RangeInclusive<u32> = 19 * 1024..=1024 * 1024;
const T_RANGE: std::ops::RangeInclusive<u32> = 2..=10;
const P_RANGE: std::ops::RangeInclusive<u32> = 1..=8;

impl Params {
    pub fn check_bounds(&self) -> Result<()> {
        if M_KIB_RANGE.contains(&self.m_kib)
            && T_RANGE.contains(&self.t)
            && P_RANGE.contains(&self.p)
        {
            Ok(())
        } else {
            Err(Error::Damaged("passphrase hashing parameters out of range"))
        }
    }

    /// Whether these are weaker than `target` in some respect and stronger in
    /// none, so an unlock should re-wrap with `target`.
    pub fn should_upgrade_to(&self, target: &Params) -> bool {
        self != target && self.m_kib <= target.m_kib && self.t <= target.t
    }
}

/// The 32-byte Argon2id output for a passphrase.
pub fn hash(passphrase: &[u8], salt: &[u8; SALT_LEN], params: &Params) -> Result<SecretKey> {
    params.check_bounds()?;
    let mut out = SecretKey::zero();
    raw(passphrase, salt, params, None, None, out.as_mut_bytes())?;
    Ok(out)
}

/// Argon2id version 0x13 without the bounds check. Uses its own work memory
/// and wipes it afterwards: argon2 0.6.0's `hash_password_into` frees its
/// memory without wiping it (checked in its source, `block.rs`, 18 Oct 2026).
fn raw(
    passphrase: &[u8],
    salt: &[u8],
    params: &Params,
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    out: &mut [u8],
) -> Result<()> {
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(params.m_kib)
        .t_cost(params.t)
        .p_cost(params.p)
        .output_len(out.len());
    if let Some(ad) = associated_data {
        builder.data(argon2::AssociatedData::new(ad).map_err(|_| Error::Internal("argon2 ad"))?);
    }
    let argon_params = builder
        .build()
        .map_err(|_| Error::Internal("argon2 parameters"))?;
    let blocks_needed = argon_params.block_count();
    let argon = match secret {
        Some(s) => Argon2::new_with_secret(s, Algorithm::Argon2id, Version::V0x13, argon_params)
            .map_err(|_| Error::Internal("argon2 secret"))?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params),
    };

    let mut memory: Vec<Block> = Vec::new();
    memory
        .try_reserve_exact(blocks_needed)
        .map_err(|_| Error::OutOfMemory)?;
    memory.resize(blocks_needed, Block::new());
    let result = argon.hash_password_into_with_memory(passphrase, salt, out, &mut memory[..]);
    memory.zeroize();
    result.map_err(|_| Error::Internal("argon2"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9106, section 5.3 (with a secret and associated data, which the
    /// app itself doesn't use; this checks the variant and version).
    #[test]
    fn rfc9106_argon2id_vector() {
        let mut out = [0u8; 32];
        raw(
            &[1u8; 32],
            &[2u8; 16],
            &Params {
                m_kib: 32,
                t: 3,
                p: 4,
            },
            Some(&[3u8; 8]),
            Some(&[4u8; 12]),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn hash_matches_raw_and_depends_on_every_input() {
        let p = Params {
            m_kib: 19 * 1024,
            t: 2,
            p: 1,
        };
        let base = hash(b"correct horse", &[9; 16], &p).unwrap();
        let mut expected = [0u8; 32];
        raw(b"correct horse", &[9; 16], &p, None, None, &mut expected).unwrap();
        assert_eq!(base.as_bytes(), &expected);

        let other_pw = hash(b"correct horsf", &[9; 16], &p).unwrap();
        let other_salt = hash(b"correct horse", &[8; 16], &p).unwrap();
        let other_t = hash(b"correct horse", &[9; 16], &Params { t: 3, ..p }).unwrap();
        for other in [other_pw, other_salt, other_t] {
            assert_ne!(other.as_bytes(), base.as_bytes());
        }
    }

    #[test]
    fn out_of_range_parameters_are_refused_before_hashing() {
        for p in [
            Params {
                m_kib: 19 * 1024 - 1,
                ..DEFAULT
            },
            Params {
                m_kib: 1024 * 1024 + 1,
                ..DEFAULT
            },
            Params {
                m_kib: 0,
                ..DEFAULT
            },
            Params { t: 1, ..DEFAULT },
            Params { t: 11, ..DEFAULT },
            Params { p: 0, ..DEFAULT },
            Params { p: 9, ..DEFAULT },
            Params {
                m_kib: u32::MAX,
                t: u32::MAX,
                p: u32::MAX,
            },
        ] {
            assert!(
                matches!(hash(b"x", &[0; 16], &p), Err(Error::Damaged(_))),
                "{p:?}"
            );
        }
        assert!(DEFAULT.check_bounds().is_ok());
    }

    /// Measures the production parameters. Run in a release build:
    /// `cargo test --release --lib -- --ignored --nocapture measure`.
    #[test]
    #[ignore]
    fn measure_default_cost() {
        let runs = 5;
        let start = std::time::Instant::now();
        for i in 0..runs {
            hash(b"correct horse battery staple", &[i as u8; 16], &DEFAULT).unwrap();
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(runs);
        println!("Argon2id {DEFAULT:?}: {ms:.0} ms per hash");
    }

    #[test]
    fn upgrade_rule() {
        assert!(!DEFAULT.should_upgrade_to(&DEFAULT));
        assert!(
            Params {
                m_kib: 19 * 1024,
                t: 2,
                p: 1
            }
            .should_upgrade_to(&DEFAULT)
        );
        assert!(Params { t: 2, ..DEFAULT }.should_upgrade_to(&DEFAULT));
        assert!(Params { p: 1, ..DEFAULT }.should_upgrade_to(&DEFAULT));
        // Stronger in one respect: keep it.
        assert!(
            !Params {
                m_kib: 128 * 1024,
                t: 2,
                p: 4
            }
            .should_upgrade_to(&DEFAULT)
        );
        assert!(
            !Params {
                m_kib: 32 * 1024,
                t: 4,
                p: 4
            }
            .should_upgrade_to(&DEFAULT)
        );
    }
}
