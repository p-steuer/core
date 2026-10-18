//! Randomness. Production code uses the operating system's generator; tests
//! can use a deterministic one to build reproducible golden files.

use crate::{Error, Result};

pub(crate) trait Rng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// The operating system's cryptographic random number generator.
pub(crate) struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|_| Error::Randomness)
    }
}

/// Random public values: salts, nonces and identifiers. Secret keys use
/// [`crate::crypto::SecretKey::random`] instead, which keeps them off the stack.
pub(crate) fn array<const N: usize>(rng: &mut dyn Rng) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

/// A uniformly random number below `bound`, without modulo bias.
pub(crate) fn below(rng: &mut dyn Rng, bound: u32) -> Result<u32> {
    assert!(bound > 0);
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let v = u32::from_le_bytes(array(rng)?);
        if v < zone {
            return Ok(v % bound);
        }
    }
}

/// A deterministic generator for tests: SHA-256(seed ‖ counter) blocks.
#[cfg(test)]
pub(crate) struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(test)]
impl TestRng {
    pub(crate) fn new(label: &str) -> Self {
        use sha2::Digest;
        Self {
            seed: sha2::Sha256::digest(label.as_bytes()).into(),
            counter: 0,
        }
    }
}

#[cfg(test)]
impl Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        use sha2::Digest;
        for chunk in buf.chunks_mut(32) {
            let mut h = sha2::Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            let block = h.finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_rng_fills_and_varies() {
        let a: [u8; 32] = array(&mut OsRng).unwrap();
        let b: [u8; 32] = array(&mut OsRng).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn test_rng_is_deterministic() {
        let a: [u8; 40] = array(&mut TestRng::new("x")).unwrap();
        let b: [u8; 40] = array(&mut TestRng::new("x")).unwrap();
        let c: [u8; 40] = array(&mut TestRng::new("y")).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn below_stays_in_range_and_covers_it() {
        let mut rng = TestRng::new("below");
        let mut seen = [false; 6];
        for _ in 0..200 {
            let v = below(&mut rng, 6).unwrap();
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }
}
