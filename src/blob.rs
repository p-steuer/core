//! Encrypted files (photos, later videos), format 1. Each file has its own
//! random key, kept in the journal, so deleting the file's record and
//! compacting the journal destroys the key (P69).
//!
//! ```text
//! header (64 bytes): magic "SCBLOBFL" | format u16 | suite u16 | vault_id [16] | blob_id [16]
//!                    | chunk size u32 | nonce prefix [16]
//! chunks: ciphertext ‖ tag of each piece of the file, all full-size except the last
//! ```
//!
//! Chunk i uses the nonce `prefix ‖ i` (64-bit big-endian) and the associated
//! data `header ‖ i ‖ is_last`, so chunks can be decrypted on their own (for
//! seeking in videos later) while reordering, truncation and appending are
//! detected. An empty file is one empty last chunk.

use zeroize::Zeroizing;

use crate::crypto::SecretKey;
use crate::crypto::aead::{self, TAG_LEN};
use crate::rand::{self, Rng};
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"SCBLOBFL";
const FORMAT: u16 = 1;
const HEADER_LEN: usize = 64;
pub(crate) const CHUNK: usize = 64 * 1024;
pub(crate) const MAX_SIZE: usize = 256 * 1024 * 1024;

fn header(
    suite: u16,
    vault_id: &[u8; 16],
    blob_id: &[u8; 16],
    chunk: u32,
    prefix: &[u8; 16],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..10].copy_from_slice(&FORMAT.to_le_bytes());
    h[10..12].copy_from_slice(&suite.to_le_bytes());
    h[12..28].copy_from_slice(vault_id);
    h[28..44].copy_from_slice(blob_id);
    h[44..48].copy_from_slice(&chunk.to_le_bytes());
    h[48..64].copy_from_slice(prefix);
    h
}

fn nonce(prefix: &[u8; 16], index: u64) -> aead::Nonce {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&index.to_be_bytes());
    n
}

fn chunk_ad(header: &[u8; HEADER_LEN], index: u64, last: bool) -> Vec<u8> {
    let mut ad = Vec::with_capacity(HEADER_LEN + 9);
    ad.extend_from_slice(header);
    ad.extend_from_slice(&index.to_le_bytes());
    ad.push(last as u8);
    ad
}

pub(crate) fn seal(
    key: &SecretKey,
    suite: u16,
    vault_id: &[u8; 16],
    blob_id: &[u8; 16],
    data: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>> {
    seal_with_chunk(key, suite, vault_id, blob_id, data, CHUNK, rng)
}

fn seal_with_chunk(
    key: &SecretKey,
    suite: u16,
    vault_id: &[u8; 16],
    blob_id: &[u8; 16],
    data: &[u8],
    chunk: usize,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>> {
    if data.len() > MAX_SIZE {
        return Err(Error::InvalidInput("file too large"));
    }
    let prefix: [u8; 16] = rand::array(rng)?;
    let h = header(suite, vault_id, blob_id, chunk as u32, &prefix);
    let count = data.len().div_ceil(chunk).max(1);
    let mut out = Vec::with_capacity(HEADER_LEN + data.len() + count * TAG_LEN);
    out.extend_from_slice(&h);
    for i in 0..count {
        let piece = &data[(i * chunk).min(data.len())..((i + 1) * chunk).min(data.len())];
        let last = i + 1 == count;
        let n = nonce(&prefix, i as u64);
        out.extend_from_slice(&aead::seal(key, &n, &chunk_ad(&h, i as u64, last), piece)?);
    }
    Ok(out)
}

pub(crate) fn open(
    key: &SecretKey,
    suite: u16,
    vault_id: &[u8; 16],
    blob_id: &[u8; 16],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let damaged = || Error::Damaged("file");
    if bytes.len() < HEADER_LEN + TAG_LEN || bytes[..8] != MAGIC[..] {
        return Err(damaged());
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT {
        return Err(Error::Unsupported("file format"));
    }
    let h: [u8; HEADER_LEN] = bytes[..HEADER_LEN].try_into().expect("64 bytes");
    let chunk = u32::from_le_bytes(h[44..48].try_into().expect("4 bytes")) as usize;
    if u16::from_le_bytes([h[10], h[11]]) != suite
        || h[12..28] != vault_id[..]
        || h[28..44] != blob_id[..]
        || !(4096..=1024 * 1024).contains(&chunk)
    {
        return Err(damaged());
    }
    let prefix: [u8; 16] = h[48..64].try_into().expect("16 bytes");

    let body = &bytes[HEADER_LEN..];
    let sealed_chunk = chunk + TAG_LEN;
    let count = body.len().div_ceil(sealed_chunk).max(1);
    let mut out = Zeroizing::new(Vec::with_capacity(body.len()));
    for i in 0..count {
        let piece = &body[i * sealed_chunk..((i + 1) * sealed_chunk).min(body.len())];
        let last = i + 1 == count;
        let n = nonce(&prefix, i as u64);
        let plain =
            aead::open(key, &n, &chunk_ad(&h, i as u64, last), piece).map_err(|_| damaged())?;
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::TestRng;

    const VAULT: [u8; 16] = [1; 16];
    const ID: [u8; 16] = [2; 16];

    fn key() -> SecretKey {
        SecretKey::from_slice(&[3; 32]).unwrap()
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn round_trip_at_chunk_edges() {
        let chunk = 4096;
        for n in [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3 * chunk + 5] {
            let d = data(n);
            let sealed =
                seal_with_chunk(&key(), 1, &VAULT, &ID, &d, chunk, &mut TestRng::new("b")).unwrap();
            assert_eq!(
                sealed.len(),
                HEADER_LEN + n + n.div_ceil(chunk).max(1) * TAG_LEN
            );
            assert_eq!(
                &open(&key(), 1, &VAULT, &ID, &sealed).unwrap()[..],
                &d[..],
                "size {n}"
            );
        }
        let big = data(3 * CHUNK + 10);
        let sealed = seal(&key(), 1, &VAULT, &ID, &big, &mut TestRng::new("big")).unwrap();
        assert_eq!(
            &open(&key(), 1, &VAULT, &ID, &sealed).unwrap()[..],
            &big[..]
        );
    }

    #[test]
    fn truncation_reordering_and_moving_are_detected() {
        let chunk = 4096;
        let d = data(3 * chunk);
        let sealed =
            seal_with_chunk(&key(), 1, &VAULT, &ID, &d, chunk, &mut TestRng::new("t")).unwrap();
        let sc = chunk + TAG_LEN;
        // Cut at every chunk boundary and in between.
        for n in [
            HEADER_LEN,
            HEADER_LEN + sc,
            HEADER_LEN + 2 * sc,
            sealed.len() - 1,
            HEADER_LEN + 10,
        ] {
            assert!(
                open(&key(), 1, &VAULT, &ID, &sealed[..n]).is_err(),
                "cut at {n}"
            );
        }
        // Chunks 0 and 1 swapped.
        let mut swapped = sealed.clone();
        swapped[HEADER_LEN..HEADER_LEN + sc]
            .copy_from_slice(&sealed[HEADER_LEN + sc..HEADER_LEN + 2 * sc]);
        swapped[HEADER_LEN + sc..HEADER_LEN + 2 * sc]
            .copy_from_slice(&sealed[HEADER_LEN..HEADER_LEN + sc]);
        assert!(open(&key(), 1, &VAULT, &ID, &swapped).is_err());
        // Something appended.
        let mut longer = sealed.clone();
        longer.extend_from_slice(&[0; 20]);
        assert!(open(&key(), 1, &VAULT, &ID, &longer).is_err());
        // Another vault, another file, another key.
        assert!(open(&key(), 1, &[9; 16], &ID, &sealed).is_err());
        assert!(open(&key(), 1, &VAULT, &[9; 16], &sealed).is_err());
        assert!(
            open(
                &SecretKey::from_slice(&[4; 32]).unwrap(),
                1,
                &VAULT,
                &ID,
                &sealed
            )
            .is_err()
        );
        // Any flipped byte.
        for i in (0..sealed.len()).step_by(97) {
            let mut b = sealed.clone();
            b[i] ^= 0x80;
            assert!(open(&key(), 1, &VAULT, &ID, &b).is_err(), "byte {i}");
        }
    }

    /// The same file sealed twice, even under the same key, gets a fresh
    /// nonce prefix, so no key and nonce repeat. (Each file also has a key of
    /// its own; this is the second line of defence.)
    #[test]
    fn the_same_file_twice_gets_fresh_nonces() {
        let d = data(100_000);
        let a = seal(&key(), 1, &VAULT, &ID, &d, &mut TestRng::new("first")).unwrap();
        let b = seal(&key(), 1, &VAULT, &ID, &d, &mut TestRng::new("second")).unwrap();
        assert_ne!(
            a[HEADER_LEN - 16..HEADER_LEN],
            b[HEADER_LEN - 16..HEADER_LEN]
        );
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }
}
