//! The journal file, format 1: an append-only sequence of encrypted batches
//! (P59). One file per generation, `journal-00000001.log` and so on; each
//! generation has its own key (P69).
//!
//! ```text
//! header (32 bytes): magic "SCJOURNL" | format u16 | suite u16 | vault_id [16] | generation u32
//! frames, each: length u32 | !length u32 | kind u8 (1 = batch) | device_id [16] | seq u64 | nonce [24] | ciphertext
//! ```
//!
//! `length` counts everything after the two length fields; `!length` is its
//! bitwise complement. A frame's associated data is the file header followed
//! by the frame's lengths, kind, device_id and seq, so a frame can't be moved
//! to another vault, generation, device or position. Sequence numbers start at
//! 1 in every file and increase by one.
//!
//! A crash while appending leaves at most an incomplete or garbled last
//! frame; reading reports it as a torn end, which is cut off. Anything wrong
//! before the last frame is damage: the vault then opens read-only and
//! nothing is deleted. The complement makes a damaged length field look like
//! damage: without it, one flipped bit in an early frame's length could make
//! every later frame look like an unfinished last one, and be cut off.

use zeroize::Zeroizing;

use crate::crypto::SecretKey;
use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
use crate::rand::Rng;
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"SCJOURNL";
const FORMAT: u16 = 1;
pub(crate) const HEADER_LEN: usize = 32;
const KIND_BATCH: u8 = 1;
/// The two length fields.
const LENGTHS: usize = 8;
/// Kind, device, seq and nonce: the fixed part after the lengths.
const FIXED: usize = 1 + 16 + 8 + NONCE_LEN;
pub(crate) const MAX_PLAINTEXT: usize = 1024 * 1024;
const MAX_FRAME: usize = FIXED + MAX_PLAINTEXT + TAG_LEN;
/// Plaintexts are padded to a multiple of this (with JSON whitespace), so
/// frame sizes say less about their content.
const PAD: usize = 128;

pub(crate) type Header = [u8; HEADER_LEN];

pub(crate) fn file_name(generation: u32) -> String {
    format!("journal-{generation:08}.log")
}

pub(crate) fn generation_of(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("journal-")?.strip_suffix(".log")?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|g| *g > 0)
}

pub(crate) fn header(suite: u16, vault_id: &[u8; 16], generation: u32) -> Header {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..10].copy_from_slice(&FORMAT.to_le_bytes());
    h[10..12].copy_from_slice(&suite.to_le_bytes());
    h[12..28].copy_from_slice(vault_id);
    h[28..32].copy_from_slice(&generation.to_le_bytes());
    h
}

/// Pads with spaces, which JSON ignores at the end.
pub(crate) fn pad(plaintext: &mut Zeroizing<Vec<u8>>) {
    let target = plaintext.len().div_ceil(PAD) * PAD;
    plaintext.resize(target, b' ');
}

/// One encrypted frame, ready to append.
pub(crate) fn seal_frame(
    key: &SecretKey,
    header: &Header,
    device: &[u8; 16],
    seq: u64,
    plaintext: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::InvalidInput("too many changes at once"));
    }
    let len = (FIXED + plaintext.len() + TAG_LEN) as u32;
    let nonce = aead::random_nonce(rng)?;
    let mut frame = Vec::with_capacity(LENGTHS + len as usize);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&(!len).to_le_bytes());
    frame.push(KIND_BATCH);
    frame.extend_from_slice(device);
    frame.extend_from_slice(&seq.to_le_bytes());
    let ad = [&header[..], &frame[..]].concat();
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&aead::seal(key, &nonce, &ad, plaintext)?);
    Ok(frame)
}

/// How a journal file ends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// Every byte belongs to a valid frame.
    Clean,
    /// An unfinished or garbled last frame starts at this offset.
    Torn(u64),
    /// Something before the last frame is wrong; reading stopped at this offset.
    Damaged(u64, &'static str),
}

pub(crate) struct Contents {
    /// Decrypted plaintexts, in order, with their sequence numbers.
    pub frames: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub end: End,
}

impl std::fmt::Debug for Contents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contents")
            .field("frames", &self.frames.len())
            .field("end", &self.end)
            .finish()
    }
}

/// Reads a whole journal file. `None` for the header means the file isn't
/// this vault's journal of this generation.
pub(crate) fn read(
    bytes: &[u8],
    key: &SecretKey,
    header: &Header,
    device: &[u8; 16],
) -> Result<Contents> {
    if bytes.len() < HEADER_LEN || bytes[..8] != MAGIC[..] {
        return Err(Error::Damaged("journal header"));
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT {
        return Err(Error::Unsupported("journal format"));
    }
    if bytes[..HEADER_LEN] != header[..] {
        return Err(Error::Damaged("journal header"));
    }
    let mut frames = Vec::new();
    let mut pos = HEADER_LEN;
    let end = loop {
        let rest = &bytes[pos..];
        if rest.is_empty() {
            break End::Clean;
        }
        let at = pos as u64;
        if rest.len() < LENGTHS {
            break End::Torn(at);
        }
        let len = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes"));
        let check = u32::from_le_bytes(rest[4..8].try_into().expect("4 bytes"));
        if check != !len {
            // A zero-filled end is what a power cut can leave behind.
            break if rest.iter().all(|b| *b == 0) {
                End::Torn(at)
            } else {
                End::Damaged(at, "frame length")
            };
        }
        let len = len as usize;
        if !(FIXED + TAG_LEN..=MAX_FRAME).contains(&len) {
            break End::Damaged(at, "frame length");
        }
        if rest.len() < LENGTHS + len {
            break End::Torn(at);
        }
        let last = rest.len() == LENGTHS + len;
        let frame = &rest[..LENGTHS + len];
        let kind = frame[8];
        let frame_device: [u8; 16] = frame[9..25].try_into().expect("16 bytes");
        let seq = u64::from_le_bytes(frame[25..33].try_into().expect("8 bytes"));
        let nonce: aead::Nonce = frame[33..33 + NONCE_LEN].try_into().expect("24 bytes");
        let ad = [&header[..], &frame[..33]].concat();
        match aead::open(key, &nonce, &ad, &frame[33 + NONCE_LEN..]) {
            Ok(plaintext) => {
                if kind != KIND_BATCH {
                    break End::Damaged(at, "frame kind");
                }
                if frame_device != *device {
                    break End::Damaged(at, "frame from another device");
                }
                if seq != frames.len() as u64 + 1 {
                    break End::Damaged(at, "missing or repeated frame");
                }
                frames.push((seq, plaintext));
                pos += LENGTHS + len;
            }
            Err(_) if last => break End::Torn(at),
            Err(_) => break End::Damaged(at, "frame doesn't decrypt"),
        }
    };
    Ok(Contents { frames, end })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::TestRng;

    const DEVICE: [u8; 16] = [7; 16];

    fn key() -> SecretKey {
        SecretKey::from_slice(&[0x42; 32]).unwrap()
    }

    fn file(n: usize) -> (Header, Vec<u8>) {
        let h = header(1, &[9; 16], 1);
        let mut rng = TestRng::new("journal");
        let mut bytes = h.to_vec();
        for seq in 1..=n as u64 {
            let msg = format!("{{\"frame\":{seq}}}");
            bytes.extend(seal_frame(&key(), &h, &DEVICE, seq, msg.as_bytes(), &mut rng).unwrap());
        }
        (h, bytes)
    }

    /// The size of the frame starting at `pos`.
    fn frame_len(bytes: &[u8], pos: usize) -> usize {
        LENGTHS + u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize
    }

    fn texts(c: &Contents) -> Vec<String> {
        c.frames
            .iter()
            .map(|(_, p)| String::from_utf8(p.to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn names() {
        assert_eq!(file_name(1), "journal-00000001.log");
        assert_eq!(generation_of("journal-00000012.log"), Some(12));
        for bad in [
            "journal-1.log",
            "journal-00000000.log",
            "journal-0000001a.log",
            "x.log",
        ] {
            assert_eq!(generation_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn round_trip() {
        let (h, bytes) = file(3);
        let c = read(&bytes, &key(), &h, &DEVICE).unwrap();
        assert_eq!(c.end, End::Clean);
        assert_eq!(
            texts(&c),
            ["{\"frame\":1}", "{\"frame\":2}", "{\"frame\":3}"]
        );
        let empty = read(&h, &key(), &h, &DEVICE).unwrap();
        assert!(empty.frames.is_empty());
        assert_eq!(empty.end, End::Clean);
    }

    #[test]
    fn padding_keeps_json_valid() {
        let mut p = Zeroizing::new(b"{\"a\":1}".to_vec());
        pad(&mut p);
        assert_eq!(p.len(), 128);
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["a"], 1);
        let mut exact = Zeroizing::new(vec![b' '; 256]);
        pad(&mut exact);
        assert_eq!(exact.len(), 256);
    }

    #[test]
    fn truncation_at_every_byte_keeps_the_complete_frames() {
        let (h, bytes) = file(3);
        let starts: Vec<usize> = {
            let mut s = vec![HEADER_LEN];
            let mut pos = HEADER_LEN;
            while pos < bytes.len() {
                pos += frame_len(&bytes, pos);
                s.push(pos);
            }
            s
        };
        for n in HEADER_LEN..bytes.len() {
            let c = read(&bytes[..n], &key(), &h, &DEVICE).unwrap();
            let complete = starts.iter().filter(|s| **s <= n).count() - 1;
            assert_eq!(c.frames.len(), complete, "cut at {n}");
            if starts.contains(&n) {
                assert_eq!(c.end, End::Clean, "cut at {n}");
            } else {
                assert_eq!(c.end, End::Torn(starts[complete] as u64), "cut at {n}");
            }
        }
        for n in 0..HEADER_LEN {
            assert!(read(&bytes[..n], &key(), &h, &DEVICE).is_err());
        }
    }

    #[test]
    fn a_garbled_or_zeroed_last_frame_is_torn() {
        let (h, bytes) = file(2);
        let second = HEADER_LEN + frame_len(&bytes, HEADER_LEN);
        for i in second..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            let c = read(&b, &key(), &h, &DEVICE).unwrap();
            assert_eq!(c.frames.len(), 1, "byte {i}");
            // A changed length field is damage; everything else in the last
            // frame looks like an unfinished write.
            if i < second + LENGTHS {
                assert_eq!(
                    c.end,
                    End::Damaged(second as u64, "frame length"),
                    "byte {i}"
                );
            } else {
                assert_eq!(c.end, End::Torn(second as u64), "byte {i}");
            }
        }
        let mut zeros = bytes[..second].to_vec();
        zeros.extend(std::iter::repeat_n(0, 300));
        assert_eq!(
            read(&zeros, &key(), &h, &DEVICE).unwrap().end,
            End::Torn(second as u64)
        );
    }

    #[test]
    fn damage_before_the_last_frame_is_reported() {
        let (h, bytes) = file(3);
        // Flip any bit in any byte of the first frame: never mistaken for a
        // torn end, so the later frames are never cut off.
        let first_end = HEADER_LEN + frame_len(&bytes, HEADER_LEN);
        for i in HEADER_LEN..first_end {
            for bit in 0..8 {
                let mut b = bytes.clone();
                b[i] ^= 1 << bit;
                let c = read(&b, &key(), &h, &DEVICE).unwrap();
                assert!(c.frames.is_empty(), "byte {i} bit {bit}");
                assert!(
                    matches!(c.end, End::Damaged(32, _)),
                    "byte {i} bit {bit}: {:?}",
                    c.end
                );
            }
        }
    }

    #[test]
    fn frames_moved_or_removed_are_damage() {
        let (h, bytes) = file(3);
        let mut pos = HEADER_LEN;
        let mut frames = Vec::new();
        while pos < bytes.len() {
            let n = frame_len(&bytes, pos);
            frames.push(bytes[pos..pos + n].to_vec());
            pos += n;
        }
        // Frame 2 removed: a gap.
        let gap = [h.to_vec(), frames[0].clone(), frames[2].clone()].concat();
        assert_eq!(
            read(&gap, &key(), &h, &DEVICE).unwrap().end,
            End::Damaged(
                (HEADER_LEN + frames[0].len()) as u64,
                "missing or repeated frame"
            )
        );
        // Frame 1 repeated.
        let repeated = [
            h.to_vec(),
            frames[0].clone(),
            frames[0].clone(),
            frames[1].clone(),
        ]
        .concat();
        assert!(matches!(
            read(&repeated, &key(), &h, &DEVICE).unwrap().end,
            End::Damaged(_, _)
        ));
        // Another vault, generation or device.
        let other_vault = header(1, &[8; 16], 1);
        let other_gen = header(1, &[9; 16], 2);
        let moved = |hd: &Header| [hd.to_vec(), frames[0].clone(), frames[1].clone()].concat();
        for hd in [other_vault, other_gen] {
            let c = read(&moved(&hd), &key(), &hd, &DEVICE).unwrap();
            assert!(c.frames.is_empty());
            assert!(matches!(c.end, End::Damaged(32, _)));
        }
        assert!(read(&bytes, &key(), &h, &[6; 16]).unwrap().end != End::Clean);
        // The file of one vault read as another's: the header check refuses it.
        assert_eq!(
            read(&bytes, &key(), &other_vault, &DEVICE).unwrap_err(),
            Error::Damaged("journal header")
        );
    }

    #[test]
    fn golden_journal_v1() {
        let (h, bytes) = file(2);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/journal_v1.hex");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(path, hex::encode(&bytes) + "\n").unwrap();
        }
        let golden = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(hex::encode(&bytes), hex::encode(&golden));
        let c = read(&golden, &key(), &h, &DEVICE).unwrap();
        assert_eq!(texts(&c), ["{\"frame\":1}", "{\"frame\":2}"]);
    }
}
