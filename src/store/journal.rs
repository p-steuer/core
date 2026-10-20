//! The journal file: an append-only sequence of encrypted batches (P59).
//! One file per generation, `journal-00000001.log` and so on; each generation
//! has its own key (P69).
//!
//! ```text
//! header (32 bytes): magic "SCJOURNL" | format u16 | suite u16 | vault_id [16] | generation u32
//! frames, each: length u32 | !length u32 | kind u8 (1 = batch) | device_id [16] | seq u64 | nonce [24] | ciphertext
//! ```
//!
//! The format says how the plaintext of a frame encodes its batch: 1 is JSON
//! padded with spaces, 2 the binary encoding of [`super::codec`] padded with
//! zeros (D55). Both are read; new files are written in format 2, and a file
//! keeps its format until compaction rewrites it.
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

use super::{Batch, codec};
use crate::crypto::SecretKey;
use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
use crate::rand::Rng;
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"SCJOURNL";
/// Archive segments (D55) have the same layout under their own magic, with
/// their year where a journal has its generation.
const ARCHIVE_MAGIC: &[u8; 8] = b"SCARCHIV";
/// Batches as JSON, padded with spaces (MVP 1).
pub(crate) const FORMAT_JSON: u16 = 1;
/// Batches in the binary encoding of [`codec`], padded with zeros (D55).
pub(crate) const FORMAT_BINARY: u16 = 2;
/// The format new journal files are written in.
pub(crate) const FORMAT: u16 = FORMAT_BINARY;
pub(crate) const HEADER_LEN: usize = 32;
const KIND_BATCH: u8 = 1;
/// The two length fields.
const LENGTHS: usize = 8;
/// Kind, device, seq and nonce: the fixed part after the lengths.
const FIXED: usize = 1 + 16 + 8 + NONCE_LEN;
pub(crate) const MAX_PLAINTEXT: usize = 1024 * 1024;
const MAX_FRAME: usize = FIXED + MAX_PLAINTEXT + TAG_LEN;
/// Plaintexts are padded to a multiple of this, so frame sizes say less
/// about their content.
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

pub(crate) fn header(format: u16, suite: u16, vault_id: &[u8; 16], generation: u32) -> Header {
    header_with(MAGIC, format, suite, vault_id, generation)
}

/// The header of an archive segment of `year`.
pub(crate) fn archive_header(format: u16, suite: u16, vault_id: &[u8; 16], year: u32) -> Header {
    header_with(ARCHIVE_MAGIC, format, suite, vault_id, year)
}

fn header_with(
    magic: &[u8; 8],
    format: u16,
    suite: u16,
    vault_id: &[u8; 16],
    generation: u32,
) -> Header {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(magic);
    h[8..10].copy_from_slice(&format.to_le_bytes());
    h[10..12].copy_from_slice(&suite.to_le_bytes());
    h[12..28].copy_from_slice(vault_id);
    h[28..32].copy_from_slice(&generation.to_le_bytes());
    h
}

/// A batch as the plaintext of a frame in a file of `format`, padded: JSON
/// with spaces, which it ignores at the end, the binary encoding with zeros.
/// The buffer has room for the padding from the start: growing it would
/// leave a copy of the plaintext behind in freed memory, unwiped.
pub(crate) fn encode(format: u16, batch: &Batch) -> Result<Zeroizing<Vec<u8>>> {
    let failed = |_| Error::Internal("encoding a batch");
    let (bound, fill) = match format {
        FORMAT_JSON => (json_len(batch).map_err(failed)?, b' '),
        FORMAT_BINARY => (codec::len_bound(batch), 0),
        _ => return Err(Error::Internal("journal format")),
    };
    let mut plaintext = Zeroizing::new(Vec::with_capacity(bound.div_ceil(PAD) * PAD));
    if format == FORMAT_JSON {
        serde_json::to_writer(&mut *plaintext, batch).map_err(failed)?;
    } else {
        codec::encode_into(batch, &mut plaintext)?;
    }
    let target = plaintext.len().div_ceil(PAD) * PAD;
    plaintext.resize(target, fill);
    Ok(plaintext)
}

/// The length of a batch as JSON, counted without writing it anywhere.
fn json_len(batch: &Batch) -> serde_json::Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, batch)?;
    Ok(count.0)
}

/// The batch in the plaintext of a frame in a file of `format`.
pub(crate) fn decode(format: u16, plaintext: &[u8]) -> Result<Batch> {
    match format {
        FORMAT_JSON => {
            serde_json::from_slice(plaintext).map_err(|_| Error::Damaged("journal batch"))
        }
        FORMAT_BINARY => codec::decode(plaintext),
        _ => Err(Error::Unsupported("journal format")),
    }
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
    /// The file's format, and its header (with that format).
    pub format: u16,
    pub header: Header,
    /// Decrypted plaintexts, in order, with their sequence numbers.
    pub frames: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub end: End,
}

impl std::fmt::Debug for Contents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contents")
            .field("format", &self.format)
            .field("frames", &self.frames.len())
            .field("end", &self.end)
            .finish()
    }
}

/// Reads a whole journal or archive file of either format. `expected` is
/// this vault's header for the generation or year; only its format may
/// differ from the file's.
pub(crate) fn read(
    bytes: &[u8],
    key: &SecretKey,
    expected: &Header,
    device: &[u8; 16],
) -> Result<Contents> {
    if bytes.len() < HEADER_LEN || bytes[..8] != expected[..8] {
        return Err(Error::Damaged("journal header"));
    }
    let format = u16::from_le_bytes([bytes[8], bytes[9]]);
    if format != FORMAT_JSON && format != FORMAT_BINARY {
        return Err(Error::Unsupported("journal format"));
    }
    if bytes[10..HEADER_LEN] != expected[10..] {
        return Err(Error::Damaged("journal header"));
    }
    let header: Header = bytes[..HEADER_LEN].try_into().expect("32 bytes");
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
    Ok(Contents {
        format,
        header,
        frames,
        end,
    })
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
        let h = header(FORMAT_JSON, 1, &[9; 16], 1);
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

    fn batch() -> Batch {
        Batch {
            hlc: 7,
            ops: vec![super::super::Op::Put {
                kind: "set".into(),
                id: "a".into(),
                fields: serde_json::json!({"reps": 5, "note": "x"})
                    .as_object()
                    .unwrap()
                    .clone(),
            }],
        }
    }

    #[test]
    fn padding_keeps_both_formats_readable() {
        for format in [FORMAT_JSON, FORMAT_BINARY] {
            let p = encode(format, &batch()).unwrap();
            assert_eq!(p.len() % PAD, 0, "format {format}");
            assert_eq!(decode(format, &p).unwrap(), batch(), "format {format}");
        }
        let json = encode(FORMAT_JSON, &batch()).unwrap();
        assert!(json.ends_with(b" "));
        let binary = encode(FORMAT_BINARY, &batch()).unwrap();
        assert!(binary.ends_with(&[0]));
        // Both pad to whole blocks; the real comparison is in the codec's tests.
        assert!(binary.len() <= json.len());
        assert_eq!(
            decode(3, &binary),
            Err(Error::Unsupported("journal format"))
        );
    }

    /// Regression (19 Oct 2026): padding could grow the plaintext's buffer
    /// beyond what was reserved, and JSON was written into a growing buffer.
    /// Each reallocation left a copy of the plaintext in freed memory,
    /// unwiped. Now the buffer has its final size from the start, which shows
    /// in its capacity (`Vec::with_capacity` reserves exactly what it's asked).
    #[test]
    fn regression_2026_10_19_plaintexts_are_never_reallocated() {
        let put = |fields: usize| super::super::Op::Put {
            kind: "set".into(),
            id: "0195f4c2-7a1b-7c3d-8e4f-123456789abc".into(),
            fields: (0..fields)
                .map(|i| (format!("f{i}"), serde_json::json!(format!("value {i}"))))
                .collect(),
        };
        let batches = [
            Batch {
                hlc: 1,
                ops: vec![],
            },
            Batch {
                hlc: 1,
                ops: vec![super::super::Op::Del {
                    kind: "set".into(),
                    id: "a".into(),
                }],
            },
            batch(),
            Batch {
                hlc: 1,
                ops: vec![put(3)],
            },
            Batch {
                hlc: u64::MAX,
                ops: (0..40).map(put).collect(),
            },
        ];
        for b in &batches {
            let json = encode(FORMAT_JSON, b).unwrap();
            assert_eq!(json.capacity(), json.len());
            let binary = encode(FORMAT_BINARY, b).unwrap();
            assert_eq!(binary.capacity(), codec::len_bound(b).div_ceil(PAD) * PAD);
            assert_eq!(decode(FORMAT_JSON, &json).unwrap(), *b);
            assert_eq!(decode(FORMAT_BINARY, &binary).unwrap(), *b);
        }
    }

    #[test]
    fn both_formats_are_read_and_others_refused() {
        let (h, bytes) = file(2);
        let c = read(&bytes, &key(), &h, &DEVICE).unwrap();
        assert_eq!((c.format, c.header), (FORMAT_JSON, h));
        // The expected header's format doesn't matter, only the rest.
        let as_binary = header(FORMAT_BINARY, 1, &[9; 16], 1);
        let c = read(&bytes, &key(), &as_binary, &DEVICE).unwrap();
        assert_eq!((c.format, c.frames.len()), (FORMAT_JSON, 2));
        let mut b = bytes.clone();
        b[8..10].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            read(&b, &key(), &h, &DEVICE).unwrap_err(),
            Error::Unsupported("journal format")
        );
        // A frame can't move to a file of the other format: the header,
        // format included, is part of its associated data.
        let mut b = bytes.clone();
        b[8..10].copy_from_slice(&FORMAT_BINARY.to_le_bytes());
        let c = read(&b, &key(), &h, &DEVICE).unwrap();
        assert!(c.frames.is_empty());
        assert!(matches!(c.end, End::Damaged(32, _)));
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
        let other_vault = header(FORMAT_JSON, 1, &[8; 16], 1);
        let other_gen = header(FORMAT_JSON, 1, &[9; 16], 2);
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
