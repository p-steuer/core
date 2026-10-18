//! The recovery key (P61): a version byte, a 32-byte random key and a CRC-16,
//! written as 56 Crockford Base32 characters in 14 groups of 4.
//!
//! The CRC catches typos before any decryption. It detects every error that
//! stays within 16 consecutive bits, so every single wrong character and
//! every swap of two neighbouring characters.

use zeroize::Zeroizing;

use crate::crypto::SecretKey;
use crate::rand::Rng;
use crate::{Error, Result};

const VERSION: u8 = 1;
const BYTES: usize = 1 + 32 + 2;
pub const CHARS: usize = 56;
const GROUP: usize = 4;

/// Crockford's Base32 alphabet: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub struct RecoveryKey(SecretKey);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

/// How far a typed recovery key is from being usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Fewer than 56 characters so far, all of them possible.
    Incomplete { chars: usize },
    /// 56 characters with a matching checksum.
    Valid,
    /// 56 characters, but the checksum doesn't match: a typo somewhere.
    Typo,
    /// A character that can't appear, too many characters, or an unknown version.
    Invalid,
}

impl RecoveryKey {
    pub(crate) fn random(rng: &mut dyn Rng) -> Result<Self> {
        Ok(Self(SecretKey::random(rng)?))
    }

    pub fn key(&self) -> &SecretKey {
        &self.0
    }

    /// The key as the user writes it down: 14 groups of 4, joined by hyphens.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0u8; BYTES]);
        bytes[0] = VERSION;
        bytes[1..33].copy_from_slice(self.0.as_bytes());
        let crc = crc16(&bytes[..33]);
        bytes[33..].copy_from_slice(&crc.to_be_bytes());
        let chars = base32_encode(&bytes[..]);
        group(&chars)
    }

    /// Reads a typed key. Case, spaces and hyphens don't matter, and O, I and
    /// L are read as 0, 1 and 1.
    pub fn parse(input: &str) -> Result<Self> {
        let chars = normalize(input).ok_or(Error::RecoveryKeyInvalid)?;
        if chars.len() != CHARS {
            return Err(Error::RecoveryKeyInvalid);
        }
        let bytes = base32_decode(&chars).ok_or(Error::RecoveryKeyInvalid)?;
        if crc16(&bytes[..33]) != u16::from_be_bytes([bytes[33], bytes[34]]) {
            return Err(Error::RecoveryKeyTypo);
        }
        if bytes[0] != VERSION {
            return Err(Error::RecoveryKeyInvalid);
        }
        Ok(Self(
            SecretKey::from_slice(&bytes[1..33]).expect("32 bytes"),
        ))
    }
}

/// Checks a key while it is being typed.
pub fn check(input: &str) -> Check {
    let Some(chars) = normalize(input) else {
        return Check::Invalid;
    };
    match chars.len() {
        n if n < CHARS => Check::Incomplete { chars: n },
        CHARS => match RecoveryKey::parse(&chars) {
            Ok(_) => Check::Valid,
            Err(Error::RecoveryKeyTypo) => Check::Typo,
            Err(_) => Check::Invalid,
        },
        _ => Check::Invalid,
    }
}

/// Regroups what was typed so far ("abcd efg" becomes "ABCD-EFG"), for showing
/// it while typing. Characters that can't appear are dropped.
pub fn format_typed(input: &str) -> Zeroizing<String> {
    let chars: Zeroizing<String> = Zeroizing::new(input.chars().filter_map(canonical).collect());
    group(&chars)
}

fn group(chars: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(chars.len() + chars.len() / GROUP));
    for (i, c) in chars.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// One typed character in canonical form; `None` for separators and
/// characters that can't appear.
fn canonical(c: char) -> Option<char> {
    match c.to_ascii_uppercase() {
        'O' => Some('0'),
        'I' | 'L' => Some('1'),
        c if c.is_ascii() && ALPHABET.contains(&(c as u8)) => Some(c),
        _ => None,
    }
}

/// The canonical characters, or `None` if anything other than separators
/// can't appear in a key.
fn normalize(input: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(CHARS));
    for c in input.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        out.push(canonical(c)?);
    }
    Some(out)
}

fn base32_encode(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 8 / 5 + 1));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    assert_eq!(bits, 0, "35 bytes are exactly 56 characters");
    out
}

fn base32_decode(chars: &str) -> Option<Zeroizing<[u8; BYTES]>> {
    let mut out = Zeroizing::new([0u8; BYTES]);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for c in chars.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = ((acc << 5) | v) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            n += 1;
        }
    }
    (n == BYTES && bits == 0).then_some(out)
}

/// CRC-16/IBM-3740 (also called CRC-16/CCITT-FALSE): polynomial 0x1021,
/// initial value 0xFFFF, no reflection, no final XOR.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::TestRng;

    fn sample() -> RecoveryKey {
        RecoveryKey::random(&mut TestRng::new("recovery")).unwrap()
    }

    #[test]
    fn crc16_catalogue_check_value() {
        // The CRC catalogue's check value for "123456789"
        // (https://reveng.sourceforge.io/crc-catalogue/16.htm).
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn encoding_shape() {
        let text = sample().encode();
        assert_eq!(text.len(), 56 + 13);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(
            text.chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8)))
        );
        // The version byte 0x01 makes every key start with "0".
        assert!(text.starts_with('0'));
    }

    #[test]
    fn golden_encoding() {
        // Fixed format: changing it would make written-down keys unusable.
        let key = RecoveryKey(SecretKey::from_slice(&[0xAB; 32]).unwrap());
        assert_eq!(&key.encode()[..], GOLDEN_AB);
        let parsed = RecoveryKey::parse(GOLDEN_AB).unwrap();
        assert_eq!(parsed.key().as_bytes(), &[0xAB; 32]);
    }

    /// The encoding of the key 0xAB × 32, computed independently with
    /// Python's `binascii.crc_hqx` (CRC 0x349A) and a separate Base32 encoder.
    const GOLDEN_AB: &str = "06NT-QAXB-NENT-QAXB-NENT-QAXB-NENT-QAXB-NENT-QAXB-NENT-QAXB-NENT-PD4T";

    #[test]
    fn round_trip_with_lenient_typing() {
        let key = sample();
        let text = key.encode();
        let sloppy = text
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        let parsed = RecoveryKey::parse(&sloppy).unwrap();
        assert_eq!(parsed.key().as_bytes(), key.key().as_bytes());
        assert_eq!(check(&sloppy), Check::Valid);
    }

    #[test]
    fn every_single_character_typo_is_caught() {
        let text: String = sample().encode().replace('-', "");
        for i in 0..CHARS {
            for &c in ALPHABET {
                if c as char == text.as_bytes()[i] as char {
                    continue;
                }
                let mut typo = text.clone().into_bytes();
                typo[i] = c;
                let typo = String::from_utf8(typo).unwrap();
                assert!(
                    matches!(
                        RecoveryKey::parse(&typo),
                        Err(Error::RecoveryKeyTypo | Error::RecoveryKeyInvalid)
                    ),
                    "position {i}, char {}",
                    c as char
                );
            }
        }
    }

    #[test]
    fn every_swap_of_neighbours_is_caught() {
        let text: String = sample().encode().replace('-', "");
        let b = text.as_bytes();
        for i in 0..CHARS - 1 {
            if b[i] == b[i + 1] {
                continue;
            }
            let mut swapped = b.to_vec();
            swapped.swap(i, i + 1);
            let swapped = String::from_utf8(swapped).unwrap();
            assert!(RecoveryKey::parse(&swapped).is_err(), "swap at {i}");
        }
    }

    #[test]
    fn check_while_typing() {
        let text = sample().encode();
        assert_eq!(check(""), Check::Incomplete { chars: 0 });
        assert_eq!(check(&text[..9]), Check::Incomplete { chars: 8 });
        assert_eq!(check(&text), Check::Valid);
        assert_eq!(check(&format!("{}0", &text[..])), Check::Invalid);
        assert_eq!(check("ABCU"), Check::Invalid);
        assert_eq!(check("ABC!"), Check::Invalid);
        let mut typo = text.to_string().into_bytes();
        typo[5] = if typo[5] == b'Z' { b'Y' } else { b'Z' };
        assert_eq!(check(std::str::from_utf8(&typo).unwrap()), Check::Typo);
    }

    #[test]
    fn unknown_version_is_invalid() {
        let mut bytes = [0u8; BYTES];
        bytes[0] = 2;
        let crc = crc16(&bytes[..33]);
        bytes[33..].copy_from_slice(&crc.to_be_bytes());
        let text = base32_encode(&bytes);
        assert_eq!(
            RecoveryKey::parse(&text).unwrap_err(),
            Error::RecoveryKeyInvalid
        );
    }

    #[test]
    fn format_typed_regroups() {
        assert_eq!(&format_typed("abcd efgh-ij")[..], "ABCD-EFGH-1J");
        assert_eq!(&format_typed("ab!c")[..], "ABC");
        assert_eq!(&format_typed("")[..], "");
    }
}
