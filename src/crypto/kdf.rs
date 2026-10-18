//! HKDF-SHA-256 (RFC 5869) with labelled info strings (P62).
//!
//! info = label ‖ 0x00 ‖ context. Every label has a fixed-length context, so
//! the encoding is unambiguous.

use hkdf::Hkdf;
use sha2::Sha256;

use super::SecretKey;

/// Labels: one per purpose, so no two derivations can ever produce the same key.
pub const LABEL_SLOT_PASSPHRASE: &str = "secure_core/v1/slot/passphrase";
pub const LABEL_SLOT_RECOVERY: &str = "secure_core/v1/slot/recovery";
pub const LABEL_KEYRING: &str = "secure_core/v1/keyring";
pub const LABEL_KEYRING_MAC: &str = "secure_core/v1/keyring/mac";

/// Derives `out.len()` bytes (at most 8160).
pub fn derive(salt: &[u8], ikm: &[u8], label: &str, context: &[&[u8]], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut info: Vec<&[u8]> = Vec::with_capacity(context.len() + 2);
    info.push(label.as_bytes());
    info.push(&[0]);
    info.extend_from_slice(context);
    hk.expand_multi_info(&info, out)
        .expect("output length within HKDF's limit");
}

/// A wrapping key and its key commitment (Albertini et al., "How to Abuse and
/// Fix Authenticated Encryption Without Key Commitment", USENIX Security
/// 2022): the commitment is stored next to the wrapped key, so a wrong key is
/// recognised before decrypting and no ciphertext opens under two keys.
pub struct CommittedKey {
    pub key: SecretKey,
    pub commitment: [u8; 32],
}

pub fn derive_committed(salt: &[u8], ikm: &[u8], label: &str, context: &[&[u8]]) -> CommittedKey {
    let mut okm = zeroize::Zeroizing::new([0u8; 64]);
    derive(salt, ikm, label, context, &mut okm[..]);
    let key = SecretKey::from_slice(&okm[..32]).expect("32 bytes");
    let commitment = okm[32..].try_into().expect("32 bytes");
    CommittedKey { key, commitment }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 5869, appendix A.1–A.3 (the SHA-256 cases), through the same
    /// HKDF type the wrapper uses.
    #[test]
    fn rfc5869_vectors() {
        let cases = [
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                concat!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                    "404142434445464748494a4b4c4d4e4f"
                ),
                concat!(
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
                ),
                concat!(
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
                    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
                    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                concat!(
                    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
                    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
                    "cc30c58179ec3e87c14c01d5c1f3434f1d87"
                ),
            ),
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, prk, okm) in cases {
            let (got_prk, hk) = Hkdf::<Sha256>::extract(Some(&h(salt)), &h(ikm));
            assert_eq!(got_prk[..], h(prk)[..]);
            let mut out = vec![0u8; h(okm).len()];
            hk.expand(&h(info), &mut out).unwrap();
            assert_eq!(out, h(okm));
        }
    }

    #[test]
    fn info_is_label_zero_context() {
        // derive() must equal plain HKDF with info = label ‖ 0x00 ‖ context.
        let mut ours = [0u8; 32];
        derive(b"salt", b"ikm", "lbl", &[b"ab", b"c"], &mut ours);
        let mut plain = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"salt"), b"ikm")
            .expand(b"lbl\0abc", &mut plain)
            .unwrap();
        assert_eq!(ours, plain);
    }

    #[test]
    fn labels_separate_keys() {
        let a = derive_committed(b"s", b"k", LABEL_SLOT_PASSPHRASE, &[]);
        let b = derive_committed(b"s", b"k", LABEL_SLOT_RECOVERY, &[]);
        assert_ne!(a.key.as_bytes(), b.key.as_bytes());
        assert_ne!(a.commitment, b.commitment);
        assert_ne!(&a.key.as_bytes()[..], &a.commitment[..]);
    }
}
