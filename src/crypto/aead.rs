//! XChaCha20-Poly1305 (suite 1): authenticated encryption with random 192-bit
//! nonces, so nonces never need to be counted or stored as state.

use chacha20poly1305::aead::array::Array;
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use super::SecretKey;
use crate::rand::{self, Rng};
use crate::{Error, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub type Nonce = [u8; NONCE_LEN];

/// Decryption failed: wrong key, wrong associated data or altered ciphertext.
/// Callers decide what that means (a wrong passphrase, or damage).
#[derive(Debug, PartialEq, Eq)]
pub struct Inauthentic;

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    let key: &Array<u8, _> = key.as_bytes()[..].try_into().expect("32-byte key");
    XChaCha20Poly1305::new(key)
}

fn nonce_ref(nonce: &Nonce) -> &Array<u8, chacha20poly1305::consts::U24> {
    nonce[..].try_into().expect("24-byte nonce")
}

/// A fresh random nonce.
pub(crate) fn random_nonce(rng: &mut dyn Rng) -> Result<Nonce> {
    rand::array(rng)
}

/// Encrypts `plaintext`; returns ciphertext ‖ tag.
pub fn seal(key: &SecretKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    cipher(key)
        .encrypt_in_place(nonce_ref(nonce), aad, &mut buf)
        .map_err(|_| Error::InvalidInput("message too long"))?;
    Ok(buf)
}

/// Decrypts ciphertext ‖ tag. The plaintext is returned in memory that is
/// wiped when dropped.
pub fn open(
    key: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    sealed: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, Inauthentic> {
    if sealed.len() < TAG_LEN {
        return Err(Inauthentic);
    }
    // Reserve the full length up front so the buffer never reallocates and
    // leaves unwiped copies behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(sealed.len()));
    buf.extend_from_slice(sealed);
    cipher(key)
        .decrypt_in_place(nonce_ref(nonce), aad, &mut *buf)
        .map_err(|_| Inauthentic)?;
    Ok(buf)
}

/// Encrypts a 32-byte key (key wrapping); the result is 48 bytes.
pub fn seal_key(
    kek: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    key: &SecretKey,
) -> Result<[u8; super::KEY_LEN + TAG_LEN]> {
    let sealed = seal(kek, nonce, aad, key.as_bytes())?;
    Ok(sealed.try_into().expect("48 bytes"))
}

/// Decrypts a wrapped 32-byte key.
pub fn open_key(
    kek: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    wrapped: &[u8; super::KEY_LEN + TAG_LEN],
) -> std::result::Result<SecretKey, Inauthentic> {
    let plain = open(kek, nonce, aad, wrapped)?;
    SecretKey::from_slice(&plain).ok_or(Inauthentic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(bytes: &[u8]) -> SecretKey {
        SecretKey::from_slice(bytes).unwrap()
    }

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn draft_xchacha_03_a_3_1() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let k = key(&hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap());
        let nonce: Nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
            .unwrap()
            .try_into()
            .unwrap();
        let expected = hex::decode(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49",
        ))
        .unwrap();
        assert_eq!(seal(&k, &nonce, &aad, plaintext).unwrap(), expected);
        assert_eq!(&open(&k, &nonce, &aad, &expected).unwrap()[..], plaintext);
    }

    /// All 315 Wycheproof XChaCha20-Poly1305 tests.
    #[test]
    fn wycheproof_xchacha20_poly1305() {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/wycheproof_xchacha20_poly1305_test.json"
        ))
        .unwrap();
        let (mut valid, mut invalid, mut other_nonce_sizes) = (0, 0, 0);
        for group in file["testGroups"].as_array().unwrap() {
            assert_eq!(group["keySize"], 256);
            assert_eq!(group["tagSize"], 128);
            for t in group["tests"].as_array().unwrap() {
                let get = |name: &str| hex::decode(t[name].as_str().unwrap()).unwrap();
                let id = &t["tcId"];
                let Ok(nonce) = Nonce::try_from(get("iv")) else {
                    // The API only takes 24-byte nonces, so these can't be expressed.
                    assert_eq!(t["result"], "invalid", "test {id}");
                    other_nonce_sizes += 1;
                    continue;
                };
                let k = key(&get("key"));
                let (aad, msg) = (get("aad"), get("msg"));
                let sealed = [get("ct"), get("tag")].concat();
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        assert_eq!(seal(&k, &nonce, &aad, &msg).unwrap(), sealed, "test {id}");
                        assert_eq!(&open(&k, &nonce, &aad, &sealed).unwrap()[..], &msg[..]);
                        valid += 1;
                    }
                    "invalid" => {
                        assert_eq!(
                            open(&k, &nonce, &aad, &sealed),
                            Err(Inauthentic),
                            "test {id}"
                        );
                        invalid += 1;
                    }
                    other => panic!("test {id}: unexpected result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid, other_nonce_sizes), (246, 60, 9));
    }

    #[test]
    fn short_input_is_inauthentic() {
        let k = key(&[1; 32]);
        assert_eq!(open(&k, &[0; 24], b"", &[0; 15]), Err(Inauthentic));
    }

    #[test]
    fn key_wrapping_round_trip() {
        let (kek, k) = (key(&[1; 32]), key(&[2; 32]));
        let wrapped = seal_key(&kek, &[3; 24], b"ad", &k).unwrap();
        assert_eq!(
            open_key(&kek, &[3; 24], b"ad", &wrapped)
                .unwrap()
                .as_bytes(),
            k.as_bytes()
        );
        assert!(open_key(&kek, &[3; 24], b"other", &wrapped).is_err());
    }

    proptest! {
        #[test]
        fn round_trip_and_any_change_is_detected(
            k in proptest::array::uniform32(any::<u8>()),
            nonce in proptest::array::uniform24(any::<u8>()),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
            msg in proptest::collection::vec(any::<u8>(), 0..300),
            flip in any::<proptest::sample::Index>(),
            bit in 0u8..8,
        ) {
            let k = key(&k);
            let sealed = seal(&k, &nonce, &aad, &msg).unwrap();
            prop_assert_eq!(&open(&k, &nonce, &aad, &sealed).unwrap()[..], &msg[..]);

            let mut altered = sealed.clone();
            let i = flip.index(altered.len());
            altered[i] ^= 1 << bit;
            prop_assert_eq!(open(&k, &nonce, &aad, &altered), Err(Inauthentic));

            let mut other_aad = aad.clone();
            other_aad.push(0);
            prop_assert_eq!(open(&k, &nonce, &other_aad, &sealed), Err(Inauthentic));

            let mut other_nonce = nonce;
            other_nonce[0] ^= 1;
            prop_assert_eq!(open(&k, &other_nonce, &aad, &sealed), Err(Inauthentic));
        }
    }
}
