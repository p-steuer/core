//! The keyring file, format 1. It holds the master key (MK), wrapped once with
//! the passphrase and once with the recovery key, and the data keys (one per
//! journal generation), wrapped with a key derived from MK.
//!
//! Layout, little-endian:
//!
//! ```text
//! magic "SCKEYRNG" | format u16 | suite u16 | vault_id [16] | device_id [16] | seq u64
//! slot count u8 (= 2), each slot: type u8, then
//!   passphrase (1): salt [16] | m_kib u32 | t u32 | p u32 | commitment [32] | nonce [24] | wrapped MK [48]
//!   recovery   (2): salt [16] | commitment [32] | nonce [24] | wrapped MK [48]
//! key count u8 (1–8), each: purpose u8 | generation u32 | nonce [24] | wrapped key [48]
//! mac [32]       HMAC-SHA-256 under a key derived from MK, over everything before
//! checksum [32]  SHA-256 over everything before
//! ```
//!
//! The checksum only tells damage apart from a wrong passphrase before any
//! key is derived; it protects against nothing. Security comes from the AEAD
//! (each wrapped key's associated data binds it to this vault, its slot type
//! and its parameters) and from the MAC, which authenticates the whole file
//! once MK is known. Magic and format stay at the same offsets in every future
//! format, so older apps can say "made by a newer version".

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::crypto::aead::{self, Nonce};
use crate::crypto::kdf::{self, CommittedKey};
use crate::crypto::pwhash::{self, Params};
use crate::crypto::{self, SecretKey};
use crate::keys::recovery::RecoveryKey;
use crate::rand::{self, Rng};
use crate::suite;
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"SCKEYRNG";
const FORMAT: u16 = 1;
const SLOT_PASSPHRASE: u8 = 1;
const SLOT_RECOVERY: u8 = 2;
pub(crate) const PURPOSE_JOURNAL: u8 = 1;
const MAX_DATA_KEYS: usize = 8;
const MAC_LEN: usize = 32;
const CHECKSUM_LEN: usize = 32;

type Wrapped = [u8; 48];

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Keyring {
    pub suite: u16,
    pub vault_id: [u8; 16],
    pub device_id: [u8; 16],
    /// Increases with every rewrite; the newest copy wins.
    pub seq: u64,
    pub passphrase: PassphraseSlot,
    pub recovery: RecoverySlot,
    pub data_keys: Vec<WrappedKey>,
    pub mac: [u8; MAC_LEN],
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PassphraseSlot {
    pub salt: [u8; 16],
    pub params: Params,
    pub commitment: [u8; 32],
    pub nonce: Nonce,
    pub wrapped: Wrapped,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecoverySlot {
    pub salt: [u8; 16],
    pub commitment: [u8; 32],
    pub nonce: Nonce,
    pub wrapped: Wrapped,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WrappedKey {
    pub purpose: u8,
    pub generation: u32,
    pub nonce: Nonce,
    pub wrapped: Wrapped,
}

// Debug never shows salts, commitments or wrapped keys (security review
// L2): a commitment lets anyone check passphrase guesses offline.
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("suite", &self.suite)
            .field("seq", &self.seq)
            .field("passphrase", &self.passphrase)
            .field("recovery", &self.recovery)
            .field("data_keys", &self.data_keys)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PassphraseSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseSlot")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RecoverySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverySlot").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKey")
            .field("purpose", &self.purpose)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Associated data shared by everything wrapped in a keyring.
fn header_ad(suite: u16, vault_id: &[u8; 16]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(28);
    ad.extend_from_slice(MAGIC);
    ad.extend_from_slice(&FORMAT.to_le_bytes());
    ad.extend_from_slice(&suite.to_le_bytes());
    ad.extend_from_slice(vault_id);
    ad
}

impl PassphraseSlot {
    pub(crate) fn seal(
        rng: &mut dyn Rng,
        normalized: &str,
        params: &Params,
        suite: u16,
        vault_id: &[u8; 16],
        mk: &SecretKey,
    ) -> Result<Self> {
        let salt = rand::array(rng)?;
        let hash = pwhash::hash(normalized.as_bytes(), &salt, params)?;
        let kek = Self::kek(&hash, &salt, suite, vault_id);
        let mut slot = Self {
            salt,
            params: *params,
            commitment: kek.commitment,
            nonce: aead::random_nonce(rng)?,
            wrapped: [0; 48],
        };
        slot.wrapped = aead::seal_key(&kek.key, &slot.nonce, &slot.ad(suite, vault_id), mk)?;
        Ok(slot)
    }

    /// The wrapping key from the Argon2id output.
    pub(crate) fn kek(
        hash: &SecretKey,
        salt: &[u8; 16],
        suite: u16,
        vault_id: &[u8; 16],
    ) -> CommittedKey {
        kdf::derive_committed(
            salt,
            hash.as_bytes(),
            kdf::LABEL_SLOT_PASSPHRASE,
            &[&suite.to_le_bytes(), vault_id],
        )
    }

    fn ad(&self, suite: u16, vault_id: &[u8; 16]) -> Vec<u8> {
        let mut ad = header_ad(suite, vault_id);
        ad.push(SLOT_PASSPHRASE);
        ad.extend_from_slice(&self.salt);
        ad.extend_from_slice(&self.params.m_kib.to_le_bytes());
        ad.extend_from_slice(&self.params.t.to_le_bytes());
        ad.extend_from_slice(&self.params.p.to_le_bytes());
        ad.extend_from_slice(&self.commitment);
        ad
    }

    pub(crate) fn matches(&self, kek: &CommittedKey) -> bool {
        crypto::equal(&kek.commitment, &self.commitment)
    }

    pub(crate) fn open(
        &self,
        kek: &CommittedKey,
        suite: u16,
        vault_id: &[u8; 16],
    ) -> Result<SecretKey> {
        if !self.matches(kek) {
            return Err(Error::WrongPassphrase);
        }
        aead::open_key(
            &kek.key,
            &self.nonce,
            &self.ad(suite, vault_id),
            &self.wrapped,
        )
        .map_err(|_| Error::Damaged("passphrase slot"))
    }
}

impl RecoverySlot {
    pub(crate) fn seal(
        rng: &mut dyn Rng,
        recovery: &RecoveryKey,
        suite: u16,
        vault_id: &[u8; 16],
        mk: &SecretKey,
    ) -> Result<Self> {
        let salt = rand::array(rng)?;
        let kek = Self::kek(recovery, &salt, suite, vault_id);
        let mut slot = Self {
            salt,
            commitment: kek.commitment,
            nonce: aead::random_nonce(rng)?,
            wrapped: [0; 48],
        };
        slot.wrapped = aead::seal_key(&kek.key, &slot.nonce, &slot.ad(suite, vault_id), mk)?;
        Ok(slot)
    }

    fn kek(
        recovery: &RecoveryKey,
        salt: &[u8; 16],
        suite: u16,
        vault_id: &[u8; 16],
    ) -> CommittedKey {
        kdf::derive_committed(
            salt,
            recovery.key().as_bytes(),
            kdf::LABEL_SLOT_RECOVERY,
            &[&suite.to_le_bytes(), vault_id],
        )
    }

    fn ad(&self, suite: u16, vault_id: &[u8; 16]) -> Vec<u8> {
        let mut ad = header_ad(suite, vault_id);
        ad.push(SLOT_RECOVERY);
        ad.extend_from_slice(&self.salt);
        ad.extend_from_slice(&self.commitment);
        ad
    }

    pub(crate) fn open(
        &self,
        recovery: &RecoveryKey,
        suite: u16,
        vault_id: &[u8; 16],
    ) -> Result<SecretKey> {
        let kek = Self::kek(recovery, &self.salt, suite, vault_id);
        if !crypto::equal(&kek.commitment, &self.commitment) {
            return Err(Error::WrongRecoveryKey);
        }
        aead::open_key(
            &kek.key,
            &self.nonce,
            &self.ad(suite, vault_id),
            &self.wrapped,
        )
        .map_err(|_| Error::Damaged("recovery slot"))
    }
}

/// The keys MK protects inside the keyring.
pub(crate) struct KeyringKeys {
    wrap: SecretKey,
    mac: SecretKey,
}

impl KeyringKeys {
    pub(crate) fn derive(mk: &SecretKey, suite: u16, vault_id: &[u8; 16]) -> Self {
        let mut wrap = SecretKey::zero();
        let mut mac = SecretKey::zero();
        let ctx: &[&[u8]] = &[&suite.to_le_bytes()];
        kdf::derive(
            vault_id,
            mk.as_bytes(),
            kdf::LABEL_KEYRING,
            ctx,
            wrap.as_mut_bytes(),
        );
        kdf::derive(
            vault_id,
            mk.as_bytes(),
            kdf::LABEL_KEYRING_MAC,
            ctx,
            mac.as_mut_bytes(),
        );
        Self { wrap, mac }
    }

    fn hmac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as KeyInit>::new_from_slice(self.mac.as_bytes()).expect("any key length")
    }
}

impl WrappedKey {
    fn ad(&self, suite: u16, vault_id: &[u8; 16]) -> Vec<u8> {
        let mut ad = header_ad(suite, vault_id);
        ad.push(self.purpose);
        ad.extend_from_slice(&self.generation.to_le_bytes());
        ad
    }
}

impl Keyring {
    /// The keyring of a new vault.
    pub(crate) fn new(
        rng: &mut dyn Rng,
        mk: &SecretKey,
        normalized_passphrase: &str,
        params: &Params,
        recovery: &RecoveryKey,
        journal_key: &SecretKey,
    ) -> Result<Self> {
        let suite = suite::current().id;
        let vault_id = rand::array(rng)?;
        let device_id = rand::array(rng)?;
        let passphrase =
            PassphraseSlot::seal(rng, normalized_passphrase, params, suite, &vault_id, mk)?;
        let recovery = RecoverySlot::seal(rng, recovery, suite, &vault_id, mk)?;
        let mut keyring = Self {
            suite,
            vault_id,
            device_id,
            seq: 1,
            passphrase,
            recovery,
            data_keys: Vec::new(),
            mac: [0; MAC_LEN],
        };
        let keys = KeyringKeys::derive(mk, suite, &vault_id);
        keyring.add_data_key(rng, &keys, PURPOSE_JOURNAL, 1, journal_key)?;
        keyring.seal_mac(&keys);
        Ok(keyring)
    }

    pub(crate) fn add_data_key(
        &mut self,
        rng: &mut dyn Rng,
        keys: &KeyringKeys,
        purpose: u8,
        generation: u32,
        key: &SecretKey,
    ) -> Result<()> {
        if self.data_keys.len() >= MAX_DATA_KEYS {
            return Err(Error::Internal("too many data keys"));
        }
        let mut wrapped = WrappedKey {
            purpose,
            generation,
            nonce: aead::random_nonce(rng)?,
            wrapped: [0; 48],
        };
        let ad = wrapped.ad(self.suite, &self.vault_id);
        wrapped.wrapped = aead::seal_key(&keys.wrap, &wrapped.nonce, &ad, key)?;
        self.data_keys.push(wrapped);
        Ok(())
    }

    /// The unwrapped data keys of one purpose, by generation.
    pub(crate) fn open_data_keys(
        &self,
        keys: &KeyringKeys,
        purpose: u8,
    ) -> Result<Vec<(u32, SecretKey)>> {
        let mut out = Vec::new();
        for k in self.data_keys.iter().filter(|k| k.purpose == purpose) {
            let key = aead::open_key(
                &keys.wrap,
                &k.nonce,
                &k.ad(self.suite, &self.vault_id),
                &k.wrapped,
            )
            .map_err(|_| Error::Damaged("keyring data key"))?;
            out.push((k.generation, key));
        }
        Ok(out)
    }

    /// Recomputes the MAC; call after every change, before writing.
    pub(crate) fn seal_mac(&mut self, keys: &KeyringKeys) {
        let body = self.body();
        self.mac = keys
            .hmac()
            .chain_update(&body)
            .finalize()
            .into_bytes()
            .into();
    }

    /// Checks the MAC: the whole file is authentic.
    pub(crate) fn verify_mac(&self, keys: &KeyringKeys) -> Result<()> {
        keys.hmac()
            .chain_update(self.body())
            .verify_slice(&self.mac)
            .map_err(|_| Error::Damaged("keyring authentication"))
    }

    /// Everything the MAC covers.
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&FORMAT.to_le_bytes());
        b.extend_from_slice(&self.suite.to_le_bytes());
        b.extend_from_slice(&self.vault_id);
        b.extend_from_slice(&self.device_id);
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.push(2);
        let p = &self.passphrase;
        b.push(SLOT_PASSPHRASE);
        b.extend_from_slice(&p.salt);
        b.extend_from_slice(&p.params.m_kib.to_le_bytes());
        b.extend_from_slice(&p.params.t.to_le_bytes());
        b.extend_from_slice(&p.params.p.to_le_bytes());
        b.extend_from_slice(&p.commitment);
        b.extend_from_slice(&p.nonce);
        b.extend_from_slice(&p.wrapped);
        let r = &self.recovery;
        b.push(SLOT_RECOVERY);
        b.extend_from_slice(&r.salt);
        b.extend_from_slice(&r.commitment);
        b.extend_from_slice(&r.nonce);
        b.extend_from_slice(&r.wrapped);
        b.push(self.data_keys.len() as u8);
        for k in &self.data_keys {
            b.push(k.purpose);
            b.extend_from_slice(&k.generation.to_le_bytes());
            b.extend_from_slice(&k.nonce);
            b.extend_from_slice(&k.wrapped);
        }
        b
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.mac);
        let checksum = Sha256::digest(&b);
        b.extend_from_slice(&checksum);
        b
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 2 + MAC_LEN + CHECKSUM_LEN {
            return Err(Error::Damaged("keyring too short"));
        }
        if &bytes[..8] != MAGIC {
            return Err(Error::Damaged("not a keyring"));
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT {
            return Err(Error::Unsupported("keyring format"));
        }
        let (content, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
        if Sha256::digest(content)[..] != checksum[..] {
            return Err(Error::Damaged("keyring checksum"));
        }
        let mut r = Reader {
            buf: &content[10..],
        };
        let suite = r.u16()?;
        suite::lookup(suite)?;
        let vault_id = r.array()?;
        let device_id = r.array()?;
        let seq = r.u64()?;
        if r.u8()? != 2 {
            return Err(Error::Damaged("keyring slot count"));
        }
        let (mut passphrase, mut recovery) = (None, None);
        for _ in 0..2 {
            match r.u8()? {
                SLOT_PASSPHRASE if passphrase.is_none() => {
                    passphrase = Some(PassphraseSlot {
                        salt: r.array()?,
                        params: Params {
                            m_kib: r.u32()?,
                            t: r.u32()?,
                            p: r.u32()?,
                        },
                        commitment: r.array()?,
                        nonce: r.array()?,
                        wrapped: r.array()?,
                    })
                }
                SLOT_RECOVERY if recovery.is_none() => {
                    recovery = Some(RecoverySlot {
                        salt: r.array()?,
                        commitment: r.array()?,
                        nonce: r.array()?,
                        wrapped: r.array()?,
                    })
                }
                _ => return Err(Error::Damaged("keyring slot type")),
            }
        }
        let count = r.u8()? as usize;
        if !(1..=MAX_DATA_KEYS).contains(&count) {
            return Err(Error::Damaged("keyring key count"));
        }
        let mut data_keys: Vec<WrappedKey> = Vec::with_capacity(count);
        for _ in 0..count {
            let k = WrappedKey {
                purpose: r.u8()?,
                generation: r.u32()?,
                nonce: r.array()?,
                wrapped: r.array()?,
            };
            if k.purpose != PURPOSE_JOURNAL {
                return Err(Error::Unsupported("keyring key purpose"));
            }
            if k.generation == 0
                || data_keys
                    .iter()
                    .any(|o| o.purpose == k.purpose && o.generation == k.generation)
            {
                return Err(Error::Damaged("keyring key generation"));
            }
            data_keys.push(k);
        }
        let mac = r.array()?;
        if !r.buf.is_empty() {
            return Err(Error::Damaged("keyring has extra bytes"));
        }
        Ok(Self {
            suite,
            vault_id,
            device_id,
            seq,
            passphrase: passphrase.expect("two distinct slots"),
            recovery: recovery.expect("two distinct slots"),
            data_keys,
            mac,
        })
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Damaged("keyring truncated"));
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::passphrase;
    use crate::rand::TestRng;

    /// Cheap Argon2id for tests (the lowest values the bounds allow).
    pub(crate) const TEST_PARAMS: Params = Params {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };

    pub(crate) const PASSPHRASE: &str = "correct horse battery staple";

    pub(crate) struct Fixture {
        pub mk: SecretKey,
        pub recovery: RecoveryKey,
        pub journal_key: SecretKey,
        pub keyring: Keyring,
    }

    pub(crate) fn fixture(label: &str) -> Fixture {
        let mut rng = TestRng::new(label);
        let mk = SecretKey::random(&mut rng).unwrap();
        let recovery = RecoveryKey::random(&mut rng).unwrap();
        let journal_key = SecretKey::random(&mut rng).unwrap();
        let pw = passphrase::normalize(PASSPHRASE);
        let keyring =
            Keyring::new(&mut rng, &mk, &pw, &TEST_PARAMS, &recovery, &journal_key).unwrap();
        Fixture {
            mk,
            recovery,
            journal_key,
            keyring,
        }
    }

    fn open_with_passphrase(k: &Keyring, pw: &str) -> Result<SecretKey> {
        let p = &k.passphrase;
        let hash = pwhash::hash(passphrase::normalize(pw).as_bytes(), &p.salt, &p.params)?;
        p.open(
            &PassphraseSlot::kek(&hash, &p.salt, k.suite, &k.vault_id),
            k.suite,
            &k.vault_id,
        )
    }

    #[test]
    fn round_trip_and_both_slots_open() {
        let f = fixture("round-trip");
        let bytes = f.keyring.to_bytes();
        let parsed = Keyring::parse(&bytes).unwrap();
        assert_eq!(parsed, f.keyring);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(bytes.len(), 52 + 1 + 133 + 121 + 1 + 77 + 32 + 32);

        let mk = open_with_passphrase(&parsed, PASSPHRASE).unwrap();
        assert_eq!(mk.as_bytes(), f.mk.as_bytes());
        let mk2 = parsed
            .recovery
            .open(&f.recovery, parsed.suite, &parsed.vault_id)
            .unwrap();
        assert_eq!(mk2.as_bytes(), f.mk.as_bytes());

        let keys = KeyringKeys::derive(&mk, parsed.suite, &parsed.vault_id);
        parsed.verify_mac(&keys).unwrap();
        let data = parsed.open_data_keys(&keys, PURPOSE_JOURNAL).unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].0, 1);
        assert_eq!(data[0].1.as_bytes(), f.journal_key.as_bytes());
    }

    #[test]
    fn wrong_secrets_are_recognised() {
        let f = fixture("wrong");
        let k = &f.keyring;
        assert_eq!(
            open_with_passphrase(k, "correct horse battery stapler").unwrap_err(),
            Error::WrongPassphrase
        );
        let other = RecoveryKey::random(&mut TestRng::new("other")).unwrap();
        assert_eq!(
            k.recovery.open(&other, k.suite, &k.vault_id).unwrap_err(),
            Error::WrongRecoveryKey
        );
    }

    #[test]
    fn a_slot_from_another_vault_doesnt_open() {
        let a = fixture("vault-a");
        let mut b = fixture("vault-b").keyring;
        b.passphrase = a.keyring.passphrase.clone();
        b.recovery = a.keyring.recovery.clone();
        // Same passphrase and recovery key as vault A, but B's vault ID.
        assert_eq!(
            open_with_passphrase(&b, PASSPHRASE).unwrap_err(),
            Error::WrongPassphrase
        );
        assert_eq!(
            b.recovery
                .open(&a.recovery, b.suite, &b.vault_id)
                .unwrap_err(),
            Error::WrongRecoveryKey
        );
    }

    #[test]
    fn parse_rejects_damage_and_unknown_versions() {
        let bytes = fixture("parse").keyring.to_bytes();
        // Any single flipped bit is caught by the checksum or the header checks.
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x10;
            assert!(Keyring::parse(&b).is_err(), "byte {i}");
        }
        for n in 0..bytes.len() {
            assert!(Keyring::parse(&bytes[..n]).is_err(), "truncated to {n}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Keyring::parse(&longer).is_err());

        let with_checksum = |mut b: Vec<u8>| {
            let n = b.len() - CHECKSUM_LEN;
            let sum = Sha256::digest(&b[..n]);
            b[n..].copy_from_slice(&sum);
            b
        };
        let mut format2 = bytes.clone();
        format2[8] = 2;
        assert_eq!(
            Keyring::parse(&with_checksum(format2)).unwrap_err(),
            Error::Unsupported("keyring format")
        );
        let mut suite2 = bytes.clone();
        suite2[10] = 2;
        assert_eq!(
            Keyring::parse(&with_checksum(suite2)).unwrap_err(),
            Error::Unsupported("cipher suite")
        );
    }

    #[test]
    fn mac_covers_every_byte() {
        // An attacker can fix up the checksum, but not the MAC: after changing
        // any byte (and recomputing the checksum), either parsing fails or the
        // MAC check under the real MK does.
        let f = fixture("mac");
        let bytes = f.keyring.to_bytes();
        for i in 0..bytes.len() - CHECKSUM_LEN {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            let n = b.len() - CHECKSUM_LEN;
            let sum = Sha256::digest(&b[..n]);
            b[n..].copy_from_slice(&sum);
            if let Ok(k) = Keyring::parse(&b) {
                let keys = KeyringKeys::derive(&f.mk, k.suite, &k.vault_id);
                assert!(k.verify_mac(&keys).is_err(), "byte {i}");
            }
        }
    }

    /// The keyring format is fixed: old files must stay readable. Set
    /// UPDATE_GOLDEN=1 to rewrite the file after a deliberate format change.
    #[test]
    fn golden_keyring_v1() {
        let f = fixture("golden-keyring-v1");
        let bytes = f.keyring.to_bytes();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/keyring_v1.hex");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(path, hex::encode(&bytes) + "\n").unwrap();
        }
        let golden = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(hex::encode(&bytes), hex::encode(&golden));
        let parsed = Keyring::parse(&golden).unwrap();
        let mk = open_with_passphrase(&parsed, PASSPHRASE).unwrap();
        assert_eq!(mk.as_bytes(), f.mk.as_bytes());
    }
}
