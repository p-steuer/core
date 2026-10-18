//! The vault: a folder holding the keyring (and, from milestone M2, the
//! encrypted journal and files). It is created once with a passphrase and a
//! recovery key, then opened with either.
//!
//! The keyring is kept twice, `keyring` and `keyring.2`. Changes write the
//! main copy first (from then on the change counts) and then the backup.
//! Opening uses the newest copy that is intact and authentic, and rewrites
//! the other one if it differs.

mod keyring;
mod lock;

use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::SecretKey;
use crate::crypto::pwhash::{self, Params};
use crate::fsio::Dir;
use crate::keys::passphrase;
use crate::keys::recovery::RecoveryKey;
use crate::rand::{OsRng, Rng};
use crate::{Error, Result};
use keyring::{Keyring, KeyringKeys, PURPOSE_JOURNAL, PassphraseSlot, RecoverySlot};
use lock::VaultLock;

const KEYRING: &str = "keyring";
const KEYRING_BACKUP: &str = "keyring.2";

#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    /// Argon2id parameters for new passphrase slots, and the upgrade target.
    pub params: Params,
}

impl Config {
    pub(crate) const PRODUCTION: Self = Self {
        params: pwhash::DEFAULT,
    };
}

/// What happened while opening or changing the vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// A damaged, missing or outdated keyring copy was rewritten.
    pub repaired_keyring: bool,
    /// The passphrase was re-wrapped with stronger Argon2id parameters.
    pub upgraded_passphrase_hashing: bool,
    /// The backup copy of the keyring couldn't be written; the next unlock
    /// repairs it.
    pub keyring_backup_stale: bool,
}

/// A vault prepared in memory: the passphrase is hashed and the recovery key
/// chosen, but nothing is written until [`PendingVault::create`], so the
/// setup can still be abandoned.
pub struct PendingVault {
    config: Config,
    mk: SecretKey,
    recovery: RecoveryKey,
    journal_key: SecretKey,
    keyring: Keyring,
}

impl PendingVault {
    /// Checks the passphrase rules (P63) and runs Argon2id (about a second
    /// on a phone).
    pub fn prepare(passphrase: &str) -> Result<Self> {
        Self::prepare_with(passphrase, &mut OsRng, Config::PRODUCTION)
    }

    pub(crate) fn prepare_with(
        passphrase: &str,
        rng: &mut dyn Rng,
        config: Config,
    ) -> Result<Self> {
        let pw = passphrase::normalize(passphrase);
        passphrase::check(&pw)?;
        let mk = SecretKey::random(rng)?;
        let recovery = RecoveryKey::random(rng)?;
        let journal_key = SecretKey::random(rng)?;
        let keyring = Keyring::new(rng, &mk, &pw, &config.params, &recovery, &journal_key)?;
        Ok(Self {
            config,
            mk,
            recovery,
            journal_key,
            keyring,
        })
    }

    /// The recovery key to show the user, once.
    pub fn recovery_key(&self) -> Zeroizing<String> {
        self.recovery.encode()
    }

    /// Writes the new vault into `path` (created if needed).
    pub fn create(self, path: &Path) -> Result<Vault> {
        self.create_in(Dir::new(path))
    }

    pub(crate) fn create_in(self, dir: Dir) -> Result<Vault> {
        dir.create_dir()?;
        let lock = VaultLock::acquire(&dir)?;
        if dir.exists(KEYRING) || dir.exists(KEYRING_BACKUP) {
            return Err(Error::VaultExists);
        }
        remove_leftovers(&dir)?;
        let backup_ok = save(&dir, &self.keyring)?;
        let keys = KeyringKeys::derive(&self.mk, self.keyring.suite, &self.keyring.vault_id);
        Ok(Vault {
            dir,
            config: self.config,
            status: Status {
                keyring_backup_stale: !backup_ok,
                ..Status::default()
            },
            open: Some(Open {
                _lock: lock,
                mk: self.mk,
                keys,
                keyring: self.keyring,
                journal_keys: vec![(1, self.journal_key)],
                pending_recovery: None,
            }),
        })
    }
}

pub struct Vault {
    dir: Dir,
    config: Config,
    status: Status,
    /// `None` once locked.
    open: Option<Open>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("locked", &self.is_locked())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

struct Open {
    _lock: VaultLock,
    mk: SecretKey,
    keys: KeyringKeys,
    keyring: Keyring,
    #[allow(dead_code)] // read by the journal (M2)
    journal_keys: Vec<(u32, SecretKey)>,
    pending_recovery: Option<RecoveryKey>,
}

pub(crate) enum Secret {
    Passphrase(Zeroizing<String>),
    Recovery(RecoveryKey),
}

impl Vault {
    /// Whether `path` holds a vault (at least one keyring copy).
    pub fn exists(path: &Path) -> bool {
        let dir = Dir::new(path);
        dir.exists(KEYRING) || dir.exists(KEYRING_BACKUP)
    }

    pub fn unlock_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        let secret = Secret::Passphrase(passphrase::normalize(passphrase));
        Self::unlock_in(Dir::new(path), secret, Config::PRODUCTION, &mut OsRng)
    }

    /// Typos in the key are reported before the vault is touched.
    pub fn unlock_with_recovery_key(path: &Path, recovery_key: &str) -> Result<Self> {
        let secret = Secret::Recovery(RecoveryKey::parse(recovery_key)?);
        Self::unlock_in(Dir::new(path), secret, Config::PRODUCTION, &mut OsRng)
    }

    pub(crate) fn unlock_in(
        dir: Dir,
        secret: Secret,
        config: Config,
        rng: &mut dyn Rng,
    ) -> Result<Self> {
        if !(dir.exists(KEYRING) || dir.exists(KEYRING_BACKUP)) {
            return Err(Error::NoVault);
        }
        let lock = VaultLock::acquire(&dir)?;
        remove_temp_files(&dir)?;

        let mut copies: Vec<(Vec<u8>, Keyring)> = Vec::new();
        let mut parse_error = None;
        for name in [KEYRING, KEYRING_BACKUP] {
            if let Some(bytes) = dir.read(name)? {
                match Keyring::parse(&bytes) {
                    Ok(k) => copies.push((bytes, k)),
                    Err(e) => {
                        parse_error.get_or_insert(e);
                    }
                }
            }
        }
        if copies.is_empty() {
            return Err(parse_error.unwrap_or(Error::NoVault));
        }
        // Newest first; on a tie the main copy first (the sort is stable).
        copies.sort_by_key(|c| std::cmp::Reverse(c.1.seq));

        let (used, mk) = open_master_key(&copies, &secret)?;

        // The newest copy that is authentic under this master key wins.
        let mut chosen = None;
        for (i, (_, k)) in copies.iter().enumerate() {
            let keys = KeyringKeys::derive(&mk, k.suite, &k.vault_id);
            if k.verify_mac(&keys).is_ok()
                && let Ok(journal_keys) = k.open_data_keys(&keys, PURPOSE_JOURNAL)
            {
                chosen = Some((i, keys, journal_keys));
                break;
            }
        }
        let (auth, keys, journal_keys) = chosen.ok_or(Error::Damaged("keyring authentication"))?;
        let mut keyring = copies[auth].1.clone();
        let mut status = Status::default();

        // Repair the other copy: best effort, opening doesn't depend on it.
        for name in [KEYRING, KEYRING_BACKUP] {
            if dir.read(name)?.as_deref() != Some(&copies[auth].0[..]) {
                if dir.write_atomic(name, &copies[auth].0).is_ok() {
                    status.repaired_keyring = true;
                } else {
                    status.keyring_backup_stale = true;
                }
            }
        }

        // Re-wrap with stronger Argon2id parameters, but only the slot this
        // passphrase really opened (never undo a newer passphrase change).
        // Best effort: if anything fails, keep the old parameters and try
        // again at the next unlock.
        if let Secret::Passphrase(pw) = &secret
            && copies[used].1.passphrase == keyring.passphrase
            && keyring.passphrase.params.should_upgrade_to(&config.params)
            && let Ok(slot) = PassphraseSlot::seal(
                rng,
                pw,
                &config.params,
                keyring.suite,
                &keyring.vault_id,
                &mk,
            )
        {
            let mut updated = keyring.clone();
            updated.passphrase = slot;
            updated.seq += 1;
            updated.seal_mac(&keys);
            if let Ok(backup_ok) = save(&dir, &updated) {
                keyring = updated;
                status.upgraded_passphrase_hashing = true;
                status.keyring_backup_stale = !backup_ok;
            }
        }

        Ok(Self {
            dir,
            config,
            status,
            open: Some(Open {
                _lock: lock,
                mk,
                keys,
                keyring,
                journal_keys,
                pending_recovery: None,
            }),
        })
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn is_locked(&self) -> bool {
        self.open.is_none()
    }

    /// Wipes the keys from memory and releases the folder.
    pub fn lock(&mut self) {
        self.open = None;
    }

    fn opened(&self) -> Result<&Open> {
        self.open.as_ref().ok_or(Error::Locked)
    }

    /// Whether `passphrase` is the current one (for confirming before a change).
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool> {
        let open = self.opened()?;
        let (k, slot) = (&open.keyring, &open.keyring.passphrase);
        let hash = pwhash::hash(
            passphrase::normalize(passphrase).as_bytes(),
            &slot.salt,
            &slot.params,
        )?;
        Ok(slot.matches(&PassphraseSlot::kek(
            &hash,
            &slot.salt,
            k.suite,
            &k.vault_id,
        )))
    }

    /// Replaces the passphrase; the recovery key stays valid.
    pub fn set_passphrase(&mut self, new_passphrase: &str) -> Result<()> {
        self.set_passphrase_with(new_passphrase, &mut OsRng)
    }

    fn set_passphrase_with(&mut self, new_passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
        let pw = passphrase::normalize(new_passphrase);
        passphrase::check(&pw)?;
        let params = self.config.params;
        self.change_keyring(|k, mk| {
            k.passphrase = PassphraseSlot::seal(rng, &pw, &params, k.suite, &k.vault_id, mk)?;
            Ok(())
        })
    }

    /// Chooses a new recovery key and returns it for showing. It replaces the
    /// old one only with [`Vault::finish_new_recovery_key`], after the user
    /// has written it down.
    pub fn begin_new_recovery_key(&mut self) -> Result<Zeroizing<String>> {
        self.begin_new_recovery_key_with(&mut OsRng)
    }

    fn begin_new_recovery_key_with(&mut self, rng: &mut dyn Rng) -> Result<Zeroizing<String>> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let key = RecoveryKey::random(rng)?;
        let text = key.encode();
        open.pending_recovery = Some(key);
        Ok(text)
    }

    pub fn finish_new_recovery_key(&mut self) -> Result<()> {
        self.finish_new_recovery_key_with(&mut OsRng)
    }

    fn finish_new_recovery_key_with(&mut self, rng: &mut dyn Rng) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let key = open
            .pending_recovery
            .take()
            .ok_or(Error::InvalidInput("no new recovery key was started"))?;
        let result = self.change_keyring(|k, mk| {
            k.recovery = RecoverySlot::seal(rng, &key, k.suite, &k.vault_id, mk)?;
            Ok(())
        });
        if result.is_err()
            && let Some(open) = self.open.as_mut()
        {
            open.pending_recovery = Some(key);
        }
        result
    }

    pub fn cancel_new_recovery_key(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.pending_recovery = None;
        }
    }

    /// Applies `change` to a copy of the keyring, saves it, then adopts it.
    fn change_keyring(
        &mut self,
        change: impl FnOnce(&mut Keyring, &SecretKey) -> Result<()>,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        let mut updated = open.keyring.clone();
        change(&mut updated, &open.mk)?;
        updated.seq += 1;
        updated.seal_mac(&open.keys);
        let backup_ok = save(&self.dir, &updated)?;
        open.keyring = updated;
        self.status.keyring_backup_stale = !backup_ok;
        Ok(())
    }
}

/// Opens the master key with the first copy whose slot accepts the secret.
fn open_master_key(copies: &[(Vec<u8>, Keyring)], secret: &Secret) -> Result<(usize, SecretKey)> {
    // Argon2id results by (salt, parameters): both copies usually share the
    // slot, and hashing twice would double the wait.
    let mut hashes: Vec<([u8; 16], Params, SecretKey)> = Vec::new();
    let mut wrong_secret = None;
    let mut other_error = None;
    for (i, (_, k)) in copies.iter().enumerate() {
        let result = match secret {
            Secret::Passphrase(pw) => {
                let slot = &k.passphrase;
                let cached = hashes
                    .iter()
                    .find(|(s, p, _)| *s == slot.salt && *p == slot.params)
                    .map(|(_, _, h)| h.duplicate());
                let hash = match cached {
                    Some(h) => Ok(h),
                    None => pwhash::hash(pw.as_bytes(), &slot.salt, &slot.params).inspect(|h| {
                        hashes.push((slot.salt, slot.params, h.duplicate()));
                    }),
                };
                hash.and_then(|h| {
                    slot.open(
                        &PassphraseSlot::kek(&h, &slot.salt, k.suite, &k.vault_id),
                        k.suite,
                        &k.vault_id,
                    )
                })
            }
            Secret::Recovery(key) => k.recovery.open(key, k.suite, &k.vault_id),
        };
        match result {
            Ok(mk) => return Ok((i, mk)),
            Err(e @ (Error::WrongPassphrase | Error::WrongRecoveryKey)) => wrong_secret = Some(e),
            Err(e) => {
                other_error.get_or_insert(e);
            }
        }
    }
    // "Wrong passphrase" is the more useful message when one copy says so.
    Err(wrong_secret.or(other_error).expect("at least one copy"))
}

/// Writes a changed keyring: the main copy first (from then on the change
/// counts), then the backup. Returns whether the backup was written.
fn save(dir: &Dir, keyring: &Keyring) -> Result<bool> {
    let bytes = keyring.to_bytes();
    dir.write_atomic(KEYRING, &bytes)?;
    Ok(dir.write_atomic(KEYRING_BACKUP, &bytes).is_ok())
}

/// Temporary files of an interrupted write.
fn remove_temp_files(dir: &Dir) -> Result<()> {
    for name in dir.list()? {
        if name.ends_with(".tmp") {
            dir.remove(&name)?;
        }
    }
    Ok(())
}

/// Files of an earlier setup that stopped before its keyring was written.
/// Without a keyring they can never be decrypted.
fn remove_leftovers(dir: &Dir) -> Result<()> {
    for name in dir.list()? {
        if name.ends_with(".tmp") || (name.starts_with("journal-") && name.ends_with(".log")) {
            dir.remove(&name)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
