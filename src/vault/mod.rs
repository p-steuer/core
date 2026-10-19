//! The vault: a folder holding the keyring, the encrypted journal and the
//! encrypted files. It is created once with a passphrase and a recovery key,
//! then opened with either.
//!
//! - **Keyring** (`keyring`, `keyring.2`): changes write the main copy first
//!   (from then on the change counts) and then the backup. Opening uses the
//!   newest copy that is intact and authentic, and rewrites the other one if
//!   it differs.
//! - **Journal** (`journal-NNNNNNNN.log`, P59): every commit appends one
//!   encrypted batch and flushes it before the change counts. Opening replays
//!   it into memory, cuts off an unfinished last batch, and opens read-only if
//!   anything before it is damaged.
//! - **Compaction** (P69): writes the surviving state under a new journal key
//!   into the next generation, switches to it, then deletes the old key and
//!   file. A crash at any step leaves either generation complete.
//! - **Files** (`blobs/<id>.blob`): each with its own key, kept in the journal.
//!
//! When a write fails so that the state on disk is uncertain, the vault
//! refuses further changes until it is opened again.

mod keyring;
mod lock;

use std::collections::BTreeSet;
use std::fs::File;
use std::path::Path;

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::blob;
use crate::crypto::SecretKey;
use crate::crypto::pwhash::{self, Params};
use crate::fsio::Dir;
use crate::keys::passphrase;
use crate::keys::recovery::RecoveryKey;
use crate::rand::{self, OsRng, Rng};
use crate::store::hlc::{self, Clock};
use crate::store::journal::{self, End};
use crate::store::{self, Batch, Change, Op, Record, Store};
use crate::{Error, Result};
use keyring::{Keyring, KeyringKeys, PURPOSE_JOURNAL, PassphraseSlot, RecoverySlot};
use lock::VaultLock;

const KEYRING: &str = "keyring";
const KEYRING_BACKUP: &str = "keyring.2";
const BLOBS: &str = "blobs";
/// The core's own record kind for file keys; the app can't see it.
const BLOB_KIND: &str = "_blob";
/// Compaction splits the surviving state into batches of about this size.
const SNAPSHOT_BATCH: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Argon2id parameters for new passphrase slots, and the upgrade target.
    pub params: Params,
    pub clock: Clock,
}

impl Config {
    pub(crate) const PRODUCTION: Self = Self {
        params: pwhash::DEFAULT,
        clock: Clock::System,
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
    /// An unfinished last change (left by a crash or power cut) was discarded.
    pub recovered_journal: bool,
    /// Why the vault can only be read, if it can.
    pub damage: Option<&'static str>,
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
        if dir.exists(KEYRING)? || dir.exists(KEYRING_BACKUP)? {
            return Err(Error::VaultExists);
        }
        remove_leftovers(&dir)?;
        // The empty journal first: until the keyring exists there is no vault,
        // and a later setup removes the journal again.
        let header = journal::header(self.keyring.suite, &self.keyring.vault_id, 1);
        let name = journal::file_name(1);
        dir.write_atomic(&name, &header)?;
        let backup_ok = save(&dir, &self.keyring)?;
        let file = dir.open_append(&name)?;
        let keys = KeyringKeys::derive(&self.mk, self.keyring.suite, &self.keyring.vault_id);
        Ok(Vault {
            config: self.config,
            status: Status {
                keyring_backup_stale: !backup_ok,
                ..Status::default()
            },
            open: Some(Open {
                _lock: lock,
                blobs: dir.sub(BLOBS),
                mk: self.mk,
                keys,
                keyring: self.keyring,
                journal: ActiveJournal {
                    generation: 1,
                    key: self.journal_key,
                    header,
                    file,
                    len: journal::HEADER_LEN as u64,
                    next_seq: 1,
                },
                store: Store::default(),
                hlc: 0,
                pending_recovery: None,
                leftover_files: false,
            }),
            dir,
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
    blobs: Dir,
    mk: SecretKey,
    keys: KeyringKeys,
    keyring: Keyring,
    journal: ActiveJournal,
    store: Store,
    /// The last clock value written.
    hlc: u64,
    pending_recovery: Option<RecoveryKey>,
    /// A journal file of an older generation couldn't be deleted.
    leftover_files: bool,
}

impl Open {
    /// What an earlier compaction left to do: keys of other generations, or
    /// files of older ones.
    fn cleanup_pending(&self) -> bool {
        self.leftover_files
            || self
                .keyring
                .data_keys
                .iter()
                .any(|k| k.generation != self.journal.generation)
    }
}

struct ActiveJournal {
    generation: u32,
    key: SecretKey,
    header: journal::Header,
    file: File,
    len: u64,
    next_seq: u64,
}

pub(crate) enum Secret {
    Passphrase(Zeroizing<String>),
    Recovery(RecoveryKey),
}

impl Vault {
    /// Whether `path` holds a vault (at least one keyring copy). If that
    /// can't be told (a storage error), the answer is yes: the app then asks
    /// for the passphrase and shows the error, instead of offering a setup
    /// that would replace the vault (security review L7).
    pub fn exists(path: &Path) -> bool {
        let dir = Dir::new(path);
        dir.exists(KEYRING)
            .and_then(|main| Ok(main || dir.exists(KEYRING_BACKUP)?))
            .unwrap_or(true)
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
        if !(dir.exists(KEYRING)? || dir.exists(KEYRING_BACKUP)?) {
            return Err(Error::NoVault);
        }
        let lock = VaultLock::acquire(&dir)?;
        dir.restrict_to_owner();
        dir.sub(BLOBS).restrict_to_owner();
        remove_temp_files(&dir)?;
        let mut status = Status::default();
        let (mk, keys, mut keyring, journal_keys) =
            open_keyring(&dir, &secret, &config, rng, &mut status)?;

        // The active generation: the newest one with both a file and a key.
        let files: BTreeSet<u32> = dir
            .list()?
            .iter()
            .filter_map(|n| journal::generation_of(n))
            .collect();
        let Some((generation, key)) = journal_keys
            .into_iter()
            .filter(|(g, _)| files.contains(g))
            .max_by_key(|(g, _)| *g)
        else {
            return Err(Error::Damaged("journal missing"));
        };
        let header = journal::header(keyring.suite, &keyring.vault_id, generation);
        let name = journal::file_name(generation);
        let bytes = dir.read(&name)?.ok_or(Error::Damaged("journal missing"))?;
        let contents = journal::read(&bytes, &key, &header, &keyring.device_id)?;
        let mut store = Store::default();
        // A journal newer than every key held means the keyring copy in use
        // is older than the data (e.g. a stale backup after the main copy was
        // damaged): read what we can, change and delete nothing (security
        // review M2).
        let mut damage = files
            .iter()
            .any(|g| *g > generation)
            .then_some("journal without its key");
        for (seq, plaintext) in &contents.frames {
            match serde_json::from_slice::<Batch>(plaintext) {
                Ok(batch) => store.apply(&batch, keyring.device_id, *seq),
                Err(_) => {
                    damage = Some("journal batch");
                    break;
                }
            }
        }
        let mut len = bytes.len() as u64;
        let file = dir.open_append(&name)?;
        match contents.end {
            End::Clean => {}
            End::Damaged(_, reason) => {
                damage.get_or_insert(reason);
            }
            End::Torn(at) if damage.is_none() => {
                dir.truncate(&file, at)?;
                len = at;
                status.recovered_journal = true;
            }
            End::Torn(_) => {}
        }
        let next_seq = contents.frames.len() as u64 + 1;
        drop(contents);
        status.damage = damage;

        let blobs = dir.sub(BLOBS);
        if damage.is_none() {
            // Leftovers of an interrupted compaction or file change. Best
            // effort: nothing depends on them.
            let _ = clean_up_generations(&dir, &mut keyring, &keys, generation, &files);
            let _ = clean_up_blobs(&blobs, &store);
        }
        let hlc = store.max_hlc();
        Ok(Self {
            dir,
            config,
            status,
            open: Some(Open {
                _lock: lock,
                blobs,
                mk,
                keys,
                keyring,
                journal: ActiveJournal {
                    generation,
                    key,
                    header,
                    file,
                    len,
                    next_seq,
                },
                store,
                hlc,
                pending_recovery: None,
                leftover_files: false,
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

    /// The open vault, if changes are allowed.
    fn writable(&mut self) -> Result<&mut Open> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if self.status.damage.is_some() {
            return Err(Error::ReadOnly);
        }
        Ok(open)
    }

    // ---- Records ----------------------------------------------------------

    /// The records of one kind, sorted by id.
    pub fn records(&self, kind: &str) -> Result<Vec<Record>> {
        store::check_kind(kind)?;
        Ok(self.opened()?.store.records(kind))
    }

    pub fn record(&self, kind: &str, id: &str) -> Result<Option<Record>> {
        store::check_kind(kind)?;
        Ok(self.opened()?.store.get(kind, id))
    }

    /// Applies `changes` together: on disk and flushed before this returns,
    /// or not at all.
    pub fn commit(&mut self, changes: Vec<Change>) -> Result<()> {
        store::validate(&changes)?;
        self.commit_ops(changes.into_iter().map(Op::from).collect())
    }

    fn commit_ops(&mut self, ops: Vec<Op>) -> Result<()> {
        let now = self.config.clock.now_ms();
        let Vault {
            dir, status, open, ..
        } = self;
        let open = open.as_mut().ok_or(Error::Locked)?;
        if status.damage.is_some() {
            return Err(Error::ReadOnly);
        }
        let batch = Batch {
            hlc: hlc::next(open.hlc, now),
            ops,
        };
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(&batch).map_err(|_| Error::Internal("encoding a batch"))?,
        );
        journal::pad(&mut plaintext);
        let j = &mut open.journal;
        let seq = j.next_seq;
        let frame = journal::seal_frame(
            &j.key,
            &j.header,
            &open.keyring.device_id,
            seq,
            &plaintext,
            &mut OsRng,
        )?;
        if let Err(e) = dir.append(&mut j.file, &frame) {
            // Take back a partial frame; if even that fails, a later frame
            // would land behind garbage, so stop writing.
            if dir.truncate(&j.file, j.len).is_err() {
                status.damage = Some("storage error; open the vault again");
            }
            return Err(e);
        }
        j.len += frame.len() as u64;
        j.next_seq += 1;
        open.hlc = batch.hlc;
        open.store.apply(&batch, open.keyring.device_id, seq);
        Ok(())
    }

    /// Whether [`Vault::compact`] has work: deleted or overwritten values to
    /// remove, or an earlier compaction to finish (an old key or file left
    /// behind, or a backup copy of the keyring that couldn't be written).
    /// Stays true until that is done (security review L4).
    pub fn needs_compaction(&self) -> bool {
        self.open.as_ref().is_some_and(|o| {
            o.store.needs_compaction() || o.cleanup_pending() || self.status.keyring_backup_stale
        })
    }

    /// Rewrites the journal with only the surviving state under a new key,
    /// then deletes the old key and file (P69). First finishes whatever an
    /// earlier compaction left.
    pub fn compact(&mut self) -> Result<()> {
        self.finish_compaction()?;
        if !self.opened()?.store.needs_compaction() {
            return Ok(());
        }
        let now = self.config.clock.now_ms();
        let dir = &self.dir;
        let status = &mut self.status;
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        if status.damage.is_some() {
            return Err(Error::ReadOnly);
        }
        let old = open.journal.generation;
        let new = old
            .checked_add(1)
            .ok_or(Error::Internal("journal generation"))?;
        let key = SecretKey::random(&mut OsRng)?;

        // 1. The keyring with both keys (a stale key of an earlier attempt
        // goes). Both copies must hold the new key before the new journal
        // exists: otherwise a later damaged main copy would leave the new
        // journal without its key (security review M2). The new key without
        // its journal is removed by the next attempt.
        let mut both = open.keyring.clone();
        both.data_keys.retain(|k| k.generation <= old);
        both.add_data_key(&mut OsRng, &open.keys, PURPOSE_JOURNAL, new, &key)?;
        both.seq += 1;
        both.seal_mac(&open.keys);
        let backup_ok = save(dir, &both)?;
        open.keyring = both;
        status.keyring_backup_stale = !backup_ok;
        if !backup_ok {
            return Err(Error::Io(
                "the keyring's backup copy can't be written".into(),
            ));
        }

        // 2. The new journal, complete, under its final name.
        let header = journal::header(open.keyring.suite, &open.keyring.vault_id, new);
        let mut bytes = header.to_vec();
        let hlc = hlc::next(open.hlc, now);
        let mut seq = 0;
        for ops in split(open.store.snapshot()) {
            seq += 1;
            let mut plaintext = Zeroizing::new(
                serde_json::to_vec(&Batch { hlc, ops })
                    .map_err(|_| Error::Internal("encoding a batch"))?,
            );
            journal::pad(&mut plaintext);
            bytes.extend(journal::seal_frame(
                &key,
                &header,
                &open.keyring.device_id,
                seq,
                &plaintext,
                &mut OsRng,
            )?);
        }
        let name = journal::file_name(new);
        if let Err(e) = dir.write_atomic(&name, &bytes) {
            // If the file arrived after all, the next unlock would use it
            // and miss later commits to the old one: remove it or stop.
            if dir.remove(&name).is_err() {
                status.damage = Some("storage error; open the vault again");
            }
            return Err(e);
        }

        // 3. Switch over. From here on the new generation counts.
        let file = match dir.open_append(&name) {
            Ok(f) => f,
            Err(e) => {
                status.damage = Some("storage error; open the vault again");
                return Err(e);
            }
        };
        open.journal = ActiveJournal {
            generation: new,
            key,
            header,
            file,
            len: bytes.len() as u64,
            next_seq: seq + 1,
        };
        open.hlc = hlc;
        open.store = open.store.compacted();

        // 4. Delete the old key, then the old file. Both copies hold the new
        // key since step 1, so the old file can go even if the backup isn't
        // written now. Whatever fails here keeps `needs_compaction` true, and
        // the next call (or unlock) finishes it.
        let mut only_new = open.keyring.clone();
        only_new.data_keys.retain(|k| k.generation == new);
        only_new.seq += 1;
        only_new.seal_mac(&open.keys);
        if let Ok(backup_ok) = save(dir, &only_new) {
            open.keyring = only_new;
            status.keyring_backup_stale = !backup_ok;
            open.leftover_files = dir
                .remove(&journal::file_name(old))
                .and_then(|_| dir.sync())
                .is_err();
        }
        Ok(())
    }

    /// Finishes an earlier compaction: removes keys of other generations and
    /// files of older ones, and rewrites a stale backup copy of the keyring.
    fn finish_compaction(&mut self) -> Result<()> {
        let Vault {
            dir, status, open, ..
        } = self;
        let open = open.as_mut().ok_or(Error::Locked)?;
        if status.damage.is_some() {
            return Err(Error::ReadOnly);
        }
        let active = open.journal.generation;
        if open
            .keyring
            .data_keys
            .iter()
            .any(|k| k.generation != active)
        {
            let mut updated = open.keyring.clone();
            updated.data_keys.retain(|k| k.generation == active);
            updated.seq += 1;
            updated.seal_mac(&open.keys);
            let backup_ok = save(dir, &updated)?;
            open.keyring = updated;
            status.keyring_backup_stale = !backup_ok;
        } else if status.keyring_backup_stale {
            dir.write_atomic(KEYRING_BACKUP, &open.keyring.to_bytes())?;
            status.keyring_backup_stale = false;
        }
        if open.leftover_files {
            for name in dir.list()? {
                if journal::generation_of(&name).is_some_and(|g| g < active) {
                    dir.remove(&name)?;
                }
            }
            dir.sync()?;
            open.leftover_files = false;
        }
        if status.keyring_backup_stale {
            return Err(Error::Io(
                "the keyring's backup copy can't be written".into(),
            ));
        }
        Ok(())
    }

    // ---- Files --------------------------------------------------------------

    /// Stores an encrypted file and returns its id.
    pub fn put_blob(&mut self, data: &[u8]) -> Result<String> {
        let open = self.writable()?;
        let id_bytes: [u8; 16] = rand::array(&mut OsRng)?;
        let id = store::hex16(&id_bytes);
        let key = SecretKey::random(&mut OsRng)?;
        let sealed = blob::seal(
            &key,
            open.keyring.suite,
            &open.keyring.vault_id,
            &id_bytes,
            data,
            &mut OsRng,
        )?;
        open.blobs.create_dir()?;
        let name = format!("{id}.blob");
        open.blobs.write_atomic(&name, &sealed)?;
        // Moved, not copied, into the record: the store wipes it when the
        // vault locks (security review L2).
        let mut key_hex = hex32(key.as_bytes());
        let mut fields = Map::new();
        fields.insert("key".into(), Value::String(std::mem::take(&mut *key_hex)));
        let result = self.commit_ops(vec![Op::Put {
            kind: BLOB_KIND.into(),
            id: id.clone(),
            fields,
        }]);
        if let Err(e) = result {
            if let Some(open) = self.open.as_ref() {
                let _ = open.blobs.remove(&name);
            }
            return Err(e);
        }
        Ok(id)
    }

    pub fn get_blob(&self, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let open = self.opened()?;
        let id_bytes = store::unhex16(id).ok_or(Error::InvalidInput("file id"))?;
        if !open.store.exists(BLOB_KIND, id) {
            return Err(Error::NotFound);
        }
        let key = open
            .store
            .field_str(BLOB_KIND, id, "key")
            .and_then(unhex32)
            .ok_or(Error::Damaged("file key"))?;
        let bytes = open
            .blobs
            .read(&format!("{id}.blob"))?
            .ok_or(Error::Damaged("file missing"))?;
        blob::open(
            &key,
            open.keyring.suite,
            &open.keyring.vault_id,
            &id_bytes,
            &bytes,
        )
    }

    /// Deletes a file. Its key disappears with the next compaction.
    pub fn delete_blob(&mut self, id: &str) -> Result<()> {
        store::unhex16(id).ok_or(Error::InvalidInput("file id"))?;
        if !self.opened()?.store.exists(BLOB_KIND, id) {
            return Err(Error::NotFound);
        }
        self.commit_ops(vec![Op::Del {
            kind: BLOB_KIND.into(),
            id: id.to_owned(),
        }])?;
        if let Some(open) = self.open.as_ref() {
            let _ = open.blobs.remove(&format!("{id}.blob"));
        }
        Ok(())
    }

    /// The ids of all stored files, so the app can delete those no record
    /// refers to any more.
    pub fn blob_ids(&self) -> Result<Vec<String>> {
        Ok(self.opened()?.store.ids(BLOB_KIND))
    }

    // ---- Passphrase and recovery key ----------------------------------------

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

/// The master key, its derived keys, the keyring copy in use and the
/// unwrapped journal keys by generation.
type OpenedKeyring = (SecretKey, KeyringKeys, Keyring, Vec<(u32, SecretKey)>);

/// Opens the master key and chooses the keyring copy to use (M1).
fn open_keyring(
    dir: &Dir,
    secret: &Secret,
    config: &Config,
    rng: &mut dyn Rng,
    status: &mut Status,
) -> Result<OpenedKeyring> {
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

    let (used, mk) = open_master_key(&copies, secret)?;

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
    // The secret must open the copy in use, not merely some copy: after a
    // change whose backup write failed, the backup still holds the old slot,
    // and the old passphrase must no longer work (security review L1).
    let same_slot = match secret {
        Secret::Passphrase(_) => copies[used].1.passphrase == copies[auth].1.passphrase,
        Secret::Recovery(_) => copies[used].1.recovery == copies[auth].1.recovery,
    };
    if !same_slot {
        return Err(match secret {
            Secret::Passphrase(_) => Error::WrongPassphrase,
            Secret::Recovery(_) => Error::WrongRecoveryKey,
        });
    }
    let mut keyring = copies[auth].1.clone();

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
    // passphrase really opened (never undo a newer passphrase change). Best
    // effort: if anything fails, keep the old parameters and try again at the
    // next unlock.
    if let Secret::Passphrase(pw) = secret
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
        if let Ok(backup_ok) = save(dir, &updated) {
            keyring = updated;
            status.upgraded_passphrase_hashing = true;
            status.keyring_backup_stale = !backup_ok;
        }
    }
    Ok((mk, keys, keyring, journal_keys))
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

/// Finishes an interrupted compaction: keys and files of other generations go.
fn clean_up_generations(
    dir: &Dir,
    keyring: &mut Keyring,
    keys: &KeyringKeys,
    active: u32,
    files: &BTreeSet<u32>,
) -> Result<()> {
    if keyring.data_keys.iter().any(|k| k.generation != active) {
        let mut updated = keyring.clone();
        updated.data_keys.retain(|k| k.generation == active);
        updated.seq += 1;
        updated.seal_mac(keys);
        save(dir, &updated)?;
        *keyring = updated;
    }
    // Only older files: a newer one would mean damage, and unlock doesn't
    // clean up then.
    for g in files.iter().filter(|g| **g < active) {
        dir.remove(&journal::file_name(*g))?;
    }
    dir.sync()
}

/// Removes files without a key: left by a crash between writing a file and
/// committing its key, or between deleting the key and the file.
fn clean_up_blobs(blobs: &Dir, store: &Store) -> Result<()> {
    if !blobs.path().exists() {
        return Ok(());
    }
    for name in blobs.list()? {
        let keep = name
            .strip_suffix(".blob")
            .is_some_and(|id| store.exists(BLOB_KIND, id));
        if !keep {
            blobs.remove(&name)?;
        }
    }
    Ok(())
}

/// Splits snapshot operations into batches of about [`SNAPSHOT_BATCH`] bytes.
/// A record too big for one batch becomes several snapshot operations with
/// some of its fields each; they merge back into the same record (security
/// review L3: one big record made every compaction fail).
fn split(ops: Vec<Op>) -> Vec<Vec<Op>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut size = 0;
    for op in ops.into_iter().flat_map(split_record) {
        let n = encoded_len(&op);
        if !current.is_empty() && size + n > SNAPSHOT_BATCH {
            batches.push(std::mem::take(&mut current));
            size = 0;
        }
        size += n;
        current.push(op);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// One record's snapshot as parts of at most [`SNAPSHOT_BATCH`] bytes (a
/// single field is at most 64 KiB of text, under 400 KiB as JSON, so every
/// part fits into a journal frame).
fn split_record(op: Op) -> Vec<Op> {
    if encoded_len(&op) <= SNAPSHOT_BATCH {
        return vec![op];
    }
    let Op::Snap {
        kind,
        id,
        alive,
        fields,
    } = &op
    else {
        return vec![op];
    };
    let mut parts = Vec::new();
    let mut part = Vec::new();
    let mut size = 0;
    for field in fields {
        let n = encoded_len(field);
        if !part.is_empty() && size + n > SNAPSHOT_BATCH {
            parts.push(Op::Snap {
                kind: kind.clone(),
                id: id.clone(),
                alive: *alive,
                fields: std::mem::take(&mut part),
            });
            size = 0;
        }
        size += n;
        part.push(field.clone());
    }
    parts.push(Op::Snap {
        kind: kind.clone(),
        id: id.clone(),
        alive: *alive,
        fields: part,
    });
    parts
}

/// The length of a value as JSON, counted without keeping a copy of it.
fn encoded_len<T: serde::Serialize>(value: &T) -> usize {
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
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

fn hex32(b: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn unhex32(s: &str) -> Option<SecretKey> {
    if s.len() != 64 {
        return None;
    }
    let mut key = SecretKey::zero();
    for (i, o) in key.as_mut_bytes().iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(key)
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
        if name.ends_with(".tmp") || journal::generation_of(&name).is_some() {
            dir.remove(&name)?;
        }
    }
    let blobs = dir.sub(BLOBS);
    if blobs.path().exists() {
        for name in blobs.list()? {
            blobs.remove(&name)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod regression_tests;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod tests;
