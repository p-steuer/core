//! Archive segments (D55): the records of each year that is two years old
//! leave the journal for an archive file of that year, with its own key, and
//! are read back only when the app asks. So unlock replays only the current
//! and the previous calendar year, however long the history.
//!
//! - A record's year is the UTC year its UUIDv7 id was created in. Records
//!   with other ids (the app's fixed ids, the core's own records) stay in the
//!   journal.
//! - Each archive's key is a record of the core's own kind `_archive` in the
//!   journal, like the keys of files: it disappears with the journal
//!   generation that held it, which shreds the archive's old versions.
//! - Changing or deleting a record of an archived year loads that archive
//!   first, so a record is never seen half. The next compaction writes the
//!   year's archive again, under a new key.
//! - While a year with such changes is in memory, it stays there: unloading
//!   it compacts first.
//! - If the clock was ahead and is set back, archives of years that aren't
//!   two years old any more are loaded at unlock, and compaction returns
//!   their records to the journal.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The core's own record kind for the keys of archive segments.
pub(super) const ARCHIVE_KIND: &str = "_archive";
/// A year is archived once the current year is this many years later: the
/// current and the previous year always stay in the journal (D55).
const KEEP_YEARS: i32 = 2;

pub(super) fn file_name(id: &str) -> String {
    format!("archive-{id}.log")
}

fn id_of(name: &str) -> Option<&str> {
    let id = name.strip_prefix("archive-")?.strip_suffix(".log")?;
    store::unhex16(id).map(|_| id)
}

/// The newest year that is archived at time `now_ms`.
pub(super) fn last_archived_year(now_ms: u64) -> i32 {
    crate::id::year_of_ms(now_ms) - KEEP_YEARS
}

/// One archive segment as the journal lists it.
pub(super) struct Entry {
    pub id: String,
    pub key: SecretKey,
}

impl Open {
    /// The archive segments, by year.
    pub(super) fn archives(&self) -> BTreeMap<i32, Entry> {
        let mut out = BTreeMap::new();
        for id in self.store.ids(ARCHIVE_KIND) {
            let year = self
                .store
                .get(ARCHIVE_KIND, &id)
                .and_then(|r| r.fields.get("year").and_then(|y| y.as_i64()))
                .and_then(|y| i32::try_from(y).ok());
            let key = self
                .store
                .field_str(ARCHIVE_KIND, &id, "key")
                .as_deref()
                .and_then(unhex32);
            if let (Some(year), Some(key)) = (year, key) {
                out.insert(year, Entry { id, key });
            }
        }
        out
    }

    /// The archived years compaction must write: those with records in the
    /// journal, or with changes since their archive was loaded.
    pub(super) fn years_to_archive(&self, now_ms: u64) -> BTreeSet<i32> {
        let last = last_archived_year(now_ms);
        self.store
            .years()
            .into_iter()
            .filter(|y| *y <= last && self.loaded.get(y) != Some(&false))
            .collect()
    }

    /// The archives of years that aren't old enough for an archive (the
    /// clock was ahead when they were written).
    pub(super) fn early_archives(&self, now_ms: u64) -> Vec<(i32, String)> {
        let last = last_archived_year(now_ms);
        self.archives()
            .range(last + 1..)
            .map(|(y, e)| (*y, e.id.clone()))
            .collect()
    }

    /// Reads one archive into memory. Nothing is added unless all of it
    /// reads.
    pub(super) fn load(&mut self, dir: &Dir, year: i32, changed: bool) -> Result<()> {
        if let Some(c) = self.loaded.get_mut(&year) {
            *c |= changed;
            return Ok(());
        }
        let archives = self.archives();
        if let Some(entry) = archives.get(&year) {
            let expected = journal::archive_header(
                journal::FORMAT,
                self.keyring.suite,
                &self.keyring.vault_id,
                year as u32,
            );
            let bytes = dir
                .read(&file_name(&entry.id))?
                .ok_or(Error::Damaged("archive missing"))?;
            let contents = journal::read(&bytes, &entry.key, &expected, &self.keyring.device_id)?;
            if !matches!(contents.end, End::Clean) {
                return Err(Error::Damaged("archive"));
            }
            // Every batch is checked before any is applied, then decoded
            // again one at a time, so a year's records aren't held twice.
            for (_, plaintext) in &contents.frames {
                journal::decode(contents.format, plaintext)?;
            }
            for (_, plaintext) in &contents.frames {
                let batch = journal::decode(contents.format, plaintext)?;
                self.store.apply_archived(&batch, self.keyring.device_id);
            }
        }
        self.loaded.insert(year, changed);
        Ok(())
    }

    /// Loads the archives of the years these operations touch, before they
    /// are written.
    pub(super) fn load_for(&mut self, dir: &Dir, ops: &[Op], now_ms: u64) -> Result<()> {
        let last = last_archived_year(now_ms);
        let years: BTreeSet<i32> = ops
            .iter()
            .filter_map(|op| match op {
                Op::Put { id, .. } | Op::Del { id, .. } | Op::Snap { id, .. } => store::year_of(id),
            })
            .filter(|y| *y <= last)
            .collect();
        for year in years {
            self.load(dir, year, true)?;
        }
        Ok(())
    }
}

/// Removes archive files that no `_archive` record names: leftovers of an
/// interrupted compaction, or old versions it replaced.
pub(super) fn clean_up(dir: &Dir, open: &Open) -> Result<()> {
    let keep: BTreeSet<String> = open.archives().into_values().map(|e| e.id).collect();
    for name in dir.list()? {
        if id_of(&name).is_some_and(|id| !keep.contains(id)) {
            dir.remove(&name)?;
        }
    }
    Ok(())
}

/// What compaction writes for the archived years: the new files, and the
/// operations that swap their key records in the journal.
pub(super) struct Written {
    pub files: Vec<String>,
    pub replaced: Vec<String>,
    pub ops: Vec<Op>,
}

/// Writes a new archive file for each year in `years`, from the records in
/// memory, each under a new key. The journal doesn't name them yet.
pub(super) fn write(
    dir: &Dir,
    open: &Open,
    years: &BTreeSet<i32>,
    stamp: Stamp,
) -> Result<Written> {
    let old = open.archives();
    let mut out = Written {
        files: Vec::new(),
        replaced: Vec::new(),
        ops: Vec::new(),
    };
    let result = (|| -> Result<()> {
        for &year in years {
            if let Some(entry) = old.get(&year) {
                out.replaced.push(entry.id.clone());
            }
            let ops: Vec<Op> = open
                .store
                .snapshot_where(move |y| y == Some(year))
                .collect();
            if ops.is_empty() {
                // Everything of that year was deleted.
                continue;
            }
            let id = store::hex16(&rand::array(&mut OsRng)?);
            let key = SecretKey::random(&mut OsRng)?;
            let header = journal::archive_header(
                journal::FORMAT,
                open.keyring.suite,
                &open.keyring.vault_id,
                year as u32,
            );
            let mut bytes = header.to_vec();
            for (seq, batch_ops) in split(ops.into_iter()).enumerate() {
                let plaintext = journal::encode(
                    journal::FORMAT,
                    &Batch {
                        hlc: stamp.hlc,
                        ops: batch_ops,
                    },
                )?;
                bytes.extend(journal::seal_frame(
                    &key,
                    &header,
                    &open.keyring.device_id,
                    seq as u64 + 1,
                    &plaintext,
                    &mut OsRng,
                )?);
            }
            let name = file_name(&id);
            dir.write_atomic(&name, &bytes)?;
            out.files.push(name);
            let index = out.ops.len() as u32;
            let s = Stamp { index, ..stamp };
            // Moved, not copied, into the record, which is wiped (as for
            // files' keys).
            let mut key_hex = hex32(key.as_bytes());
            out.ops.push(Op::Snap {
                kind: ARCHIVE_KIND.into(),
                id,
                alive: s,
                fields: vec![
                    (
                        "key".into(),
                        s,
                        Value::String(std::mem::take(&mut *key_hex)),
                    ),
                    ("year".into(), s, Value::from(year)),
                ],
            });
        }
        Ok(())
    })();
    if let Err(e) = result {
        for name in &out.files {
            let _ = dir.remove(name);
        }
        return Err(e);
    }
    Ok(out)
}

impl Vault {
    /// After unlock: the years the journal still holds records of, though
    /// they are archived, come into memory with their archives (their changes
    /// wait for compaction), and files no archive record names go.
    pub(super) fn open_archives(&mut self) {
        let now = self.config.clock.now_ms();
        let Vault {
            dir, status, open, ..
        } = self;
        let Some(open) = open.as_mut() else {
            return;
        };
        let last = last_archived_year(now);
        let mut years: Vec<i32> = open
            .store
            .years()
            .into_iter()
            .filter(|y| *y <= last)
            .collect();
        years.extend(open.early_archives(now).into_iter().map(|(y, _)| y));
        for year in years {
            if open.load(dir, year, true).is_err() {
                // Compaction would write the year from part of its records.
                status.damage.get_or_insert("archive");
            }
        }
        if status.damage.is_none() {
            let _ = clean_up(dir, open);
        }
    }

    /// The years whose records are in archive segments, oldest first.
    pub fn archive_years(&self) -> Result<Vec<i32>> {
        Ok(self.opened()?.archives().into_keys().collect())
    }

    /// Whether an archived year's records are in memory.
    pub fn archive_loaded(&self, year: i32) -> Result<bool> {
        Ok(self.opened()?.loaded.contains_key(&year))
    }

    /// Brings an archived year's records into memory, until the vault locks
    /// or [`Vault::unload_archive`].
    pub fn load_archive(&mut self, year: i32) -> Result<()> {
        let Vault { dir, open, .. } = self;
        let open = open.as_mut().ok_or(Error::Locked)?;
        if !open.archives().contains_key(&year) {
            return Err(Error::NotFound);
        }
        open.load(dir, year, false)?;
        open.requested.insert(year);
        Ok(())
    }

    /// Takes an archived year's records out of memory. If they were changed,
    /// compaction saves the changes first.
    pub fn unload_archive(&mut self, year: i32) -> Result<()> {
        if self.opened()?.loaded.get(&year) == Some(&true) {
            self.compact()?;
        }
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.requested.remove(&year);
        if open.loaded.remove(&year).is_some() {
            open.store.retain_years(|y| y != Some(year));
        }
        Ok(())
    }
}
