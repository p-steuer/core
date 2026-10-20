//! Archive segments (D55), through the vault, with a clock driven by hand.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::keyring::tests::{PASSPHRASE, TEST_PARAMS};
use super::*;
use crate::id::uuid_v7;
use crate::rand::TestRng;

/// 1 January of each year, 00:00 UTC.
fn jan1(year: i32) -> u64 {
    match year {
        2025 => 1_735_689_600_000,
        2026 => 1_767_225_600_000,
        2027 => 1_798_761_600_000,
        2028 => 1_830_297_600_000,
        _ => unreachable!("not used"),
    }
}

/// 15 January and 1 June of a year.
fn january(year: i32) -> u64 {
    jan1(year) + 14 * 86_400_000
}
fn june(year: i32) -> u64 {
    jan1(year) + 151 * 86_400_000
}

struct Fixture {
    tmp: tempfile::TempDir,
    now: Arc<AtomicU64>,
}

impl Fixture {
    fn new(now_ms: u64) -> Self {
        Fixture {
            tmp: tempfile::tempdir().unwrap(),
            now: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn config(&self) -> Config {
        Config {
            params: TEST_PARAMS,
            clock: Clock::Manual(self.now.clone()),
        }
    }

    fn set(&self, now_ms: u64) {
        self.now.store(now_ms, Ordering::SeqCst);
    }

    fn make(&self) -> Vault {
        PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("archive"), self.config())
            .unwrap()
            .create_in(Dir::new(self.path()))
            .unwrap()
    }

    fn unlock(&self) -> Vault {
        let secret = Secret::Passphrase(passphrase::normalize(PASSPHRASE));
        Vault::unlock_in(
            Dir::new(self.path()),
            secret,
            self.config(),
            &mut TestRng::new("unlock"),
        )
        .unwrap()
    }

    fn archive_files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("archive-"))
            .collect();
        names.sort();
        names
    }
}

/// A record id created at `ms`.
fn id_at(ms: u64, label: &str) -> String {
    uuid_v7(ms, &mut TestRng::new(label)).unwrap()
}

fn put(kind: &str, id: &str, f: serde_json::Value) -> Change {
    Change::Put {
        kind: kind.into(),
        id: id.into(),
        fields: f.as_object().unwrap().clone(),
    }
}

fn ids(v: &Vault, kind: &str) -> Vec<String> {
    v.records(kind).unwrap().into_iter().map(|r| r.id).collect()
}

/// A vault with a set from June 2025, one from June 2026 and a record with a
/// fixed id, written in June 2026.
fn three_records() -> (Fixture, Vault, String, String) {
    let f = Fixture::new(june(2026));
    let mut v = f.make();
    let old = id_at(june(2025), "2025");
    let new = id_at(june(2026), "2026");
    v.commit(vec![
        put("set", &old, json!({"reps": 5, "note": "from 2025"})),
        put("set", &new, json!({"reps": 6})),
        put("profile", "me", json!({"height_cm": 180})),
    ])
    .unwrap();
    (f, v, old, new)
}

#[test]
fn a_year_is_archived_only_once_it_is_two_years_old() {
    let (f, mut v, old, new) = three_records();
    let mut both = vec![old.clone(), new.clone()];
    both.sort();
    // June 2026: nothing to archive.
    assert!(!v.needs_compaction());
    v.compact().unwrap();
    assert_eq!(v.archive_years().unwrap(), Vec::<i32>::new());

    // January 2027: 2025 is two years old, 2026 isn't (the user's amendment
    // of D55: in January 2027 all of 2026 is still there).
    f.set(january(2027));
    assert!(v.needs_compaction());
    v.compact().unwrap();
    assert!(!v.needs_compaction());
    assert_eq!(v.archive_years().unwrap(), [2025]);
    assert_eq!(ids(&v, "set"), [new.as_str()]);
    assert_eq!(f.archive_files().len(), 1);
    v.lock();

    let mut v = f.unlock();
    assert_eq!(ids(&v, "set"), [new.as_str()]);
    assert_eq!(ids(&v, "profile"), ["me"]);
    assert!(!v.archive_loaded(2025).unwrap());
    v.load_archive(2025).unwrap();
    assert!(v.archive_loaded(2025).unwrap());
    assert_eq!(ids(&v, "set"), both);
    let r = v.record("set", &old).unwrap().unwrap();
    assert_eq!(r.fields["note"], "from 2025");
    v.unload_archive(2025).unwrap();
    assert_eq!(ids(&v, "set"), [new.as_str()]);

    // January 2028: now 2026 goes too; the fixed id never does.
    f.set(january(2028));
    v.compact().unwrap();
    assert_eq!(v.archive_years().unwrap(), [2025, 2026]);
    assert!(ids(&v, "set").is_empty());
    assert_eq!(ids(&v, "profile"), ["me"]);
    v.lock();
    let mut v = f.unlock();
    assert!(ids(&v, "set").is_empty());
    v.load_archive(2026).unwrap();
    assert_eq!(ids(&v, "set"), [new]);
    assert_eq!(v.load_archive(2024), Err(Error::NotFound));
}

#[test]
fn a_year_the_app_loaded_stays_in_memory_through_compaction() {
    let (f, mut v, old, _) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    v.load_archive(2025).unwrap();
    v.commit(vec![put("set", "x", json!({"reps": 1}))]).unwrap();
    v.commit(vec![Change::Delete {
        kind: "set".into(),
        id: "x".into(),
    }])
    .unwrap();
    v.compact().unwrap();
    assert!(v.archive_loaded(2025).unwrap());
    assert!(v.record("set", &old).unwrap().is_some());
}

#[test]
fn changing_an_archived_record_loads_its_year_and_rewrites_it() {
    let (f, mut v, old, new) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    let before = f.archive_files();
    v.lock();

    let mut v = f.unlock();
    // The app changes one field of a record it got from the archive.
    v.commit(vec![put("set", &old, json!({"reps": 7}))])
        .unwrap();
    assert!(v.archive_loaded(2025).unwrap());
    let r = v.record("set", &old).unwrap().unwrap();
    assert_eq!(
        (r.fields["reps"].clone(), r.fields["note"].clone()),
        (json!(7), json!("from 2025"))
    );
    assert!(v.needs_compaction());
    v.lock();

    // Not yet compacted: the change waits in the journal, and its year comes
    // into memory with the archive, whole.
    let mut v = f.unlock();
    assert!(v.archive_loaded(2025).unwrap());
    assert_eq!(
        v.record("set", &old).unwrap().unwrap().fields["note"],
        "from 2025"
    );
    assert!(v.needs_compaction());
    v.compact().unwrap();
    // A new file under a new key; the old one is gone.
    let after = f.archive_files();
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    assert_eq!(ids(&v, "set"), [new]);
    v.lock();

    let mut v = f.unlock();
    assert!(!v.archive_loaded(2025).unwrap());
    v.load_archive(2025).unwrap();
    let r = v.record("set", &old).unwrap().unwrap();
    assert_eq!(
        (r.fields["reps"].clone(), r.fields["note"].clone()),
        (json!(7), json!("from 2025"))
    );
}

#[test]
fn deleting_an_archived_record_removes_it_from_the_archive() {
    let (f, mut v, old, _) = three_records();
    let other = id_at(june(2025) + 1, "2025b");
    v.commit(vec![put("set", &other, json!({"reps": 3}))])
        .unwrap();
    f.set(january(2027));
    v.compact().unwrap();
    let before = f.archive_files();
    v.lock();

    let mut v = f.unlock();
    v.commit(vec![Change::Delete {
        kind: "set".into(),
        id: old.clone(),
    }])
    .unwrap();
    v.compact().unwrap();
    assert_ne!(f.archive_files(), before);
    v.load_archive(2025).unwrap();
    assert_eq!(v.record("set", &old).unwrap(), None);
    assert!(v.record("set", &other).unwrap().is_some());

    // Deleting the year's last record leaves no archive at all.
    v.commit(vec![Change::Delete {
        kind: "set".into(),
        id: other,
    }])
    .unwrap();
    v.compact().unwrap();
    assert_eq!(v.archive_years().unwrap(), Vec::<i32>::new());
    assert!(f.archive_files().is_empty());
}

#[test]
fn unloading_a_changed_year_saves_it_first() {
    let (f, mut v, old, _) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    v.load_archive(2025).unwrap();
    v.commit(vec![put("set", &old, json!({"reps": 9}))])
        .unwrap();
    v.unload_archive(2025).unwrap();
    assert!(!v.archive_loaded(2025).unwrap());
    assert!(!v.needs_compaction());
    assert_eq!(v.record("set", &old).unwrap(), None);
    v.load_archive(2025).unwrap();
    assert_eq!(v.record("set", &old).unwrap().unwrap().fields["reps"], 9);
}

#[test]
fn a_damaged_or_swapped_archive_is_refused() {
    let (f, mut v, old, new) = three_records();
    f.set(january(2028));
    v.compact().unwrap();
    let files = f.archive_files();
    assert_eq!(files.len(), 2);
    v.lock();
    let names: BTreeMap<i32, String> = {
        let v = f.unlock();
        let o = v.opened().unwrap();
        o.archives()
            .into_iter()
            .map(|(y, e)| (y, archive::file_name(&e.id)))
            .collect()
    };
    let (p25, p26) = (f.path().join(&names[&2025]), f.path().join(&names[&2026]));
    let good25 = std::fs::read(&p25).unwrap();

    // A flipped byte.
    let mut bad = good25.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    std::fs::write(&p25, &bad).unwrap();
    let mut v = f.unlock();
    assert!(matches!(v.load_archive(2025), Err(Error::Damaged(_))));
    assert!(!v.archive_loaded(2025).unwrap());
    assert_eq!(v.record("set", &old).unwrap(), None);
    // The rest of the vault works.
    v.load_archive(2026).unwrap();
    assert!(v.record("set", &new).unwrap().is_some());
    v.lock();

    // Another year's archive under this year's name.
    std::fs::copy(&p26, &p25).unwrap();
    let mut v = f.unlock();
    assert!(matches!(v.load_archive(2025), Err(Error::Damaged(_))));
    v.lock();

    // A journal file isn't an archive, and the other way round.
    let journal = std::fs::read(f.path().join(journal::file_name(
        f.unlock().opened().unwrap().journal.generation,
    )))
    .unwrap();
    std::fs::write(&p25, &journal).unwrap();
    let mut v = f.unlock();
    assert!(matches!(v.load_archive(2025), Err(Error::Damaged(_))));
    std::fs::write(&p25, &good25).unwrap();
    v.load_archive(2025).unwrap();
    assert!(v.record("set", &old).unwrap().is_some());
}

#[test]
fn a_needed_archive_that_cant_be_read_makes_the_vault_read_only() {
    let (f, mut v, old, _) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    // A change to 2025 waits in the journal...
    v.commit(vec![put("set", &old, json!({"reps": 8}))])
        .unwrap();
    v.lock();
    // ...and its archive is damaged: compacting would write 2025 from part
    // of its records, so nothing may change.
    let name = f.archive_files().remove(0);
    let path = f.path().join(name);
    let mut b = std::fs::read(&path).unwrap();
    let last = b.len() - 1;
    b[last] ^= 1;
    std::fs::write(&path, &b).unwrap();
    let mut v = f.unlock();
    assert_eq!(v.status().damage, Some("archive"));
    assert_eq!(v.compact(), Err(Error::ReadOnly));
    assert!(path.exists());
}

#[test]
fn leftover_archive_files_are_removed() {
    let (f, mut v, _, _) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    v.lock();
    let kept = f.archive_files();
    let leftover = format!("archive-{}.log", "ab".repeat(16));
    std::fs::write(f.path().join(&leftover), b"from a compaction that stopped").unwrap();
    std::fs::write(f.path().join("archive-notes.txt"), b"not ours").unwrap();
    let _v = f.unlock();
    assert_eq!(
        f.archive_files(),
        [kept, vec!["archive-notes.txt".into()]].concat()
    );
}

#[test]
fn archive_keys_are_core_records_the_app_cant_see() {
    let (f, mut v, _, _) = three_records();
    f.set(january(2027));
    v.compact().unwrap();
    assert!(v.records(archive::ARCHIVE_KIND).is_err());
    let o = v.opened().unwrap();
    let archives = o.archives();
    let entry = &archives[&2025];
    // The key is held once, as text the store wipes, and never printed.
    let key_hex = o
        .store
        .field_str(archive::ARCHIVE_KIND, &entry.id, "key")
        .unwrap();
    assert!(matches!(key_hex, std::borrow::Cow::Borrowed(_)));
    for shown in [format!("{:?}", o.store), format!("{v:?}")] {
        assert!(!shown.contains(&*key_hex), "{shown}");
    }
}

#[test]
fn archives_written_while_the_clock_was_ahead_come_back() {
    let (f, mut v, old, new) = three_records();
    // The clock jumps to 2028: 2025 and 2026 are archived.
    f.set(january(2028));
    v.compact().unwrap();
    assert_eq!(v.archive_years().unwrap(), [2025, 2026]);
    v.lock();
    // Set right again, in June 2026: nothing may stay hidden.
    f.set(june(2026) + 86_400_000);
    let mut v = f.unlock();
    let mut both = vec![old.clone(), new.clone()];
    both.sort();
    assert_eq!(ids(&v, "set"), both);
    assert!(v.needs_compaction());
    v.compact().unwrap();
    assert_eq!(v.archive_years().unwrap(), Vec::<i32>::new());
    assert!(f.archive_files().is_empty());
    v.lock();
    let v = f.unlock();
    assert_eq!(ids(&v, "set"), both);
    assert_eq!(
        v.record("set", &old).unwrap().unwrap().fields["note"],
        "from 2025"
    );
}
