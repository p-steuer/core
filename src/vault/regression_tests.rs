//! Regression tests for the findings of the security review of M8
//! (19 Oct 2026; DEVELOPMENT.md). Each failed before its fix.

use std::path::Path;

use serde_json::{Map, Value, json};

use super::keyring::tests::{PASSPHRASE, TEST_PARAMS};
use super::*;
use crate::fsio::faults::Faults;
use crate::rand::TestRng;

const TEST: Config = Config {
    params: TEST_PARAMS,
    clock: Clock::System,
};
const NEW_PASSPHRASE: &str = "violet otter mango ladder frost";
/// A folder in place of the backup's temporary file: every write of the
/// backup copy fails while it is there.
const BACKUP_BLOCKER: &str = "keyring.2.tmp";

fn make(path: &Path) -> (Vault, String) {
    let pending =
        PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("regression"), TEST).unwrap();
    let recovery = pending.recovery_key().to_string();
    (pending.create_in(Dir::new(path)).unwrap(), recovery)
}

fn unlock_with(dir: Dir, secret: Secret) -> Result<Vault> {
    Vault::unlock_in(dir, secret, TEST, &mut TestRng::new("unlock"))
}

fn unlock(path: &Path, pw: &str) -> Result<Vault> {
    unlock_with(
        Dir::new(path),
        Secret::Passphrase(passphrase::normalize(pw)),
    )
}

fn unlock_recovery(path: &Path, key: &str) -> Result<Vault> {
    unlock_with(Dir::new(path), Secret::Recovery(RecoveryKey::parse(key)?))
}

fn put(kind: &str, id: &str, f: Value) -> Change {
    Change::Put {
        kind: kind.into(),
        id: id.into(),
        fields: f.as_object().unwrap().clone(),
    }
}

fn del(kind: &str, id: &str) -> Change {
    Change::Delete {
        kind: kind.into(),
        id: id.into(),
    }
}

fn ids(v: &Vault) -> Vec<String> {
    v.records("set")
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect()
}

fn journals(path: &Path) -> Vec<u32> {
    Dir::new(path)
        .list()
        .unwrap()
        .iter()
        .filter_map(|n| journal::generation_of(n))
        .collect()
}

/// M2 (a): a stale backup copy (from before a compaction) and a damaged main
/// copy made unlock fall back to the old generation and delete the newer
/// journal, losing everything written since. Now nothing is deleted and the
/// vault opens read-only.
#[test]
fn m2_a_stale_keyring_copy_never_deletes_a_newer_journal() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, _) = make(p);
    v.commit(vec![put("set", "a", json!({"reps": 1}))]).unwrap();
    v.commit(vec![del("set", "a")]).unwrap();
    v.commit(vec![put("set", "b", json!({"reps": 2}))]).unwrap();
    let old_keyring = std::fs::read(p.join(KEYRING_BACKUP)).unwrap();
    let old_journal = std::fs::read(p.join(journal::file_name(1))).unwrap();
    v.compact().unwrap();
    v.commit(vec![put("set", "c", json!({"reps": 3}))]).unwrap();
    v.lock();
    // An old backup and old journal come back (e.g. restored files), then
    // the main copy is damaged.
    std::fs::write(p.join(KEYRING_BACKUP), &old_keyring).unwrap();
    std::fs::write(p.join(journal::file_name(1)), &old_journal).unwrap();
    std::fs::write(p.join(KEYRING), b"garbage").unwrap();

    let mut v = unlock(p, PASSPHRASE).unwrap();
    assert_eq!(journals(p), vec![1, 2], "the newer journal stays");
    assert_eq!(v.status().damage, Some("journal without its key"));
    assert_eq!(ids(&v), vec!["b".to_string()]);
    assert_eq!(
        v.commit(vec![put("set", "d", json!({}))]).unwrap_err(),
        Error::ReadOnly
    );
}

/// M2 (b): compaction went on although the backup copy couldn't be written,
/// so the new journal's key was in one file only; damage to it made the
/// vault unopenable even with the recovery key. Now compaction stops first.
#[test]
fn m2_compaction_stops_when_the_backup_copy_cant_be_written() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, recovery) = make(p);
    v.commit(vec![put("set", "a", json!({"reps": 1}))]).unwrap();
    v.commit(vec![del("set", "a")]).unwrap();
    v.commit(vec![put("set", "b", json!({"reps": 2}))]).unwrap();
    std::fs::create_dir(p.join(BACKUP_BLOCKER)).unwrap();
    assert!(matches!(v.compact(), Err(Error::Io(_))));
    assert!(v.status().keyring_backup_stale);
    assert!(v.needs_compaction(), "still due");
    assert_eq!(journals(p), vec![1], "no journal without a second key copy");
    v.commit(vec![put("set", "c", json!({"reps": 3}))]).unwrap();
    v.lock();

    let mut main = std::fs::read(p.join(KEYRING)).unwrap();
    main[100] ^= 1;
    std::fs::write(p.join(KEYRING), &main).unwrap();
    let v = unlock(p, PASSPHRASE).unwrap();
    assert_eq!(ids(&v), vec!["b".to_string(), "c".to_string()]);
    drop(v);
    let v = unlock_recovery(p, &recovery).unwrap();
    assert_eq!(ids(&v), vec!["b".to_string(), "c".to_string()]);
    drop(v);

    // Once the backup can be written again, compaction finishes.
    std::fs::remove_dir(p.join(BACKUP_BLOCKER)).unwrap();
    let mut v = unlock(p, PASSPHRASE).unwrap();
    v.compact().unwrap();
    assert!(!v.needs_compaction());
    assert!(!v.status().keyring_backup_stale);
    assert_eq!(journals(p), vec![2]);
    assert_eq!(
        std::fs::read(p.join(KEYRING)).unwrap(),
        std::fs::read(p.join(KEYRING_BACKUP)).unwrap()
    );
}

/// L1: after a passphrase change that couldn't update the backup copy, the
/// old passphrase still opened the vault, with the newest data.
#[test]
fn l1_the_old_passphrase_is_refused_after_a_change_with_a_stale_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, _) = make(p);
    v.commit(vec![put("set", "a", json!({"reps": 1}))]).unwrap();
    std::fs::create_dir(p.join(BACKUP_BLOCKER)).unwrap();
    v.set_passphrase(NEW_PASSPHRASE).unwrap();
    assert!(v.status().keyring_backup_stale);
    v.lock();
    assert_eq!(unlock(p, PASSPHRASE).unwrap_err(), Error::WrongPassphrase);
    drop(unlock(p, NEW_PASSPHRASE).unwrap());
    assert_eq!(unlock(p, PASSPHRASE).unwrap_err(), Error::WrongPassphrase);
    // After the backup is repaired, too.
    std::fs::remove_dir(p.join(BACKUP_BLOCKER)).unwrap();
    let v = unlock(p, NEW_PASSPHRASE).unwrap();
    assert!(v.status().repaired_keyring);
    drop(v);
    assert_eq!(unlock(p, PASSPHRASE).unwrap_err(), Error::WrongPassphrase);
}

/// L1: the same for a replaced recovery key.
#[test]
fn l1_the_old_recovery_key_is_refused_after_a_replacement_with_a_stale_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, old) = make(p);
    std::fs::create_dir(p.join(BACKUP_BLOCKER)).unwrap();
    let new = v.begin_new_recovery_key().unwrap().to_string();
    v.finish_new_recovery_key().unwrap();
    assert!(v.status().keyring_backup_stale);
    v.lock();
    assert_eq!(
        unlock_recovery(p, &old).unwrap_err(),
        Error::WrongRecoveryKey
    );
    drop(unlock_recovery(p, &new).unwrap());
}

/// L2: the core's file keys sat as plain strings in the store, and `Debug`
/// printed them with every record's texts and the keyring's commitments.
#[test]
fn l2_debug_output_holds_no_keys_and_no_texts() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut v, _) = make(tmp.path());
    let id = v.put_blob(b"photo").unwrap();
    let marker = "private-note-marker";
    v.commit(vec![put("set", "s", json!({"note": marker}))])
        .unwrap();
    let open = v.opened().unwrap();
    let key = open
        .store
        .field_str(BLOB_KIND, &id, "key")
        .unwrap()
        .into_owned();
    let record = v.record("set", "s").unwrap().unwrap();
    let change = put("set", "s", json!({"note": marker}));
    for shown in [
        format!("{:?}", open.store),
        format!("{record:?}"),
        format!("{change:?}"),
        format!("{:?}", open.store.snapshot().collect::<Vec<_>>()),
        format!("{:?}", open.keyring),
    ] {
        assert!(!shown.contains(&key), "{shown}");
        assert!(!shown.contains(marker), "{shown}");
        assert!(!shown.contains("commitment"), "{shown}");
    }
    assert_eq!(&v.get_blob(&id).unwrap()[..], b"photo");
}

/// L3: one record whose snapshot exceeded a journal frame made every
/// compaction fail, so deleted values were never destroyed.
#[test]
fn l3_a_big_record_doesnt_stop_compaction() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, _) = make(p);
    // Control characters take 6 bytes each in JSON.
    let big: String = "\u{1}".repeat(64 * 1024);
    for f in ["a", "b", "c"] {
        let mut fields = Map::new();
        fields.insert(f.into(), Value::String(big.clone()));
        v.commit(vec![Change::Put {
            kind: "note".into(),
            id: "n1".into(),
            fields,
        }])
        .unwrap();
    }
    v.commit(vec![put("set", "x", json!({"reps": 1}))]).unwrap();
    v.commit(vec![del("set", "x")]).unwrap();
    assert!(v.needs_compaction());
    v.compact().unwrap();
    assert!(!v.needs_compaction());
    v.lock();
    let v = unlock(p, PASSPHRASE).unwrap();
    let note = v.record("note", "n1").unwrap().unwrap();
    for f in ["a", "b", "c"] {
        assert_eq!(note.fields[f], Value::String(big.clone()), "field {f}");
    }
    assert!(v.record("set", "x").unwrap().is_none());
}

/// L4: when compaction's last step (deleting the old key and file) failed,
/// `compact` still reported success and `needs_compaction` turned false, so
/// the app took the deletion as done.
#[test]
fn l4_a_failed_cleanup_keeps_compaction_due() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let (mut v, _) = make(p);
    v.commit(vec![put("set", "a", json!({"reps": 1}))]).unwrap();
    v.commit(vec![del("set", "a")]).unwrap();
    v.lock();
    // Compaction passes 26 crash points; the last 11 are step 4 (two keyring
    // copies, then removing the old file).
    let secret = Secret::Passphrase(passphrase::normalize(PASSPHRASE));
    let mut v = unlock_with(Dir::with_faults(p, Faults::crash_at(15)), secret).unwrap();
    v.compact().unwrap();
    assert!(v.needs_compaction(), "the old key is still in the keyring");
    drop(v);
    let v = unlock(p, PASSPHRASE).unwrap();
    assert!(!v.needs_compaction());
    assert_eq!(v.opened().unwrap().keyring.data_keys.len(), 1);
    assert_eq!(journals(p), vec![2]);
}
