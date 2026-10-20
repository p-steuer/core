//! The journal, compaction and files, through the vault (M2).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::keyring::tests::{PASSPHRASE, TEST_PARAMS};
use super::tests::copy_vault;
use super::*;
use crate::fsio::faults::Faults;
use crate::rand::TestRng;

const TEST: Config = Config {
    params: TEST_PARAMS,
    clock: Clock::System,
};

fn make(path: &Path) -> Vault {
    PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("store"), TEST)
        .unwrap()
        .create_in(Dir::new(path))
        .unwrap()
}

fn unlock(path: &Path) -> Vault {
    unlock_with(Dir::new(path), TEST)
}

fn unlock_with(dir: Dir, config: Config) -> Vault {
    let secret = Secret::Passphrase(passphrase::normalize(PASSPHRASE));
    Vault::unlock_in(dir, secret, config, &mut TestRng::new("unlock")).unwrap()
}

fn put(kind: &str, id: &str, f: serde_json::Value) -> Change {
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

fn snapshot(v: &Vault) -> Vec<Record> {
    let mut all = v.records("set").unwrap();
    all.extend(v.records("weight").unwrap());
    all
}

fn journal_name(v: &Vault) -> String {
    journal::file_name(v.opened().unwrap().journal.generation)
}

fn len(path: &Path, name: &str) -> u64 {
    std::fs::metadata(path.join(name)).unwrap().len()
}

/// Every file in the folder and its subfolders, as bytes.
fn all_files(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_dir() {
            out.extend(all_files(&p));
        } else {
            out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn records_survive_locking_and_follow_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    v.commit(vec![
        put("set", "s1", json!({"reps": 5, "weight_g": 100000})),
        put("set", "s2", json!({"reps": 3})),
        put("weight", "w1", json!({"weight_g": 80000})),
    ])
    .unwrap();
    v.commit(vec![put("set", "s1", json!({"reps": 6}))])
        .unwrap();
    v.commit(vec![del("set", "s2")]).unwrap();
    let before = snapshot(&v);
    assert_eq!(before.len(), 2);
    assert_eq!(
        v.record("set", "s1").unwrap().unwrap().fields["weight_g"],
        100000
    );
    assert_eq!(v.record("set", "s1").unwrap().unwrap().fields["reps"], 6);
    v.lock();
    assert_eq!(v.records("set").unwrap_err(), Error::Locked);

    let mut v = unlock(tmp.path());
    assert_eq!(snapshot(&v), before);
    assert_eq!(v.status(), Status::default());
    // Undo of the delete: written again.
    v.commit(vec![put("set", "s2", json!({"reps": 3}))])
        .unwrap();
    v.lock();
    assert_eq!(unlock(tmp.path()).records("set").unwrap().len(), 2);
}

#[test]
fn invalid_changes_write_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let name = journal_name(&v);
    let size = len(tmp.path(), &name);
    assert!(v.commit(vec![put("Set", "a", json!({}))]).is_err());
    assert!(v.commit(vec![put("_blob", "a", json!({}))]).is_err());
    assert!(v.commit(vec![put("set", "a", json!({"x": [1]}))]).is_err());
    assert!(v.commit(vec![]).is_err());
    assert_eq!(
        v.records("_blob").unwrap_err(),
        Error::InvalidInput("record kind")
    );
    assert_eq!(len(tmp.path(), &name), size);
}

#[test]
fn the_clock_going_back_doesnt_undo_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicU64::new(1_800_000_000_000));
    let config = Config {
        params: TEST_PARAMS,
        clock: Clock::Manual(now.clone()),
    };
    let mut v = PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("clock"), config.clone())
        .unwrap()
        .create_in(Dir::new(tmp.path()))
        .unwrap();
    v.commit(vec![put("set", "s1", json!({"reps": 1}))])
        .unwrap();
    now.store(1_700_000_000_000, Ordering::SeqCst); // a year back
    v.commit(vec![put("set", "s1", json!({"reps": 2}))])
        .unwrap();
    assert_eq!(v.record("set", "s1").unwrap().unwrap().fields["reps"], 2);
    v.lock();
    let mut v = unlock_with(Dir::new(tmp.path()), config);
    assert_eq!(v.record("set", "s1").unwrap().unwrap().fields["reps"], 2);
    v.commit(vec![put("set", "s1", json!({"reps": 3}))])
        .unwrap();
    assert_eq!(v.record("set", "s1").unwrap().unwrap().fields["reps"], 3);
}

#[test]
fn an_unfinished_last_change_is_cut_off() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let name = journal_name(&v);
    v.commit(vec![put("set", "s1", json!({"reps": 1}))])
        .unwrap();
    let good = len(tmp.path(), &name);
    v.commit(vec![put("set", "s2", json!({"reps": 2}))])
        .unwrap();
    let full = len(tmp.path(), &name);
    v.lock();
    for cut in [good + 1, good + 8, good + 9, (good + full) / 2, full - 1] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join(&name))
            .unwrap();
        file.set_len(cut).unwrap();
        drop(file);
        let mut v = unlock(tmp.path());
        assert!(v.status().recovered_journal, "cut at {cut}");
        assert_eq!(v.status().damage, None);
        assert_eq!(v.records("set").unwrap().len(), 1, "cut at {cut}");
        assert_eq!(len(tmp.path(), &name), good);
        // Writing continues normally.
        v.commit(vec![put("set", "s2", json!({"reps": 2}))])
            .unwrap();
        v.lock();
        let v = unlock(tmp.path());
        assert_eq!(v.records("set").unwrap().len(), 2);
        assert_eq!(len(tmp.path(), &name), full);
        drop(v);
    }
}

#[test]
fn damage_opens_read_only_and_deletes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let name = journal_name(&v);
    v.commit(vec![put("set", "s1", json!({"reps": 1}))])
        .unwrap();
    v.commit(vec![put("set", "s2", json!({"reps": 2}))])
        .unwrap();
    v.commit(vec![put("set", "s3", json!({"reps": 3}))])
        .unwrap();
    v.lock();
    // Damage the second frame: the first stays readable.
    let mut bytes = std::fs::read(tmp.path().join(&name)).unwrap();
    let second =
        journal::HEADER_LEN + 8 + u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    bytes[second + 60] ^= 1;
    std::fs::write(tmp.path().join(&name), &bytes).unwrap();

    let mut v = unlock(tmp.path());
    assert_eq!(v.status().damage, Some("frame doesn't decrypt"));
    assert_eq!(v.records("set").unwrap().len(), 1);
    assert_eq!(
        v.commit(vec![put("set", "x", json!({}))]).unwrap_err(),
        Error::ReadOnly
    );
    assert_eq!(v.compact().unwrap_err(), Error::ReadOnly);
    assert_eq!(v.put_blob(b"x").unwrap_err(), Error::ReadOnly);
    v.lock();
    assert_eq!(
        std::fs::read(tmp.path().join(&name)).unwrap(),
        bytes,
        "nothing deleted"
    );
}

#[test]
fn a_crash_at_any_step_of_a_commit_keeps_all_or_nothing() {
    let template = tempfile::tempdir().unwrap();
    let mut v = make(template.path());
    v.commit(vec![put("set", "old", json!({"reps": 1}))])
        .unwrap();
    drop(v);
    let change = || {
        vec![
            put("set", "new", json!({"reps": 2})),
            put("set", "old", json!({"reps": 9})),
        ]
    };

    let tmp = tempfile::tempdir().unwrap();
    copy_vault(template.path(), tmp.path());
    let faults = Faults::counting();
    let mut v = unlock_with(Dir::with_faults(tmp.path(), faults.clone()), TEST);
    let start = faults.passed();
    v.commit(change()).unwrap();
    let total = faults.passed() - start;
    assert_eq!((start, total), (0, 2));

    for n in 0..=total {
        let tmp = tempfile::tempdir().unwrap();
        copy_vault(template.path(), tmp.path());
        let mut v = unlock_with(Dir::with_faults(tmp.path(), Faults::crash_at(n)), TEST);
        let result = v.commit(change());
        drop(v);
        let mut v = unlock(tmp.path());
        assert_eq!(v.status().damage, None, "step {n}");
        let new = v.record("set", "new").unwrap();
        let old = v.record("set", "old").unwrap().unwrap();
        if new.is_some() {
            assert_eq!(old.fields["reps"], 9, "step {n}: half a commit");
        } else {
            assert_eq!(old.fields["reps"], 1, "step {n}: half a commit");
            assert!(result.is_err(), "step {n}: reported success but lost");
        }
        // And writing goes on.
        v.commit(vec![put("set", "later", json!({}))]).unwrap();
        v.lock();
        assert!(
            unlock(tmp.path()).record("set", "later").unwrap().is_some(),
            "step {n}"
        );
    }
}

#[test]
fn compaction_keeps_the_state_and_destroys_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    v.commit(vec![put(
        "set",
        "s1",
        json!({"reps": 5, "note": "first-note-marker"}),
    )])
    .unwrap();
    v.commit(vec![put("set", "s1", json!({"note": "kept-marker"}))])
        .unwrap();
    v.commit(vec![put("set", "s2", json!({"note": "deleted-marker"}))])
        .unwrap();
    v.commit(vec![del("set", "s2")]).unwrap();
    assert!(v.needs_compaction());
    let before = snapshot(&v);
    let old_key = *v.opened().unwrap().journal.key.as_bytes();

    v.compact().unwrap();
    assert!(!v.needs_compaction());
    assert_eq!(snapshot(&v), before);
    let open = v.opened().unwrap();
    assert_eq!(open.journal.generation, 2);
    assert_eq!(open.keyring.data_keys.len(), 1);
    assert_eq!(open.keyring.data_keys[0].generation, 2);
    let new_key = open.journal.key.duplicate();
    assert!(!tmp.path().join(journal::file_name(1)).exists());
    v.commit(vec![put("set", "s3", json!({"reps": 1}))])
        .unwrap();
    v.lock();

    let v = unlock(tmp.path());
    assert_eq!(v.records("set").unwrap().len(), 2);
    assert_eq!(
        v.record("set", "s1").unwrap().unwrap().fields["note"],
        "kept-marker"
    );
    // Both keyring copies hold only the new key.
    for name in [KEYRING, KEYRING_BACKUP] {
        let k = Keyring::parse(&std::fs::read(tmp.path().join(name)).unwrap()).unwrap();
        assert_eq!(
            k.data_keys.iter().map(|k| k.generation).collect::<Vec<_>>(),
            [2]
        );
    }
    // The decrypted new journal holds no old or deleted value.
    let k = &v.opened().unwrap().keyring;
    let bytes = std::fs::read(tmp.path().join(journal::file_name(2))).unwrap();
    let header = journal::header(journal::FORMAT, k.suite, &k.vault_id, 2);
    let contents = journal::read(&bytes, &new_key, &header, &k.device_id).unwrap();
    let text: Vec<u8> = contents
        .frames
        .iter()
        .flat_map(|(_, p)| p.to_vec())
        .collect();
    assert!(contains(&text, b"kept-marker"));
    assert!(!contains(&text, b"first-note-marker"));
    assert!(!contains(&text, b"deleted-marker"));
    assert_ne!(old_key, *new_key.as_bytes());
}

#[test]
fn a_crash_at_any_step_of_compaction_loses_nothing() {
    let template = tempfile::tempdir().unwrap();
    let mut v = make(template.path());
    for i in 0..5 {
        v.commit(vec![put("set", &format!("s{i}"), json!({"reps": i}))])
            .unwrap();
    }
    v.commit(vec![del("set", "s0")]).unwrap();
    let expected = snapshot(&v);
    drop(v);

    let tmp = tempfile::tempdir().unwrap();
    copy_vault(template.path(), tmp.path());
    let faults = Faults::counting();
    let mut v = unlock_with(Dir::with_faults(tmp.path(), faults.clone()), TEST);
    v.compact().unwrap();
    let total = faults.passed();
    // Two keyring rewrites of two copies each, and the new journal file:
    // 5 atomic writes of 5 steps, plus removing the old file.
    assert_eq!(total, 5 * 5 + 1);

    for n in 0..=total {
        let tmp = tempfile::tempdir().unwrap();
        copy_vault(template.path(), tmp.path());
        let mut v = unlock_with(Dir::with_faults(tmp.path(), Faults::crash_at(n)), TEST);
        let _ = v.compact();
        drop(v);

        let mut v = unlock(tmp.path());
        assert_eq!(v.status().damage, None, "step {n}");
        assert_eq!(snapshot(&v), expected, "step {n}");
        let open = v.opened().unwrap();
        assert_eq!(open.keyring.data_keys.len(), 1, "step {n}: leftover key");
        let journals = Dir::new(tmp.path())
            .list()
            .unwrap()
            .into_iter()
            .filter(|f| journal::generation_of(f).is_some())
            .count();
        assert_eq!(journals, 1, "step {n}: leftover journal");
        // Later commits land in the generation the next unlock reads.
        v.commit(vec![put("set", "later", json!({}))]).unwrap();
        v.lock();
        let v = unlock(tmp.path());
        assert!(v.record("set", "later").unwrap().is_some(), "step {n}");
    }
}

#[test]
fn files_round_trip_and_disappear() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let photo: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    let id = v.put_blob(&photo).unwrap();
    assert_eq!(id.len(), 32);
    assert_eq!(&v.get_blob(&id).unwrap()[..], &photo[..]);
    assert_eq!(v.blob_ids().unwrap(), std::slice::from_ref(&id));
    v.lock();
    let mut v = unlock(tmp.path());
    assert_eq!(&v.get_blob(&id).unwrap()[..], &photo[..]);

    v.delete_blob(&id).unwrap();
    assert_eq!(v.get_blob(&id).unwrap_err(), Error::NotFound);
    assert_eq!(v.delete_blob(&id).unwrap_err(), Error::NotFound);
    assert!(!tmp.path().join(BLOBS).join(format!("{id}.blob")).exists());
    assert!(v.blob_ids().unwrap().is_empty());
    assert_eq!(
        v.get_blob("not-an-id").unwrap_err(),
        Error::InvalidInput("file id")
    );
    v.compact().unwrap();
    v.lock();
    let v = unlock(tmp.path());
    assert!(v.blob_ids().unwrap().is_empty());
}

#[test]
fn files_without_a_key_are_removed_at_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let id = v.put_blob(b"kept").unwrap();
    v.lock();
    let blobs = tmp.path().join(BLOBS);
    std::fs::write(
        blobs.join("0123456789abcdef0123456789abcdef.blob"),
        b"orphan",
    )
    .unwrap();
    std::fs::write(blobs.join("x.blob.tmp"), b"torn").unwrap();
    let v = unlock(tmp.path());
    let names: Vec<String> = Dir::new(&blobs).list().unwrap();
    assert_eq!(names, [format!("{id}.blob")]);
    assert_eq!(&v.get_blob(&id).unwrap()[..], b"kept");
}

#[test]
fn a_crash_while_storing_a_file_leaves_no_orphan() {
    let template = tempfile::tempdir().unwrap();
    drop(make(template.path()));
    let total = {
        let tmp = tempfile::tempdir().unwrap();
        copy_vault(template.path(), tmp.path());
        let faults = Faults::counting();
        let mut v = unlock_with(Dir::with_faults(tmp.path(), faults.clone()), TEST);
        v.put_blob(b"photo").unwrap();
        faults.passed()
    };
    assert_eq!(total, 5 + 2);
    for n in 0..=total {
        let tmp = tempfile::tempdir().unwrap();
        copy_vault(template.path(), tmp.path());
        let mut v = unlock_with(Dir::with_faults(tmp.path(), Faults::crash_at(n)), TEST);
        let result = v.put_blob(b"photo");
        drop(v);
        let v = unlock(tmp.path());
        let ids = v.blob_ids().unwrap();
        let files = Dir::new(tmp.path().join(BLOBS)).list().unwrap_or_default();
        assert_eq!(files.len(), ids.len(), "step {n}: {files:?}");
        if let Ok(id) = result {
            assert_eq!(ids, std::slice::from_ref(&id), "step {n}");
            assert_eq!(&v.get_blob(&id).unwrap()[..], b"photo");
        }
    }
}

#[test]
fn no_plaintext_reaches_the_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    v.commit(vec![put(
        "profile",
        "profile",
        json!({"name": "Plaintext-Marker-Name", "height_mm": 1789}),
    )])
    .unwrap();
    v.commit(vec![put(
        "set",
        "s1",
        json!({"note": "plaintext-marker-note"}),
    )])
    .unwrap();
    v.put_blob(b"plaintext-marker-photo").unwrap();
    v.compact().unwrap();
    v.commit(vec![put(
        "set",
        "s2",
        json!({"note": "plaintext-marker-later"}),
    )])
    .unwrap();
    v.lock();
    let files = all_files(tmp.path());
    assert!(files.len() >= 5);
    for (name, bytes) in files {
        for marker in [
            &b"Plaintext-Marker"[..],
            b"plaintext-marker",
            b"\"name\"",
            b"profile",
            b"height_mm",
        ] {
            assert!(
                !contains(&bytes, marker),
                "{name} contains {}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

/// An edit never re-encrypts what is already on disk (crypto design,
/// "Nonces"): a commit appends a frame under a fresh random nonce, so no key
/// and nonce ever encrypt two different plaintexts. With a stream cipher such
/// as ChaCha20 that would reveal their XOR.
#[test]
fn edits_append_under_fresh_nonces_and_never_rewrite_earlier_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let path = tmp.path().join(journal_name(&v));
    v.commit(vec![put("set", "a", json!({"reps": 5}))]).unwrap();
    let before = std::fs::read(&path).unwrap();
    for _ in 0..2 {
        v.commit(vec![put("set", "a", json!({"reps": 6}))]).unwrap();
    }
    let after = std::fs::read(&path).unwrap();
    assert_eq!(&after[..before.len()], &before[..], "earlier bytes changed");

    // Journal format 1: length, its complement, kind, device, seq, nonce,
    // ciphertext.
    let (mut pos, mut nonces, mut bodies) = (journal::HEADER_LEN, Vec::new(), Vec::new());
    while pos < after.len() {
        let len = u32::from_le_bytes(after[pos..pos + 4].try_into().unwrap()) as usize;
        let nonce = pos + 8 + 1 + 16 + 8;
        nonces.push(after[nonce..nonce + 24].to_vec());
        bodies.push(after[nonce + 24..pos + 8 + len].to_vec());
        pos += 8 + len;
    }
    assert_eq!(pos, after.len());
    assert!(nonces.len() >= 3);
    let mut unique = nonces.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), nonces.len(), "a nonce repeated");
    // The same edit twice gives unrelated ciphertexts.
    assert_ne!(bodies[bodies.len() - 1], bodies[bodies.len() - 2]);
}

/// Measures how the journal grows with years of daily logging: one strength
/// session a day, 5 exercises × 4 sets, with the app's field names. The first
/// year commits like the app does (57 small commits a session, whole records
/// each time); the rest writes finished sessions in one commit each. Run in a
/// release build:
/// `cargo test --release --lib -- --ignored --nocapture measure_years`.
#[test]
#[ignore]
fn measure_years_of_daily_sessions() {
    use std::time::Instant;

    use serde_json::{Value, json};

    const DAY_MS: i64 = 86_400_000;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let journal_mb = || -> f64 {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("journal-"))
            .map(|e| e.metadata().unwrap().len())
            .sum::<u64>() as f64
            / 1e6
    };
    let rss_mb = || -> f64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let kb: f64 = s
            .lines()
            .find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap()
            .parse()
            .unwrap();
        kb / 1e3
    };
    let id = || crate::new_record_id().unwrap();
    let rec = |kind: &str, id: &str, f: Value| put(kind, id, f);

    let mut v = make(dir);
    v.lock();
    let t = Instant::now();
    let mut v = unlock(dir);
    let base_ms = t.elapsed().as_secs_f64() * 1e3;
    let base_rss = rss_mb();
    println!("baseline: unlock {base_ms:.0} ms (Argon2id test parameters), RSS {base_rss:.0} MB");

    // One session; `app_like` commits it as the app does.
    let session = |v: &mut Vault, day: i64, app_like: bool| {
        let start = 1_700_000_000_000 + day * DAY_MS;
        let s = id();
        let session_fields = |ended: Option<i64>| json!({"started_ms": start, "tz_min": 60, "name": "Push day", "notes": null, "ended_ms": ended});
        let mut all = vec![rec("session", &s, session_fields(None))];
        if app_like {
            v.commit(all.clone()).unwrap();
        }
        for x in 0..5i64 {
            let e = id();
            let entry = |started: Option<i64>, finished: Option<i64>| json!({"session": s, "exercise": "bench_press", "position": x, "started_ms": started, "finished_ms": finished, "notes": null});
            let set = |o: i64, reps: Option<i64>, done: Option<i64>, rest: Option<i64>| {
                json!({"entry": e, "order": o, "weight_g": 100_000, "target_reps": 5,
                       "rest_planned_s": 120, "predict_1rm": o == 0, "reps": reps,
                       "done_ms": done, "rest_taken_s": rest, "notes": null})
            };
            let sets: Vec<String> = (0..4).map(|_| id()).collect();
            let t0 = start + x * 900_000;
            if app_like {
                v.commit(vec![rec("exercise_entry", &e, entry(None, None))])
                    .unwrap();
                v.commit(
                    sets.iter()
                        .enumerate()
                        .map(|(o, sid)| rec("set", sid, set(o as i64, None, None, None)))
                        .collect(),
                )
                .unwrap();
                v.commit(vec![rec("exercise_entry", &e, entry(Some(t0), None))])
                    .unwrap();
                for (o, sid) in sets.iter().enumerate() {
                    let done = t0 + o as i64 * 150_000;
                    v.commit(vec![rec(
                        "set",
                        sid,
                        set(o as i64, Some(5), Some(done), None),
                    )])
                    .unwrap();
                    if o < 3 {
                        v.commit(vec![rec(
                            "set",
                            sid,
                            set(o as i64, Some(5), Some(done), Some(120)),
                        )])
                        .unwrap();
                    }
                }
                v.commit(vec![rec(
                    "exercise_entry",
                    &e,
                    entry(Some(t0), Some(t0 + 600_000)),
                )])
                .unwrap();
            } else {
                all.push(rec(
                    "exercise_entry",
                    &e,
                    entry(Some(t0), Some(t0 + 600_000)),
                ));
                for (o, sid) in sets.iter().enumerate() {
                    let done = t0 + o as i64 * 150_000;
                    let rest = (o < 3).then_some(120);
                    all.push(rec("set", sid, set(o as i64, Some(5), Some(done), rest)));
                }
            }
        }
        if app_like {
            v.commit(vec![rec(
                "session",
                &s,
                session_fields(Some(start + 4_500_000)),
            )])
            .unwrap();
        } else {
            all[0] = rec("session", &s, session_fields(Some(start + 4_500_000)));
            v.commit(all).unwrap();
        }
    };
    // Compaction runs only when it's due; a deletion makes it due.
    let compact = |v: &mut Vault| {
        v.commit(vec![put("weight", "probe", json!({"weight_g": 1}))])
            .unwrap();
        v.commit(vec![del("weight", "probe")]).unwrap();
        let t = Instant::now();
        v.compact().unwrap();
        t.elapsed().as_secs_f64()
    };

    let mut day = 0i64;
    let t = Instant::now();
    while day < 365 {
        session(&mut v, day, true);
        day += 1;
    }
    let raw = journal_mb();
    println!(
        "year 1, as the app commits ({:.0} s): journal {raw:.2} MB before compaction, due: {}",
        t.elapsed().as_secs_f64(),
        v.needs_compaction()
    );
    let secs = compact(&mut v);
    println!("  after compaction ({secs:.2} s): {:.2} MB", journal_mb());

    println!(
        "years | sessions | journal MB | compaction s | unlock ms (minus Argon2id) | RSS MB open"
    );
    for years in [1i64, 5, 10, 25, 50] {
        while day < years * 365 {
            session(&mut v, day, false);
            day += 1;
        }
        let secs = compact(&mut v);
        let open_rss = rss_mb() - base_rss;
        v.lock();
        let t = Instant::now();
        v = unlock(dir);
        let ms = t.elapsed().as_secs_f64() * 1e3 - base_ms;
        println!(
            "{years:5} | {day:8} | {:10.1} | {secs:12.2} | {ms:26.0} | {open_rss:11.0}",
            journal_mb()
        );
    }
}

/// A journal in format 1, as MVP 1 wrote it, opens unchanged, keeps taking
/// appends in format 1, and is rewritten in format 2 by the next compaction
/// (D55).
#[test]
fn a_format_1_journal_is_read_and_migrated() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path());
    let (key, k) = {
        let o = v.opened().unwrap();
        (o.journal.key.duplicate(), o.keyring.clone())
    };
    v.lock();
    let header = journal::header(journal::FORMAT_JSON, k.suite, &k.vault_id, 1);
    let batch = Batch {
        hlc: 1 << 16,
        ops: vec![Op::from(put(
            "set",
            "a",
            json!({"reps": 5, "note": "kept"}),
        ))],
    };
    let plaintext = journal::encode(journal::FORMAT_JSON, &batch).unwrap();
    assert_eq!(plaintext[0], b'{');
    let mut bytes = header.to_vec();
    bytes.extend(
        journal::seal_frame(
            &key,
            &header,
            &k.device_id,
            1,
            &plaintext,
            &mut TestRng::new("v1"),
        )
        .unwrap(),
    );
    std::fs::write(tmp.path().join(journal::file_name(1)), &bytes).unwrap();

    let format_of = |name: &str| {
        let b = std::fs::read(tmp.path().join(name)).unwrap();
        u16::from_le_bytes([b[8], b[9]])
    };
    let mut v = unlock(tmp.path());
    assert_eq!(v.status().damage, None);
    assert_eq!(
        v.record("set", "a").unwrap().unwrap().fields["note"],
        "kept"
    );
    assert!(v.needs_compaction(), "an old format makes compaction due");
    v.commit(vec![put("set", "b", json!({"reps": 6}))]).unwrap();
    v.lock();
    assert_eq!(format_of(&journal::file_name(1)), journal::FORMAT_JSON);

    let mut v = unlock(tmp.path());
    assert_eq!(v.records("set").unwrap().len(), 2);
    v.compact().unwrap();
    assert!(!v.needs_compaction());
    let name = journal_name(&v);
    assert_eq!(format_of(&name), journal::FORMAT_BINARY);
    v.commit(vec![put("set", "c", json!({"reps": 7}))]).unwrap();
    v.lock();

    let v = unlock(tmp.path());
    assert_eq!(v.status().damage, None);
    assert_eq!(v.records("set").unwrap().len(), 3);
    assert_eq!(
        v.record("set", "a").unwrap().unwrap().fields["note"],
        "kept"
    );
}
