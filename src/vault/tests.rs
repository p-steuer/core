use std::path::Path;

use sha2::{Digest, Sha256};

use super::keyring::tests::{PASSPHRASE, TEST_PARAMS};
use super::*;
use crate::fsio::faults::Faults;
use crate::rand::TestRng;

const TEST: Config = Config {
    params: TEST_PARAMS,
    clock: Clock::System,
};
const NEW_PASSPHRASE: &str = "violet otter mango ladder frost";

struct Made {
    vault: Vault,
    recovery: String,
}

fn make(path: &Path, label: &str) -> Made {
    let pending = PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new(label), TEST).unwrap();
    let recovery = pending.recovery_key().to_string();
    let vault = pending.create_in(Dir::new(path)).unwrap();
    Made { vault, recovery }
}

fn with_passphrase(path: &Path, pw: &str) -> Result<Vault> {
    let secret = Secret::Passphrase(passphrase::normalize(pw));
    Vault::unlock_in(Dir::new(path), secret, TEST, &mut TestRng::new("unlock"))
}

fn with_recovery(path: &Path, key: &str) -> Result<Vault> {
    let secret = Secret::Recovery(RecoveryKey::parse(key)?);
    Vault::unlock_in(Dir::new(path), secret, TEST, &mut TestRng::new("unlock"))
}

fn journal_key(v: &Vault) -> [u8; 32] {
    *v.opened().unwrap().journal.key.as_bytes()
}

/// Copies every file of a vault folder (not the lock).
pub(super) fn copy_vault(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() && entry.file_name() != "LOCK" {
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

fn read(path: &Path, name: &str) -> Vec<u8> {
    std::fs::read(path.join(name)).unwrap()
}

fn write(path: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(path.join(name), bytes).unwrap();
}

/// Changes one byte and fixes up the (unkeyed) checksum, as an attacker could.
fn tamper(bytes: &[u8], i: usize) -> Vec<u8> {
    let mut b = bytes.to_vec();
    b[i] ^= 0x01;
    let n = b.len() - 32;
    let sum = Sha256::digest(&b[..n]);
    b[n..].copy_from_slice(&sum);
    b
}

#[test]
fn create_then_unlock_with_either_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let Made {
        mut vault,
        recovery,
    } = make(tmp.path(), "basic");
    let key = journal_key(&vault);
    assert!(Vault::exists(tmp.path()));
    assert_eq!(read(tmp.path(), KEYRING), read(tmp.path(), KEYRING_BACKUP));
    vault.lock();
    assert!(vault.is_locked());

    let mut v = with_passphrase(tmp.path(), PASSPHRASE).unwrap();
    assert_eq!(journal_key(&v), key);
    assert_eq!(v.status(), Status::default());
    v.lock();
    let v = with_recovery(tmp.path(), &recovery).unwrap();
    assert_eq!(journal_key(&v), key);
}

#[test]
fn nothing_is_written_before_create() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("vault");
    let pending =
        PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("pending"), TEST).unwrap();
    assert!(!path.exists());
    drop(pending);
    assert!(!path.exists());
    assert!(!Vault::exists(&path));
    assert_eq!(
        with_passphrase(&path, PASSPHRASE).unwrap_err(),
        Error::NoVault
    );
}

#[test]
fn wrong_secrets_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut made = make(tmp.path(), "wrong");
    made.vault.lock();
    assert_eq!(
        with_passphrase(tmp.path(), "correct horse battery stapler").unwrap_err(),
        Error::WrongPassphrase
    );
    let other = tempfile::tempdir().unwrap();
    let other_key = make(other.path(), "other").recovery;
    assert_eq!(
        with_recovery(tmp.path(), &other_key).unwrap_err(),
        Error::WrongRecoveryKey
    );
    // A typo is caught before the vault is read.
    let mut typo = made.recovery.clone().into_bytes();
    typo[3] = if typo[3] == b'Z' { b'Y' } else { b'Z' };
    let typo = String::from_utf8(typo).unwrap();
    assert_eq!(
        Vault::unlock_with_recovery_key(tmp.path(), &typo).unwrap_err(),
        Error::RecoveryKeyTypo
    );
}

#[test]
fn passphrase_rules_apply_at_setup() {
    let mut rng = TestRng::new("rules");
    for (pw, error) in [
        ("short", Error::PassphraseTooShort),
        ("qwerty123456789", Error::PassphraseTooWeak),
        ("  qwerty123456789   ", Error::PassphraseTooWeak),
    ] {
        assert_eq!(
            PendingVault::prepare_with(pw, &mut rng, TEST).err(),
            Some(error),
            "{pw}"
        );
    }
}

#[test]
fn equivalent_spellings_of_the_passphrase_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let composed = "caf\u{00E9} au lait sur la plage";
    let decomposed = "cafe\u{0301} au lait sur la plage";
    let pending = PendingVault::prepare_with(composed, &mut TestRng::new("nfc"), TEST).unwrap();
    drop(pending.create_in(Dir::new(tmp.path())).unwrap());
    for pw in [
        decomposed,
        " caf\u{00E9} au lait sur la plage ",
        "caf\u{00E9}\u{00A0}au lait sur la plage",
    ] {
        drop(with_passphrase(tmp.path(), pw).unwrap());
    }
    assert_eq!(
        with_passphrase(tmp.path(), "Caf\u{00E9} au lait sur la plage").unwrap_err(),
        Error::WrongPassphrase
    );
}

#[test]
fn only_one_open_vault_and_only_one_vault_per_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let mut made = make(tmp.path(), "once");
    assert_eq!(
        with_passphrase(tmp.path(), PASSPHRASE).err(),
        Some(Error::InUse)
    );
    let again = PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("again"), TEST).unwrap();
    assert_eq!(
        again.create_in(Dir::new(tmp.path())).err(),
        Some(Error::InUse)
    );
    made.vault.lock();
    let again = PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("again"), TEST).unwrap();
    assert_eq!(
        again.create_in(Dir::new(tmp.path())).err(),
        Some(Error::VaultExists)
    );
    drop(with_passphrase(tmp.path(), PASSPHRASE).unwrap());
}

#[test]
fn a_locked_vault_refuses_everything() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = make(tmp.path(), "locked").vault;
    v.lock();
    assert_eq!(v.verify_passphrase(PASSPHRASE).unwrap_err(), Error::Locked);
    assert_eq!(v.set_passphrase(NEW_PASSPHRASE).unwrap_err(), Error::Locked);
    assert_eq!(v.begin_new_recovery_key().unwrap_err(), Error::Locked);
    assert_eq!(v.finish_new_recovery_key().unwrap_err(), Error::Locked);
}

#[test]
fn changing_the_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let Made {
        mut vault,
        recovery,
    } = make(tmp.path(), "change");
    let key = journal_key(&vault);
    assert!(vault.verify_passphrase(PASSPHRASE).unwrap());
    assert!(!vault.verify_passphrase(NEW_PASSPHRASE).unwrap());
    assert_eq!(
        vault.set_passphrase("too weak").unwrap_err(),
        Error::PassphraseTooShort
    );
    vault
        .set_passphrase_with(NEW_PASSPHRASE, &mut TestRng::new("set"))
        .unwrap();
    assert!(vault.verify_passphrase(NEW_PASSPHRASE).unwrap());
    vault.lock();

    assert_eq!(
        with_passphrase(tmp.path(), PASSPHRASE).unwrap_err(),
        Error::WrongPassphrase
    );
    let mut v = with_passphrase(tmp.path(), NEW_PASSPHRASE).unwrap();
    assert_eq!(journal_key(&v), key);
    v.lock();
    // The recovery key still works.
    drop(with_recovery(tmp.path(), &recovery).unwrap());
    assert_eq!(read(tmp.path(), KEYRING), read(tmp.path(), KEYRING_BACKUP));
}

#[test]
fn replacing_the_recovery_key() {
    let tmp = tempfile::tempdir().unwrap();
    let Made {
        mut vault,
        recovery: old,
    } = make(tmp.path(), "recovery");
    assert!(vault.finish_new_recovery_key().is_err());

    // Cancelled: the old key stays.
    vault
        .begin_new_recovery_key_with(&mut TestRng::new("cancelled"))
        .unwrap();
    vault.cancel_new_recovery_key();
    assert!(vault.finish_new_recovery_key().is_err());

    let new = vault
        .begin_new_recovery_key_with(&mut TestRng::new("new-key"))
        .unwrap()
        .to_string();
    assert_ne!(new, old);
    vault
        .finish_new_recovery_key_with(&mut TestRng::new("finish"))
        .unwrap();
    vault.lock();
    assert_eq!(
        with_recovery(tmp.path(), &old).unwrap_err(),
        Error::WrongRecoveryKey
    );
    drop(with_recovery(tmp.path(), &new).unwrap());
    drop(with_passphrase(tmp.path(), PASSPHRASE).unwrap());
}

#[test]
fn weaker_hashing_is_upgraded_at_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    make(tmp.path(), "upgrade").vault.lock();
    let stronger = Config {
        params: Params {
            m_kib: 24 * 1024,
            t: 3,
            p: 1,
        },
        clock: Clock::System,
    };
    let secret = || Secret::Passphrase(passphrase::normalize(PASSPHRASE));
    let mut v = Vault::unlock_in(
        Dir::new(tmp.path()),
        secret(),
        stronger.clone(),
        &mut TestRng::new("u"),
    )
    .unwrap();
    assert!(v.status().upgraded_passphrase_hashing);
    assert_eq!(
        v.opened().unwrap().keyring.passphrase.params,
        stronger.params
    );
    v.lock();
    let again = Vault::unlock_in(
        Dir::new(tmp.path()),
        secret(),
        stronger.clone(),
        &mut TestRng::new("u"),
    )
    .unwrap();
    assert_eq!(again.status(), Status::default());
    assert_eq!(read(tmp.path(), KEYRING), read(tmp.path(), KEYRING_BACKUP));
}

#[test]
fn a_missing_or_damaged_copy_is_repaired() {
    let tmp = tempfile::tempdir().unwrap();
    let made = make(tmp.path(), "repair");
    drop(made.vault);
    let good = read(tmp.path(), KEYRING);
    for (name, broken) in [
        (KEYRING, None),
        (KEYRING_BACKUP, None),
        (KEYRING, Some(b"garbage".to_vec())),
        (KEYRING_BACKUP, Some(good[..good.len() - 1].to_vec())),
    ] {
        match &broken {
            None => std::fs::remove_file(tmp.path().join(name)).unwrap(),
            Some(b) => write(tmp.path(), name, b),
        }
        let v = with_recovery(tmp.path(), &made.recovery).unwrap();
        assert!(v.status().repaired_keyring, "{name}");
        drop(v);
        assert_eq!(read(tmp.path(), KEYRING), good);
        assert_eq!(read(tmp.path(), KEYRING_BACKUP), good);
    }
    // Both copies damaged: nothing opens.
    write(tmp.path(), KEYRING, b"garbage");
    write(tmp.path(), KEYRING_BACKUP, b"garbage");
    assert_eq!(
        with_recovery(tmp.path(), &made.recovery).unwrap_err(),
        Error::Damaged("keyring too short")
    );
}

#[test]
fn the_newest_copy_wins() {
    let tmp = tempfile::tempdir().unwrap();
    let mut vault = make(tmp.path(), "newest").vault;
    let old = read(tmp.path(), KEYRING);
    vault
        .set_passphrase_with(NEW_PASSPHRASE, &mut TestRng::new("set"))
        .unwrap();
    vault.lock();
    let new = read(tmp.path(), KEYRING);
    // As after a crash between the two writes, in either order on disk.
    for (main, backup) in [(&new, &old), (&old, &new)] {
        write(tmp.path(), KEYRING, main);
        write(tmp.path(), KEYRING_BACKUP, backup);
        let v = with_passphrase(tmp.path(), NEW_PASSPHRASE).unwrap();
        assert!(v.status().repaired_keyring);
        drop(v);
        assert_eq!(read(tmp.path(), KEYRING), new);
        assert_eq!(read(tmp.path(), KEYRING_BACKUP), new);
    }
}

#[test]
fn every_tampered_byte_is_caught() {
    let tmp = tempfile::tempdir().unwrap();
    let made = make(tmp.path(), "tamper");
    drop(made.vault);
    let good = read(tmp.path(), KEYRING);
    for i in 0..good.len() - 32 {
        // Both copies changed the same way: opening must fail.
        let bad = tamper(&good, i);
        write(tmp.path(), KEYRING, &bad);
        write(tmp.path(), KEYRING_BACKUP, &bad);
        assert!(
            with_recovery(tmp.path(), &made.recovery).is_err(),
            "byte {i}, both copies"
        );

        // Only the main copy changed: the backup is used and the main copy
        // is restored.
        write(tmp.path(), KEYRING_BACKUP, &good);
        drop(with_recovery(tmp.path(), &made.recovery).unwrap());
        assert_eq!(read(tmp.path(), KEYRING), good, "byte {i}, main copy");
    }
}

#[test]
fn tampered_passphrase_slots_are_caught() {
    // One byte in every field of the passphrase slot (Argon2id runs each
    // time, so not every byte).
    let tmp = tempfile::tempdir().unwrap();
    let made = make(tmp.path(), "tamper-pw");
    drop(made.vault);
    let good = read(tmp.path(), KEYRING);
    let slot = 52 + 1 + 1; // header, slot count, slot type
    for (field, offset) in [
        ("salt", 0),
        ("m_kib", 16),
        ("t", 20),
        ("p", 24),
        ("commitment", 28),
        ("nonce", 60),
        ("wrapped key", 84),
        ("tag", 120),
    ] {
        let bad = tamper(&good, slot + offset);
        write(tmp.path(), KEYRING, &bad);
        write(tmp.path(), KEYRING_BACKUP, &bad);
        assert!(with_passphrase(tmp.path(), PASSPHRASE).is_err(), "{field}");
    }
    write(tmp.path(), KEYRING, &good);
    write(tmp.path(), KEYRING_BACKUP, &good);
    drop(with_passphrase(tmp.path(), PASSPHRASE).unwrap());
}

#[test]
fn bad_hashing_parameters_leave_the_recovery_key_working() {
    let tmp = tempfile::tempdir().unwrap();
    let Made {
        mut vault,
        recovery,
    } = make(tmp.path(), "params");
    // Rewrite the keyring properly (valid MAC) with parameters out of range.
    vault
        .change_keyring(|k, _| {
            k.passphrase.params.m_kib = 8;
            Ok(())
        })
        .unwrap();
    vault.lock();
    assert_eq!(
        with_passphrase(tmp.path(), PASSPHRASE).unwrap_err(),
        Error::Damaged("passphrase hashing parameters out of range")
    );
    let mut v = with_recovery(tmp.path(), &recovery).unwrap();
    // After recovery the app asks for a new passphrase, which fixes the slot.
    v.set_passphrase_with(NEW_PASSPHRASE, &mut TestRng::new("fix"))
        .unwrap();
    v.lock();
    drop(with_passphrase(tmp.path(), NEW_PASSPHRASE).unwrap());
}

#[test]
fn a_crash_during_setup_leaves_no_vault_or_a_working_one() {
    let total = {
        let tmp = tempfile::tempdir().unwrap();
        let faults = Faults::counting();
        let pending =
            PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("setup"), TEST).unwrap();
        drop(
            pending
                .create_in(Dir::with_faults(tmp.path(), faults.clone()))
                .unwrap(),
        );
        faults.passed()
    };
    assert!(total >= 10);
    for n in 0..total {
        let tmp = tempfile::tempdir().unwrap();
        let pending =
            PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("setup"), TEST).unwrap();
        let recovery = pending.recovery_key().to_string();
        let result = pending.create_in(Dir::with_faults(tmp.path(), Faults::crash_at(n)));
        drop(result);
        if Vault::exists(tmp.path()) {
            drop(with_passphrase(tmp.path(), PASSPHRASE).unwrap());
            drop(with_recovery(tmp.path(), &recovery).unwrap());
        } else {
            // The setup can simply be repeated.
            let again =
                PendingVault::prepare_with(PASSPHRASE, &mut TestRng::new("retry"), TEST).unwrap();
            drop(again.create_in(Dir::new(tmp.path())).unwrap());
            drop(with_passphrase(tmp.path(), PASSPHRASE).unwrap());
        }
    }
}

#[test]
fn a_crash_while_changing_the_passphrase_keeps_one_of_them() {
    let template = tempfile::tempdir().unwrap();
    let made = make(template.path(), "crash-change");
    let key = journal_key(&made.vault);
    drop(made.vault);
    let unlock_faulty = |path: &Path, faults: std::sync::Arc<Faults>| {
        let secret = Secret::Passphrase(passphrase::normalize(PASSPHRASE));
        Vault::unlock_in(
            Dir::with_faults(path, faults),
            secret,
            TEST,
            &mut TestRng::new("x"),
        )
        .unwrap()
    };
    let fresh_copy = || {
        let tmp = tempfile::tempdir().unwrap();
        copy_vault(template.path(), tmp.path());
        tmp
    };

    // Opening a clean vault changes nothing on disk; the change itself is
    // two atomic writes of 5 steps each.
    let tmp = fresh_copy();
    let faults = Faults::counting();
    let mut v = unlock_faulty(tmp.path(), faults.clone());
    assert_eq!(faults.passed(), 0);
    v.set_passphrase_with(NEW_PASSPHRASE, &mut TestRng::new("y"))
        .unwrap();
    let total = faults.passed();
    assert_eq!(total, 10);

    for n in 0..=total {
        let tmp = fresh_copy();
        let mut v = unlock_faulty(tmp.path(), Faults::crash_at(n));
        let result = v.set_passphrase_with(NEW_PASSPHRASE, &mut TestRng::new("y"));
        // From step 5 on, the main copy is written and flushed: the change counts.
        assert_eq!(result.is_ok(), n >= 5, "step {n}");
        drop(v);

        let old = with_passphrase(tmp.path(), PASSPHRASE).map(|v| journal_key(&v));
        let new = with_passphrase(tmp.path(), NEW_PASSPHRASE).map(|v| journal_key(&v));
        assert!(
            old.is_ok() || new.is_ok(),
            "step {n}: neither passphrase works"
        );
        for k in [&old, &new].into_iter().flatten() {
            assert_eq!(*k, key, "step {n}");
        }
        if n >= 5 {
            assert!(new.is_ok(), "step {n}");
        }
        // Once the new passphrase has opened the vault, the old one is gone.
        if new.is_ok() {
            assert_eq!(
                with_passphrase(tmp.path(), PASSPHRASE).unwrap_err(),
                Error::WrongPassphrase,
                "step {n}"
            );
        }
    }
}
