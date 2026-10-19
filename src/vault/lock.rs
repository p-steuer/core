//! Only one open vault per folder: an in-process registry plus an operating
//! system file lock on `LOCK`, so neither a second open in this app nor a
//! second process can write at the same time.

use std::collections::HashSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::fsio::Dir;
use crate::{Error, Result};

fn registry() -> &'static Mutex<HashSet<PathBuf>> {
    static OPEN: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    OPEN.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Released when dropped.
#[derive(Debug)]
pub(crate) struct VaultLock {
    key: PathBuf,
    _file: File,
}

impl VaultLock {
    pub(crate) fn acquire(dir: &Dir) -> Result<Self> {
        let key = dir.path().canonicalize()?;
        if !registry()
            .lock()
            .expect("lock registry")
            .insert(key.clone())
        {
            return Err(Error::InUse);
        }
        match Self::os_lock(dir) {
            Ok(file) => Ok(Self { key, _file: file }),
            Err(e) => {
                registry().lock().expect("lock registry").remove(&key);
                Err(e)
            }
        }
    }

    fn os_lock(dir: &Dir) -> Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(dir.file("LOCK"))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(Error::InUse),
            // Some file systems have no locks; the registry still protects
            // against a second open inside this app.
            Err(TryLockError::Error(e)) if e.kind() == ErrorKind::Unsupported => Ok(file),
            Err(TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        if let Ok(mut open) = registry().lock() {
            open.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_fails_until_the_first_is_released() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::new(tmp.path());
        let first = VaultLock::acquire(&dir).unwrap();
        assert_eq!(VaultLock::acquire(&dir).unwrap_err(), Error::InUse);
        // The same folder under another spelling of its path.
        let other = Dir::new(tmp.path().join(".").join("."));
        assert_eq!(VaultLock::acquire(&other).unwrap_err(), Error::InUse);
        drop(first);
        let _again = VaultLock::acquire(&dir).unwrap();
    }

    #[test]
    fn os_lock_blocks_another_open_file() {
        // Without the registry: the file lock alone refuses a second holder.
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::new(tmp.path());
        let _held = VaultLock::os_lock(&dir).unwrap();
        assert_eq!(VaultLock::os_lock(&dir).unwrap_err(), Error::InUse);
    }
}
