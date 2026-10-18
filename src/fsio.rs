//! File operations of the vault folder. Every change goes through here, so
//! tests can simulate a crash at each step (`faults`).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use crate::Result;

pub(crate) struct Dir {
    path: PathBuf,
    #[cfg(test)]
    faults: Option<std::sync::Arc<faults::Faults>>,
}

impl Dir {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            #[cfg(test)]
            faults: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_faults(path: impl Into<PathBuf>, f: std::sync::Arc<faults::Faults>) -> Self {
        Self {
            path: path.into(),
            faults: Some(f),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub(crate) fn exists(&self, name: &str) -> bool {
        self.file(name).exists()
    }

    /// A crash point: in tests, may simulate a crash here.
    #[inline]
    fn point(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(f) = &self.faults {
            f.point()?;
        }
        Ok(())
    }

    /// The whole file, or `None` if it doesn't exist.
    pub(crate) fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.file(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn create_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.path)?;
        Ok(())
    }

    /// Replaces `name` with `data` so that after a crash the file holds
    /// either the old or the new content, never a mix: write a temporary
    /// file, flush it to disk, rename it over the old one, flush the folder.
    pub(crate) fn write_atomic(&self, name: &str, data: &[u8]) -> Result<()> {
        let tmp = self.file(&format!("{name}.tmp"));
        self.point()?;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        if let Err(e) = self.point() {
            // A crash in the middle of writing leaves a torn temporary file.
            let _ = f.write_all(&data[..data.len() / 2]);
            return Err(e);
        }
        f.write_all(data)?;
        self.point()?;
        f.sync_all()?;
        drop(f);
        self.point()?;
        fs::rename(&tmp, self.file(name))?;
        self.point()?;
        self.sync()
    }

    /// Removes a file; a missing file is fine.
    pub(crate) fn remove(&self, name: &str) -> Result<()> {
        self.point()?;
        match fs::remove_file(self.file(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The names of the regular files in the folder.
    pub(crate) fn list(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Flushes the folder itself, so renames and removals survive a power cut.
    pub(crate) fn sync(&self) -> Result<()> {
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod faults {
    use std::sync::{Arc, Mutex};

    use crate::{Error, Result};

    /// Simulates a crash at the n-th crash point. After that every further
    /// file change fails too, like a process that has stopped.
    pub(crate) struct Faults {
        state: Mutex<State>,
    }

    struct State {
        crash_at: Option<usize>,
        passed: usize,
        crashed: bool,
    }

    impl Faults {
        pub(crate) fn crash_at(n: usize) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(State {
                    crash_at: Some(n),
                    passed: 0,
                    crashed: false,
                }),
            })
        }

        /// Counts crash points without crashing.
        pub(crate) fn counting() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(State {
                    crash_at: None,
                    passed: 0,
                    crashed: false,
                }),
            })
        }

        pub(crate) fn passed(&self) -> usize {
            self.state.lock().unwrap().passed
        }

        pub(crate) fn crashed(&self) -> bool {
            self.state.lock().unwrap().crashed
        }

        pub(crate) fn point(&self) -> Result<()> {
            let mut s = self.state.lock().unwrap();
            if s.crashed || s.crash_at == Some(s.passed) {
                s.crashed = true;
                return Err(Error::Io("simulated crash".into()));
            }
            s.passed += 1;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::new(tmp.path());
        dir.write_atomic("a", b"one").unwrap();
        dir.write_atomic("a", b"two").unwrap();
        assert_eq!(dir.read("a").unwrap().unwrap(), b"two");
        assert_eq!(dir.list().unwrap(), vec!["a".to_string()]);
        assert_eq!(dir.read("missing").unwrap(), None);
        dir.remove("a").unwrap();
        dir.remove("a").unwrap();
        assert!(!dir.exists("a"));
    }

    #[test]
    fn a_crash_at_any_step_leaves_old_or_new() {
        let total = {
            let tmp = tempfile::tempdir().unwrap();
            let counter = faults::Faults::counting();
            let dir = Dir::with_faults(tmp.path(), counter.clone());
            dir.write_atomic("a", b"new").unwrap();
            counter.passed()
        };
        assert_eq!(total, 5);
        for n in 0..=total {
            let tmp = tempfile::tempdir().unwrap();
            Dir::new(tmp.path()).write_atomic("a", b"old").unwrap();
            let f = faults::Faults::crash_at(n);
            let dir = Dir::with_faults(tmp.path(), f.clone());
            let result = dir.write_atomic("a", b"new");
            assert_eq!(result.is_err(), n < total, "step {n}");
            let content = Dir::new(tmp.path()).read("a").unwrap().unwrap();
            assert!(content == b"old" || content == b"new", "step {n}");
            if n < 4 {
                assert_eq!(content, b"old", "step {n}: the rename hasn't happened");
            }
            // After a crash, nothing else can change.
            if f.crashed() {
                assert!(dir.remove("a").is_err());
            }
        }
    }
}
