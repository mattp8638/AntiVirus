//! Repository on a local path (internal disk, USB drive, mounted share).

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use super::{validate_key, Backend, PutOutcome};
use crate::error::{Error, Result};

pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Open an existing directory as a backend root.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(Error::NotARepository(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        Ok(LocalBackend { root })
    }

    /// Create the directory (and parents) if needed. Refuses a non-empty
    /// directory that is not already a repository, so `init` can never
    /// scatter files into somebody's existing folder.
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        if fs::read_dir(&root)?.next().is_some() {
            return Err(Error::InvalidArgument(format!(
                "{} is not empty",
                root.display()
            )));
        }
        Ok(LocalBackend { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(key.split('/').fold(self.root.clone(), |p, s| p.join(s)))
    }

    fn tmp_path(&self) -> Result<PathBuf> {
        let mut r = [0u8; 12];
        crate::crypto::fill_random(&mut r)?;
        Ok(self
            .root
            .join("tmp")
            .join(format!("{}.tmp", hex::encode(r))))
    }
}

fn sync_dir(_dir: &Path) {
    // Persist the directory entry on Unix. Windows has no equivalent for
    // directories; NTFS journals metadata.
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(_dir) {
        let _ = d.sync_all();
    }
}

impl Backend for LocalBackend {
    fn put(&self, key: &str, data: &[u8]) -> Result<PutOutcome> {
        let dest = self.path(key)?;
        if dest.exists() {
            return Ok(PutOutcome::AlreadyExists);
        }
        let parent = dest.parent().expect("key has a parent");
        fs::create_dir_all(parent)?;
        let tmp = self.tmp_path()?;
        fs::create_dir_all(tmp.parent().unwrap())?;
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        // hard_link fails if `dest` exists: atomic create-only publish.
        let res = match fs::hard_link(&tmp, &dest) {
            Ok(()) => Ok(PutOutcome::Created),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(PutOutcome::AlreadyExists),
            Err(_) => {
                // Filesystems without hard links (FAT, some shares): fall
                // back to rename after an existence check. Narrow race, but
                // objects are content-addressed or unique, so a concurrent
                // writer would write identical or unrelated data.
                if dest.exists() {
                    Ok(PutOutcome::AlreadyExists)
                } else {
                    fs::rename(&tmp, &dest)
                        .map(|_| PutOutcome::Created)
                        .map_err(Error::from)
                }
            }
        };
        let _ = fs::remove_file(&tmp);
        if matches!(res, Ok(PutOutcome::Created)) {
            sync_dir(parent);
        }
        res
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let p = self.path(key)?;
        fs::read(&p).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::NotFound(key.to_string())
            } else {
                e.into()
            }
        })
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path(key)?.is_file())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let prefix = prefix.trim_end_matches('/');
        let base = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.path(prefix)?
        };
        let mut out = Vec::new();
        if !base.is_dir() {
            return Ok(out);
        }
        let mut stack = vec![(base, prefix.to_string())];
        while let Some((dir, key)) = stack.pop() {
            for ent in fs::read_dir(&dir)? {
                let ent = ent?;
                let name = ent.file_name();
                let Some(name) = name.to_str() else { continue };
                let k = if key.is_empty() {
                    name.to_string()
                } else {
                    format!("{key}/{name}")
                };
                let ft = ent.file_type()?;
                if ft.is_dir() {
                    if k != "tmp" {
                        stack.push((ent.path(), k));
                    }
                } else if ft.is_file() && validate_key(&k).is_ok() {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let p = self.path(key)?;
        fs::remove_file(&p).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::NotFound(key.to_string())
            } else {
                e.into()
            }
        })
    }

    fn size(&self, key: &str) -> Result<u64> {
        let p = self.path(key)?;
        std::fs::metadata(&p).map(|m| m.len()).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::NotFound(key.to_string())
            } else {
                e.into()
            }
        })
    }

    fn describe(&self) -> String {
        format!("local:{}", self.root.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_only_put_get_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let b = LocalBackend::create(dir.path().join("repo")).unwrap();
        assert_eq!(b.put("a/b/c", b"one").unwrap(), PutOutcome::Created);
        assert_eq!(b.put("a/b/c", b"two").unwrap(), PutOutcome::AlreadyExists);
        assert_eq!(b.get("a/b/c").unwrap(), b"one");
        assert!(b.exists("a/b/c").unwrap());
        assert!(!b.exists("a/b/d").unwrap());
        assert!(matches!(b.get("nope"), Err(Error::NotFound(_))));
        b.put("a/x", b"").unwrap();
        let mut l = b.list("a").unwrap();
        l.sort();
        assert_eq!(l, vec!["a/b/c", "a/x"]);
        assert!(b.list("zzz").unwrap().is_empty());
        // tmp/ is never listed and is empty after puts.
        assert!(!b.list("").unwrap().iter().any(|k| k.starts_with("tmp")));
        b.delete("a/x").unwrap();
        assert!(!b.exists("a/x").unwrap());
        assert!(b.get("../etc/passwd").is_err());
    }

    #[test]
    fn create_refuses_non_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("precious.txt"), b"x").unwrap();
        assert!(LocalBackend::create(dir.path()).is_err());
    }
}
