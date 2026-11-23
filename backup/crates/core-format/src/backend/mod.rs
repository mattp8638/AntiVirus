//! Storage backends. A backend stores opaque objects under slash-separated
//! keys. It never sees plaintext or keys: everything except `config.json`
//! and public signer metadata is encrypted before it gets here.

use crate::error::{Error, Result};

pub mod local;

pub use local::LocalBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    /// An object with this key already exists; nothing was written.
    AlreadyExists,
}

/// Object storage used by a repository.
///
/// Contract:
/// * `put` is create-only. It must never replace an existing object, and a
///   concurrent reader must never see a partial object (write to a
///   temporary name, then publish atomically).
/// * `get` returns the whole object or `Error::NotFound`.
/// * `list` returns full keys under `prefix` in no particular order.
/// * `delete` is only used by admin operations (prune, retention) and may be
///   refused by append-only backends, or with `Error::Retained` while an
///   object lock keeps the object.
pub trait Backend: Send + Sync {
    fn put(&self, key: &str, data: &[u8]) -> Result<PutOutcome>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn exists(&self, key: &str) -> Result<bool>;
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
    fn delete(&self, key: &str) -> Result<()>;
    /// Stored size of an object in bytes.
    fn size(&self, key: &str) -> Result<u64> {
        Ok(self.get(key)?.len() as u64)
    }
    /// Human-readable location, for logs.
    fn describe(&self) -> String;
    /// Days each object is kept immutable after it is written or extended
    /// (S3 Object Lock), if the backend locks objects.
    fn lock_days(&self) -> Option<u32> {
        None
    }
    /// Move `key`'s lock to now + `lock_days`. Never shortens a lock. Returns
    /// false when the backend does not lock objects.
    fn extend_lock(&self, _key: &str) -> Result<bool> {
        Ok(false)
    }
}

/// Reject keys that could escape the repository root or are not ones the
/// format produces.
pub fn validate_key(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key.len() <= 512
        && !key.starts_with('/')
        && !key.ends_with('/')
        && key
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "invalid object key {key:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        for good in ["config.json", "chunks/ab/abcd", "keys/x-y_z.json"] {
            assert!(validate_key(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a/",
            "a\\b",
            "a b",
            "C:x",
        ] {
            assert!(validate_key(bad).is_err(), "{bad}");
        }
    }
}
