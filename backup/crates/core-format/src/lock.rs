//! Repository locks: shared for writers that add data (backup) or read it
//! (restore, verify, forget), exclusive for prune, which deletes chunks.
//!
//! ```text
//! locks/<lock id>.<seq>.json   { "kind", "hostname", "pid", "created", "refreshed" }
//! ```
//! Objects are create-only, so a refresh writes `<seq + 1>` and then deletes
//! `<seq>`; a live lock is never absent. Acquire writes first and checks
//! second, so of two racing acquirers at least one sees the other. A lock
//! not refreshed for `STALE_AFTER` seconds belongs to a crashed process.

use std::collections::BTreeMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::timefmt::now_unix;

pub const REFRESH_EVERY: u64 = 120;
pub const STALE_AFTER: i64 = 1800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockKind {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    pub kind: LockKind,
    pub hostname: String,
    pub pid: u32,
    pub created: i64,
    pub refreshed: i64,
}

/// A held lock. Refreshed in the background; released on drop.
pub struct RepoLock {
    backend: Arc<dyn Backend>,
    id: String,
    seq: Arc<Mutex<u64>>,
    stop: Option<mpsc::Sender<()>>,
    refresher: Option<JoinHandle<()>>,
    pub kind: LockKind,
}

fn key(id: &str, seq: u64) -> String {
    format!("locks/{id}.{seq}.json")
}

/// Latest record per lock id, with the key it was read from.
pub fn list_locks(b: &dyn Backend) -> Result<BTreeMap<String, Vec<(u64, String)>>> {
    let mut m: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    for k in b.list("locks")? {
        let Some(name) = k
            .strip_prefix("locks/")
            .and_then(|n| n.strip_suffix(".json"))
        else {
            continue;
        };
        let Some((id, seq)) = name.split_once('.') else {
            continue;
        };
        let Ok(seq) = seq.parse::<u64>() else {
            continue;
        };
        m.entry(id.to_string()).or_default().push((seq, k));
    }
    for v in m.values_mut() {
        v.sort();
    }
    Ok(m)
}

fn read_latest(b: &dyn Backend, keys: &[(u64, String)]) -> Option<LockRecord> {
    keys.iter()
        .rev()
        .find_map(|(_, k)| b.get(k).ok().and_then(|d| serde_json::from_slice(&d).ok()))
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
}

pub fn acquire(backend: Arc<dyn Backend>, kind: LockKind) -> Result<RepoLock> {
    acquire_at(backend, kind, now_unix())
}

/// `now` is injectable for tests.
pub fn acquire_at(backend: Arc<dyn Backend>, kind: LockKind, now: i64) -> Result<RepoLock> {
    acquire_inner(backend, kind, now, Duration::from_secs(REFRESH_EVERY))
}

fn acquire_inner(
    backend: Arc<dyn Backend>,
    kind: LockKind,
    now: i64,
    refresh: Duration,
) -> Result<RepoLock> {
    let mut idb = [0u8; 16];
    crate::crypto::fill_random(&mut idb)?;
    let id = hex::encode(idb);
    let rec = LockRecord {
        kind,
        hostname: hostname(),
        pid: std::process::id(),
        created: now,
        refreshed: now,
    };
    backend.put(&key(&id, 0), &serde_json::to_vec(&rec)?)?;

    let mut conflict = None;
    let mut stale = Vec::new();
    for (other, keys) in list_locks(&*backend)? {
        if other == id {
            continue;
        }
        let Some(r) = read_latest(&*backend, &keys) else {
            continue;
        };
        if now - r.refreshed > STALE_AFTER {
            stale.push(keys);
            continue;
        }
        let clash = match kind {
            LockKind::Shared => r.kind == LockKind::Exclusive,
            LockKind::Exclusive => true,
        };
        if clash && conflict.is_none() {
            conflict = Some(r);
        }
    }
    if let Some(r) = conflict {
        let _ = backend.delete(&key(&id, 0));
        let what = match r.kind {
            LockKind::Exclusive => "is being pruned",
            LockKind::Shared => "is in use by a backup, restore or verification",
        };
        return Err(Error::Busy(format!(
            "the repository {what} on {} (pid {}); try again later",
            r.hostname, r.pid
        )));
    }
    if kind == LockKind::Exclusive {
        for keys in stale {
            for (_, k) in keys {
                let _ = backend.delete(&k);
            }
        }
    }

    let seq = Arc::new(Mutex::new(0u64));
    // Dropping the sender wakes the refresher immediately.
    let (stop, wake) = mpsc::channel::<()>();
    let (b2, id2, seq2) = (backend.clone(), id.clone(), seq.clone());
    let refresher = std::thread::spawn(move || {
        while let Err(RecvTimeoutError::Timeout) = wake.recv_timeout(refresh) {
            let mut s = seq2.lock().unwrap();
            let r = LockRecord {
                refreshed: now_unix(),
                ..rec.clone()
            };
            if let Ok(data) = serde_json::to_vec(&r) {
                if b2.put(&key(&id2, *s + 1), &data).is_ok() {
                    let _ = b2.delete(&key(&id2, *s));
                    *s += 1;
                }
            }
        }
    });
    Ok(RepoLock {
        backend,
        id,
        seq,
        stop: Some(stop),
        refresher: Some(refresher),
        kind,
    })
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(h) = self.refresher.take() {
            let _ = h.join();
        }
        let s = *self.seq.lock().unwrap();
        let _ = self.backend.delete(&key(&self.id, s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;

    fn backend() -> (tempfile::TempDir, Arc<dyn Backend>) {
        let d = tempfile::tempdir().unwrap();
        let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(d.path().join("r")).unwrap());
        (d, b)
    }

    #[test]
    fn shared_locks_coexist_and_block_exclusive() {
        let (_d, b) = backend();
        let a = acquire(b.clone(), LockKind::Shared).unwrap();
        let c = acquire(b.clone(), LockKind::Shared).unwrap();
        assert!(matches!(
            acquire(b.clone(), LockKind::Exclusive),
            Err(Error::Busy(_))
        ));
        drop(a);
        drop(c);
        assert!(
            list_locks(&*b).unwrap().is_empty(),
            "released locks are removed"
        );
        let x = acquire(b.clone(), LockKind::Exclusive).unwrap();
        assert!(
            matches!(acquire(b.clone(), LockKind::Shared), Err(Error::Busy(m)) if m.contains("pruned"))
        );
        assert!(matches!(
            acquire(b.clone(), LockKind::Exclusive),
            Err(Error::Busy(_))
        ));
        drop(x);
        acquire(b.clone(), LockKind::Shared).unwrap();
    }

    #[test]
    fn failed_acquire_leaves_nothing_behind() {
        let (_d, b) = backend();
        let _x = acquire(b.clone(), LockKind::Exclusive).unwrap();
        for _ in 0..3 {
            let _ = acquire(b.clone(), LockKind::Shared);
        }
        assert_eq!(list_locks(&*b).unwrap().len(), 1);
    }

    #[test]
    fn stale_locks_are_ignored_and_cleared_by_exclusive() {
        let (_d, b) = backend();
        let old = LockRecord {
            kind: LockKind::Shared,
            hostname: "crashed".into(),
            pid: 1,
            created: 0,
            refreshed: 0,
        };
        b.put("locks/deadbeef.7.json", &serde_json::to_vec(&old).unwrap())
            .unwrap();
        let x = acquire_at(b.clone(), LockKind::Exclusive, STALE_AFTER + 10).unwrap();
        assert!(
            !b.exists("locks/deadbeef.7.json").unwrap(),
            "stale lock removed"
        );
        drop(x);
        // A fresh lock from another host blocks exclusive.
        let fresh = LockRecord {
            refreshed: 1000,
            ..old
        };
        b.put("locks/cafe.0.json", &serde_json::to_vec(&fresh).unwrap())
            .unwrap();
        assert!(acquire_at(b.clone(), LockKind::Exclusive, 1100).is_err());
    }

    #[test]
    fn refresh_replaces_without_a_gap() {
        let (_d, b) = backend();
        let l = acquire_inner(
            b.clone(),
            LockKind::Shared,
            now_unix(),
            Duration::from_millis(30),
        )
        .unwrap();
        for _ in 0..40 {
            // At every observation exactly one key exists for the lock.
            let locks = list_locks(&*b).unwrap();
            assert_eq!(locks.len(), 1);
            assert!(!locks.values().next().unwrap().is_empty());
            std::thread::sleep(Duration::from_millis(5));
        }
        let seq = *l.seq.lock().unwrap();
        assert!(seq >= 2, "refreshed {seq} times");
        drop(l);
        assert!(list_locks(&*b).unwrap().is_empty());
    }

    #[test]
    fn newest_sequence_wins() {
        let (_d, b) = backend();
        let mk = |t| {
            serde_json::to_vec(&LockRecord {
                kind: LockKind::Exclusive,
                hostname: "h".into(),
                pid: 1,
                created: 0,
                refreshed: t,
            })
            .unwrap()
        };
        b.put("locks/aa.1.json", &mk(0)).unwrap(); // stale on its own
        b.put("locks/aa.2.json", &mk(5000)).unwrap(); // refreshed
        assert!(acquire_at(b.clone(), LockKind::Shared, 5100).is_err());
    }
}
