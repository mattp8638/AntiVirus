//! Restore one disk of an image to a target.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use core_format::extent::{self, Extent};
use core_format::manifest::{ChunkRef, ManifestBody};
use core_format::Repository;
use serde::{Deserialize, Serialize};

use crate::control::JobControl;
use crate::target::WriteTarget;
use crate::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub workers: usize,
    /// Write zeros over captured ranges whose chunk is all-zero. Needed when
    /// the target may hold old data (a used disk); unnecessary for a fresh
    /// sparse file.
    pub zero_fill: bool,
    /// Lay the image onto a target of a different size (`fit`): move the
    /// GPT to the target's end, allow a smaller target when the partitions
    /// fit. Off: the target must be at least the image disk's size and is
    /// written byte for byte.
    pub fit: bool,
    /// With `fit` onto a larger target: give the new space to the last
    /// partition (its file system is grown by the caller, `crate::grow`).
    pub grow: bool,
    /// After writing, read every restored chunk back from the target and
    /// check it against its content ID (and zero-filled ranges against
    /// zeros): evidence that the target holds exactly the backup's data.
    pub verify: bool,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        RestoreOptions {
            workers: 4,
            zero_fill: true,
            fit: false,
            grow: false,
            verify: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub image_id: uuid::Uuid,
    pub disk: u32,
    pub target: String,
    pub bytes_written: u64,
    pub chunks_restored: u64,
    pub zero_ranges_written: u64,
    /// The partition given the extra space (`grow`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grown: Option<crate::fit::Grown>,
    /// Why nothing was grown, when `grow` was asked for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Read-back check of the target (`RestoreOptions::verify`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

/// What reading the restored disk back found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// False when the target cannot be read back. The data was still
    /// authenticated chunk by chunk when it was read from the backup.
    pub supported: bool,
    pub chunks_checked: u64,
    pub bytes_checked: u64,
    pub zero_ranges_checked: u64,
    /// Chunks (or zero ranges) whose content on the target differs.
    pub mismatches: u64,
    /// Offsets of the first mismatches (at most 20).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub first_mismatches: Vec<u64>,
    /// Chunks past the end of a smaller target (`fit`): nothing was written there.
    pub outside_target: u64,
    /// SHA-256 over the disk's chunk map (index and content ID, in order):
    /// names exactly the content restored, and can be recomputed from the
    /// image manifest.
    pub content_sha256: String,
}

/// SHA-256 of a disk image's chunk map, in index order.
pub fn content_digest(disk: &core_format::manifest::DiskImage) -> String {
    use sha2::{Digest, Sha256};
    let mut chunks: Vec<&ChunkRef> = disk.chunks.iter().collect();
    chunks.sort_by_key(|c| c.0);
    let mut h = Sha256::new();
    h.update(disk.size.to_le_bytes());
    for ChunkRef(index, id) in chunks {
        h.update(index.to_le_bytes());
        h.update(id.to_hex().as_bytes());
    }
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the restored chunks back and compare them with their content IDs.
#[allow(clippy::too_many_arguments)]
pub fn verify_disk(
    repo: &Repository,
    image: &ManifestBody,
    disk_index: u32,
    target: &dyn WriteTarget,
    limit: u64,
    zero_fill: bool,
    workers: usize,
    ctl: &JobControl,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Verification> {
    let disk = image
        .disks
        .iter()
        .find(|d| d.index == disk_index)
        .ok_or_else(|| EngineError::InvalidInput(format!("image has no disk {disk_index}")))?;
    let cs = image.chunk_size as u64;
    let mut v = Verification {
        supported: true,
        content_sha256: content_digest(disk),
        ..Default::default()
    };
    // Probe once: a target that cannot be read back says so instead of failing the restore.
    if let Some(ChunkRef(index, _)) = disk.chunks.first() {
        let mut probe = vec![0u8; 1];
        if let Err(e) = target.read_at(index * cs, &mut probe) {
            if e.kind() == std::io::ErrorKind::Unsupported {
                v.supported = false;
                return Ok(v);
            }
        }
    }
    let total = extent::total_len(&disk.used_extents);
    let done = AtomicU64::new(0);
    let checked = AtomicU64::new(0);
    let outside = AtomicU64::new(0);
    let mism: Mutex<(u64, Vec<u64>)> = Mutex::new((0, Vec::new()));
    let first_err: Mutex<Option<EngineError>> = Mutex::new(None);
    let queue: Mutex<std::slice::Iter<'_, ChunkRef>> = Mutex::new(disk.chunks.iter());
    let note = |off: u64| {
        let mut m = mism.lock().unwrap();
        m.0 += 1;
        if m.1.len() < 20 {
            m.1.push(off);
        }
    };
    std::thread::scope(|s| {
        for _ in 0..workers.max(1) {
            s.spawn(|| loop {
                if !ctl.checkpoint() || first_err.lock().unwrap().is_some() {
                    break;
                }
                let Some(ChunkRef(index, id)) = queue.lock().unwrap().next().copied() else {
                    break;
                };
                let off = index * cs;
                let len = cs.min(disk.size - off);
                if off + len > limit {
                    outside.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut buf = vec![0u8; len as usize];
                match target.read_at(off, &mut buf) {
                    Ok(()) => {
                        if repo.chunk_id(&buf) != id {
                            note(off);
                        }
                        checked.fetch_add(1, Ordering::Relaxed);
                        let d = done.fetch_add(len, Ordering::Relaxed) + len;
                        progress(d.min(total), total);
                    }
                    Err(e) => {
                        first_err.lock().unwrap().get_or_insert(EngineError::Io(e));
                        break;
                    }
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().unwrap() {
        return Err(e);
    }
    if ctl.is_cancelled() {
        return Err(EngineError::Cancelled);
    }
    let mut zero_ranges = 0;
    if zero_fill {
        let present: std::collections::HashSet<u64> = disk.chunks.iter().map(|c| c.0).collect();
        for i in 0..disk.size.div_ceil(cs) {
            if present.contains(&i) {
                continue;
            }
            let range = Extent(i * cs, cs.min(disk.size - i * cs));
            for e in extent::clip(&disk.used_extents, range) {
                if e.0 + e.1 > limit {
                    continue;
                }
                let mut buf = vec![0u8; e.1 as usize];
                target.read_at(e.0, &mut buf)?;
                if buf.iter().any(|b| *b != 0) {
                    note(e.0);
                }
                zero_ranges += 1;
            }
        }
    }
    let (n, first) = mism.into_inner().unwrap();
    v.chunks_checked = checked.load(Ordering::Relaxed);
    v.bytes_checked = done.load(Ordering::Relaxed);
    v.zero_ranges_checked = zero_ranges;
    v.mismatches = n;
    v.first_mismatches = first;
    v.outside_target = outside.load(Ordering::Relaxed);
    Ok(v)
}

pub fn restore_disk(
    repo: &Repository,
    image: &ManifestBody,
    disk_index: u32,
    target: &dyn WriteTarget,
    opts: &RestoreOptions,
    ctl: &JobControl,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<RestoreReport> {
    let _lock = crate::reader_lock(repo)?;
    let disk = image
        .disks
        .iter()
        .find(|d| d.index == disk_index)
        .ok_or_else(|| EngineError::InvalidInput(format!("image has no disk {disk_index}")))?;
    let mut notes = Vec::new();
    let fit = if opts.fit || opts.grow {
        let mut f = crate::fit::plan(disk, target.size(), target.logical_sector_size())?;
        if opts.grow {
            match f.grow(disk) {
                Ok(Some(_)) => {}
                Ok(None) => notes.push(
                    "nothing to grow: the last partition already reaches the end of the target"
                        .into(),
                ),
                Err(e) => notes.push(e),
            }
        }
        Some(f)
    } else {
        if target.size() < disk.size {
            return Err(EngineError::Safety(format!(
                "target is {} bytes, image disk is {} bytes",
                target.size(),
                disk.size
            )));
        }
        None
    };
    let clipped = crate::fit::Clipped {
        inner: target,
        limit: fit.as_ref().map_or(u64::MAX, |f| f.clip()),
    };
    let target: &dyn WriteTarget = &clipped;
    let cs = image.chunk_size as u64;
    let total = extent::total_len(&disk.used_extents);
    let done = AtomicU64::new(0);
    let chunks_restored = AtomicU64::new(0);
    let queue: Mutex<std::slice::Iter<'_, ChunkRef>> = Mutex::new(disk.chunks.iter());
    let first_err: Mutex<Option<EngineError>> = Mutex::new(None);

    std::thread::scope(|s| {
        for _ in 0..opts.workers.max(1) {
            s.spawn(|| loop {
                if !ctl.checkpoint() || first_err.lock().unwrap().is_some() {
                    break;
                }
                let next = queue.lock().unwrap().next().copied();
                let Some(ChunkRef(index, id)) = next else {
                    break;
                };
                let r = (|| -> Result<u64> {
                    let data = repo.get_chunk(&id)?;
                    let off = index * cs;
                    let expect = cs.min(disk.size - off);
                    if data.len() as u64 != expect {
                        return Err(EngineError::Format(core_format::Error::integrity(format!(
                            "chunk {id} at index {index} has length {}, expected {expect}",
                            data.len()
                        ))));
                    }
                    target.write_at(off, &data)?;
                    Ok(expect)
                })();
                match r {
                    Ok(n) => {
                        chunks_restored.fetch_add(1, Ordering::Relaxed);
                        let d = done.fetch_add(n, Ordering::Relaxed) + n;
                        progress(d.min(total), total);
                    }
                    Err(e) => {
                        first_err.lock().unwrap().get_or_insert(e);
                        ctl.cancel();
                        break;
                    }
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().unwrap() {
        return Err(e);
    }
    if ctl.is_cancelled() {
        return Err(EngineError::Cancelled);
    }

    // Captured ranges that had no chunk were all zeros at backup time.
    let mut zero_ranges = 0u64;
    let mut zero_bytes = 0u64;
    if opts.zero_fill {
        let present: std::collections::HashSet<u64> = disk.chunks.iter().map(|c| c.0).collect();
        let zeros = vec![0u8; cs as usize];
        for i in 0..disk.size.div_ceil(cs) {
            if present.contains(&i) {
                continue;
            }
            let range = Extent(i * cs, cs.min(disk.size - i * cs));
            for e in extent::clip(&disk.used_extents, range) {
                target.write_at(e.0, &zeros[..e.1 as usize])?;
                zero_ranges += 1;
                zero_bytes += e.1;
            }
        }
    }
    target.sync()?;
    // Verify before `finish` rewrites the partition table for a resized target.
    let verification = if opts.verify {
        Some(verify_disk(
            repo,
            image,
            disk_index,
            target,
            clipped.limit,
            opts.zero_fill,
            opts.workers,
            ctl,
            &|_, _| {},
        )?)
    } else {
        None
    };
    if let Some(f) = &fit {
        f.finish(clipped.inner)?;
    }
    Ok(RestoreReport {
        image_id: image.image_id,
        disk: disk_index,
        target: target.describe(),
        bytes_written: done.load(Ordering::Relaxed) + zero_bytes,
        chunks_restored: chunks_restored.load(Ordering::Relaxed),
        zero_ranges_written: zero_ranges,
        grown: fit.as_ref().and_then(|f| f.grown().cloned()),
        notes,
        verification,
    })
}
