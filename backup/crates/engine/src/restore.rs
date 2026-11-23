//! Restore one disk of an image to a target.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use core_format::extent::{self, Extent};
use core_format::manifest::{ChunkRef, ManifestBody};
use core_format::Repository;
use serde::Serialize;

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
}

impl Default for RestoreOptions {
    fn default() -> Self {
        RestoreOptions {
            workers: 4,
            zero_fill: true,
            fit: false,
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
    let fit = if opts.fit {
        Some(crate::fit::plan(
            disk,
            target.size(),
            target.logical_sector_size(),
        )?)
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
    })
}
