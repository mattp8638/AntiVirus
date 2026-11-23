//! Copy images from one repository to another: off-site copies
//! (docs/design/offsite-copy.md).
//!
//! The two repositories have their own keys, so chunks are decrypted from
//! the source and encrypted again for the destination (where their IDs
//! differ: they are keyed per repository). Manifests are rebuilt for the
//! destination and signed with its key for the machine. The copied images
//! are then verified in the destination.
//!
//! A copy gets its own image ID, derived from the destination and the
//! source image ([`copy_id`]): the same image always maps to the same ID in a
//! given destination (so a later run sees it is there, and a copied parent
//! is found), and two repositories never hold the same image ID.

use std::collections::{BTreeMap, HashSet};

use core_format::manifest::{ChunkRef, ImageKind};
use core_format::Repository;
use serde::Serialize;
use uuid::Uuid;

use crate::verify::{verify, VerifyLevel};
use crate::{EngineError, JobControl, Result};

/// The ID an image copied from another repository has in `dst_repo`.
pub fn copy_id(dst_repo: Uuid, source_image: Uuid) -> Uuid {
    let mut h = blake3::Hasher::new_derive_key("fenrir-backup image copy id v1");
    h.update(dst_repo.as_bytes());
    h.update(source_image.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h.finalize().as_bytes()[..16]);
    // RFC 9562 version 8 (custom), variant 10.
    b[6] = (b[6] & 0x0F) | 0x80;
    b[8] = (b[8] & 0x3F) | 0x80;
    Uuid::from_bytes(b)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CopyReport {
    /// Images copied by this run, oldest first: their IDs in the destination.
    pub copied: Vec<Uuid>,
    /// Images the destination already had.
    pub already_there: usize,
    /// Chunks written to the destination, and those it already had.
    pub chunks_written: u64,
    pub chunks_present: u64,
    /// Bytes stored in the destination (compressed, encrypted).
    pub bytes_stored: u64,
    /// The destination's verification of the copied images.
    pub verified: bool,
}

/// Copy `images` (or every image the destination does not have) from `src`
/// to `dst`, then verify them there (`full`: re-read every chunk).
pub fn copy_images(
    src: &Repository,
    dst: &Repository,
    images: Option<&[Uuid]>,
    full_verify: bool,
    ctl: &JobControl,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<CopyReport> {
    if src.config().repo_id == dst.config().repo_id {
        return Err(EngineError::InvalidInput(
            "the source and the destination are the same repository".into(),
        ));
    }
    if src.chunk_size() != dst.chunk_size() {
        return Err(EngineError::InvalidInput(format!(
            "the repositories use different chunk sizes ({} and {} KiB); copy into one created with the source's",
            src.chunk_size() / 1024,
            dst.chunk_size() / 1024
        )));
    }
    let _src_lock = crate::reader_lock(src)?;
    let _dst_lock = dst.lock(core_format::lock::LockKind::Shared)?;

    let present: HashSet<Uuid> = dst.list_image_ids()?.into_iter().collect();
    let dst_repo = dst.config().repo_id;
    let wanted: Vec<Uuid> = match images {
        Some(v) => v.to_vec(),
        None => src.list_image_ids()?,
    };
    let mut report = CopyReport::default();
    // Oldest first, so an image's parent is copied before it.
    let mut todo = Vec::new();
    for id in wanted {
        if present.contains(&copy_id(dst_repo, id)) {
            report.already_there += 1;
            continue;
        }
        let m = src.load_manifest(&id)?;
        todo.push(m);
    }
    todo.sort_by_key(|m| m.created_unix);
    let total: u64 = todo
        .iter()
        .flat_map(|m| &m.disks)
        .map(|d| d.chunks.len() as u64)
        .sum();
    let mut done = 0u64;
    // Source chunk → destination chunk, across images (they share most).
    let mut mapped: BTreeMap<core_format::chunk::ChunkId, core_format::chunk::ChunkId> =
        BTreeMap::new();
    let mut have: HashSet<Uuid> = present;
    for mut m in todo {
        for d in &mut m.disks {
            for ChunkRef(_, id) in d.chunks.iter_mut() {
                if !ctl.checkpoint() {
                    return Err(EngineError::Cancelled);
                }
                let new_id = match mapped.get(id) {
                    Some(n) => *n,
                    None => {
                        let data = src.get_chunk(id)?;
                        let n = dst.chunk_id(&data);
                        if dst.has_chunk(&n)? {
                            report.chunks_present += 1;
                        } else {
                            let (_, stored) = dst.put_chunk(&n, &data)?;
                            report.chunks_written += 1;
                            report.bytes_stored += stored;
                        }
                        mapped.insert(*id, n);
                        n
                    }
                };
                *id = new_id;
                done += 1;
                progress(done, total);
            }
        }
        m.repo_id = dst_repo;
        m.image_id = copy_id(dst_repo, m.image_id);
        m.parent = m.parent.map(|p| copy_id(dst_repo, p));
        if m.parent.is_some_and(|p| !have.contains(&p)) {
            // The parent is not in the destination: this image stands alone
            // there (every image holds all its chunks anyway).
            m.parent = None;
            m.kind = ImageKind::Full;
        }
        let signer = dst.signer_for_machine(&m.machine.machine_id)?;
        dst.store_manifest(&m, &signer)?;
        have.insert(m.image_id);
        report.copied.push(m.image_id);
    }
    drop(_dst_lock);
    if !report.copied.is_empty() {
        let v = verify(
            dst,
            Some(&report.copied),
            if full_verify {
                VerifyLevel::Full
            } else {
                VerifyLevel::Quick
            },
            ctl,
            4,
        )?;
        if !v.ok {
            return Err(EngineError::Format(core_format::Error::integrity(format!(
                "the copied images did not verify in the destination: {} bad manifest(s), {} missing and {} corrupt chunk(s)",
                v.bad_manifests.len(),
                v.missing_chunks.len(),
                v.corrupt_chunks.len()
            ))));
        }
        report.verified = true;
    }
    Ok(report)
}
