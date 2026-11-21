//! Repository and image verification.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Mutex;

use core_format::chunk::ChunkId;
use core_format::{Error as FormatError, Repository};
use serde::Serialize;
use uuid::Uuid;

use crate::control::JobControl;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "level", content = "percent")]
pub enum VerifyLevel {
    /// Manifests decrypt and verify; every referenced chunk exists.
    Quick,
    /// Quick plus decrypt and re-hash this percentage of referenced chunks.
    Sample(f64),
    /// Decrypt and re-hash every referenced chunk.
    Full,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkProblem {
    pub chunk: String,
    pub problem: String,
    pub images: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestProblem {
    pub image_id: Uuid,
    pub problem: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub level: VerifyLevel,
    pub images_checked: usize,
    pub chunks_referenced: usize,
    pub chunks_read: usize,
    pub bad_manifests: Vec<ManifestProblem>,
    pub missing_chunks: Vec<ChunkProblem>,
    pub corrupt_chunks: Vec<ChunkProblem>,
    pub ok: bool,
}

/// Verify `images` (all images if `None`).
pub fn verify(
    repo: &Repository,
    images: Option<&[Uuid]>,
    level: VerifyLevel,
    ctl: &JobControl,
    workers: usize,
) -> Result<VerifyReport> {
    let _lock = crate::reader_lock(repo)?;
    let ids: Vec<Uuid> = match images {
        Some(v) => v.to_vec(),
        None => repo.list_image_ids()?,
    };
    let mut bad_manifests = Vec::new();
    let mut refs: BTreeMap<ChunkId, Vec<Uuid>> = BTreeMap::new();
    for id in &ids {
        match repo.load_manifest(id) {
            Ok(m) => {
                for c in m.chunk_ids() {
                    refs.entry(c).or_default().push(*id);
                }
            }
            Err(e) => bad_manifests.push(ManifestProblem {
                image_id: *id,
                problem: e.to_string(),
            }),
        }
    }

    // One listing instead of one existence probe per chunk.
    let stored: HashSet<String> = repo.backend().list("chunks")?.into_iter().collect();
    let mut missing = Vec::new();
    for (c, imgs) in &refs {
        if !stored.contains(&c.object_key()) {
            missing.push(ChunkProblem {
                chunk: c.to_hex(),
                problem: "missing".into(),
                images: imgs.clone(),
            });
        }
    }
    let missing_set: BTreeSet<String> = missing.iter().map(|m| m.chunk.clone()).collect();

    let candidates: Vec<&ChunkId> = refs
        .keys()
        .filter(|c| !missing_set.contains(&c.to_hex()))
        .collect();
    let to_read: Vec<&ChunkId> = match level {
        VerifyLevel::Quick => vec![],
        VerifyLevel::Full => candidates,
        VerifyLevel::Sample(pct) => sample(candidates, pct),
    };

    let corrupt = Mutex::new(Vec::new());
    let queue = Mutex::new(to_read.iter());
    std::thread::scope(|s| {
        for _ in 0..workers.max(1) {
            s.spawn(|| loop {
                if !ctl.checkpoint() {
                    break;
                }
                let Some(c) = queue.lock().unwrap().next().copied() else {
                    break;
                };
                match repo.get_chunk(c) {
                    Ok(_) => {}
                    Err(e) => {
                        let problem = match e {
                            FormatError::NotFound(_) => "missing".to_string(),
                            e => e.to_string(),
                        };
                        corrupt.lock().unwrap().push(ChunkProblem {
                            chunk: c.to_hex(),
                            problem,
                            images: refs[c].clone(),
                        });
                    }
                }
            });
        }
    });
    if ctl.is_cancelled() {
        return Err(crate::EngineError::Cancelled);
    }
    let mut corrupt = corrupt.into_inner().unwrap();
    corrupt.sort_by(|a, b| a.chunk.cmp(&b.chunk));
    let ok = bad_manifests.is_empty() && missing.is_empty() && corrupt.is_empty();
    Ok(VerifyReport {
        level,
        images_checked: ids.len(),
        chunks_referenced: refs.len(),
        chunks_read: to_read.len(),
        bad_manifests,
        missing_chunks: missing,
        corrupt_chunks: corrupt,
        ok,
    })
}

/// Uniform random sample of ceil(pct% of n) items, at least one if any.
fn sample<T>(mut v: Vec<T>, pct: f64) -> Vec<T> {
    let pct = pct.clamp(0.0, 100.0);
    let k = ((v.len() as f64) * pct / 100.0).ceil() as usize;
    let k = if pct > 0.0 { k.max(1).min(v.len()) } else { 0 };
    // Partial Fisher–Yates with OS randomness.
    for i in 0..k {
        let mut r = [0u8; 8];
        let _ = core_format::crypto::fill_random(&mut r);
        let j = i + (u64::from_le_bytes(r) % (v.len() - i) as u64) as usize;
        v.swap(i, j);
    }
    v.truncate(k);
    v
}

#[cfg(test)]
mod tests {
    use super::sample;

    #[test]
    fn sample_sizes() {
        assert_eq!(sample((0..100).collect(), 10.0).len(), 10);
        assert_eq!(sample((0..100).collect(), 0.0).len(), 0);
        assert_eq!(sample((0..3).collect(), 1.0).len(), 1);
        assert_eq!(sample((0..3).collect(), 100.0).len(), 3);
        let s: std::collections::HashSet<i32> =
            sample((0..50).collect(), 100.0).into_iter().collect();
        assert_eq!(s.len(), 50);
    }
}
