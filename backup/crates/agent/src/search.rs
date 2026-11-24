//! Searching across backups (crate `catalog`, design: docs/design/search.md).
//!
//! Each image's file catalogue is built once (an `IndexImage` job queued
//! after each backup, or by a search that meets an image without one) and
//! kept in the state directory: `catalogue/<repository>/<image>.zst`.
//! Searches read the catalogues only, so they take seconds; file names leave
//! this machine only as the matches of a search.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use core_format::Repository;
use protocol::{JobState, JobUpdate};
use serde_json::json;
use uuid::Uuid;

use crate::jobs::{finished, Ctx, Reporter};

/// Catalogues kept per repository (the newest, by when they were last used).
const KEEP: usize = 300;
const MAX_HITS: usize = 2000;

fn dir(ctx: &Ctx, repo: &Repository) -> PathBuf {
    ctx.state_dir
        .join("catalogue")
        .join(repo.config().repo_id.to_string())
}

fn path(ctx: &Ctx, repo: &Repository, image: Uuid) -> PathBuf {
    dir(ctx, repo).join(format!("{image}.zst"))
}

/// The cached catalogue of `image`, if there is one.
fn cached(ctx: &Ctx, repo: &Repository, image: Uuid) -> Option<catalog::Catalogue> {
    let p = path(ctx, repo, image);
    let c = catalog::Catalogue::load(&p).ok()?;
    // Touch it, so trimming keeps the ones in use.
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .and_then(|f| f.set_modified(std::time::SystemTime::now()));
    Some(c)
}

/// Build the catalogue of `image` and keep it.
pub fn build(
    ctx: &Ctx,
    repo: &Repository,
    image: Uuid,
    rep: &Reporter,
) -> anyhow::Result<catalog::Catalogue> {
    let m = repo.load_manifest(&image)?;
    let mut c = catalog::Catalogue::new();
    let cancel = || ctx.ctl.is_cancelled();
    if m.os.family == filebackup::FAMILY {
        let mut fs = filebackup::IndexVolume::open(repo, &m)?;
        let v = crate::browse::folder_volume(&m);
        c.add_volume(
            catalog::VolumeRef {
                label: "Files and folders".into(),
                disk: v.disk,
                partition: v.partition,
            },
            &mut fs,
            &cancel,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let mut disks: Vec<(u32, Arc<nbd_server::ImageExport>)> = Vec::new();
        for v in filebrowse::volumes(&m) {
            let label = crate::malware::volume_label(&v);
            if !v.browsable {
                c.skipped
                    .push(format!("{label}: {}", v.note.clone().unwrap_or_default()));
                continue;
            }
            rep.progress("indexing", 0, 0, &label);
            let disk = match disks.iter().find(|(i, _)| *i == v.disk) {
                Some((_, d)) => d.clone(),
                None => {
                    let d = Arc::new(nbd_server::ImageExport::new(repo, &m, v.disk, 64 << 20)?);
                    disks.push((v.disk, d.clone()));
                    d
                }
            };
            match filebrowse::open(&m, disk, v.disk, v.partition) {
                Ok(mut fs) => c
                    .add_volume(
                        catalog::VolumeRef {
                            label,
                            disk: v.disk,
                            partition: v.partition,
                        },
                        fs.as_mut(),
                        &cancel,
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                Err(e) => c.skipped.push(format!("{label}: {e}")),
            }
        }
    }
    c.save(&path(ctx, repo, image))?;
    trim(ctx, repo);
    Ok(c)
}

fn trim(ctx: &Ctx, repo: &Repository) {
    let Ok(rd) = std::fs::read_dir(dir(ctx, repo)) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    if files.len() > KEEP {
        files.sort();
        for (_, p) in &files[..files.len() - KEEP] {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn index(
    ctx: &Ctx,
    repo: &Repository,
    image: Uuid,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let c = match cached(ctx, repo, image) {
        Some(c) => c,
        None => build(ctx, repo, image, rep)?,
    };
    let mut u = finished(JobState::Succeeded);
    u.result = Some(json!({ "image_id": image, "entries": c.entries.len(), "skipped": c.skipped }));
    Ok(u)
}

/// Search the catalogues of `images` (newest first, as given), building
/// missing ones while `budget` lasts.
pub fn search(
    ctx: &Ctx,
    repo: &Repository,
    query: &str,
    images: &[Uuid],
    limit: u32,
    budget: Duration,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let q = catalog::Query::parse(query)
        .ok_or_else(|| anyhow::anyhow!("type part of a file or folder name to search for"))?;
    let limit = (limit as usize).clamp(1, MAX_HITS);
    let started = Instant::now();
    let (mut hits, mut searched, mut not_indexed, mut truncated) =
        (Vec::new(), 0usize, Vec::new(), false);
    let known: std::collections::HashSet<Uuid> = repo.list_image_ids()?.into_iter().collect();
    for (n, id) in images.iter().enumerate() {
        if ctx.ctl.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if !known.contains(id) {
            continue;
        }
        rep.progress("searching", n as u64, images.len() as u64, "");
        let cat = match cached(ctx, repo, *id) {
            Some(c) => c,
            None if started.elapsed() < budget => match build(ctx, repo, *id, rep) {
                Ok(c) => c,
                Err(_) => {
                    not_indexed.push(*id);
                    continue;
                }
            },
            None => {
                not_indexed.push(*id);
                continue;
            }
        };
        searched += 1;
        let (found, more) = catalog::search(&cat, &q, limit - hits.len());
        hits.extend(found.into_iter().map(|h| (id, h)));
        if more || hits.len() >= limit {
            truncated = true;
            break;
        }
    }
    let mut u = finished(JobState::Succeeded);
    u.result = Some(json!({
        "query": query,
        "hits": hits.iter().map(|(id, h)| json!({
            "image_id": id, "volume": h.volume, "path": h.path, "size": h.size,
            "modified": h.modified, "folder": h.folder,
        })).collect::<Vec<_>>(),
        "searched": searched,
        "not_indexed": not_indexed,
        "truncated": truncated,
    }));
    Ok(u)
}
