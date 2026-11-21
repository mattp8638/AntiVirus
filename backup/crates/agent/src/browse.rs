//! File-level browsing and restore from images (the `filebrowse` crate).
//!
//! Browsing is one job per folder. Opening a repository and decrypting the
//! manifest takes a moment, so the opened image is kept for a few minutes
//! after the last request; the server polls this agent every second while
//! someone is browsing it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use core_format::ManifestBody;
use filebrowse::{Conflict, RestoreOptions};
use nbd_server::ImageExport;
use protocol::{JobState, JobUpdate, RepoAccess, VolumeRef};
use uuid::Uuid;

use crate::jobs::{finished, open_repo, Ctx, Reporter};

/// Idle time after which the opened image is closed (and network shares
/// released). It holds a shared repository lock, which delays space
/// reclamation, so keep it short.
const KEEP_OPEN: Duration = Duration::from_secs(300);
const LIST_LIMIT: usize = 5000;

struct Session {
    repository: Uuid,
    image: Uuid,
    manifest: Arc<ManifestBody>,
    disks: Vec<(u32, Arc<ImageExport>)>,
    repo: core_format::Repository,
    last: Instant,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

/// Is an image open for browsing? (Keeps network shares connected.)
pub fn active() -> bool {
    SESSION.lock().unwrap().is_some()
}

/// Close the opened image after `KEEP_OPEN` without requests. True if one was closed.
pub fn expire() -> bool {
    let mut g = SESSION.lock().unwrap();
    if g.as_ref().is_some_and(|s| s.last.elapsed() > KEEP_OPEN) {
        *g = None;
        return true;
    }
    false
}

fn manifest(ctx: &Ctx, access: &RepoAccess, image: Uuid) -> anyhow::Result<Arc<ManifestBody>> {
    let mut g = SESSION.lock().unwrap();
    if let Some(s) = g
        .as_mut()
        .filter(|s| s.repository == access.repository_id && s.image == image)
    {
        s.last = Instant::now();
        return Ok(s.manifest.clone());
    }
    *g = None;
    let repo = open_repo(ctx, access)?;
    let m = Arc::new(
        repo.load_manifest(&image)
            .map_err(|e| anyhow!("image {image}: {e}"))?,
    );
    *g = Some(Session {
        repository: access.repository_id,
        image,
        manifest: m.clone(),
        disks: vec![],
        repo,
        last: Instant::now(),
    });
    Ok(m)
}

fn disk(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    index: u32,
) -> anyhow::Result<(Arc<ManifestBody>, Arc<ImageExport>)> {
    let m = manifest(ctx, access, image)?;
    let mut g = SESSION.lock().unwrap();
    let s = g.as_mut().ok_or_else(|| anyhow!("image closed"))?;
    if let Some((_, d)) = s.disks.iter().find(|(i, _)| *i == index) {
        return Ok((m, d.clone()));
    }
    let d = Arc::new(ImageExport::new(&s.repo, &m, index, 64 << 20)?);
    s.disks.push((index, d.clone()));
    Ok((m, d))
}

fn open(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    v: VolumeRef,
) -> anyhow::Result<Box<dyn filebrowse::Volumefs>> {
    let (m, d) = disk(ctx, access, image, v.disk)?;
    Ok(filebrowse::open(&m, d, v.disk, v.partition)?)
}

pub fn browse(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    volume: Option<VolumeRef>,
    path: &str,
) -> anyhow::Result<JobUpdate> {
    let result = match volume {
        None => {
            let m = manifest(ctx, access, image)?;
            serde_json::json!({ "volumes": filebrowse::volumes(&m) })
        }
        Some(v) => {
            let mut fs = open(ctx, access, image, v)?;
            let listing = filebrowse::list(fs.as_mut(), path, LIST_LIMIT)?;
            serde_json::json!({ "volume": v, "listing": listing })
        }
    };
    let mut u = finished(JobState::Succeeded);
    u.result = Some(result);
    Ok(u)
}

#[allow(clippy::too_many_arguments)]
pub fn restore_files(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    volume: VolumeRef,
    paths: &[String],
    target: &str,
    keep_structure: bool,
    conflict: &str,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let target = PathBuf::from(target.trim());
    if !target.is_absolute() {
        bail!("the restore folder must be a full path on this machine, e.g. C:\\Restored or /srv/restored");
    }
    let conflict = match conflict {
        "rename" => Conflict::Rename,
        "skip" => Conflict::Skip,
        "overwrite" => Conflict::Overwrite,
        c => bail!("unknown choice for existing files: {c}"),
    };
    let mut fs = open(ctx, access, image, volume)?;
    let opts = RestoreOptions {
        target,
        keep_structure,
        conflict,
    };
    let ctl = ctx.ctl.clone();
    let report = filebrowse::restore(
        fs.as_mut(),
        paths,
        &opts,
        &|| ctl.is_cancelled(),
        &|r, cur| {
            rep.progress(
                "restoring",
                r.bytes,
                0,
                &format!("{} files · {cur}", r.files),
            )
        },
    );
    // Keep the image open: the next request is likely another restore or folder.
    if let Some(s) = SESSION.lock().unwrap().as_mut() {
        s.last = Instant::now();
    }
    let report = report?;
    let state = match (report.files, report.failed_total) {
        (_, 0) => JobState::Succeeded,
        (0, _) => JobState::Failed,
        _ => JobState::Warning,
    };
    let mut u = finished(state);
    if report.failed_total > 0 {
        let what = report
            .failed
            .iter()
            .take(5)
            .map(|f| format!("{}: {}", f.path, f.error))
            .collect::<Vec<_>>();
        if state == JobState::Failed {
            u.error = Some(format!("nothing was restored. {}", what.join("; ")));
        } else {
            u.warnings = vec![format!(
                "{} item(s) could not be restored",
                report.failed_total
            )];
            u.warnings.extend(what);
        }
    }
    u.result = Some(serde_json::to_value(&report)?);
    Ok(u)
}
