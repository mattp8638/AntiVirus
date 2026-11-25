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
    let m = manifest(ctx, access, image)?;
    if m.os.family == filebackup::FAMILY {
        // A folder backup: its index is the volume.
        let g = SESSION.lock().unwrap();
        let s = g.as_ref().ok_or_else(|| anyhow!("image closed"))?;
        return Ok(Box::new(filebackup::IndexVolume::open(&s.repo, &m)?));
    }
    let (m, d) = disk(ctx, access, image, v.disk)?;
    Ok(filebrowse::open(&m, d, v.disk, v.partition)?)
}

/// The one "volume" of a folder backup: everything it holds, from the root
/// (`/C:/Users/...`, `/home/...`, `//server/share/...`).
pub fn folder_volume(m: &ManifestBody) -> filebrowse::Volume {
    filebrowse::Volume {
        disk: 1,
        partition: 1,
        filesystem: core_format::fsdetect::FsType::Unknown,
        size: m.disks.get(1).map(|d| d.size).unwrap_or(0),
        mount_points: vec!["Files and folders".into()],
        name: "Files and folders".into(),
        browsable: true,
        note: None,
    }
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
            let volumes = if m.os.family == filebackup::FAMILY {
                vec![folder_volume(&m)]
            } else {
                filebrowse::volumes(&m)
            };
            serde_json::json!({ "volumes": volumes })
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
    if target.trim() == ORIGINAL {
        return restore_to_original(ctx, access, image, volume, paths, conflict, rep);
    }
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

/// Target meaning "where each item was" (folder backups only).
pub const ORIGINAL: &str = "@original";

/// The folder a folder-backup item came from, as a path on this machine:
/// `/C:/Users/anna/x` -> `C:\Users\anna`, `/home/anna/x` -> `/home/anna`,
/// `/UNC/nas/share/dir/x` -> `\\nas\share\dir`.
pub fn original_parent(p: &str, windows: bool) -> anyhow::Result<PathBuf> {
    let parts = filebrowse::components(p)?;
    let unc = parts.first().is_some_and(|f| f == "UNC");
    if parts.len() < 2 || (unc && parts.len() < 4) {
        bail!("{p}: choose a file or folder inside a backed-up folder");
    }
    let up = &parts[..parts.len() - 1];
    Ok(PathBuf::from(if unc {
        format!("\\\\{}", up[1..].join("\\"))
    } else if windows {
        let mut s = up.join("\\");
        if up.len() == 1 {
            s.push('\\'); // C: -> C:\
        }
        s
    } else {
        format!("/{}", up.join("/"))
    }))
}

/// Folder backups: put each chosen item back in the folder it came from.
fn restore_to_original(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    volume: VolumeRef,
    paths: &[String],
    conflict: &str,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m = manifest(ctx, access, image)?;
    if m.os.family != filebackup::FAMILY {
        bail!("restoring to the original place is for folder backups; choose a folder");
    }
    let mut total = filebrowse::RestoreReport::default();
    let mut last = finished(JobState::Succeeded);
    for p in paths {
        let parent = original_parent(p, cfg!(windows))?;
        std::fs::create_dir_all(&parent)?;
        last = restore_files(
            ctx,
            access,
            image,
            volume,
            std::slice::from_ref(p),
            &parent.to_string_lossy(),
            false,
            conflict,
            rep,
        )?;
        if let Some(r) = last
            .result
            .as_ref()
            .and_then(|v| serde_json::from_value::<filebrowse::RestoreReport>(v.clone()).ok())
        {
            total.files += r.files;
            total.folders += r.folders;
            total.bytes += r.bytes;
            total.skipped += r.skipped;
            total.failed_total += r.failed_total;
            total.failed.extend(r.failed);
        }
    }
    let state = match (total.files, total.failed_total) {
        (_, 0) => JobState::Succeeded,
        (0, _) => JobState::Failed,
        _ => JobState::Warning,
    };
    last.state = state;
    if state == JobState::Failed && last.error.is_none() {
        last.error = Some("nothing was restored".into());
    }
    last.result = Some(serde_json::to_value(&total)?);
    Ok(last)
}

/// Restore `paths` into a private temporary folder, then send them to the
/// browser as an encrypted tar archive (docs/design/file-download.md).
#[allow(clippy::too_many_arguments)]
pub fn download_files(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    volume: VolumeRef,
    paths: &[String],
    recipient: &str,
    manifest: bool,
    job: Uuid,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let work = crate::config::state_dir()
        .join("downloads")
        .join(job.to_string());
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(work.join("files"))?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(work.clone());
    let mut u = restore_files(
        ctx,
        access,
        image,
        volume,
        paths,
        &work.join("files").to_string_lossy(),
        true,
        "overwrite",
        rep,
    )?;
    if u.state == JobState::Failed {
        return Ok(u);
    }
    rep.progress("packing", 0, 1, "");
    // eDiscovery: each file's SHA-256 in the archive, and the manifest's own hash in the result.
    let listed = if manifest {
        let files = crate::download::hash_tree(&work.join("files"))?;
        Some(crate::download::write_manifest(
            &work.join("files"),
            serde_json::json!({ "image_id": image, "volume": volume, "selected": paths }),
            files,
        )?)
    } else {
        None
    };
    let tar = work.join("files.tar");
    crate::download::tar_dir(&work.join("files"), &mut std::fs::File::create(&tar)?)?;
    let name = format!("restore-{}.tar", &image.to_string()[..8]);
    let header = send_archive(ctx, rep, job, &tar, recipient, &name)?;
    let restored = u.result.take().unwrap_or_default();
    let mut result = serde_json::json!({ "download": header, "restored": restored });
    if let Some((sha, n)) = listed {
        result["manifest_sha256"] = sha.into();
        result["manifest_files"] = n.into();
    }
    u.result = Some(result);
    Ok(u)
}

/// Encrypt an archive for the browser's key and upload it as this job's download.
pub(crate) fn send_archive(
    ctx: &Ctx,
    rep: &Reporter,
    job: Uuid,
    tar: &std::path::Path,
    recipient: &str,
    name: &str,
) -> anyhow::Result<protocol::download::DownloadHeader> {
    let total = std::fs::metadata(tar)?.len();
    crate::download::encrypt_and_send(tar, recipient, name, |off, bytes| {
        rep.progress("sending", off, total, "encrypted for your browser");
        let (code, _, body) = ctx.client.raw(
            "POST",
            &format!("/api/agent/jobs/{job}/download?offset={off}"),
            Some(bytes),
            std::time::Duration::from_secs(300),
            4096,
        )?;
        if code >= 300 {
            anyhow::bail!(
                "the server refused the upload ({code}): {}",
                String::from_utf8_lossy(&body)
            );
        }
        Ok(())
    })
}

#[cfg(test)]
mod original_tests {
    use super::original_parent;
    use std::path::PathBuf;

    #[test]
    fn items_go_back_to_their_folder() {
        assert_eq!(
            original_parent("/C:/Users/anna/report.docx", true).unwrap(),
            PathBuf::from("C:\\Users\\anna")
        );
        assert_eq!(
            original_parent("/C:/notes.txt", true).unwrap(),
            PathBuf::from("C:\\")
        );
        assert_eq!(
            original_parent("/home/anna/report.docx", false).unwrap(),
            PathBuf::from("/home/anna")
        );
        assert_eq!(
            original_parent("/UNC/nas/share/dir/x.pdf", true).unwrap(),
            PathBuf::from("\\\\nas\\share\\dir")
        );
        assert_eq!(
            original_parent("/UNC/nas/share/x.pdf", false).unwrap(),
            PathBuf::from("\\\\nas\\share")
        );
        assert!(original_parent("/C:", true).is_err());
        assert!(original_parent("/UNC/nas/share", true).is_err());
    }
}
