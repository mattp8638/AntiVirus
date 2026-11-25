//! Folder backups: chosen files and folders (crate `filebackup`, design:
//! docs/design/file-backup.md). On Windows the volumes holding them are
//! snapshotted with VSS first, and on macOS the Data volume with an APFS
//! local snapshot (`/` then means the whole Data volume), so open files are
//! copied as they were at one moment; network shares and Linux read the
//! live files.

use anyhow::anyhow;
use core_format::manifest::MachineInfo;
use core_format::Repository;
use protocol::{BackupSettings, JobState, JobUpdate};
use serde_json::json;

use crate::jobs::{finished, report_of, Ctx, Reporter};

/// Folder backups have their own machine ID, so their retention and
/// lineage are kept apart from the same machine's disk images.
pub fn machine_id(ctx: &Ctx) -> String {
    format!("files:{}", ctx.cfg.machine_id)
}

pub fn run(
    ctx: &Ctx,
    repo: &Repository,
    paths: &[String],
    excludes: &[String],
    s: &BackupSettings,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    if paths.is_empty() {
        return Err(anyhow!("choose at least one file or folder to back up"));
    }
    let roots: Vec<String> = paths.iter().map(|p| filebackup::logical(p)).collect();
    let machine = MachineInfo {
        machine_id: machine_id(ctx),
        hostname: crate::inventory::hostname(),
    };
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(unused_mut))]
    let mut notes: Vec<String> = Vec::new();
    rep.progress("snapshot", 0, 1, "preparing");
    // What the files were read from, reported with the result.
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(unused_mut))]
    let mut snapshot: Option<String> = None;

    #[cfg(windows)]
    let snap = match snapshot_win::win::paths::PathSnapshot::create(paths) {
        Ok(s) => {
            notes.extend(s.notes.iter().cloned());
            snapshot = Some("VSS".to_string());
            Some(s)
        }
        Err(e) => {
            notes.push(format!("No VSS snapshot ({e}): files were read live, so files open for writing may be skipped or inconsistent"));
            None
        }
    };
    #[cfg(windows)]
    let translate = |p: &str| match &snap {
        Some(s) if !p.starts_with("UNC/") => s.translate(p),
        _ => filebackup::live(p),
    };
    #[cfg(target_os = "macos")]
    let snap = match crate::macsnap::Snapshot::create() {
        Ok(s) => {
            notes.extend(s.notes.iter().cloned());
            snapshot = Some(format!("APFS {}", s.name()));
            Some(s)
        }
        Err(e) => {
            notes.push(format!("No APFS snapshot ({e}): files were read live, so files open for writing may be inconsistent"));
            None
        }
    };
    #[cfg(target_os = "macos")]
    let translate = |p: &str| match &snap {
        Some(s) if !p.starts_with("UNC/") => s.translate(&filebackup::live(p)),
        _ => filebackup::live(p),
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let translate = |p: &str| filebackup::live(p);

    let progress = |path: &str, bytes: u64, files: u64| {
        rep.progress(
            "reading",
            files,
            0,
            &format!("{files} files, {}: {path}", human(bytes)),
        );
    };
    let cancel = || ctx.ctl.is_cancelled();
    let r = filebackup::backup(
        repo,
        machine,
        &translate,
        &filebackup::Options {
            roots: &roots,
            excludes,
            label: s.label.clone(),
            cancel: &cancel,
            progress: &progress,
        },
    );
    #[cfg(windows)]
    if let Some(sn) = snap {
        if let Err(e) = sn.finish(r.is_ok()) {
            notes.push(format!("releasing the VSS snapshot: {e}"));
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(sn) = snap {
        if let Err(e) = sn.finish() {
            notes.push(format!("removing the APFS snapshot: {e}"));
        }
    }
    let r = r.map_err(|e| anyhow!("{e}"))?;
    let m = repo.load_manifest(&r.image_id)?;
    let mut warnings = notes;
    warnings.extend(r.warnings.iter().cloned());
    let mut u = finished(if warnings.is_empty() {
        JobState::Succeeded
    } else {
        JobState::Warning
    });
    u.images = Some(vec![report_of(&m)]);
    u.warnings = warnings;
    u.result = Some(json!({ "images": [{
        "image_id": r.image_id, "files": r.files, "folders": r.folders, "bytes": r.bytes,
        "files_read": r.files_read, "bytes_read": r.bytes_read, "files_unchanged": r.files_unchanged,
        "files_failed": r.files_failed, "excluded": r.excluded,
    }], "snapshot": snapshot }));
    Ok(u)
}

fn human(b: u64) -> String {
    let u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < u.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", u[i])
}
