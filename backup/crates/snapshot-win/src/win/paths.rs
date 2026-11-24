//! VSS snapshots of the volumes holding chosen files and folders (folder
//! backups): open and locked files are read as they were at one moment.

use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{GetVolumeNameForVolumeMountPointW, GetVolumePathNameW};
use windows::Win32::Storage::Vss::VSS_BT_COPY;

use super::vss::{SnapshotSet, VssError};
use crate::paths::PathMap;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(b: &[u16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(&b[..n])
}

/// Mount point (`C:\`) and volume GUID name of a local path.
fn mount_and_volume(path: &str) -> Option<(String, String)> {
    let p = wide(&path.replace('/', "\\"));
    let mut mount = vec![0u16; 1024];
    unsafe { GetVolumePathNameW(PCWSTR(p.as_ptr()), &mut mount) }.ok()?;
    let mut name = vec![0u16; 64];
    unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(mount.as_ptr()), &mut name) }.ok()?;
    Some((from_wide(&mount), from_wide(&name)))
}

/// Snapshots of the volumes holding `roots` (logical paths). Network shares
/// and paths on volumes VSS cannot snapshot are read live; `notes` says which.
pub struct PathSnapshot {
    set: Option<SnapshotSet>,
    pub map: PathMap,
    pub notes: Vec<String>,
}

impl PathSnapshot {
    pub fn create(roots: &[String]) -> Result<PathSnapshot, VssError> {
        let mut mounts: Vec<(String, String)> = Vec::new();
        let mut notes = Vec::new();
        for r in roots {
            let r = r.replace('/', "\\");
            if r.starts_with("\\\\") {
                notes.push(format!(
                    "{r} is a network share: read live, without a snapshot"
                ));
                continue;
            }
            match mount_and_volume(&r) {
                Some(mv) if !mounts.iter().any(|(_, v)| v == &mv.1) => mounts.push(mv),
                Some(_) => {}
                None => notes.push(format!("{r}: its volume was not found; read live")),
            }
        }
        if mounts.is_empty() {
            return Ok(PathSnapshot {
                set: None,
                map: PathMap::default(),
                notes,
            });
        }
        let volumes: Vec<String> = mounts.iter().map(|(_, v)| v.clone()).collect();
        let set = SnapshotSet::create(&volumes, VSS_BT_COPY)?;
        let mut map = PathMap::default();
        for (mount, volume) in &mounts {
            if let Some(s) = set
                .snapshots
                .iter()
                .find(|s| s.volume.eq_ignore_ascii_case(volume))
            {
                map.add(mount, &s.device);
            } else {
                notes.push(format!("{mount} could not be snapshotted; read live"));
            }
        }
        Ok(PathSnapshot {
            set: Some(set),
            map,
            notes,
        })
    }

    pub fn translate(&self, logical: &str) -> PathBuf {
        self.map.translate(logical)
    }

    /// Release the snapshots (BackupComplete when `ok`).
    pub fn finish(self, ok: bool) -> Result<(), VssError> {
        match self.set {
            Some(s) => s.complete(ok),
            None => Ok(()),
        }
    }
}
