//! Linux image sources.
//!
//! `open_disk`: an unmounted block device or a raw image file (a mounted
//! device only with an explicit opt-in, marked `inconsistent`).
//! `live::prepare`: the running system, consistent through LVM snapshots and
//! frozen copies (docs/design/phase-6.md).

#[cfg(target_os = "linux")]
pub mod apps;
pub mod blk;
#[cfg(target_os = "linux")]
pub mod live;
pub mod lvm;

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;

use core_format::manifest::Consistency;
use engine::{DiskInfo, ReadAtSource};

pub struct OpenedDisk {
    pub source: ReadAtSource<File>,
    pub consistency: Consistency,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct InUse(pub String);

impl std::fmt::Display for InUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InUse {}

/// Open `path` read-only as an image source.
///
/// A block device that is mounted (or holds mounted partitions) is refused
/// unless `allow_in_use` is set, in which case the image is marked
/// `Consistency::Inconsistent`.
pub fn open_disk(
    path: &Path,
    allow_in_use: bool,
) -> Result<OpenedDisk, Box<dyn std::error::Error + Send + Sync>> {
    let mut f = File::open(path)?;
    let size = f.seek(SeekFrom::End(0))?;
    let mut info = DiskInfo {
        size,
        device: path.display().to_string(),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    let mut consistency = Consistency::Offline;
    if is_block(&f.metadata()?) {
        if let Err(e) = describe_block_device(path, &f, &mut info) {
            if !allow_in_use {
                return Err(Box::new(InUse(format!(
                    "{e}. Imaging a live filesystem without a snapshot gives an inconsistent image; \
                     unmount it, boot the recovery environment, or pass --allow-inconsistent"
                ))));
            }
            warnings.push(format!(
                "{}: imaged while in use without a snapshot; the image may be inconsistent",
                path.display()
            ));
            consistency = Consistency::Inconsistent;
        }
    }
    Ok(OpenedDisk {
        source: ReadAtSource { inner: f, info },
        consistency,
        warnings,
    })
}

/// Fill in sector sizes and identity; Err if the device is in use.
#[cfg(target_os = "linux")]
fn describe_block_device(
    path: &Path,
    f: &File,
    info: &mut DiskInfo,
) -> Result<(), engine::EngineError> {
    (info.logical_sector_size, info.physical_sector_size) =
        linux::sector_sizes(f).unwrap_or((512, 512));
    (info.model, info.serial) = linux::model_serial(path);
    engine::target::linux::check_block_device_unused(path)
}

#[cfg(not(target_os = "linux"))]
fn describe_block_device(
    _path: &Path,
    _f: &File,
    _info: &mut DiskInfo,
) -> Result<(), engine::EngineError> {
    Ok(())
}

#[cfg(unix)]
fn is_block(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    m.file_type().is_block_device()
}

#[cfg(not(unix))]
fn is_block(_m: &std::fs::Metadata) -> bool {
    false
}

/// Machine identity on Linux: systemd/dbus machine-id.
pub fn machine_id() -> io::Result<String> {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let s = s.trim();
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no machine-id"))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    // From <linux/fs.h>: _IO(0x12, 104) and _IO(0x12, 123).
    const BLKSSZGET: libc::c_ulong = 0x1268;
    const BLKPBSZGET: libc::c_ulong = 0x127B;

    pub fn sector_sizes(f: &File) -> io::Result<(u32, u32)> {
        let mut l: libc::c_int = 0;
        let mut p: libc::c_uint = 0;
        // SAFETY: both ioctls write one integer to the pointer given.
        unsafe {
            if libc::ioctl(f.as_raw_fd(), BLKSSZGET as _, &mut l) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(f.as_raw_fd(), BLKPBSZGET as _, &mut p) != 0 {
                p = l as libc::c_uint;
            }
        }
        Ok((l as u32, p))
    }

    pub fn model_serial(path: &Path) -> (String, String) {
        let name = std::fs::canonicalize(path)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        let rd = |f: &str| {
            std::fs::read_to_string(format!("/sys/block/{name}/{f}"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        (rd("device/model"), rd("device/serial"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::DiskSource;

    #[test]
    fn opens_image_file_as_offline_source() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("disk.img");
        std::fs::write(&p, vec![7u8; 1 << 20]).unwrap();
        let d = open_disk(&p, false).unwrap();
        assert_eq!(d.consistency, Consistency::Offline);
        assert_eq!(d.source.info().size, 1 << 20);
        let mut b = [0u8; 4];
        d.source.read_at(1000, &mut b).unwrap();
        assert_eq!(b, [7; 4]);
    }
}
