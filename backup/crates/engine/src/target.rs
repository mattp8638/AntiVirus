//! Restore targets and the safety checks that guard them.
//!
//! Rule: the engine never writes to anything the caller did not name, and
//! never without a `DestructiveConfirmation` for exactly that target.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::{EngineError, Result};

/// Proof that a human confirmed overwriting a specific target. The CLI
/// builds it only after `--yes`; the UI only after the user types the
/// target's name. The engine checks it names the target being opened.
#[derive(Debug, Clone)]
pub struct DestructiveConfirmation {
    target: PathBuf,
}

impl DestructiveConfirmation {
    pub fn confirmed_by_user(target: impl AsRef<Path>) -> Self {
        DestructiveConfirmation {
            target: target.as_ref().to_path_buf(),
        }
    }
    pub fn target(&self) -> &Path {
        &self.target
    }
}

/// Positional writer.
pub trait WriteTarget: Send + Sync {
    fn size(&self) -> u64;
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn sync(&self) -> io::Result<()>;
    fn describe(&self) -> String;
    /// Logical sector size of a disk target, if known.
    fn logical_sector_size(&self) -> Option<u32> {
        None
    }
}

#[derive(Debug)]
pub struct FileTarget {
    file: File,
    path: PathBuf,
    size: u64,
    pub is_block_device: bool,
    sector: Option<u32>,
}

impl FileTarget {
    /// Open `path` for restore after safety checks.
    ///
    /// * Regular file: created if missing (`create`), extended to
    ///   `min_size` if shorter. Existing files need the confirmation too.
    /// * Block device (Linux): must not be mounted, swapped on, or hold a
    ///   mounted partition / device-mapper child; must be >= `min_size`.
    /// * Windows raw devices are refused in Phase 1: physical-disk restore
    ///   runs from the recovery environment.
    pub fn open(
        path: &Path,
        min_size: u64,
        create: bool,
        confirm: &DestructiveConfirmation,
    ) -> Result<FileTarget> {
        if confirm.target() != path {
            return Err(EngineError::Safety(format!(
                "confirmation was given for {} but the target is {}",
                confirm.target().display(),
                path.display()
            )));
        }
        #[cfg(windows)]
        {
            if is_windows_device_path(&path.to_string_lossy()) {
                return Err(EngineError::Safety(
                    "restoring to a physical disk from a running Windows is not supported; boot the recovery environment".into(),
                ));
            }
        }
        let meta = std::fs::metadata(path);
        let is_block = match &meta {
            Ok(m) => is_block_device(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display())).into())
            }
        };
        if is_block {
            #[cfg(target_os = "linux")]
            linux::check_block_device_unused(path)?;
            let mut f = OpenOptions::new().read(true).write(true).open(path)?;
            let size = f.seek(SeekFrom::End(0))?;
            if size < min_size {
                return Err(EngineError::Safety(format!(
                    "target {} is {} bytes, image needs {} bytes (resized restore is not available yet)",
                    path.display(),
                    size,
                    min_size
                )));
            }
            return Ok(FileTarget {
                file: f,
                path: path.to_path_buf(),
                size,
                is_block_device: true,
                #[cfg(target_os = "linux")]
                sector: linux::logical_sector_size(path),
                #[cfg(not(target_os = "linux"))]
                sector: None,
            });
        }
        match &meta {
            Ok(m) if !m.is_file() => {
                return Err(EngineError::Safety(format!(
                    "{} is neither a regular file nor a block device",
                    path.display()
                )))
            }
            Err(_) if !create => {
                return Err(EngineError::InvalidInput(format!(
                    "{} does not exist",
                    path.display()
                )))
            }
            _ => {}
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .open(path)?;
        let cur = f.metadata()?.len();
        if cur < min_size {
            f.set_len(min_size)?; // sparse where supported
        }
        Ok(FileTarget {
            file: f,
            path: path.to_path_buf(),
            size: cur.max(min_size),
            is_block_device: false,
            sector: None,
        })
    }
}

/// True for Windows paths naming a device or volume rather than a file:
/// `\\.\PhysicalDrive0`, `\\.\C:`, `\\?\Volume{..}`, `\\?\GLOBALROOT\..`.
/// Long file paths (`\\?\C:\dir\file`, `\\?\UNC\server\share\file`) are files.
pub fn is_windows_device_path(p: &str) -> bool {
    let s = p.replace('/', "\\").to_ascii_lowercase();
    if s.starts_with(r"\\.\") {
        return true;
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        let drive_file = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
        return !(drive_file || rest.starts_with(r"unc\"));
    }
    false
}

#[cfg(unix)]
fn is_block_device(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    m.file_type().is_block_device()
}

#[cfg(not(unix))]
fn is_block_device(_m: &std::fs::Metadata) -> bool {
    false
}

impl WriteTarget for FileTarget {
    fn size(&self) -> u64 {
        self.size
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::write_all_at(&self.file, data, offset)
        }
        #[cfg(windows)]
        {
            let mut done = 0;
            while done < data.len() {
                done += std::os::windows::fs::FileExt::seek_write(
                    &self.file,
                    &data[done..],
                    offset + done as u64,
                )?;
            }
            Ok(())
        }
    }
    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
    fn describe(&self) -> String {
        self.path.display().to_string()
    }
    fn logical_sector_size(&self) -> Option<u32> {
        self.sector
    }
}

#[cfg(test)]
mod tests {
    use super::is_windows_device_path as dev;

    #[test]
    fn windows_device_paths() {
        assert!(dev(r"\\.\PhysicalDrive0"));
        assert!(dev(r"\\.\C:"));
        assert!(dev(r"\\?\Volume{0b5f}\"));
        assert!(dev(r"\\?\GLOBALROOT\Device\HarddiskVolume3"));
        assert!(dev(r"\\?\C:"));
        assert!(!dev(r"\\?\C:\restore\disk.img"));
        assert!(!dev(r"\\?\UNC\nas\share\disk.img"));
        assert!(!dev(r"D:\disk.img"));
        assert!(!dev("/tmp/disk.img"));
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use crate::{EngineError, Result};

    /// Logical sector size of a block device, from sysfs.
    pub fn logical_sector_size(path: &Path) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        let (ma, mi) = major_minor(std::fs::metadata(path).ok()?.rdev());
        let base = std::path::PathBuf::from(format!("/sys/dev/block/{ma}:{mi}"));
        // Partitions have no queue/ of their own; it is on the parent disk.
        [base.join("queue"), base.join("../queue")]
            .iter()
            .find_map(|q| std::fs::read_to_string(q.join("logical_block_size")).ok())
            .and_then(|s| s.trim().parse().ok())
    }

    pub fn major_minor(rdev: u64) -> (u64, u64) {
        let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
        let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
        (major, minor)
    }

    /// `/sys/dev/block/M:m` → the device and all its partitions and holders.
    fn device_tree(major: u64, minor: u64) -> Vec<String> {
        let mut out = vec![format!("{major}:{minor}")];
        let base = format!("/sys/dev/block/{major}:{minor}");
        let Ok(real) = std::fs::canonicalize(&base) else {
            return out;
        };
        let mut stack = vec![real];
        while let Some(dir) = stack.pop() {
            // Partitions are subdirectories with a `dev` file; holders are
            // listed under holders/.
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.join("partition").exists() {
                        if let Ok(d) = std::fs::read_to_string(p.join("dev")) {
                            out.push(d.trim().to_string());
                        }
                        stack.push(p);
                    }
                }
            }
            if let Ok(rd) = std::fs::read_dir(dir.join("holders")) {
                for e in rd.flatten() {
                    if let Ok(real) = std::fs::canonicalize(e.path()) {
                        if let Ok(d) = std::fs::read_to_string(real.join("dev")) {
                            out.push(d.trim().to_string());
                        }
                        stack.push(real);
                    }
                }
            }
        }
        out
    }

    /// Refuse a block device that is in use: mounted (directly, via a
    /// partition, or via dm/md holders) or used as swap.
    pub fn check_block_device_unused(path: &Path) -> Result<()> {
        let m = std::fs::metadata(path)?;
        let (maj, min) = major_minor(m.rdev());
        let devs = device_tree(maj, min);
        if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
            for line in mi.lines() {
                // Field 3 is major:minor.
                if let Some(mm) = line.split_whitespace().nth(2) {
                    if devs.iter().any(|d| d == mm) {
                        let mp = line.split_whitespace().nth(4).unwrap_or("?");
                        return Err(EngineError::Safety(format!(
                            "{} is in use: mounted at {mp}",
                            path.display()
                        )));
                    }
                }
            }
        }
        if let Ok(sw) = std::fs::read_to_string("/proc/swaps") {
            for line in sw.lines().skip(1) {
                if let Some(dev) = line.split_whitespace().next() {
                    if let Ok(sm) = std::fs::metadata(dev) {
                        let (a, b) = major_minor(sm.rdev());
                        if devs.contains(&format!("{a}:{b}")) {
                            return Err(EngineError::Safety(format!(
                                "{} is in use as swap",
                                path.display()
                            )));
                        }
                    }
                }
            }
        }
        if devs.len() > 1 {
            // Holders (dm, md, LVM) that are not mounted may still be in use.
            let holders = std::fs::read_dir(format!("/sys/dev/block/{maj}:{min}/holders"))
                .map(|r| r.count())
                .unwrap_or(0);
            if holders > 0 {
                return Err(EngineError::Safety(format!(
                    "{} is held by device-mapper/md (LVM, RAID or encryption); deactivate it first",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decodes_dev_numbers() {
            // makedev(8, 1) and makedev(259, 65537) per glibc encoding.
            assert_eq!(major_minor(0x801), (8, 1));
            let (maj, min) = (259u64, 65537u64);
            #[allow(clippy::identity_op)]
            let dev =
                (maj & 0xfff) << 8 | (min & 0xff) | ((min & !0xff) << 12) | ((maj & !0xfff) << 32);
            assert_eq!(major_minor(dev), (259, 65537));
        }
    }
}
