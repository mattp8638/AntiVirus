//! Physical disks for restore (design: phase-2 §6): listing them, and
//! taking one over for a raw write.
//!
//! Windows refuses raw writes to sectors that belong to a mounted volume.
//! Before a whole-disk restore every volume on the target disk is locked
//! (`FSCTL_LOCK_VOLUME`, which fails while files are open on it) and
//! dismounted, and an offline or read-only disk is brought online and made
//! writable for this session only. Afterwards the partition table is
//! re-read (`IOCTL_DISK_UPDATE_PROPERTIES`) so the restored volumes appear.
//! The disk that holds Windows itself is always refused.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{DeleteVolumeMountPointW, SetVolumeMountPointW};
use windows::Win32::System::Ioctl::{
    FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME, IOCTL_DISK_GET_DISK_ATTRIBUTES,
    IOCTL_DISK_SET_DISK_ATTRIBUTES, IOCTL_DISK_UPDATE_PROPERTIES,
};
use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, FIRMWARE_TABLE_PROVIDER};

use super::{ioctl, system};

#[derive(Debug, Clone)]
pub struct PhysicalDisk {
    pub number: u32,
    /// `\\.\PhysicalDriveN`.
    pub path: String,
    pub size: u64,
    pub sector_size: u32,
    pub model: String,
    pub serial: String,
    /// Holds the running Windows.
    pub system: bool,
    /// Holds the medium this system started from (Windows PE) or a page file.
    pub in_use: bool,
}

/// `\\.\PhysicalDrive3` → 3.
pub fn disk_number(path: &str) -> Option<u32> {
    let l = path.to_ascii_lowercase();
    l.strip_prefix(r"\\.\physicaldrive")?.parse().ok()
}

/// (volume GUID path with trailing backslash, offset on the disk, length)
/// for each volume that lies on disk `number`.
pub fn volumes_on_disk(number: u32) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for name in system::list_volumes() {
        let Ok(f) = ioctl::open_read(name.trim_end_matches('\\')) else {
            continue;
        };
        if let Ok(ex) = ioctl::volume_disk_extents(&f) {
            for (disk, start, len) in ex {
                if disk == number {
                    out.push((name.clone(), start, len));
                }
            }
        }
    }
    out
}

fn disk_of_volume(volume: &str) -> Vec<u32> {
    ioctl::open_read(volume.trim_end_matches('\\'))
        .and_then(|f| ioctl::volume_disk_extents(&f))
        .map(|ex| ex.into_iter().map(|e| e.0).collect())
        .unwrap_or_default()
}

/// Disks holding the running Windows (none on Windows PE, which runs from
/// a RAM disk).
pub fn system_disks() -> Vec<u32> {
    system::system_volume()
        .map(|v| disk_of_volume(&v))
        .unwrap_or_default()
}

/// Disks holding the medium Windows PE started from (its `sources\boot.wim`
/// or our settings file), or a page file.
fn busy_disks() -> Vec<u32> {
    let mut out = Vec::new();
    for v in system::list_volumes() {
        let busy = [r"sources\boot.wim", r"fenrir\recovery.json", "pagefile.sys"]
            .iter()
            .any(|f| Path::new(&format!("{v}{f}")).exists());
        if busy {
            out.extend(disk_of_volume(&v));
        }
    }
    out
}

/// Every physical disk.
pub fn list() -> Vec<PhysicalDisk> {
    let sys = system_disks();
    let busy = busy_disks();
    let mut out = Vec::new();
    for n in 0..64u32 {
        let path = format!(r"\\.\PhysicalDrive{n}");
        let Ok(f) = ioctl::open_read(&path) else {
            continue;
        };
        let Ok((size, sector_size)) = ioctl::disk_geometry(&f) else {
            continue;
        };
        let (model, serial) = ioctl::device_description(&f);
        out.push(PhysicalDisk {
            number: n,
            path,
            size,
            sector_size,
            model,
            serial,
            system: sys.contains(&n),
            in_use: busy.contains(&n),
        });
    }
    out
}

/// A disk taken over for a restore: its volumes locked and dismounted.
/// Dropping it releases the volumes; call [`DiskLock::finish`] after a
/// successful write so Windows reads the new partition table.
pub struct DiskLock {
    pub number: u32,
    disk: File,
    volumes: Vec<File>,
}

impl DiskLock {
    /// Re-read the partition table (the restored volumes appear), then
    /// release the old volumes.
    pub fn finish(self) -> io::Result<()> {
        let r = ioctl::ioctl(&self.disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], &mut []).map(|_| ());
        drop(self.volumes);
        r
    }
}

/// Take disk `number` over for a whole-disk write.
pub fn lock_for_restore(number: u32) -> io::Result<DiskLock> {
    if system_disks().contains(&number) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "that disk holds the running Windows; restore it from the recovery media",
        ));
    }
    let path = format!(r"\\.\PhysicalDrive{number}");
    let disk = ioctl::open_rw(&path)?;
    make_writable(&disk)?;
    let mut volumes = Vec::new();
    for (name, _, _) in volumes_on_disk(number) {
        let dev = name.trim_end_matches('\\');
        let v = ioctl::open_rw(dev)?;
        let mut locked = false;
        for _ in 0..5 {
            if ioctl::ioctl(&v, FSCTL_LOCK_VOLUME, &[], &mut []).is_ok() {
                locked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if !locked {
            let letters = system::mount_points(&name).join(", ");
            return Err(io::Error::other(format!(
                "a volume on that disk ({}) is in use; close the programs using it and try again",
                if letters.is_empty() {
                    name.clone()
                } else {
                    letters
                }
            )));
        }
        ioctl::ioctl(&v, FSCTL_DISMOUNT_VOLUME, &[], &mut [])?;
        volumes.push(v);
    }
    Ok(DiskLock {
        number,
        disk,
        volumes,
    })
}

/// Bring an offline or read-only disk online and writable, for this boot
/// only (new disks are often offline under the SAN policy).
fn make_writable(disk: &File) -> io::Result<()> {
    const OFFLINE: u64 = 0x1;
    const READ_ONLY: u64 = 0x2;
    let mut get = [0u8; 16];
    if ioctl::ioctl(disk, IOCTL_DISK_GET_DISK_ATTRIBUTES, &[], &mut get).is_err() {
        return Ok(());
    }
    let attrs = u64::from_le_bytes(get[8..16].try_into().unwrap());
    let mask = attrs & (OFFLINE | READ_ONLY);
    if mask == 0 {
        return Ok(());
    }
    // SET_DISK_ATTRIBUTES: Version, Persist, Reserved1[3], Attributes,
    // AttributesMask, Reserved2[4].
    let mut set = [0u8; 40];
    set[0..4].copy_from_slice(&40u32.to_le_bytes());
    set[16..24].copy_from_slice(&mask.to_le_bytes());
    ioctl::ioctl(disk, IOCTL_DISK_SET_DISK_ATTRIBUTES, &set, &mut [])?;
    Ok(())
}

/// A volume made reachable as a folder for the offline Windows changes:
/// its drive letter if it has one, else mounted at a folder until dropped.
pub struct VolumeRoot {
    pub root: PathBuf,
    mounted_at: Option<Vec<u16>>,
}

impl Drop for VolumeRoot {
    fn drop(&mut self) {
        if let Some(w) = &self.mounted_at {
            unsafe {
                let _ = DeleteVolumeMountPointW(PCWSTR(w.as_ptr()));
            }
        }
    }
}

/// `volume` (`\\?\Volume{...}\`) as a folder; `folder` is used when it has
/// no drive letter.
pub fn volume_root(volume: &str, folder: &Path) -> io::Result<VolumeRoot> {
    if let Some(mp) = system::mount_points(volume).into_iter().next() {
        return Ok(VolumeRoot {
            root: PathBuf::from(mp),
            mounted_at: None,
        });
    }
    std::fs::create_dir_all(folder)?;
    let mut dir = folder.to_string_lossy().to_string();
    if !dir.ends_with('\\') {
        dir.push('\\');
    }
    let w = ioctl::wide(&dir);
    let v = ioctl::wide(volume);
    unsafe { SetVolumeMountPointW(PCWSTR(w.as_ptr()), PCWSTR(v.as_ptr())) }
        .map_err(|e| io::Error::other(format!("mounting {volume} at {dir}: {e}")))?;
    Ok(VolumeRoot {
        root: PathBuf::from(dir),
        mounted_at: Some(w),
    })
}

/// (system UUID, serial number) from SMBIOS, for a stable recovery identity.
pub fn hardware_identity() -> Option<(Option<String>, String)> {
    let rsmb = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
    let n = unsafe { GetSystemFirmwareTable(rsmb, 0, None) } as usize;
    if n == 0 {
        return None;
    }
    let mut buf = vec![0u8; n];
    let got = unsafe { GetSystemFirmwareTable(rsmb, 0, Some(&mut buf)) } as usize;
    crate::parse::smbios_system(&buf[..got.min(n)])
}

/// How this machine started: ("uefi" | "bios", Secure Boot on).
pub fn firmware_mode() -> (Option<String>, Option<bool>) {
    let b = system::boot_config_basic();
    let fw = match b.firmware {
        core_format::manifest::Firmware::Uefi => Some("uefi".to_string()),
        core_format::manifest::Firmware::Bios => Some("bios".to_string()),
        core_format::manifest::Firmware::Unknown => None,
    };
    (fw, b.secure_boot)
}

/// Open `path` (`\\.\PhysicalDriveN`) as a restore target: the disk must be
/// a listed physical disk that is not the system disk or the medium this
/// system started from; its volumes are locked and dismounted. Keep the
/// lock until writing (including boot fix-ups) is done, then call
/// [`DiskLock::finish`].
pub fn take_over(
    path: &str,
    confirm: &engine::DestructiveConfirmation,
) -> engine::Result<(engine::FileTarget, DiskLock)> {
    let n = disk_number(path).ok_or_else(|| {
        engine::EngineError::InvalidInput(format!(
            "{path} is not a physical disk (\\\\.\\PhysicalDriveN)"
        ))
    })?;
    let d = list()
        .into_iter()
        .find(|d| d.number == n)
        .ok_or_else(|| engine::EngineError::InvalidInput(format!("no disk {path}")))?;
    if d.system || d.in_use {
        return Err(engine::EngineError::Safety(format!(
            "{path} is in use (it holds the running Windows, the medium it started from, or a page file)"
        )));
    }
    let lock = lock_for_restore(n)?;
    let t = engine::FileTarget::open_device(Path::new(path), d.size, d.sector_size, confirm)?;
    Ok((t, lock))
}
