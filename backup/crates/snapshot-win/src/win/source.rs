//! Assemble an application-consistent image source for the running system.

use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;

use core_format::extent;
use core_format::fsdetect::FsType;
use core_format::io::ReadAt;
use core_format::manifest::{CaptureMethod, Consistency, ExcludedFile, MachineInfo};
use core_format::partition::{self, PartitionTable};
use engine::{CapturePlan, DiskInfo, DiskSource, ImageMeta, PartitionPlan};
use windows::Win32::Security::{SE_BACKUP_NAME, SE_SYSTEM_ENVIRONMENT_NAME};
use windows::Win32::Storage::Vss::{VSS_BT_COPY, VSS_BT_FULL};
use windows::Win32::System::Com::{
    CoInitializeEx, CoInitializeSecurity, COINIT_MULTITHREADED, EOAC_DYNAMIC_CLOAKING,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY,
};

use super::vss::{SnapshotSet, VssError};
use super::{ioctl, system};
use crate::composite::{CompositeDisk, Overlay, SharedReader};

/// Files whose contents are never imaged. Their directory entries stay, so
/// the restored system sees them, filled with zeros; Windows recreates the
/// paging file and ignores a hibernation file without a valid header.
pub const EXCLUDED_FILES: &[&str] = &["pagefile.sys", "hiberfil.sys", "swapfile.sys"];

#[derive(Debug, Clone, Default)]
pub struct VssOptions {
    /// VSS_BT_FULL instead of VSS_BT_COPY: lets writers (SQL Server,
    /// Exchange) treat this as a full backup and truncate their logs. Off
    /// by default so Fenrir-Backup never breaks another tool's log chain.
    pub full_backup_type: bool,
    /// Additional physical disk numbers to include besides the system disk.
    pub extra_disks: Vec<u32>,
}

/// A prepared system backup: sources to hand to the engine, the metadata
/// for the manifest, and the live snapshot set.
pub struct SystemBackup {
    pub disks: Vec<CompositeDisk>,
    pub meta: ImageMeta,
    snapshots: Option<SnapshotSet>,
}

impl SystemBackup {
    pub fn sources(&self) -> Vec<&dyn DiskSource> {
        self.disks.iter().map(|d| d as &dyn DiskSource).collect()
    }

    /// Tell VSS how it went and release the snapshots. Call after the
    /// engine has stored the manifest (success) or failed.
    pub fn finish(mut self, success: bool) -> Result<(), VssError> {
        match self.snapshots.take() {
            Some(s) => s.complete(success),
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
pub struct PrepareError(pub String);

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PrepareError {}

impl From<io::Error> for PrepareError {
    fn from(e: io::Error) -> Self {
        PrepareError(e.to_string())
    }
}
impl From<VssError> for PrepareError {
    fn from(e: VssError) -> Self {
        PrepareError(e.to_string())
    }
}
impl From<core_format::Error> for PrepareError {
    fn from(e: core_format::Error) -> Self {
        PrepareError(e.to_string())
    }
}

struct FileReader(std::fs::File);

impl ReadAt for FileReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_at(offset, buf)
    }
}

struct VolumeInfo {
    name: String,
    disk: u32,
    start: u64,
    len: u64,
}

fn init_com() -> Result<(), PrepareError> {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        // S_FALSE (already initialised) is fine; RPC_E_CHANGED_MODE is not.
        if hr.is_err() {
            return Err(PrepareError(format!("CoInitializeEx: {hr:?}")));
        }
        // VSS needs at least identify-level impersonation; ignore "too
        // late" if the host process already configured security.
        let _ = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IDENTIFY,
            None,
            EOAC_DYNAMIC_CLOAKING,
            None,
        );
    }
    Ok(())
}

/// Volumes with a single extent, mapped to (disk, offset).
fn map_volumes() -> Vec<VolumeInfo> {
    let mut out = Vec::new();
    for name in system::list_volumes() {
        let dev = name.trim_end_matches('\\');
        let Ok(f) = ioctl::open_read(dev) else {
            continue;
        };
        if let Ok(ex) = ioctl::volume_disk_extents(&f) {
            if let [(disk, start, len)] = ex[..] {
                out.push(VolumeInfo {
                    name,
                    disk,
                    start,
                    len,
                });
            }
        }
    }
    out
}

/// Snapshot every supported volume on the system disk (plus extra disks)
/// and build one source per disk.
pub fn prepare_system_backup(opts: &VssOptions) -> Result<SystemBackup, PrepareError> {
    init_com()?;
    if !system::enable_privilege(SE_BACKUP_NAME) {
        return Err(PrepareError("SeBackupPrivilege is not available: run as Administrator or as the Fenrir-Backup service".into()));
    }
    let can_read_firmware = system::enable_privilege(SE_SYSTEM_ENVIRONMENT_NAME);

    let mut warnings = Vec::new();
    let sysvol = system::system_volume()?;
    let sys_ex = ioctl::volume_disk_extents(&ioctl::open_read(sysvol.trim_end_matches('\\'))?)?;
    if sys_ex.len() != 1 {
        return Err(PrepareError("the system volume spans several disks (dynamic disk / Storage Spaces); not supported yet".into()));
    }
    let mut disk_numbers: BTreeSet<u32> = sys_ex.iter().map(|e| e.0).collect();
    disk_numbers.extend(opts.extra_disks.iter().copied());

    let volumes = map_volumes();

    // Read each disk's partition table from the raw device.
    struct Disk {
        number: u32,
        info: DiskInfo,
        raw: SharedReader,
        table: PartitionTable,
    }
    let mut disks = Vec::new();
    for &n in &disk_numbers {
        let path = format!(r"\\.\PhysicalDrive{n}");
        let f = ioctl::open_read(&path)?;
        let (size, ss) = ioctl::disk_geometry(&f)?;
        let (model, serial) = ioctl::device_description(&f);
        let pss = ioctl::physical_sector_size(&f).unwrap_or(ss);
        let raw: SharedReader = Arc::new(FileReader(f));
        let table = partition::read_table(&*raw, size, ss)?;
        disks.push(Disk {
            number: n,
            info: DiskInfo {
                size,
                logical_sector_size: ss,
                physical_sector_size: pss,
                model,
                serial,
                device: path,
            },
            raw,
            table,
        });
    }

    // Which partitions have a volume, and which of those VSS supports.
    let mut to_snapshot = Vec::new();
    for d in &disks {
        for p in &d.table.partitions {
            if let Some(v) = volumes
                .iter()
                .find(|v| v.disk == d.number && v.start == p.start && v.len <= p.length)
            {
                if SnapshotSet::is_supported(&v.name) {
                    to_snapshot.push(v.name.clone());
                }
            }
        }
    }
    if to_snapshot.is_empty() {
        return Err(PrepareError(
            "no volume on the selected disks can be snapshotted by VSS".into(),
        ));
    }
    let set = SnapshotSet::create(
        &to_snapshot,
        if opts.full_backup_type {
            VSS_BT_FULL
        } else {
            VSS_BT_COPY
        },
    )?;
    let consistency = if set.writer_issues.is_empty() {
        Consistency::Application
    } else {
        for w in &set.writer_issues {
            warnings.push(format!(
                "VSS writer '{}' failed (state {}, 0x{:08X}); its data is crash-consistent only",
                w.writer, w.state, w.failure.0 as u32
            ));
        }
        Consistency::Crash
    };

    let mut sources = Vec::new();
    let mut excluded_all = Vec::new();
    for d in disks {
        let mut overlays = Vec::new();
        let mut plan = CapturePlan::default();
        for p in &d.table.partitions {
            let vol = volumes
                .iter()
                .find(|v| v.disk == d.number && v.start == p.start && v.len <= p.length);
            let snap = vol.and_then(|v| set.snapshots.iter().find(|s| s.volume == v.name));
            let mut first = [0u8; 512];
            let bitlocker =
                d.raw.read_at(p.start, &mut first).is_ok() && &first[3..11] == b"-FVE-FS-";
            let mut pp = PartitionPlan {
                number: p.number,
                used: None,
                capture: CaptureMethod::RawFull,
                filesystem: None,
                volume: vol.map(|v| v.name.clone()),
                mount_points: vol
                    .map(|v| system::mount_points(&v.name))
                    .unwrap_or_default(),
                encryption: None,
            };
            if bitlocker {
                pp.encryption = Some("bitlocker".into());
                if snap.is_some() {
                    warnings.push(format!(
                        "partition {} is BitLocker-protected: the image holds its decrypted contents (encrypted by the repository key); a restored volume is not BitLocker-encrypted until re-enabled",
                        p.number
                    ));
                } else {
                    warnings.push(format!("partition {} is BitLocker-protected and not snapshotted: captured encrypted, raw", p.number));
                }
            }
            if let Some(s) = snap {
                let dev = ioctl::open_read(&s.device)?;
                // Bytes the snapshot device can serve; past that (the NTFS
                // backup boot sector) reads go to the live disk.
                let device_len = [
                    Some(p.length),
                    ioctl::device_length(&dev).ok(),
                    ioctl::ntfs_volume_length(&dev),
                ]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(p.length);
                pp.capture = CaptureMethod::SnapshotFull;
                if let Some(cluster) = ioctl::ntfs_cluster_size(&dev) {
                    pp.filesystem = Some(FsType::Ntfs);
                    let used = ioctl::volume_bitmap(&dev, cluster, p.start)?;
                    let mut holes = Vec::new();
                    for name in EXCLUDED_FILES {
                        let path = format!(r"{}\{}", s.device, name);
                        if let Ok(f) = ioctl::open_attributes(&path) {
                            if let Ok(ex) = ioctl::file_extents(&f, cluster, p.start) {
                                let bytes = extent::total_len(&ex);
                                if bytes > 0 {
                                    let mp = pp
                                        .mount_points
                                        .first()
                                        .cloned()
                                        .unwrap_or_else(|| s.volume.clone());
                                    excluded_all.push(ExcludedFile {
                                        path: format!("{mp}{name}"),
                                        bytes,
                                    });
                                    holes.extend(ex);
                                }
                            }
                        }
                    }
                    pp.used = Some(extent::subtract(&used, &extent::normalize(holes)));
                    pp.capture = CaptureMethod::SnapshotBitmap;
                }
                overlays.push(Overlay {
                    start: p.start,
                    len: p.length,
                    device_len,
                    device: Arc::new(FileReader(dev)),
                    decrypted: bitlocker,
                });
            }
            plan.partitions.push(pp);
        }
        sources.push(CompositeDisk::new(d.info, d.raw, overlays, plan)?);
    }

    let mut boot = system::boot_config();
    if !can_read_firmware {
        boot.notes
            .push("SeSystemEnvironmentPrivilege could not be enabled".into());
    }
    // Locate the BCD store: ESP for UEFI, the active partition for BIOS.
    for v in &volumes {
        for rel in [r"EFI\Microsoft\Boot\BCD", r"Boot\BCD"] {
            if std::path::Path::new(&format!("{}{}", v.name, rel)).exists() {
                boot.bcd = Some(format!("{}{}", v.name, rel));
            }
        }
    }

    let meta = ImageMeta {
        machine: MachineInfo {
            machine_id: system::machine_id(),
            hostname: system::hostname(),
        },
        consistency,
        os: system::os_info(),
        boot,
        drivers: system::boot_start_drivers(),
        label: None,
        warnings,
        vm: None,
    };
    if meta.machine.machine_id.is_empty() {
        return Err(PrepareError("could not read the machine GUID".into()));
    }
    // Excluded files are reported through the capture plan of the first disk.
    if let Some(first) = sources.first_mut() {
        first.plan.excluded = excluded_all;
    }
    Ok(SystemBackup {
        disks: sources,
        meta,
        snapshots: Some(set),
    })
}
