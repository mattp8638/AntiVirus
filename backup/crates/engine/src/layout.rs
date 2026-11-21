//! Decide which bytes of a disk go into the image.

use core_format::extent::{self, Extent};
use core_format::fsdetect::{self, FsType};
use core_format::manifest::{CaptureMethod, PartitionRecord};
use core_format::partition::{PartitionRole, PartitionTable, Scheme};

use crate::source::{CapturePlan, SourceReader};
use crate::DiskSource;

pub struct DiskLayout {
    pub used: Vec<Extent>,
    pub partitions: Vec<PartitionRecord>,
}

/// Build the normalised used-extent list and per-partition records.
///
/// Always included in full: the partition table regions, everything from
/// the start of the disk to the first partition (MBR boot code and the
/// post-MBR gap some BIOS bootloaders use), and boot-critical partitions
/// (ESP, MSR, recovery, BIOS boot).
pub fn plan_disk(
    src: &dyn DiskSource,
    size: u64,
    table: &PartitionTable,
    plan: &CapturePlan,
) -> std::io::Result<DiskLayout> {
    let mut layout = plan_disk_unfiltered(src, size, table, plan);
    if let Some(alloc) = src.allocated_extents()? {
        let alloc = extent::normalize(alloc);
        layout.used = extent::intersect(&layout.used, &alloc);
        for r in &mut layout.partitions {
            r.captured_bytes = extent::total_len(&extent::clip(&layout.used, r.entry.extent()));
        }
    }
    Ok(layout)
}

fn plan_disk_unfiltered(
    src: &dyn DiskSource,
    size: u64,
    table: &PartitionTable,
    plan: &CapturePlan,
) -> DiskLayout {
    let whole = Extent(0, size);
    let mut used = table.raw_extents();
    let mut records = Vec::new();

    if table.scheme == Scheme::None {
        return DiskLayout {
            used: vec![whole],
            partitions: records,
        };
    }

    let first_start = table
        .partitions
        .iter()
        .filter(|p| p.role != PartitionRole::Extended)
        .map(|p| p.start)
        .min()
        .unwrap_or(size);
    used.push(Extent(0, first_start.min(size)));

    for p in &table.partitions {
        if p.role == PartitionRole::Extended {
            // A container; its EBRs are in the raw regions, its logical
            // partitions are listed separately.
            continue;
        }
        let pext = match p.extent().intersect(&whole) {
            Some(e) => e,
            None => continue,
        };
        let pp = plan.partitions.iter().find(|x| x.number == p.number);
        let detected = fsdetect::detect(&SourceReader(src), pext.0, pext.1);
        let (captured, capture) = match pp {
            Some(pp) if !p.role.is_boot_critical() => match &pp.used {
                Some(u) => {
                    // Clamp to the partition; a provider bug must not make
                    // us capture outside it. The first and last 64 KiB are
                    // always kept: boot sector / superblock at the start,
                    // and at the end the NTFS backup boot sector (outside
                    // the cluster bitmap) and similar trailing metadata.
                    let mut v = extent::clip(&extent::normalize(u.clone()), pext);
                    let edge = pext.1.min(64 * 1024);
                    v.push(Extent(pext.0, edge));
                    v.push(Extent(pext.end() - edge, edge));
                    (extent::normalize(v), pp.capture)
                }
                None => (vec![pext], pp.capture),
            },
            Some(pp) => (
                vec![pext],
                if pp.capture == CaptureMethod::SnapshotBitmap {
                    CaptureMethod::SnapshotFull
                } else {
                    pp.capture
                },
            ),
            None => (vec![pext], CaptureMethod::RawFull),
        };
        let fs = pp
            .and_then(|x| x.filesystem)
            .filter(|f| *f != FsType::Unknown)
            .unwrap_or(detected);
        records.push(PartitionRecord {
            entry: p.clone(),
            filesystem: fs,
            capture,
            captured_bytes: extent::total_len(&captured),
            volume: pp.and_then(|x| x.volume.clone()),
            mount_points: pp.map(|x| x.mount_points.clone()).unwrap_or_default(),
            encryption: pp.and_then(|x| x.encryption.clone()).or_else(|| match fs {
                FsType::Bitlocker => Some("bitlocker".into()),
                FsType::Luks => Some("luks".into()),
                _ => None,
            }),
        });
        used.extend(captured);
    }
    DiskLayout {
        used: extent::clip(&extent::normalize(used), whole),
        partitions: records,
    }
}
