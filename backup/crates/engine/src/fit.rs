//! Restore a disk image onto a disk of a different size (design: phase-2 §4.1).
//!
//! Larger target: the image is written as is, then the GPT is moved to the
//! target's real end (primary header updated, backup header and entries
//! written at the last LBAs, the stale backup zeroed). With [`Fit::grow`]
//! the last partition also gets the new space (phase-5-grow-clone.md §1);
//! its file system is grown afterwards by `crate::grow`. Smaller target: allowed only when every partition still fits; the
//! old backup GPT, the only data past the new end, is clipped. MBR disks
//! only need the size checks.

use std::io;

use core_format::extent::Extent;
use core_format::fsdetect::FsType;
use core_format::manifest::DiskImage;
use core_format::partition::{PartitionRole, Scheme};

use crate::target::WriteTarget;
use crate::{EngineError, Result};

/// How to lay one image disk onto one target.
#[derive(Debug, Clone)]
pub struct Fit {
    sector: u64,
    target_size: u64,
    /// Image bytes at or after this offset are not written.
    clip: u64,
    gpt: Option<GptFit>,
    /// MBR disks whose last partition was grown: the new first sector.
    mbr_patch: Option<Vec<u8>>,
    grown: Option<Grown>,
}

/// The partition given the space past its old end.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Grown {
    pub number: u32,
    /// Byte offset of the partition.
    pub start: u64,
    pub old_length: u64,
    pub new_length: u64,
    pub filesystem: FsType,
    /// Its number as Windows counts (table order, without the extended
    /// container or empty entries), for diskpart.
    pub windows_number: u32,
}

/// File systems that can use a larger partition (now or once mounted).
pub fn growable(fs: FsType) -> bool {
    matches!(
        fs,
        FsType::Ntfs | FsType::Ext | FsType::Xfs | FsType::Btrfs | FsType::LvmPv | FsType::Luks
    )
}

#[derive(Debug, Clone)]
struct GptFit {
    mbr: Vec<u8>,
    /// Header template (from the primary, else the backup).
    header: Vec<u8>,
    /// Entry array, padded to whole sectors.
    entries: Vec<u8>,
    primary_entries_lba: u64,
    /// Old backup header and entries (offset, length), to zero if they now
    /// lie inside the target.
    stale: Vec<Extent>,
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn mib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

/// Work out how `disk` goes onto a target of `target_size` bytes, or why it
/// cannot. `target_sector` is the target's logical sector size if known.
pub fn plan(disk: &DiskImage, target_size: u64, target_sector: Option<u32>) -> Result<Fit> {
    let table = &disk.partition_table;
    let ss = table.sector_size as u64;
    if let Some(t) = target_sector {
        if table.scheme != Scheme::None && t as u64 != ss {
            return Err(EngineError::Safety(format!(
                "the image disk uses {ss}-byte sectors and the target {t}-byte sectors; its partition table would point at the wrong places"
            )));
        }
    }
    let part_end = table
        .partitions
        .iter()
        .map(|p| p.start + p.length)
        .max()
        .unwrap_or(0);
    let mut fit = Fit {
        sector: ss,
        target_size,
        clip: target_size.min(disk.size),
        gpt: None,
        mbr_patch: None,
        grown: None,
    };
    let limit = match table.scheme {
        Scheme::None => {
            if target_size < disk.size {
                return Err(EngineError::Safety(format!(
                    "the image disk has no partition table and is {}; the target is {}",
                    mib(disk.size),
                    mib(target_size)
                )));
            }
            disk.size
        }
        Scheme::Mbr => target_size,
        Scheme::Gpt => {
            let g = gpt_parts(disk)?;
            let es = g.entries.len() as u64 / ss;
            let last = target_size / ss - 1;
            let last_usable = last
                .checked_sub(es + 1)
                .ok_or_else(|| EngineError::Safety("the target is too small for a GPT".into()))?;
            let first_usable = le64(&g.header, 40);
            if last_usable < first_usable || g.primary_entries_lba + es > first_usable {
                return Err(EngineError::Safety(
                    "the target is too small for a GPT".into(),
                ));
            }
            fit.gpt = Some(g);
            (last_usable + 1) * ss
        }
    };
    if part_end > limit {
        return Err(EngineError::Safety(format!(
            "the partitions on this image disk need {}; the target has room for {}",
            mib(part_end + (disk.size.saturating_sub(limit).min(1 << 20))),
            mib(limit)
        )));
    }
    // Anything captured past the limit other than the old backup GPT
    // would be lost.
    let old_backup = core_format::extent::normalize(
        fit.gpt
            .as_ref()
            .map(|g| g.stale.clone())
            .unwrap_or_default(),
    );
    for e in &disk.used_extents {
        let end = e.0 + e.1;
        if end <= limit {
            continue;
        }
        let mut lost = Extent(e.0.max(limit), end - e.0.max(limit));
        for b in &old_backup {
            if b.0 <= lost.0 && b.0 + b.1 >= lost.0 + lost.1 {
                lost.1 = 0;
            }
        }
        if lost.1 > 0 && lost.0 < disk.size {
            return Err(EngineError::Safety(format!(
                "the image has data at {} which is past the end of the target ({})",
                mib(lost.0),
                mib(limit)
            )));
        }
    }
    Ok(fit)
}

fn gpt_parts(disk: &DiskImage) -> Result<GptFit> {
    let table = &disk.partition_table;
    let ss = table.sector_size as u64;
    let bad = |m: &str| EngineError::InvalidInput(format!("image partition table: {m}"));
    let mbr = table
        .raw_regions
        .iter()
        .find(|r| r.offset == 0)
        .ok_or_else(|| bad("no MBR"))?
        .data
        .clone();
    let is_header = |d: &[u8]| d.len() as u64 == ss && d.starts_with(b"EFI PART");
    let headers: Vec<_> = table
        .raw_regions
        .iter()
        .filter(|r| is_header(&r.data))
        .collect();
    let primary = headers.iter().find(|r| r.offset == ss);
    let template = primary
        .or(headers.first())
        .ok_or_else(|| bad("no GPT header"))?;
    let header = template.data.clone();
    let entries_lba = le64(&header, 72);
    let entries = table
        .raw_regions
        .iter()
        .find(|r| r.offset == entries_lba * ss && !is_header(&r.data))
        .or_else(|| {
            table
                .raw_regions
                .iter()
                .find(|r| r.offset != 0 && !is_header(&r.data))
        })
        .ok_or_else(|| bad("no GPT entries"))?
        .data
        .clone();
    let n = u32::from_le_bytes(header[80..84].try_into().unwrap()) as u64;
    let esz = u32::from_le_bytes(header[84..88].try_into().unwrap()) as u64;
    if entries.len() as u64 != (n * esz).div_ceil(ss) * ss {
        return Err(bad("GPT entry array has the wrong length"));
    }
    let primary_entries_lba = if primary.is_some() { entries_lba } else { 2 };
    // Old backup structures: the header that is not at LBA 1 and the entry
    // array it points at.
    let mut stale = Vec::new();
    for h in headers.iter().filter(|r| r.offset != ss) {
        stale.push(Extent(h.offset, ss));
        let elba = le64(&h.data, 72);
        stale.push(Extent(elba * ss, entries.len() as u64));
    }
    Ok(GptFit {
        mbr,
        header,
        entries,
        primary_entries_lba,
        stale,
    })
}

/// The smallest target `disk` fits on (with [`plan`]).
pub fn min_size(disk: &DiskImage) -> u64 {
    let t = &disk.partition_table;
    let ss = t.sector_size as u64;
    let end = t
        .partitions
        .iter()
        .map(|p| p.start + p.length)
        .max()
        .unwrap_or(0);
    match t.scheme {
        Scheme::None => disk.size,
        Scheme::Mbr => end.max(ss),
        Scheme::Gpt => match gpt_parts(disk) {
            Ok(g) => {
                let first = le64(&g.header, 40) * ss;
                end.max(first) + g.entries.len() as u64 + ss
            }
            Err(_) => disk.size,
        },
    }
}

impl Fit {
    /// Image bytes at or after this offset are not written.
    pub fn clip(&self) -> u64 {
        self.clip
    }

    /// What [`Fit::grow`] changed.
    pub fn grown(&self) -> Option<&Grown> {
        self.grown.as_ref()
    }

    /// Give the space past the last partition to it, if its file system can
    /// use it. Returns why not otherwise (`Ok(None)`: nothing to gain).
    pub fn grow(&mut self, disk: &DiskImage) -> std::result::Result<Option<Grown>, String> {
        const ALIGN: u64 = 1 << 20;
        let t = &disk.partition_table;
        let ss = self.sector;
        let Some(p) = t
            .partitions
            .iter()
            .filter(|p| p.role != PartitionRole::Extended)
            .max_by_key(|p| p.start + p.length)
        else {
            return Ok(None);
        };
        let fs = disk
            .partitions
            .iter()
            .find(|r| r.entry.number == p.number)
            .map(|r| r.filesystem)
            .unwrap_or(FsType::Unknown);
        let limit = match (&t.scheme, &self.gpt) {
            (Scheme::Gpt, Some(g)) => {
                let es = g.entries.len() as u64 / ss;
                (self.target_size / ss - 1 - es) * ss // first byte of the backup entries
            }
            (Scheme::Mbr, _) => self.target_size.min((u32::MAX as u64 + 1) * ss),
            _ => return Ok(None),
        };
        // Ends on a whole MiB (a multiple of every sector size).
        let new_end = limit / ALIGN * ALIGN;
        if new_end <= p.start + p.length {
            return Ok(None);
        }
        if !growable(fs) {
            return Err(format!(
                "partition {} ({fs:?}) is the last on the disk, but its file system cannot be grown; the extra space is left free",
                p.number
            ));
        }
        let new_length = new_end - p.start;
        match t.scheme {
            Scheme::Gpt => {
                let g = self.gpt.as_mut().expect("GPT fit");
                let n = u32::from_le_bytes(g.header[80..84].try_into().unwrap()) as usize;
                let esz = u32::from_le_bytes(g.header[84..88].try_into().unwrap()) as usize;
                let i = p.number as usize - 1;
                if i >= n || (i + 1) * esz > g.entries.len() {
                    return Err(format!("partition {} has no GPT entry", p.number));
                }
                let last_lba = new_end / ss - 1;
                g.entries[i * esz + 40..i * esz + 48].copy_from_slice(&last_lba.to_le_bytes());
                let crc = crc32fast::hash(&g.entries[..n * esz]);
                g.header[88..92].copy_from_slice(&crc.to_le_bytes());
            }
            Scheme::Mbr => {
                if p.number > 4 {
                    return Err(format!(
                        "partition {} is a logical partition; growing it would need its extended partition grown too, so the extra space is left free",
                        p.number
                    ));
                }
                let mut mbr = t
                    .raw_regions
                    .iter()
                    .find(|r| r.offset == 0)
                    .map(|r| r.data.clone())
                    .ok_or("the image has no MBR")?;
                let e = 446 + (p.number as usize - 1) * 16;
                let first = u32::from_le_bytes(mbr[e + 8..e + 12].try_into().unwrap()) as u64;
                if first * ss != p.start {
                    return Err(format!(
                        "MBR entry {} does not match partition {}",
                        p.number, p.number
                    ));
                }
                let sectors = (new_length / ss).min(u32::MAX as u64) as u32;
                mbr[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
                self.mbr_patch = Some(mbr);
            }
            Scheme::None => return Ok(None),
        }
        let g = Grown {
            number: p.number,
            start: p.start,
            old_length: p.length,
            new_length,
            filesystem: fs,
            windows_number: t
                .partitions
                .iter()
                .filter(|x| x.role != PartitionRole::Extended && x.number <= p.number)
                .count() as u32,
        };
        self.grown = Some(g.clone());
        Ok(Some(g))
    }

    /// After the image is written: put the partition table in order for the
    /// target's size.
    pub fn finish(&self, t: &dyn WriteTarget) -> io::Result<()> {
        if let Some(m) = &self.mbr_patch {
            t.write_at(0, m)?;
            return t.sync();
        }
        let Some(g) = &self.gpt else {
            return Ok(());
        };
        let ss = self.sector;
        let es = g.entries.len() as u64 / ss;
        let last = self.target_size / ss - 1;
        let backup_elba = last - es;
        let last_usable = backup_elba - 1;

        let mut mbr = g.mbr.clone();
        for i in 0..4 {
            let e = 446 + i * 16;
            if mbr[e + 4] == 0xEE {
                let first = u32::from_le_bytes(mbr[e + 8..e + 12].try_into().unwrap()) as u64;
                let size = (last + 1 - first).min(u32::MAX as u64) as u32;
                mbr[e + 12..e + 16].copy_from_slice(&size.to_le_bytes());
            }
        }

        let header = |my: u64, alt: u64, elba: u64| {
            let mut h = g.header.clone();
            h[24..32].copy_from_slice(&my.to_le_bytes());
            h[32..40].copy_from_slice(&alt.to_le_bytes());
            h[48..56].copy_from_slice(&last_usable.to_le_bytes());
            h[72..80].copy_from_slice(&elba.to_le_bytes());
            let hsize = u32::from_le_bytes(h[12..16].try_into().unwrap()) as usize;
            h[16..20].fill(0);
            let crc = crc32fast::hash(&h[..hsize]);
            h[16..20].copy_from_slice(&crc.to_le_bytes());
            h
        };

        // Zero the old backup first: it may overlap where the new one goes
        // only when the size is unchanged, in which case it is rewritten
        // below anyway.
        let new_area = Extent(backup_elba * ss, (es + 1) * ss);
        for s in &g.stale {
            if s.0 + s.1 <= self.target_size && s.0 + s.1 <= new_area.0 {
                t.write_at(s.0, &vec![0u8; s.1 as usize])?;
            }
        }
        t.write_at(0, &mbr)?;
        t.write_at(ss, &header(1, last, g.primary_entries_lba))?;
        t.write_at(g.primary_entries_lba * ss, &g.entries)?;
        t.write_at(backup_elba * ss, &g.entries)?;
        t.write_at(last * ss, &header(last, 1, backup_elba))?;
        t.sync()
    }
}

/// A target that ignores writes at or past `limit`.
pub struct Clipped<'a> {
    pub inner: &'a dyn WriteTarget,
    pub limit: u64,
}

impl WriteTarget for Clipped<'_> {
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if offset >= self.limit {
            return Ok(());
        }
        let n = data.len().min((self.limit - offset) as usize);
        self.inner.write_at(offset, &data[..n])
    }
    fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn logical_sector_size(&self) -> Option<u32> {
        self.inner.logical_sector_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_format::io::ReadAt;
    use core_format::partition::testutil::{write_gpt, write_mbr, GptPart};
    use core_format::partition::{gpt_types, read_table};
    use std::sync::Mutex;
    use uuid::Uuid;

    struct Mem(Mutex<Vec<u8>>);
    impl WriteTarget for Mem {
        fn size(&self) -> u64 {
            self.0.lock().unwrap().len() as u64
        }
        fn write_at(&self, o: u64, d: &[u8]) -> io::Result<()> {
            let mut v = self.0.lock().unwrap();
            if o as usize + d.len() > v.len() {
                return Err(io::Error::other("write past end"));
            }
            v[o as usize..o as usize + d.len()].copy_from_slice(d);
            Ok(())
        }
        fn sync(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "mem".into()
        }
    }
    struct Bytes<'a>(&'a [u8]);
    impl ReadAt for Bytes<'_> {
        fn read_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
            b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
            Ok(())
        }
    }

    const MIB: u64 = 1 << 20;

    /// A GPT disk of `size` with partitions ending at `end` bytes.
    fn gpt_disk(size: u64, ss: usize, end: u64) -> (Vec<u8>, DiskImage) {
        let mut d = vec![0u8; size as usize];
        let lba = |b: u64| b / ss as u64;
        write_gpt(
            &mut d,
            ss,
            Uuid::from_u128(7),
            &[
                GptPart {
                    type_guid: gpt_types::ESP,
                    first_lba: lba(MIB),
                    last_lba: lba(5 * MIB) - 1,
                    name: "EFI",
                },
                GptPart {
                    type_guid: gpt_types::BASIC_DATA,
                    first_lba: lba(5 * MIB),
                    last_lba: lba(end) - 1,
                    name: "data",
                },
            ],
        );
        // Recognisable data in the last partition.
        d[(end - 4096) as usize..end as usize].fill(0xAB);
        let table = read_table(&Bytes(&d), size, ss as u32).unwrap();
        let mut used: Vec<Extent> = table.raw_extents();
        used.push(Extent(MIB, end - MIB));
        let used = core_format::extent::normalize(used);
        (d, image(size, ss as u32, table, used))
    }

    fn image(
        size: u64,
        ss: u32,
        table: core_format::partition::PartitionTable,
        used: Vec<Extent>,
    ) -> DiskImage {
        DiskImage {
            index: 0,
            size,
            logical_sector_size: ss,
            physical_sector_size: ss,
            model: String::new(),
            serial: String::new(),
            device: String::new(),
            partition_table: table,
            partitions: vec![],
            used_extents: used,
            chunks: vec![],
        }
    }

    /// What restore does: copy the used extents, clipped, then finish.
    fn restore(src: &[u8], img: &DiskImage, target_size: u64) -> Result<Vec<u8>> {
        let f = plan(img, target_size, Some(img.partition_table.sector_size))?;
        let t = Mem(Mutex::new(vec![0x5Au8; target_size as usize]));
        let c = Clipped {
            inner: &t,
            limit: f.clip(),
        };
        for e in &img.used_extents {
            c.write_at(e.0, &src[e.0 as usize..(e.0 + e.1) as usize])
                .unwrap();
        }
        f.finish(&t).unwrap();
        Ok(t.0.into_inner().unwrap())
    }

    #[test]
    fn grows_gpt_to_a_larger_disk() {
        for ss in [512usize, 4096] {
            let (src, img) = gpt_disk(64 * MIB, ss, 60 * MIB);
            let out = restore(&src, &img, 100 * MIB).unwrap();
            let t = read_table(&Bytes(&out), 100 * MIB, ss as u32).unwrap();
            assert!(t.backup_table_valid, "backup GPT at the new end ({ss})");
            assert_eq!(t.partitions, img.partition_table.partitions);
            assert_eq!(t.disk_guid, img.partition_table.disk_guid);
            let last = 100 * MIB / ss as u64 - 1;
            assert_eq!(t.last_usable_lba, Some(last - 16384 / ss as u64 - 1));
            // The old backup header is gone, the data is intact.
            let old = (64 * MIB - ss as u64) as usize;
            assert!(out[old..old + ss].iter().all(|&b| b == 0));
            assert!(out[(60 * MIB - 4096) as usize..(60 * MIB) as usize]
                .iter()
                .all(|&b| b == 0xAB));
            // Protective MBR covers the new disk.
            let pm = u32::from_le_bytes(out[458..462].try_into().unwrap()) as u64;
            assert_eq!(pm, last);
        }
    }

    #[test]
    fn shrinks_gpt_when_the_partitions_fit() {
        let (src, img) = gpt_disk(64 * MIB, 512, 40 * MIB);
        let out = restore(&src, &img, 48 * MIB).unwrap();
        let t = read_table(&Bytes(&out), 48 * MIB, 512).unwrap();
        assert!(t.backup_table_valid);
        assert_eq!(t.partitions, img.partition_table.partitions);
        assert!(out[(40 * MIB - 4096) as usize..(40 * MIB) as usize]
            .iter()
            .all(|&b| b == 0xAB));
    }

    #[test]
    fn same_size_is_unchanged() {
        let (src, img) = gpt_disk(64 * MIB, 512, 60 * MIB);
        let out = restore(&src, &img, 64 * MIB).unwrap();
        for e in &img.used_extents {
            assert_eq!(
                &out[e.0 as usize..(e.0 + e.1) as usize],
                &src[e.0 as usize..(e.0 + e.1) as usize]
            );
        }
    }

    #[test]
    fn refuses_when_partitions_do_not_fit() {
        let (_, img) = gpt_disk(64 * MIB, 512, 60 * MIB);
        let e = plan(&img, 60 * MIB, Some(512)).unwrap_err().to_string();
        assert!(e.contains("need"), "{e}");
    }

    #[test]
    fn refuses_a_different_sector_size() {
        let (_, img) = gpt_disk(64 * MIB, 512, 60 * MIB);
        assert!(plan(&img, 128 * MIB, Some(4096)).is_err());
        assert!(plan(&img, 128 * MIB, None).is_ok());
    }

    #[test]
    fn min_size_is_the_smallest_that_plans() {
        let (_, img) = gpt_disk(64 * MIB, 512, 40 * MIB);
        let m = min_size(&img);
        assert!(plan(&img, m, Some(512)).is_ok());
        assert!(plan(&img, m - 512, Some(512)).is_err());
    }

    #[test]
    fn mbr_disks_fit_by_partition_end() {
        let mut d = vec![0u8; (64 * MIB) as usize];
        write_mbr(&mut d, 0x1234, &[(0x07, 2048, 30 * 2048, true)]);
        let table = read_table(&Bytes(&d), 64 * MIB, 512).unwrap();
        let used = vec![Extent(0, 31 * MIB)];
        let img = image(64 * MIB, 512, table, used);
        let out = restore(&d, &img, 32 * MIB).unwrap();
        assert_eq!(&out[..512], &d[..512]);
        assert!(plan(&img, 16 * MIB, Some(512)).is_err());
        assert!(plan(&img, 1 << 30, Some(512)).is_ok());
    }

    #[test]
    fn unpartitioned_disks_never_shrink() {
        let table = read_table(&Bytes(&vec![0u8; 4096]), 4096, 512).unwrap();
        let img = image(64 * MIB, 512, table, vec![Extent(0, MIB)]);
        assert!(plan(&img, 32 * MIB, Some(512)).is_err());
        assert!(plan(&img, 64 * MIB, Some(512)).is_ok());
    }

    fn with_fs(mut img: DiskImage, fs: FsType) -> DiskImage {
        img.partitions = img
            .partition_table
            .partitions
            .iter()
            .map(|e| core_format::manifest::PartitionRecord {
                entry: e.clone(),
                filesystem: if e.number == 1 { FsType::Fat32 } else { fs },
                capture: core_format::manifest::CaptureMethod::RawFull,
                captured_bytes: e.length,
                volume: None,
                mount_points: vec![],
                encryption: None,
            })
            .collect();
        img
    }

    fn grow_restore(src: &[u8], img: &DiskImage, target_size: u64) -> (Vec<u8>, Option<Grown>) {
        let mut f = plan(img, target_size, Some(img.partition_table.sector_size)).unwrap();
        let g = f.grow(img).unwrap();
        let t = Mem(Mutex::new(vec![0x5Au8; target_size as usize]));
        let c = Clipped {
            inner: &t,
            limit: f.clip(),
        };
        for e in &img.used_extents {
            c.write_at(e.0, &src[e.0 as usize..(e.0 + e.1) as usize])
                .unwrap();
        }
        f.finish(&t).unwrap();
        (t.0.into_inner().unwrap(), g)
    }

    #[test]
    fn grow_gives_the_last_gpt_partition_the_new_space() {
        for ss in [512usize, 4096] {
            let (src, img) = gpt_disk(64 * MIB, ss, 60 * MIB);
            let img = with_fs(img, FsType::Ntfs);
            let (out, g) = grow_restore(&src, &img, 100 * MIB + 12345 / ss as u64 * ss as u64);
            let g = g.expect("grown");
            assert_eq!((g.number, g.old_length), (2, 55 * MIB));
            // Up to the last whole MiB before the backup entries.
            assert_eq!(g.start + g.new_length, 99 * MIB);
            // The table read back is valid (both headers, entry CRCs) and says so.
            let t = read_table(&Bytes(&out), out.len() as u64, ss as u32).unwrap();
            assert!(t.backup_table_valid, "{ss}");
            assert_eq!(t.partitions[1].length, g.new_length);
            assert_eq!(t.partitions[0], img.partition_table.partitions[0]);
            assert!(out[(60 * MIB - 4096) as usize..(60 * MIB) as usize]
                .iter()
                .all(|&b| b == 0xAB));
        }
    }

    #[test]
    fn grow_leaves_file_systems_that_cannot_grow() {
        let (_, img) = gpt_disk(64 * MIB, 512, 60 * MIB);
        for fs in [
            FsType::Fat32,
            FsType::Swap,
            FsType::Bitlocker,
            FsType::Unknown,
        ] {
            let img = with_fs(img.clone(), fs);
            let mut f = plan(&img, 128 * MIB, Some(512)).unwrap();
            assert!(f.grow(&img).is_err(), "{fs:?}");
            assert!(f.grown().is_none());
        }
        // Nothing to gain: the partition already ends at the last whole MiB.
        let (_, img) = gpt_disk(64 * MIB, 512, 63 * MIB);
        let img = with_fs(img, FsType::Ext);
        let mut f = plan(&img, 64 * MIB, Some(512)).unwrap();
        assert_eq!(f.grow(&img).unwrap(), None);
    }

    #[test]
    fn grow_mbr_primary_partition() {
        let size = 64 * MIB;
        let mut d = vec![0u8; size as usize];
        let s = |b: u64| (b / 512) as u32;
        write_mbr(
            &mut d,
            0x1234,
            &[
                (0x0C, s(MIB), s(4 * MIB), true),
                (0x83, s(5 * MIB), s(50 * MIB), false),
            ],
        );
        d[(55 * MIB - 512) as usize..(55 * MIB) as usize].fill(0xCD);
        let table = read_table(&Bytes(&d), size, 512).unwrap();
        let mut used = table.raw_extents();
        used.push(Extent(MIB, 54 * MIB));
        let img = with_fs(
            image(size, 512, table, core_format::extent::normalize(used)),
            FsType::Ext,
        );
        let (out, g) = grow_restore(&d, &img, 200 * MIB + 512);
        let g = g.unwrap();
        assert_eq!(g.start + g.new_length, 200 * MIB);
        let t = read_table(&Bytes(&out), out.len() as u64, 512).unwrap();
        assert_eq!(t.partitions[1].length, 195 * MIB);
        assert_eq!(t.partitions[0], img.partition_table.partitions[0]);
        assert_eq!(
            &out[440..444],
            &0x1234u32.to_le_bytes(),
            "disk signature kept"
        );
        assert!(out[(55 * MIB - 512) as usize..(55 * MIB) as usize]
            .iter()
            .all(|&b| b == 0xCD));
    }
}
