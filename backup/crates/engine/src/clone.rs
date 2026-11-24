//! Copy a disk straight onto another, without a repository
//! (phase-5-grow-clone.md §2). The backup planning decides what to copy
//! (partition tables, used extents); the restore steps lay it onto the
//! target (fit, GPT move, grow).

use std::sync::atomic::{AtomicU64, Ordering};

use core_format::extent;
use core_format::manifest::DiskImage;
use serde::Serialize;

use crate::fit::{Clipped, Grown};
use crate::{DiskSource, EngineError, JobControl, Result, WriteTarget};

#[derive(Debug, Clone, Default)]
pub struct CloneOptions {
    /// The target may be a different size (see `RestoreOptions::fit`).
    pub fit: bool,
    /// Give a larger target's extra space to the last partition.
    pub grow: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloneReport {
    pub source: String,
    pub target: String,
    pub source_size: u64,
    pub target_size: u64,
    pub bytes_copied: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grown: Option<Grown>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// What would be copied: the disk as a backup would describe it (no chunks).
pub fn describe(src: &dyn DiskSource) -> Result<DiskImage> {
    let p = crate::backup::plan_image(&[src])?
        .pop()
        .ok_or_else(|| EngineError::InvalidInput("no disk".into()))?;
    Ok(DiskImage {
        index: 0,
        size: p.info.size,
        logical_sector_size: p.sector_size,
        physical_sector_size: p.info.physical_sector_size.max(p.sector_size),
        model: p.info.model,
        serial: p.info.serial,
        device: p.info.device,
        partition_table: p.table,
        partitions: p.layout.partitions,
        used_extents: p.layout.used,
        chunks: vec![],
    })
}

/// Copy `src` onto `target`. Returns the description used, for the boot
/// loader fix-up afterwards.
pub fn clone_disk(
    src: &dyn DiskSource,
    target: &dyn WriteTarget,
    opts: &CloneOptions,
    ctl: &JobControl,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<(CloneReport, DiskImage)> {
    let disk = describe(src)?;
    let mut notes = Vec::new();
    let fit = if opts.fit || opts.grow {
        let mut f = crate::fit::plan(&disk, target.size(), target.logical_sector_size())?;
        if opts.grow {
            match f.grow(&disk) {
                Ok(Some(_)) => {}
                Ok(None) => notes.push(
                    "nothing to grow: the last partition already reaches the end of the target"
                        .into(),
                ),
                Err(e) => notes.push(e),
            }
        }
        Some(f)
    } else {
        if target.size() < disk.size {
            return Err(EngineError::Safety(format!(
                "target is {} bytes, the source disk {} bytes (use fit to clone onto a smaller disk the partitions fit on)",
                target.size(),
                disk.size
            )));
        }
        None
    };
    let clipped = Clipped {
        inner: target,
        limit: fit.as_ref().map_or(u64::MAX, |f| f.clip()),
    };
    let total = extent::total_len(&disk.used_extents);
    let done = AtomicU64::new(0);
    let mut buf = vec![0u8; 4 << 20];
    for e in &disk.used_extents {
        let mut pos = e.0;
        while pos < e.0 + e.1 {
            if !ctl.checkpoint() {
                return Err(EngineError::Cancelled);
            }
            let n = (e.0 + e.1 - pos).min(buf.len() as u64) as usize;
            src.read_at(pos, &mut buf[..n])?;
            clipped.write_at(pos, &buf[..n])?;
            pos += n as u64;
            let d = done.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
            progress(d, total);
        }
    }
    target.sync()?;
    if let Some(f) = &fit {
        f.finish(target)?;
    }
    let report = CloneReport {
        source: src.info().device,
        target: target.describe(),
        source_size: disk.size,
        target_size: target.size(),
        bytes_copied: done.load(Ordering::Relaxed),
        grown: fit.as_ref().and_then(|f| f.grown().cloned()),
        notes,
    };
    Ok((report, disk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReadAtSource;
    use core_format::extent::Extent;
    use core_format::partition::testutil::{write_gpt, GptPart};
    use core_format::partition::{gpt_types, read_table};
    use std::io;
    use std::sync::Mutex;

    const MIB: u64 = 1 << 20;

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

    /// A GPT disk whose second partition holds an ext4 superblock (so it may
    /// grow) and a recognisable pattern.
    fn source() -> Vec<u8> {
        let size = 64 * MIB;
        let mut d = vec![0u8; size as usize];
        write_gpt(
            &mut d,
            512,
            uuid::Uuid::from_u128(9),
            &[
                GptPart {
                    type_guid: gpt_types::ESP,
                    first_lba: 2048,
                    last_lba: 10 * 2048 - 1,
                    name: "EFI",
                },
                GptPart {
                    type_guid: gpt_types::LINUX_FS,
                    first_lba: 10 * 2048,
                    last_lba: 60 * 2048 - 1,
                    name: "root",
                },
            ],
        );
        let p = (10 * MIB) as usize;
        // ext2/3/4 superblock magic at 1024 + 56.
        d[p + 1024 + 56..p + 1024 + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
        for (i, b) in d[p + 4096..p + 8 * MIB as usize].iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        d
    }

    #[test]
    fn clones_onto_a_larger_disk_and_grows_the_last_partition() {
        let src = source();
        let s = ReadAtSource {
            inner: src.clone(),
            info: crate::DiskInfo {
                size: src.len() as u64,
                logical_sector_size: 512,
                device: "src".into(),
                ..Default::default()
            },
        };
        let t = Mem(Mutex::new(vec![0x77u8; (128 * MIB) as usize]));
        let (r, disk) = clone_disk(
            &s,
            &t,
            &CloneOptions {
                fit: true,
                grow: true,
            },
            &JobControl::new(),
            &|_, _| {},
        )
        .unwrap();
        let g = r.grown.expect("grown");
        assert_eq!(g.number, 2);
        assert_eq!(g.start + g.new_length, 127 * MIB);
        assert_eq!(r.bytes_copied, extent::total_len(&disk.used_extents));
        let out = t.0.into_inner().unwrap();
        let table = read_table(&out, out.len() as u64, 512).unwrap();
        assert!(table.backup_table_valid);
        assert_eq!(table.partitions[1].length, g.new_length);
        // The partitions' contents are the source's.
        for e in [Extent(MIB, 9 * MIB), Extent(10 * MIB, 50 * MIB)] {
            for u in extent::clip(&disk.used_extents, e) {
                assert_eq!(
                    &out[u.0 as usize..(u.0 + u.1) as usize],
                    &src[u.0 as usize..(u.0 + u.1) as usize]
                );
            }
        }
    }

    #[test]
    fn refuses_a_smaller_disk_without_fit() {
        let src = source();
        let s = ReadAtSource {
            inner: src.clone(),
            info: crate::DiskInfo {
                size: src.len() as u64,
                logical_sector_size: 512,
                ..Default::default()
            },
        };
        let t = Mem(Mutex::new(vec![0u8; (62 * MIB) as usize]));
        let e = clone_disk(
            &s,
            &t,
            &CloneOptions::default(),
            &JobControl::new(),
            &|_, _| {},
        );
        assert!(matches!(e, Err(EngineError::Safety(_))));
        // With fit it goes: the partitions end at 60 MiB.
        let (r, _) = clone_disk(
            &s,
            &t,
            &CloneOptions {
                fit: true,
                grow: false,
            },
            &JobControl::new(),
            &|_, _| {},
        )
        .unwrap();
        assert!(r.grown.is_none());
    }
}
