//! A disk assembled from the raw device plus overlays: byte ranges of the
//! disk served by something else (a VSS or LVM snapshot device, a copy taken
//! while the file system was frozen, zeros). Everything else is read from
//! the raw disk. Used by the Windows and Linux live sources.

use std::io;
use std::sync::Arc;

use crate::{CapturePlan, DiskInfo, DiskSource};
use core_format::io::ReadAt;
use core_format::partition::PartitionTable;

pub type SharedReader = Arc<dyn ReadAt + Send + Sync>;

/// `head` followed by zeros, without end: an in-memory copy (a metadata area
/// read before a snapshot existed), a swap area reduced to its header, or
/// plain zeros (an empty head).
pub struct HeadThenZeros(pub Vec<u8>);

impl ReadAt for HeadThenZeros {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        buf.fill(0);
        let len = self.0.len() as u64;
        if offset < len {
            let n = ((len - offset) as usize).min(buf.len());
            buf[..n].copy_from_slice(&self.0[offset as usize..offset as usize + n]);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Overlay {
    /// Absolute disk offset where the partition starts.
    pub start: u64,
    pub len: u64,
    /// Bytes the snapshot device holds (at most `len`). A volume is often
    /// shorter than its partition (NTFS keeps its backup boot sector in the
    /// partition's last sector, outside the volume); the rest of the
    /// partition is read from the raw disk.
    pub device_len: u64,
    /// Snapshot device; offset `device_base` = `start`.
    pub device: SharedReader,
    /// Offset in `device` that corresponds to `start` (0 for a partition
    /// snapshot; the segment's offset in the logical volume for LVM).
    pub device_base: u64,
    /// The snapshot serves a decrypted view of an encrypted volume
    /// (BitLocker). The partition tail past `device_len` is then not read
    /// from the disk, which holds ciphertext there: its first 512 bytes are
    /// a copy of the decrypted boot sector (NTFS keeps its backup boot
    /// sector there) and the rest is zeros.
    pub decrypted: bool,
}

pub struct CompositeDisk {
    pub info: DiskInfo,
    pub raw: SharedReader,
    overlays: Vec<Overlay>,
    pub plan: CapturePlan,
}

impl CompositeDisk {
    pub fn new(
        info: DiskInfo,
        raw: SharedReader,
        mut overlays: Vec<Overlay>,
        plan: CapturePlan,
    ) -> io::Result<Self> {
        overlays.sort_by_key(|o| o.start);
        for w in overlays.windows(2) {
            if w[0].start + w[0].len > w[1].start {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "overlapping snapshot overlays",
                ));
            }
        }
        Ok(CompositeDisk {
            info,
            raw,
            overlays,
            plan,
        })
    }
}

impl DiskSource for CompositeDisk {
    fn info(&self) -> DiskInfo {
        self.info.clone()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut pos = offset;
        let end = offset + buf.len() as u64;
        while pos < end {
            let done = (pos - offset) as usize;
            // Overlay containing pos, or the next overlay after pos.
            let cur = self
                .overlays
                .iter()
                .find(|o| pos >= o.start && pos < o.start + o.device_len.min(o.len));
            let (stop, dev, dev_off): (u64, &SharedReader, u64) = match cur {
                Some(o) => (
                    (o.start + o.device_len.min(o.len)).min(end),
                    &o.device,
                    o.device_base + (pos - o.start),
                ),
                None => {
                    let next = self
                        .overlays
                        .iter()
                        .filter(|o| o.start > pos)
                        .map(|o| o.start)
                        .min()
                        .unwrap_or(u64::MAX);
                    (next.min(end), &self.raw, pos)
                }
            };
            // Tail of a decrypted volume's partition: synthesised.
            if cur.is_none() {
                if let Some(o) = self.overlays.iter().find(|o| {
                    o.decrypted && pos >= o.start + o.device_len.min(o.len) && pos < o.start + o.len
                }) {
                    let tail = o.start + o.device_len.min(o.len);
                    let stop = (o.start + o.len).min(end);
                    let out = &mut buf[done..done + (stop - pos) as usize];
                    out.fill(0);
                    // Overlap with [tail, tail + 512): the boot sector copy.
                    let (s, e) = (pos.max(tail), stop.min(tail + 512));
                    if s < e {
                        let mut boot = [0u8; 512];
                        o.device.read_at(o.device_base, &mut boot)?;
                        out[(s - pos) as usize..(e - pos) as usize]
                            .copy_from_slice(&boot[(s - tail) as usize..(e - tail) as usize]);
                    }
                    pos = stop;
                    continue;
                }
            }
            let n = (stop - pos) as usize;
            dev.read_at(dev_off, &mut buf[done..done + n]).map_err(|e| {
                let what = match cur {
                    Some(o) => format!(
                        "snapshot of the partition at {} (partition {} bytes, snapshot device {} bytes)",
                        o.start, o.len, o.device_len
                    ),
                    None => format!("raw disk ({} bytes)", self.info.size),
                };
                io::Error::new(
                    e.kind(),
                    format!("{e}: reading {n} bytes at {dev_off} of the {what}"),
                )
            })?;
            pos = stop;
        }
        Ok(())
    }

    fn capture_plan(&self, _table: &PartitionTable) -> io::Result<CapturePlan> {
        Ok(self.plan.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_reads_across_boundaries() {
        let raw: SharedReader = Arc::new(vec![b'r'; 100]);
        let snap_a: SharedReader = Arc::new((0..20u8).collect::<Vec<u8>>());
        let snap_b: SharedReader = Arc::new(vec![b'b'; 10]);
        let d = CompositeDisk::new(
            DiskInfo {
                size: 100,
                ..Default::default()
            },
            raw,
            vec![
                Overlay {
                    start: 60,
                    len: 10,
                    device_len: 10,
                    device: snap_b,
                    device_base: 0,
                    decrypted: false,
                },
                Overlay {
                    start: 10,
                    len: 20,
                    device_len: 20,
                    device: snap_a,
                    device_base: 0,
                    decrypted: false,
                },
            ],
            CapturePlan::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 100];
        d.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..10], &[b'r'; 10]);
        assert_eq!(&buf[10..30], &(0..20u8).collect::<Vec<u8>>()[..]);
        assert_eq!(&buf[30..60], &[b'r'; 30]);
        assert_eq!(&buf[60..70], &[b'b'; 10]);
        assert_eq!(&buf[70..], &[b'r'; 30]);
        let mut small = [0u8; 4];
        d.read_at(28, &mut small).unwrap();
        assert_eq!(small, [18, 19, b'r', b'r']);
    }

    #[test]
    fn rejects_overlapping_overlays() {
        let r: SharedReader = Arc::new(vec![0u8; 10]);
        let o = |s| Overlay {
            start: s,
            len: 5,
            device_len: 5,
            device: r.clone(),
            device_base: 0,
            decrypted: false,
        };
        assert!(CompositeDisk::new(
            DiskInfo::default(),
            r.clone(),
            vec![o(0), o(3)],
            CapturePlan::default()
        )
        .is_err());
    }

    #[test]
    fn partition_tail_beyond_the_snapshot_volume_comes_from_the_disk() {
        // Partition 10..30, but the snapshot volume is 15 bytes long (NTFS:
        // the backup boot sector lies after the volume). The snapshot
        // device itself ends there: reading past it would fail.
        let raw: SharedReader = Arc::new(vec![b'r'; 40]);
        let snap: SharedReader = Arc::new(vec![b's'; 15]);
        let d = CompositeDisk::new(
            DiskInfo {
                size: 40,
                ..Default::default()
            },
            raw,
            vec![Overlay {
                start: 10,
                len: 20,
                device_len: 15,
                device: snap,
                device_base: 0,
                decrypted: false,
            }],
            CapturePlan::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 40];
        d.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..10], &[b'r'; 10]);
        assert_eq!(&buf[10..25], &[b's'; 15]);
        assert_eq!(&buf[25..], &[b'r'; 15], "partition tail from the disk");
        // The probe that failed on Windows: the last bytes of the partition.
        let mut tail = [0u8; 4];
        d.read_at(26, &mut tail).unwrap();
        assert_eq!(tail, [b'r'; 4]);
    }

    #[test]
    fn decrypted_volume_tail_is_a_boot_sector_copy_and_zeros() {
        // BitLocker: the disk holds ciphertext ('x'); the snapshot is the
        // decrypted NTFS volume. Partition 1024..4096, volume 2048 bytes.
        let raw: SharedReader = Arc::new(vec![b'x'; 5000]);
        let mut vol = vec![b'v'; 2048];
        vol[..3].copy_from_slice(b"NTF");
        let snap: SharedReader = Arc::new(vol);
        let d = CompositeDisk::new(
            DiskInfo {
                size: 5000,
                ..Default::default()
            },
            raw,
            vec![Overlay {
                start: 1024,
                len: 3072,
                device_len: 2048,
                device: snap,
                device_base: 0,
                decrypted: true,
            }],
            CapturePlan::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 5000];
        d.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..1024], &[b'x'; 1024][..]);
        assert_eq!(&buf[1024..1027], b"NTF");
        let tail = 1024 + 2048;
        assert_eq!(&buf[tail..tail + 3], b"NTF", "backup boot sector");
        assert_eq!(&buf[tail + 3..tail + 512], &vec![b'v'; 509][..]);
        assert!(
            buf[tail + 512..4096].iter().all(|&b| b == 0),
            "no ciphertext"
        );
        assert_eq!(
            &buf[4096..],
            &[b'x'; 904][..],
            "after the partition: the disk"
        );
        // A read starting inside the boot sector copy.
        let mut part = [0u8; 4];
        d.read_at(tail as u64 + 1, &mut part).unwrap();
        assert_eq!(&part, b"TFvv");
    }

    #[test]
    fn device_base_maps_a_segment_into_its_volume() {
        // An LVM segment: disk 100..140 is offset 1000..1040 of the snapshot.
        let raw: SharedReader = Arc::new(vec![b'r'; 200]);
        let lv: SharedReader = Arc::new((0..2000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        let meta: SharedReader = Arc::new(HeadThenZeros(vec![b'm'; 8]));
        let d = CompositeDisk::new(
            DiskInfo {
                size: 200,
                ..Default::default()
            },
            raw,
            vec![
                Overlay {
                    start: 100,
                    len: 40,
                    device_len: 40,
                    device: lv,
                    device_base: 1000,
                    decrypted: false,
                },
                Overlay {
                    start: 0,
                    len: 16,
                    device_len: 16,
                    device: meta,
                    device_base: 0,
                    decrypted: false,
                },
            ],
            CapturePlan::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 200];
        d.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..8], &[b'm'; 8]);
        assert_eq!(&buf[8..16], &[0; 8], "head, then zeros");
        assert_eq!(&buf[16..100], &[b'r'; 84][..]);
        let want: Vec<u8> = (1000..1040u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(&buf[100..140], &want[..]);
        assert_eq!(&buf[140..], &[b'r'; 60][..]);
    }
}
