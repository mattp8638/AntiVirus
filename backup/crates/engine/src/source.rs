//! What the engine reads from: a whole disk, plus optional knowledge about
//! which parts of it matter.

use std::io;

use core_format::extent::Extent;
use core_format::fsdetect::FsType;
use core_format::manifest::{CaptureMethod, ExcludedFile};
use core_format::partition::PartitionTable;

#[derive(Debug, Clone, Default)]
pub struct DiskInfo {
    pub size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub model: String,
    pub serial: String,
    /// OS path, e.g. `\\.\PhysicalDrive0` or `/dev/nvme0n1`.
    pub device: String,
}

/// How to capture one partition. Produced by a snapshot provider.
#[derive(Debug, Clone)]
pub struct PartitionPlan {
    /// Partition number as in the partition table.
    pub number: u32,
    /// Absolute disk byte ranges to capture. `None` = the whole partition.
    pub used: Option<Vec<Extent>>,
    pub capture: CaptureMethod,
    pub filesystem: Option<FsType>,
    pub volume: Option<String>,
    pub mount_points: Vec<String>,
    pub encryption: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CapturePlan {
    pub partitions: Vec<PartitionPlan>,
    pub excluded: Vec<ExcludedFile>,
    pub warnings: Vec<String>,
}

/// A readable disk. Reads are positional and must be safe to call from
/// several threads (the engine reads from one thread today, but sources
/// must not rely on that).
pub trait DiskSource: Send + Sync {
    fn info(&self) -> DiskInfo;

    /// Read exactly `buf.len()` bytes at absolute disk offset `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Capture plan for the partitions in `table`. The default captures
    /// every partition in full from the raw disk.
    fn capture_plan(&self, _table: &PartitionTable) -> io::Result<CapturePlan> {
        Ok(CapturePlan::default())
    }

    /// Byte ranges that hold data at all (thin/sparse sources such as
    /// virtual disks). Everything outside reads as zeros and is never read.
    /// `None` = everything may hold data.
    fn allocated_extents(&self) -> io::Result<Option<Vec<core_format::extent::Extent>>> {
        Ok(None)
    }
}

/// Adapter so partition parsing can read from a `DiskSource`.
pub(crate) struct SourceReader<'a>(pub &'a dyn DiskSource);

impl core_format::io::ReadAt for SourceReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_at(offset, buf)
    }
}

/// A disk held in memory or a raw image file; used by tests and for
/// imaging unmounted devices. Captures everything in full.
pub struct ReadAtSource<R: core_format::io::ReadAt + Send + Sync> {
    pub inner: R,
    pub info: DiskInfo,
}

impl<R: core_format::io::ReadAt + Send + Sync> DiskSource for ReadAtSource<R> {
    fn info(&self) -> DiskInfo {
        self.info.clone()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(offset, buf)
    }
}
