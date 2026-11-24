//! Read-only virtual disk formats as Fenrir-Backup image sources.

#![forbid(unsafe_code)]

mod crc32c;
pub mod vhdx;
pub mod writer;

#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

use std::io;
use std::path::Path;

use core_format::extent::Extent;
use core_format::io::ReadAt;
use engine::{DiskInfo, DiskSource};

pub use vhdx::{Vhdx, VhdxInfo};

/// A VHDX (and its parent chain) as an image source. Only allocated
/// blocks are read.
pub struct VhdxSource {
    disk: Vhdx,
    label: String,
}

impl VhdxSource {
    pub fn open(path: impl AsRef<Path>, label: impl Into<String>) -> io::Result<Self> {
        Ok(VhdxSource {
            disk: Vhdx::open(path)?,
            label: label.into(),
        })
    }

    pub fn vhdx(&self) -> &Vhdx {
        &self.disk
    }
}

impl DiskSource for VhdxSource {
    fn info(&self) -> DiskInfo {
        let i = self.disk.info();
        DiskInfo {
            size: i.virtual_size,
            logical_sector_size: i.logical_sector_size,
            physical_sector_size: i.physical_sector_size,
            model: "Hyper-V virtual disk (VHDX)".into(),
            serial: i.virtual_disk_id.to_string(),
            device: self.label.clone(),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.disk.read_at(offset, buf)
    }

    fn allocated_extents(&self) -> io::Result<Option<Vec<Extent>>> {
        Ok(Some(self.disk.allocated()))
    }
}

/// Restore target that writes a dynamic VHDX. Call `finish` afterwards.
pub struct VhdxTarget {
    writer: writer::VhdxWriter,
}

impl VhdxTarget {
    pub fn create(
        path: &Path,
        virtual_size: u64,
        logical_sector: u32,
        physical_sector: u32,
        chunk_size: u32,
    ) -> io::Result<Self> {
        let block = writer::DEFAULT_BLOCK_SIZE.max(chunk_size as u64);
        Ok(VhdxTarget {
            writer: writer::VhdxWriter::create(
                path,
                virtual_size,
                logical_sector,
                physical_sector,
                block,
            )?,
        })
    }

    /// Write the block table; the file is a valid VHDX after this.
    pub fn finish(self) -> io::Result<u64> {
        self.writer.finish()
    }
}

impl engine::WriteTarget for VhdxTarget {
    fn size(&self) -> u64 {
        self.writer.virtual_size()
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.writer.write_at(offset, data)
    }
    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        self.writer.path().display().to_string()
    }
}
