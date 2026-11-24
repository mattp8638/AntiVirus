//! Virtual disk formats: VHDX as an image source, and restore targets in
//! the native formats of Hyper-V (VHDX), QEMU/KVM (qcow2), VirtualBox (VDI)
//! and VMware (VMDK).

#![forbid(unsafe_code)]

mod crc32c;
pub mod qcow2;
mod sparse;
pub mod vdi;
pub mod vhdx;
pub mod vmdk;
pub mod writer;

pub use sparse::VirtualDiskTarget;

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

impl VirtualDiskTarget for VhdxTarget {
    fn finish(self: Box<Self>) -> io::Result<u64> {
        self.writer.finish()
    }
}

/// A virtual disk file format to restore into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Hyper-V.
    Vhdx,
    /// QEMU/KVM, Proxmox, libvirt.
    Qcow2,
    /// VirtualBox.
    Vdi,
    /// VMware Workstation, Fusion, Player (ESXi after `vmkfstools -i`).
    Vmdk,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Vhdx => "vhdx",
            Format::Qcow2 => "qcow2",
            Format::Vdi => "vdi",
            Format::Vmdk => "vmdk",
        }
    }

    /// A new disk file (never overwrites) of `size` virtual bytes.
    pub fn create(
        self,
        path: &Path,
        size: u64,
        logical_sector: u32,
        physical_sector: u32,
        chunk_size: u32,
    ) -> io::Result<Box<dyn VirtualDiskTarget>> {
        // The other formats address 512-byte sectors.
        if self != Format::Vhdx && logical_sector != 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "this disk has {logical_sector}-byte sectors, which {} files cannot hold; restore it as VHDX",
                    self.extension()
                ),
            ));
        }
        Ok(match self {
            Format::Vhdx => Box::new(VhdxTarget::create(
                path,
                size,
                logical_sector,
                physical_sector,
                chunk_size,
            )?),
            Format::Qcow2 => Box::new(qcow2::Qcow2Target::create(path, size)?),
            Format::Vdi => Box::new(vdi::VdiTarget::create(path, size)?),
            Format::Vmdk => Box::new(vmdk::VmdkTarget::create(path, size)?),
        })
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;
    use std::process::Command;

    const MIB: u64 = 1024 * 1024;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) | 1)
            .collect()
    }

    /// Writes scattered data (some all-zero, some crossing block edges, from
    /// several threads), checks the file with `qemu-img check` where QEMU can,
    /// and compares it with the same writes to a raw file (`qemu-img compare`).
    /// Without qemu-img (it is installed in CI) only the writing is tested.
    fn roundtrip(format: Format, size: u64) {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(format!("disk.{}", format.extension()));
        let raw = d.path().join("disk.raw");
        let t = format
            .create(&path, size, 512, 4096, (4 * MIB) as u32)
            .unwrap();
        let rawf = std::fs::File::create(&raw).unwrap();
        rawf.set_len(size).unwrap();
        let writes: Vec<(u64, Vec<u8>)> = vec![
            (0, pattern(4096, 1)),
            (MIB - 512, pattern(8192, 2)), // across 64 KiB and 1 MiB edges
            (3 * MIB, vec![0u8; MIB as usize]), // zero: not allocated
            (5 * MIB + 7 * 512, pattern(200 * 1024, 3)),
            (size - 4096, pattern(4096, 4)), // the very end
            (40 * MIB, pattern(MIB as usize, 5)),
        ];
        std::thread::scope(|s| {
            for (off, data) in &writes {
                let t = &t;
                s.spawn(move || t.write_at(*off, data).unwrap());
            }
        });
        for (off, data) in &writes {
            sparse::write_at(&rawf, *off, data).unwrap();
        }
        assert!(t.write_at(size - 1, &[1, 2]).is_err(), "beyond the end");
        let allocated = t.finish().unwrap();
        assert!(allocated > 0);
        // A file is never overwritten.
        assert!(format
            .create(&path, size, 512, 4096, (4 * MIB) as u32)
            .is_err());

        let Ok(out) = Command::new("qemu-img").arg("--version").output() else {
            eprintln!("qemu-img not installed: format not checked");
            return;
        };
        assert!(out.status.success());
        let fmt = format.extension();
        let c = Command::new("qemu-img")
            .args(["check", "-f", fmt])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            c.status.success(),
            "qemu-img check: {}{}",
            String::from_utf8_lossy(&c.stdout),
            String::from_utf8_lossy(&c.stderr)
        );
        let info = Command::new("qemu-img")
            .args(["info", "--output=json", "-f", fmt])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            info.status.success(),
            "{}",
            String::from_utf8_lossy(&info.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(v["virtual-size"].as_u64(), Some(size), "{v}");
        let c = Command::new("qemu-img")
            .args(["compare", "-f", fmt, "-F", "raw"])
            .arg(&path)
            .arg(&raw)
            .output()
            .unwrap();
        assert!(
            c.status.success(),
            "qemu-img compare: {}{}",
            String::from_utf8_lossy(&c.stdout),
            String::from_utf8_lossy(&c.stderr)
        );
    }

    #[test]
    fn qcow2_is_read_back_by_qemu() {
        roundtrip(Format::Qcow2, 64 * MIB);
        // More than one L2 table (512 MiB each) and a size not a cluster multiple.
        roundtrip(Format::Qcow2, 1300 * MIB + 512);
    }

    #[test]
    fn vdi_is_read_back_by_qemu() {
        roundtrip(Format::Vdi, 64 * MIB);
        roundtrip(Format::Vdi, 100 * MIB + 512);
    }

    #[test]
    fn vmdk_is_read_back_by_qemu() {
        roundtrip(Format::Vmdk, 64 * MIB);
        // More than one grain table (32 MiB each) and a size not a grain multiple.
        roundtrip(Format::Vmdk, 100 * MIB + 512);
    }

    #[test]
    fn vhdx_through_the_same_entry_point() {
        roundtrip(Format::Vhdx, 64 * MIB);
    }

    #[test]
    fn sector_sizes_and_limits_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let e = Format::Qcow2.create(&d.path().join("a.qcow2"), 64 * MIB, 4096, 4096, 1 << 20);
        assert!(e.err().unwrap().to_string().contains("VHDX"));
        assert!(Format::Vmdk
            .create(&d.path().join("b.vmdk"), 3 << 40, 512, 512, 1 << 20)
            .is_err());
        assert!(Format::Vdi
            .create(&d.path().join("c.vdi"), 1000, 512, 512, 1 << 20)
            .is_err());
    }
}
