//! VMDK writer: a single growable file (`monolithicSparse`, hosted sparse
//! extent version 1), as VMware Workstation, Fusion and Player create, and
//! VirtualBox and QEMU read. Follows VMware's published Virtual Disk Format
//! 1.1 specification. ESXi uses another layout: copy the file to a datastore
//! and convert it there (`vmkfstools -i disk.vmdk -d thin new.vmdk`).
//!
//! Layout written (in 512-byte sectors):
//!
//! ```text
//! 0          sparse extent header
//! 1..21      embedded descriptor
//! 21..       redundant grain directory and its grain tables
//! then       grain directory and its grain tables
//! overhead   (64 KiB aligned) grains, appended as first written
//! ```
//!
//! Every grain table is allocated up front, as VMware does; their entries
//! are written at finish. A zero entry is a grain never written (it reads as
//! zero). The format addresses grains by 32-bit sector numbers, so a disk is
//! at most 2 TiB.

use std::io;
use std::path::Path;

use crate::sparse::{write_at, write_target_via_sparse, Sparse, VirtualDiskTarget};

const SECTOR: u64 = 512;
/// Grain size in sectors (64 KiB).
const GRAIN_SECTORS: u64 = 128;
const GRAIN: u64 = GRAIN_SECTORS * SECTOR;
const GTES_PER_GT: u64 = 512;
const DESCRIPTOR_OFFSET: u64 = 1;
const DESCRIPTOR_SECTORS: u64 = 20;
/// The largest disk: grain offsets (32-bit sectors) must also cover the
/// metadata in front of the grains.
pub const MAX_SIZE: u64 = 2 * 1024 * 1024 * 1024 * 1024 - 1024 * 1024 * 1024;

pub struct VmdkTarget {
    s: Sparse,
    num_gts: u64,
    rgd_offset: u64,
    gd_offset: u64,
}

fn sectors(bytes: u64) -> u64 {
    bytes.div_ceil(SECTOR)
}

/// The descriptor text for an extent file named `file_name`.
fn descriptor(size: u64, file_name: &str) -> String {
    let capacity = size / SECTOR;
    let cylinders = (capacity / (16 * 63)).clamp(1, 16383);
    format!(
        "# Disk DescriptorFile\nversion=1\nCID={:08x}\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\n\
         # Extent description\nRW {capacity} SPARSE \"{file_name}\"\n\n\
         # The Disk Data Base\n#DDB\n\n\
         ddb.virtualHWVersion = \"4\"\nddb.adapterType = \"lsilogic\"\n\
         ddb.geometry.cylinders = \"{cylinders}\"\nddb.geometry.heads = \"16\"\nddb.geometry.sectors = \"63\"\n",
        uuid::Uuid::new_v4().as_u128() as u32
    )
}

impl VmdkTarget {
    /// A new file (never overwrites) of `size` virtual bytes.
    pub fn create(path: &Path, size: u64) -> io::Result<Self> {
        if size == 0 || size % SECTOR != 0 || size > MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a VMDK must be a non-zero multiple of 512 bytes, at most 2 TiB",
            ));
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file name"))?;
        if file_name.contains('"') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "file name"));
        }
        let grains = size.div_ceil(GRAIN);
        let num_gts = grains.div_ceil(GTES_PER_GT);
        let gd_sectors = sectors(num_gts * 4);
        let gts_sectors = num_gts * sectors(GTES_PER_GT * 4);
        let rgd_offset = DESCRIPTOR_OFFSET + DESCRIPTOR_SECTORS;
        let gd_offset = rgd_offset + gd_sectors + gts_sectors;
        let overhead =
            (gd_offset + gd_sectors + gts_sectors).div_ceil(GRAIN_SECTORS) * GRAIN_SECTORS;
        let s = Sparse::create(path, size, GRAIN, overhead * SECTOR)?;

        let mut h = vec![0u8; SECTOR as usize];
        h[0..4].copy_from_slice(b"KDMV");
        h[4..8].copy_from_slice(&1u32.to_le_bytes());
        // valid newline detection, redundant grain table in use
        h[8..12].copy_from_slice(&3u32.to_le_bytes());
        h[12..20].copy_from_slice(&(size / SECTOR).to_le_bytes());
        h[20..28].copy_from_slice(&GRAIN_SECTORS.to_le_bytes());
        h[28..36].copy_from_slice(&DESCRIPTOR_OFFSET.to_le_bytes());
        h[36..44].copy_from_slice(&DESCRIPTOR_SECTORS.to_le_bytes());
        h[44..48].copy_from_slice(&(GTES_PER_GT as u32).to_le_bytes());
        h[48..56].copy_from_slice(&rgd_offset.to_le_bytes());
        h[56..64].copy_from_slice(&gd_offset.to_le_bytes());
        h[64..72].copy_from_slice(&overhead.to_le_bytes());
        h[72] = 0; // clean
        h[73] = b'\n';
        h[74] = b' ';
        h[75] = b'\r';
        h[76] = b'\n';
        // compression 77..79: none
        write_at(&s.file, 0, &h)?;

        let d = descriptor(size, file_name);
        if d.len() as u64 > DESCRIPTOR_SECTORS * SECTOR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descriptor too long",
            ));
        }
        write_at(&s.file, DESCRIPTOR_OFFSET * SECTOR, d.as_bytes())?;

        // Both grain directories point at their (still empty) grain tables.
        for dir in [rgd_offset, gd_offset] {
            let first_gt = dir + gd_sectors;
            let gd: Vec<u8> = (0..num_gts)
                .flat_map(|i| ((first_gt + i * sectors(GTES_PER_GT * 4)) as u32).to_le_bytes())
                .collect();
            write_at(&s.file, dir * SECTOR, &gd)?;
        }
        Ok(VmdkTarget {
            s,
            num_gts,
            rgd_offset,
            gd_offset,
        })
    }
}

write_target_via_sparse!(VmdkTarget);

impl VirtualDiskTarget for VmdkTarget {
    fn finish(self: Box<Self>) -> io::Result<u64> {
        let (blocks, _) = self.s.blocks();
        let mut gts = vec![0u8; (self.num_gts * GTES_PER_GT * 4) as usize];
        let mut allocated = 0;
        for (i, &b) in blocks.iter().enumerate() {
            if b != 0 {
                gts[i * 4..i * 4 + 4].copy_from_slice(&((b / SECTOR) as u32).to_le_bytes());
                allocated += 1;
            }
        }
        let gd_sectors = sectors(self.num_gts * 4);
        for dir in [self.rgd_offset, self.gd_offset] {
            write_at(&self.s.file, (dir + gd_sectors) * SECTOR, &gts)?;
        }
        self.s.file.sync_all()?;
        Ok(allocated)
    }
}
