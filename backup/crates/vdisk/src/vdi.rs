//! VDI writer, the native disk format of Oracle VirtualBox (dynamic image,
//! header version 1.1, 1 MiB blocks).
//!
//! Layout written:
//!
//! ```text
//! 0        pre-header (text and signature) and header
//! 512      block map: one 32-bit entry per virtual block
//! 1 MiB+   data blocks (1 MiB aligned), appended as first written
//! ```
//!
//! A block map entry is the block's position among the data blocks, or
//! 0xFFFFFFFF for a block that was never written (it reads as zero).

use std::io;
use std::path::Path;

use uuid::Uuid;

use crate::sparse::{write_at, write_target_via_sparse, Sparse, VirtualDiskTarget};

const MIB: u64 = 1024 * 1024;
pub const BLOCK: u64 = MIB;
const MAP_OFFSET: u64 = 512;
const SIGNATURE: u32 = 0xBEDA_107F;
const VERSION_1_1: u32 = 0x0001_0001;
const HEADER_SIZE: u32 = 400;
const IMAGE_DYNAMIC: u32 = 1;
const FREE: u32 = 0xFFFF_FFFF;

pub struct VdiTarget {
    s: Sparse,
    data_offset: u64,
}

impl VdiTarget {
    /// A new file (never overwrites) of `size` virtual bytes.
    pub fn create(path: &Path, size: u64) -> io::Result<Self> {
        let blocks = size.div_ceil(BLOCK);
        if size == 0 || size % 512 != 0 || MAP_OFFSET + blocks * 4 > u32::MAX as u64 - MIB {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtual size must be a non-zero multiple of 512, below 1 PiB",
            ));
        }
        let data_offset = (MAP_OFFSET + blocks * 4).div_ceil(MIB) * MIB;
        Ok(VdiTarget {
            s: Sparse::create(path, size, BLOCK, data_offset)?,
            data_offset,
        })
    }
}

write_target_via_sparse!(VdiTarget);

impl VirtualDiskTarget for VdiTarget {
    fn finish(self: Box<Self>) -> io::Result<u64> {
        let (blocks, _) = self.s.blocks();
        let mut map = Vec::with_capacity(blocks.len() * 4);
        let mut allocated = 0u32;
        for &b in &blocks {
            let e = if b == 0 {
                FREE
            } else {
                allocated += 1;
                ((b - self.data_offset) / BLOCK) as u32
            };
            map.extend_from_slice(&e.to_le_bytes());
        }
        write_at(&self.s.file, MAP_OFFSET, &map)?;

        let mut h = vec![0u8; 512];
        let text = b"<<< Oracle VM VirtualBox Disk Image >>>\n";
        h[..text.len()].copy_from_slice(text);
        let put32 =
            |h: &mut Vec<u8>, at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put32(&mut h, 0x40, SIGNATURE);
        put32(&mut h, 0x44, VERSION_1_1);
        put32(&mut h, 0x48, HEADER_SIZE);
        put32(&mut h, 0x4C, IMAGE_DYNAMIC);
        // flags 0x50 and comment 0x54..0x154: zero
        put32(&mut h, 0x154, MAP_OFFSET as u32);
        put32(&mut h, 0x158, self.data_offset as u32);
        // legacy geometry: cylinders, heads, sectors unset (0); sector size
        put32(&mut h, 0x168, 512);
        h[0x170..0x178].copy_from_slice(&self.s.size.to_le_bytes());
        put32(&mut h, 0x178, BLOCK as u32);
        // extra data per block 0x17C: 0
        put32(&mut h, 0x180, blocks.len() as u32);
        put32(&mut h, 0x184, allocated);
        h[0x188..0x198].copy_from_slice(Uuid::new_v4().to_bytes_le().as_slice());
        h[0x198..0x1A8].copy_from_slice(Uuid::new_v4().to_bytes_le().as_slice());
        // linkage and parent UUIDs 0x1A8..0x1C8: none (zero)
        // logical geometry 0x1C8: unset, sector size 512
        put32(&mut h, 0x1D4, 512);
        write_at(&self.s.file, 0, &h)?;
        self.s.file.sync_all()?;
        Ok(allocated as u64)
    }
}
