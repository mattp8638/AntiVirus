//! Dynamic VHDX writer, following [MS-VHDX]. Used to restore images as
//! virtual disks that Hyper-V can attach and Windows can mount.
//!
//! Layout written:
//!
//! ```text
//! 0          file type identifier ("vhdxfile", creator)
//! 64 KiB     header 1        128 KiB  header 2
//! 192 KiB    region table    256 KiB  region table copy
//! 1 MiB      log (1 MiB, empty: LogGuid is zero)
//! 2 MiB      metadata region (1 MiB)
//! 3 MiB      BAT
//! ...        payload blocks, appended as first written
//! ```
//!
//! Blocks are allocated on the first non-zero write; all-zero writes to an
//! unallocated block are dropped, so the file only holds data. The BAT is
//! written by `finish`; until then the file is not a valid VHDX.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;

use crate::crc32c::crc32c;
use crate::vhdx::*;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const LOG_OFFSET: u64 = MIB;
const LOG_LENGTH: u64 = MIB;
const META_OFFSET: u64 = 2 * MIB;
const META_LENGTH: u64 = MIB;
const BAT_OFFSET: u64 = 3 * MIB;
const FULLY_PRESENT: u64 = 6;

pub const DEFAULT_BLOCK_SIZE: u64 = 32 * MIB;

struct State {
    /// File offset of each payload block, 0 = not allocated.
    blocks: Vec<u64>,
    next: u64,
}

pub struct VhdxWriter {
    file: File,
    path: PathBuf,
    size: u64,
    block_size: u64,
    chunk_ratio: u64,
    bat_len: u64,
    state: Mutex<State>,
}

fn write_at(f: &File, off: u64, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_all_at(f, data, off)
    }
    #[cfg(windows)]
    {
        let mut done = 0;
        while done < data.len() {
            done += std::os::windows::fs::FileExt::seek_write(f, &data[done..], off + done as u64)?;
        }
        Ok(())
    }
}

impl VhdxWriter {
    /// Create a new file (never overwrites).
    pub fn create(
        path: &Path,
        virtual_size: u64,
        logical_sector: u32,
        physical_sector: u32,
        block_size: u64,
    ) -> io::Result<VhdxWriter> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
        if logical_sector != 512 && logical_sector != 4096 {
            return Err(bad("logical sector size must be 512 or 4096"));
        }
        if !(MIB..=256 * MIB).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(bad("block size must be a power of two from 1 to 256 MiB"));
        }
        if virtual_size == 0
            || virtual_size % logical_sector as u64 != 0
            || virtual_size > 64 * 1024 * 1024 * MIB
        {
            return Err(bad(
                "virtual size must be a non-zero multiple of the sector size, at most 64 TiB",
            ));
        }
        let chunk_ratio = (1u64 << 23) * logical_sector as u64 / block_size;
        let data_blocks = virtual_size.div_ceil(block_size);
        let entries = data_blocks + (data_blocks - 1) / chunk_ratio;
        let bat_len = (entries * 8).div_ceil(MIB) * MIB;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        let w = VhdxWriter {
            file,
            path: path.to_path_buf(),
            size: virtual_size,
            block_size,
            chunk_ratio,
            bat_len,
            state: Mutex::new(State {
                blocks: vec![0; data_blocks as usize],
                next: BAT_OFFSET + bat_len,
            }),
        };
        w.write_structures(logical_sector, physical_sector)?;
        Ok(w)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn virtual_size(&self) -> u64 {
        self.size
    }

    fn write_structures(&self, logical: u32, physical: u32) -> io::Result<()> {
        // File type identifier.
        let mut ident = vec![0u8; 64 * KIB as usize];
        ident[0..8].copy_from_slice(b"vhdxfile");
        for (i, c) in "Fenrir-Backup".encode_utf16().enumerate() {
            ident[8 + i * 2..10 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        write_at(&self.file, 0, &ident)?;

        // Headers: identical but for the sequence number.
        let (file_guid, data_guid) = (Uuid::new_v4(), Uuid::new_v4());
        for (seq, off) in [(1u64, 64 * KIB), (2, 128 * KIB)] {
            let mut h = vec![0u8; 4 * KIB as usize];
            h[0..4].copy_from_slice(b"head");
            h[8..16].copy_from_slice(&seq.to_le_bytes());
            h[16..32].copy_from_slice(&file_guid.to_bytes_le());
            h[32..48].copy_from_slice(&data_guid.to_bytes_le());
            // LogGuid stays zero: the log is empty.
            h[64..66].copy_from_slice(&0u16.to_le_bytes()); // LogVersion
            h[66..68].copy_from_slice(&1u16.to_le_bytes()); // Version
            h[68..72].copy_from_slice(&(LOG_LENGTH as u32).to_le_bytes());
            h[72..80].copy_from_slice(&LOG_OFFSET.to_le_bytes());
            let c = crc32c(&h);
            h[4..8].copy_from_slice(&c.to_le_bytes());
            write_at(&self.file, off, &h)?;
        }

        // Region table and its copy.
        let mut r = vec![0u8; 64 * KIB as usize];
        r[0..4].copy_from_slice(b"regi");
        r[8..12].copy_from_slice(&2u32.to_le_bytes());
        for (i, (g, o, l)) in [
            (REGION_BAT, BAT_OFFSET, self.bat_len),
            (REGION_METADATA, META_OFFSET, META_LENGTH),
        ]
        .iter()
        .enumerate()
        {
            let e = 16 + i * 32;
            r[e..e + 16].copy_from_slice(&g.to_bytes_le());
            r[e + 16..e + 24].copy_from_slice(&o.to_le_bytes());
            r[e + 24..e + 28].copy_from_slice(&(*l as u32).to_le_bytes());
            r[e + 28..e + 32].copy_from_slice(&1u32.to_le_bytes()); // required
        }
        let c = crc32c(&r);
        r[4..8].copy_from_slice(&c.to_le_bytes());
        write_at(&self.file, 192 * KIB, &r)?;
        write_at(&self.file, 256 * KIB, &r)?;

        // Empty log region.
        write_at(&self.file, LOG_OFFSET, &vec![0u8; LOG_LENGTH as usize])?;

        // Metadata: table at the region start, items from 64 KiB.
        // Flags: bit 1 IsVirtualDisk, bit 2 IsRequired.
        let items: [(Uuid, Vec<u8>, u32); 5] = [
            (
                META_FILE_PARAMETERS,
                [(self.block_size as u32).to_le_bytes(), 0u32.to_le_bytes()].concat(),
                4,
            ),
            (META_VIRTUAL_DISK_SIZE, self.size.to_le_bytes().to_vec(), 6),
            (
                META_VIRTUAL_DISK_ID,
                Uuid::new_v4().to_bytes_le().to_vec(),
                6,
            ),
            (META_LOGICAL_SECTOR_SIZE, logical.to_le_bytes().to_vec(), 6),
            (
                META_PHYSICAL_SECTOR_SIZE,
                physical.max(logical).to_le_bytes().to_vec(),
                6,
            ),
        ];
        let mut m = vec![0u8; META_LENGTH as usize];
        m[0..8].copy_from_slice(b"metadata");
        m[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
        let mut data_off = 64 * KIB as usize;
        for (i, (g, data, flags)) in items.iter().enumerate() {
            let e = 32 + i * 32;
            m[e..e + 16].copy_from_slice(&g.to_bytes_le());
            m[e + 16..e + 20].copy_from_slice(&(data_off as u32).to_le_bytes());
            m[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
            m[e + 24..e + 28].copy_from_slice(&flags.to_le_bytes());
            m[data_off..data_off + data.len()].copy_from_slice(data);
            data_off += data.len().div_ceil(8) * 8;
        }
        write_at(&self.file, META_OFFSET, &m)?;
        // BAT: all blocks not present until finish().
        self.file.set_len(BAT_OFFSET + self.bat_len)?;
        Ok(())
    }

    /// Write `data` at virtual offset `off`.
    pub fn write_at(&self, off: u64, data: &[u8]) -> io::Result<()> {
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if end > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write beyond the virtual disk",
            ));
        }
        let mut pos = 0usize;
        while pos < data.len() {
            let v = off + pos as u64;
            let block = v / self.block_size;
            let within = v % self.block_size;
            let n = ((self.block_size - within) as usize).min(data.len() - pos);
            let piece = &data[pos..pos + n];
            let file_off = {
                let mut st = self.state.lock().unwrap();
                let b = &mut st.blocks[block as usize];
                if *b == 0 {
                    if piece.iter().all(|&x| x == 0) {
                        pos += n;
                        continue; // unallocated blocks read as zero
                    }
                    let at = st.next;
                    st.next += self.block_size;
                    st.blocks[block as usize] = at;
                    // Extending the file zero-fills the new block.
                    self.file.set_len(st.next)?;
                    at
                } else {
                    *b
                }
            };
            write_at(&self.file, file_off + within, piece)?;
            pos += n;
        }
        Ok(())
    }

    /// Write the BAT and flush. Returns the number of allocated blocks.
    pub fn finish(self) -> io::Result<u64> {
        let st = self.state.lock().unwrap();
        let data_blocks = st.blocks.len() as u64;
        let entries = data_blocks + (data_blocks - 1) / self.chunk_ratio;
        let mut bat = vec![0u8; (entries * 8) as usize];
        let mut allocated = 0;
        for (b, &off) in st.blocks.iter().enumerate() {
            if off != 0 {
                let idx = b as u64 + b as u64 / self.chunk_ratio;
                let e = FULLY_PRESENT | ((off / MIB) << 20);
                bat[(idx * 8) as usize..(idx * 8 + 8) as usize].copy_from_slice(&e.to_le_bytes());
                allocated += 1;
            }
        }
        write_at(&self.file, BAT_OFFSET, &bat)?;
        self.file.sync_all()?;
        Ok(allocated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhdx::Vhdx;
    use core_format::io::ReadAt;

    #[test]
    fn four_k_sector_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("4kn.vhdx");
        let w = VhdxWriter::create(&p, 64 * MIB, 4096, 4096, 32 * MIB).unwrap();
        w.write_at(33 * MIB, &[3u8; 8192]).unwrap();
        w.finish().unwrap();
        let v = Vhdx::open(&p).unwrap();
        assert_eq!(v.info().logical_sector_size, 4096);
        let mut b = vec![0u8; 8192];
        v.read_at(33 * MIB, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 3));
    }

    #[test]
    fn roundtrip_through_our_reader() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("out.vhdx");
        let size = 70 * MIB + 4096;
        let w = VhdxWriter::create(&p, size, 512, 4096, 32 * MIB).unwrap();
        let a: Vec<u8> = (0..3 * MIB).map(|i| (i % 251) as u8).collect();
        w.write_at(MIB, &a).unwrap(); // block 0
        w.write_at(40 * MIB, &vec![0u8; MIB as usize]).unwrap(); // zeros: no allocation
        w.write_at(size - 4096, &[7u8; 4096]).unwrap(); // last partial block
        w.write_at(31 * MIB, &vec![5u8; 2 * MIB as usize]).unwrap(); // spans blocks 0 and 1
        assert!(w.write_at(size - 1, &[1, 2]).is_err());
        assert_eq!(w.finish().unwrap(), 3);
        let v = Vhdx::open(&p).unwrap();
        assert_eq!(v.info().virtual_size, size);
        let mut all = vec![0u8; size as usize];
        v.read_at(0, &mut all).unwrap();
        assert_eq!(&all[MIB as usize..4 * MIB as usize], &a[..]);
        assert!(all[31 * MIB as usize..33 * MIB as usize]
            .iter()
            .all(|&b| b == 5));
        assert!(all[40 * MIB as usize..41 * MIB as usize]
            .iter()
            .all(|&b| b == 0));
        assert!(all[size as usize - 4096..].iter().all(|&b| b == 7));
        // Blocks 0, 1 (data) and 2 (the tail) are contiguous: one extent.
        assert_eq!(v.allocated(), vec![core_format::extent::Extent(0, size)]);
        // Never overwrites.
        assert!(VhdxWriter::create(&p, size, 512, 4096, 32 * MIB).is_err());
    }
}
