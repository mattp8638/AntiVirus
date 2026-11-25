//! Minimal VHDX writer for tests. Produces files that follow MS-VHDX
//! closely enough for the reader and for Hyper-V-style chains; it is not
//! used in production code.

use std::collections::BTreeMap;
use std::path::Path;

use uuid::Uuid;

use crate::crc32c::crc32c;
use crate::vhdx::*;

const MIB: u64 = 1024 * 1024;

pub enum Block {
    Full(Vec<u8>),
    Zero,
    /// Block data plus which logical sectors are present in this file.
    Partial {
        data: Vec<u8>,
        present: Vec<bool>,
    },
}

pub struct Builder {
    pub virtual_size: u64,
    pub block_size: u64,
    pub logical: u64,
    pub data_write_guid: Uuid,
    /// (relative path, parent's DataWriteGuid)
    pub parent: Option<(String, Uuid)>,
    pub blocks: BTreeMap<u64, Block>,
    pub log_guid: Uuid,
}

impl Builder {
    pub fn new(virtual_size: u64, block_size: u64) -> Self {
        Builder {
            virtual_size,
            block_size,
            logical: 512,
            data_write_guid: Uuid::new_v4(),
            parent: None,
            blocks: BTreeMap::new(),
            log_guid: Uuid::nil(),
        }
    }

    pub fn write(&self, path: &Path) {
        let bs = self.block_size;
        let chunk_ratio = (1u64 << 23) * self.logical / bs;
        let data_blocks = self.virtual_size.div_ceil(bs);
        let diff = self.parent.is_some();
        let entries = if diff {
            data_blocks.div_ceil(chunk_ratio) * (chunk_ratio + 1)
        } else {
            data_blocks + (data_blocks - 1) / chunk_ratio
        };
        let meta_off = MIB;
        let bat_off = 2 * MIB;
        let bat_len = (entries * 8).div_ceil(MIB) * MIB;
        let mut next = bat_off + bat_len;
        let mut file = vec![0u8; next as usize];
        let mut bat = vec![0u64; entries as usize];
        let mut bitmaps: BTreeMap<u64, (u64, Vec<u8>)> = BTreeMap::new();

        for (&b, blk) in &self.blocks {
            let idx = (b + b / chunk_ratio) as usize;
            match blk {
                Block::Zero => bat[idx] = 2,
                Block::Full(d) | Block::Partial { data: d, .. } => {
                    assert_eq!(d.len() as u64, bs);
                    let off = next;
                    next += bs;
                    file.resize(next as usize, 0);
                    file[off as usize..next as usize].copy_from_slice(d);
                    let state = if matches!(blk, Block::Full(_)) { 6 } else { 7 };
                    bat[idx] = state | ((off / MIB) << 20);
                    if let Block::Partial { present, .. } = blk {
                        let chunk = b / chunk_ratio;
                        let e = bitmaps
                            .entry(chunk)
                            .or_insert_with(|| (0, vec![0u8; MIB as usize]));
                        let first_sector = b * bs / self.logical;
                        for (i, &p) in present.iter().enumerate() {
                            if p {
                                let bit = (first_sector + i as u64) % (1 << 23);
                                e.1[(bit / 8) as usize] |= 1 << (bit % 8);
                            }
                        }
                    }
                }
            }
        }
        for (chunk, (_, bits)) in bitmaps.iter_mut() {
            let off = next;
            next += MIB;
            file.resize(next as usize, 0);
            file[off as usize..next as usize].copy_from_slice(bits);
            bat[(chunk * (chunk_ratio + 1) + chunk_ratio) as usize] = 6 | ((off / MIB) << 20);
        }
        for (i, e) in bat.iter().enumerate() {
            let o = bat_off as usize + i * 8;
            file[o..o + 8].copy_from_slice(&e.to_le_bytes());
        }

        file[0..8].copy_from_slice(b"vhdxfile");
        for (n, off) in [(1u64, 64 * 1024usize), (2, 128 * 1024)] {
            let mut h = vec![0u8; 4096];
            h[0..4].copy_from_slice(b"head");
            h[8..16].copy_from_slice(&n.to_le_bytes());
            h[16..32].copy_from_slice(&Uuid::new_v4().to_bytes_le());
            h[32..48].copy_from_slice(&self.data_write_guid.to_bytes_le());
            h[48..64].copy_from_slice(&self.log_guid.to_bytes_le());
            h[66..68].copy_from_slice(&1u16.to_le_bytes());
            h[68..72].copy_from_slice(&(MIB as u32).to_le_bytes());
            let c = crc32c(&h);
            h[4..8].copy_from_slice(&c.to_le_bytes());
            file[off..off + 4096].copy_from_slice(&h);
        }
        let mut r = vec![0u8; 64 * 1024];
        r[0..4].copy_from_slice(b"regi");
        r[8..12].copy_from_slice(&2u32.to_le_bytes());
        for (i, (g, o, l)) in [
            (REGION_BAT, bat_off, bat_len),
            (REGION_METADATA, meta_off, MIB),
        ]
        .iter()
        .enumerate()
        {
            let e = 16 + i * 32;
            r[e..e + 16].copy_from_slice(&g.to_bytes_le());
            r[e + 16..e + 24].copy_from_slice(&o.to_le_bytes());
            r[e + 24..e + 28].copy_from_slice(&(*l as u32).to_le_bytes());
            r[e + 28..e + 32].copy_from_slice(&1u32.to_le_bytes());
        }
        let c = crc32c(&r);
        r[4..8].copy_from_slice(&c.to_le_bytes());
        file[192 * 1024..256 * 1024].copy_from_slice(&r);
        file[256 * 1024..320 * 1024].copy_from_slice(&r);

        // Metadata.
        let mut items: Vec<(Uuid, Vec<u8>, u32)> = vec![
            (
                META_FILE_PARAMETERS,
                [
                    (bs as u32).to_le_bytes(),
                    (if diff { 2u32 } else { 0 }).to_le_bytes(),
                ]
                .concat(),
                4,
            ),
            (
                META_VIRTUAL_DISK_SIZE,
                self.virtual_size.to_le_bytes().to_vec(),
                6,
            ),
            (
                META_VIRTUAL_DISK_ID,
                Uuid::new_v4().to_bytes_le().to_vec(),
                6,
            ),
            (
                META_LOGICAL_SECTOR_SIZE,
                (self.logical as u32).to_le_bytes().to_vec(),
                6,
            ),
            (META_PHYSICAL_SECTOR_SIZE, 4096u32.to_le_bytes().to_vec(), 6),
        ];
        if let Some((rel, link)) = &self.parent {
            let kv = [
                ("parent_linkage".to_string(), format!("{{{link}}}")),
                ("relative_path".to_string(), rel.clone()),
            ];
            let mut pl = LOCATOR_TYPE_VHDX.to_bytes_le().to_vec();
            pl.extend_from_slice(&0u16.to_le_bytes());
            pl.extend_from_slice(&(kv.len() as u16).to_le_bytes());
            let mut strings = Vec::new();
            let base = 20 + kv.len() * 12;
            for (k, v) in &kv {
                let ku: Vec<u8> = k.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
                let vu: Vec<u8> = v.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
                let ko = base + strings.len();
                strings.extend_from_slice(&ku);
                let vo = base + strings.len();
                strings.extend_from_slice(&vu);
                pl.extend_from_slice(&(ko as u32).to_le_bytes());
                pl.extend_from_slice(&(vo as u32).to_le_bytes());
                pl.extend_from_slice(&(ku.len() as u16).to_le_bytes());
                pl.extend_from_slice(&(vu.len() as u16).to_le_bytes());
            }
            pl.extend_from_slice(&strings);
            items.push((META_PARENT_LOCATOR, pl, 4));
        }
        let m = meta_off as usize;
        file[m..m + 8].copy_from_slice(b"metadata");
        file[m + 10..m + 12].copy_from_slice(&(items.len() as u16).to_le_bytes());
        let mut data_off = 64 * 1024usize;
        for (i, (g, data, flags)) in items.iter().enumerate() {
            let e = m + 32 + i * 32;
            file[e..e + 16].copy_from_slice(&g.to_bytes_le());
            file[e + 16..e + 20].copy_from_slice(&(data_off as u32).to_le_bytes());
            file[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
            file[e + 24..e + 28].copy_from_slice(&flags.to_le_bytes());
            file[m + data_off..m + data_off + data.len()].copy_from_slice(data);
            data_off += data.len().div_ceil(8) * 8;
        }
        std::fs::write(path, file).unwrap();
    }
}
