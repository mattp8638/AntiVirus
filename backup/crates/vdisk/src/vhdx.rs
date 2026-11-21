//! VHDX reader, implemented from Microsoft's published Open Specification
//! [MS-VHDX] "Virtual Hard Disk v2 (VHDX) File Format". Read-only.
//!
//! Supported: fixed, dynamic and differencing disks (parent chains up to
//! 64 deep), 512 and 4096-byte logical sectors. A file whose log is not
//! empty (it was not closed cleanly) is refused: replaying the log means
//! writing to the file, which a backup must never do.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use core_format::extent::{self, Extent};
use core_format::io::ReadAt;
use uuid::{uuid, Uuid};

use crate::crc32c::crc32c;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

pub const REGION_BAT: Uuid = uuid!("2DC27766-F623-4200-9D64-115E9BFD4A08");
pub const REGION_METADATA: Uuid = uuid!("8B7CA206-4790-4B9A-B8FE-575F050F886E");
pub const META_FILE_PARAMETERS: Uuid = uuid!("CAA16737-FA36-4D43-B3B6-33F0AA44E76B");
pub const META_VIRTUAL_DISK_SIZE: Uuid = uuid!("2FA54224-CD1B-4876-B211-5DBED83BF4B8");
pub const META_VIRTUAL_DISK_ID: Uuid = uuid!("BECA12AB-B2E6-4523-93EF-C309E000C746");
pub const META_LOGICAL_SECTOR_SIZE: Uuid = uuid!("8141BF1D-A96F-4709-BA47-F233A8FAAB5F");
pub const META_PHYSICAL_SECTOR_SIZE: Uuid = uuid!("CDA348C7-445D-4471-9CC9-E9885251C556");
pub const META_PARENT_LOCATOR: Uuid = uuid!("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C");
pub const LOCATOR_TYPE_VHDX: Uuid = uuid!("B04AEFB7-D19E-4A81-B789-25B8E9445913");

// BAT entry states (MS-VHDX 2.5.1.1).
const PAYLOAD_NOT_PRESENT: u8 = 0;
const PAYLOAD_UNDEFINED: u8 = 1;
const PAYLOAD_ZERO: u8 = 2;
const PAYLOAD_UNMAPPED: u8 = 3;
const PAYLOAD_FULLY_PRESENT: u8 = 6;
const PAYLOAD_PARTIALLY_PRESENT: u8 = 7;
const SB_PRESENT: u8 = 6;

const MAX_CHAIN: usize = 64;

#[derive(Debug)]
pub struct VhdxError(pub String);

impl std::fmt::Display for VhdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for VhdxError {}

impl From<VhdxError> for io::Error {
    fn from(e: VhdxError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e.0)
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    VhdxError(msg.into()).into()
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn guid(b: &[u8], o: usize) -> Uuid {
    Uuid::from_bytes_le(b[o..o + 16].try_into().unwrap())
}

/// Verify a structure whose CRC-32C covers `buf` with the 4-byte checksum
/// at `at` treated as zero.
fn checksum_ok(buf: &[u8], at: usize) -> bool {
    let stored = u32le(buf, at);
    let mut b = buf.to_vec();
    b[at..at + 4].fill(0);
    crc32c(&b) == stored
}

/// One file in a chain.
struct Layer {
    file: File,
    path: PathBuf,
    block_size: u64,
    has_parent: bool,
    bat: Vec<u64>,
    chunk_ratio: u64,
    logical_sector: u64,
    data_write_guid: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxInfo {
    pub virtual_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub block_size: u32,
    pub virtual_disk_id: Uuid,
    /// Files in the chain, child first.
    pub chain: Vec<PathBuf>,
}

/// A virtual disk opened read-only; the chain is resolved at open time.
pub struct Vhdx {
    layers: Vec<Layer>,
    info: VhdxInfo,
}

struct Parsed {
    layer: Layer,
    virtual_size: u64,
    physical_sector: u32,
    disk_id: Uuid,
    locator: Vec<(String, String)>,
}

fn parse_file(path: &Path) -> io::Result<Parsed> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let len = file.metadata()?.len();
    if len < MIB {
        return Err(bad(format!(
            "{}: too small to be a VHDX file",
            path.display()
        )));
    }
    let mut ident = [0u8; 8];
    file.read_at(0, &mut ident)?;
    if &ident != b"vhdxfile" {
        return Err(bad(format!(
            "{}: not a VHDX file (VHD and other formats are not supported)",
            path.display()
        )));
    }

    // Headers at 64 KiB and 128 KiB: use the valid one with the higher sequence number.
    let mut best: Option<Vec<u8>> = None;
    for off in [64 * KIB, 128 * KIB] {
        let mut h = vec![0u8; 4096];
        file.read_at(off, &mut h)?;
        if &h[0..4] == b"head"
            && checksum_ok(&h, 4)
            && u16le(&h, 66) == 1
            && best.as_ref().is_none_or(|b| u64le(&h, 8) > u64le(b, 8))
        {
            best = Some(h);
        }
    }
    let h = best.ok_or_else(|| bad(format!("{}: no valid VHDX header", path.display())))?;
    let data_write_guid = guid(&h, 32);
    let log_guid = guid(&h, 48);
    if !log_guid.is_nil() {
        return Err(bad(format!(
            "{}: the VHDX log is not empty (the file was not closed cleanly); attach it once in Hyper-V to replay the log",
            path.display()
        )));
    }

    // Region table at 192 KiB (copy at 256 KiB).
    let mut regions = None;
    for off in [192 * KIB, 256 * KIB] {
        let mut r = vec![0u8; 64 * KIB as usize];
        file.read_at(off, &mut r)?;
        if &r[0..4] == b"regi" && checksum_ok(&r, 4) {
            regions = Some(r);
            break;
        }
    }
    let r = regions.ok_or_else(|| bad(format!("{}: no valid region table", path.display())))?;
    let count = u32le(&r, 8) as usize;
    if count > 2047 {
        return Err(bad("region table entry count out of range"));
    }
    let (mut bat_region, mut meta_region) = (None, None);
    for i in 0..count {
        let e = &r[16 + i * 32..16 + (i + 1) * 32];
        let (id, off, rlen, req) = (
            guid(e, 0),
            u64le(e, 16),
            u32le(e, 24) as u64,
            u32le(e, 28) & 1,
        );
        if off.checked_add(rlen).is_none_or(|end| end > len) {
            return Err(bad("region beyond end of file"));
        }
        if id == REGION_BAT {
            bat_region = Some((off, rlen));
        } else if id == REGION_METADATA {
            meta_region = Some((off, rlen));
        } else if req != 0 {
            return Err(bad(format!("unknown required VHDX region {id}")));
        }
    }
    let (moff, mlen) = meta_region.ok_or_else(|| bad("VHDX metadata region missing"))?;
    let (boff, blen) = bat_region.ok_or_else(|| bad("VHDX BAT region missing"))?;
    if mlen > 16 * MIB || blen > 1024 * MIB {
        return Err(bad("VHDX region size out of range"));
    }

    // Metadata.
    let mut m = vec![0u8; mlen as usize];
    file.read_at(moff, &mut m)?;
    if &m[0..8] != b"metadata" {
        return Err(bad("VHDX metadata table signature missing"));
    }
    let mcount = u16le(&m, 10) as usize;
    if 32 + mcount * 32 > m.len() {
        return Err(bad("metadata entry count out of range"));
    }
    let item = |want: Uuid| -> io::Result<Option<&[u8]>> {
        for i in 0..mcount {
            let e = &m[32 + i * 32..64 + i * 32];
            if guid(e, 0) == want {
                let (o, l) = (u32le(e, 16) as usize, u32le(e, 20) as usize);
                return m
                    .get(o..o + l)
                    .map(Some)
                    .ok_or_else(|| bad("metadata item beyond region"));
            }
        }
        Ok(None)
    };
    for i in 0..mcount {
        let e = &m[32 + i * 32..64 + i * 32];
        let id = guid(e, 0);
        let required = u32le(e, 24) & 4 != 0;
        let known = [
            META_FILE_PARAMETERS,
            META_VIRTUAL_DISK_SIZE,
            META_VIRTUAL_DISK_ID,
            META_LOGICAL_SECTOR_SIZE,
            META_PHYSICAL_SECTOR_SIZE,
            META_PARENT_LOCATOR,
        ];
        if required && !known.contains(&id) {
            return Err(bad(format!("unknown required VHDX metadata item {id}")));
        }
    }
    let fp = item(META_FILE_PARAMETERS)?
        .filter(|b| b.len() >= 8)
        .ok_or_else(|| bad("file parameters missing"))?;
    let block_size = u32le(fp, 0) as u64;
    let has_parent = u32le(fp, 4) & 2 != 0;
    let virtual_size = item(META_VIRTUAL_DISK_SIZE)?
        .filter(|b| b.len() >= 8)
        .map(|b| u64le(b, 0))
        .ok_or_else(|| bad("virtual disk size missing"))?;
    let logical = item(META_LOGICAL_SECTOR_SIZE)?
        .filter(|b| b.len() >= 4)
        .map(|b| u32le(b, 0))
        .ok_or_else(|| bad("logical sector size missing"))? as u64;
    let physical = item(META_PHYSICAL_SECTOR_SIZE)?
        .filter(|b| b.len() >= 4)
        .map(|b| u32le(b, 0))
        .unwrap_or(logical as u32);
    let disk_id = item(META_VIRTUAL_DISK_ID)?
        .filter(|b| b.len() >= 16)
        .map(|b| guid(b, 0))
        .unwrap_or_default();
    if !(MIB..=256 * MIB).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(bad("VHDX block size out of range"));
    }
    if logical != 512 && logical != 4096 {
        return Err(bad("VHDX logical sector size must be 512 or 4096"));
    }
    if virtual_size == 0 || virtual_size % logical != 0 || virtual_size > 64 * 1024 * 1024 * MIB {
        return Err(bad("VHDX virtual size out of range"));
    }

    let mut locator = Vec::new();
    if has_parent {
        let pl = item(META_PARENT_LOCATOR)?
            .ok_or_else(|| bad("differencing disk without parent locator"))?;
        if pl.len() < 20 || guid(pl, 0) != LOCATOR_TYPE_VHDX {
            return Err(bad("unsupported parent locator type"));
        }
        let n = u16le(pl, 18) as usize;
        for i in 0..n {
            let o = 20 + i * 12;
            let e = pl
                .get(o..o + 12)
                .ok_or_else(|| bad("parent locator entry beyond item"))?;
            let (ko, vo, kl, vl) = (
                u32le(e, 0) as usize,
                u32le(e, 4) as usize,
                u16le(e, 8) as usize,
                u16le(e, 10) as usize,
            );
            let utf16 = |o: usize, l: usize| -> io::Result<String> {
                let b = pl
                    .get(o..o + l)
                    .ok_or_else(|| bad("parent locator string beyond item"))?;
                Ok(String::from_utf16_lossy(
                    &b.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                ))
            };
            locator.push((utf16(ko, kl)?, utf16(vo, vl)?));
        }
    }

    // BAT.
    let chunk_ratio = (1u64 << 23) * logical / block_size;
    let data_blocks = virtual_size.div_ceil(block_size);
    let entries = if has_parent {
        let bitmap_blocks = data_blocks.div_ceil(chunk_ratio);
        bitmap_blocks * (chunk_ratio + 1)
    } else {
        data_blocks + (data_blocks - 1) / chunk_ratio
    };
    if entries * 8 > blen {
        return Err(bad("VHDX BAT region too small for the disk size"));
    }
    let mut raw = vec![0u8; (entries * 8) as usize];
    file.read_at(boff, &mut raw)?;
    let bat: Vec<u64> = raw
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();

    Ok(Parsed {
        layer: Layer {
            file,
            path: path.to_path_buf(),
            block_size,
            has_parent,
            bat,
            chunk_ratio,
            logical_sector: logical,
            data_write_guid,
        },
        virtual_size,
        physical_sector: physical,
        disk_id,
        locator,
    })
}

fn locate_parent(
    child: &Path,
    locator: &[(String, String)],
) -> io::Result<(PathBuf, Option<Uuid>)> {
    let get = |k: &str| {
        locator
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let linkage = get("parent_linkage")
        .and_then(|s| Uuid::parse_str(s.trim_matches(|c| c == '{' || c == '}')).ok());
    let dir = child.parent().unwrap_or(Path::new("."));
    let mut candidates = Vec::new();
    if let Some(rel) = get("relative_path") {
        let rel = rel
            .trim_start_matches(".\\")
            .replace('\\', std::path::MAIN_SEPARATOR_STR);
        candidates.push(dir.join(rel));
    }
    for k in ["absolute_win32_path", "volume_path"] {
        if let Some(p) = get(k) {
            candidates.push(PathBuf::from(p));
        }
    }
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .map(|p| (p, linkage))
        .ok_or_else(|| {
            bad(format!(
                "{}: parent disk not found (locator: {locator:?})",
                child.display()
            ))
        })
}

impl Vhdx {
    /// Open a VHDX and its parents.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Vhdx> {
        let first = parse_file(path.as_ref())?;
        let info = VhdxInfo {
            virtual_size: first.virtual_size,
            logical_sector_size: first.layer.logical_sector as u32,
            physical_sector_size: first.physical_sector,
            block_size: first.layer.block_size as u32,
            virtual_disk_id: first.disk_id,
            chain: vec![first.layer.path.clone()],
        };
        let mut layers = Vec::new();
        let mut cur = first;
        loop {
            let next = if cur.layer.has_parent {
                if layers.len() + 1 >= MAX_CHAIN {
                    return Err(bad("differencing chain deeper than 64"));
                }
                let (ppath, linkage) = locate_parent(&cur.layer.path, &cur.locator)?;
                let parent = parse_file(&ppath)?;
                if let Some(l) = linkage {
                    if l != parent.layer.data_write_guid {
                        return Err(bad(format!(
                            "{}: parent {} has changed since the child was created (linkage mismatch)",
                            cur.layer.path.display(),
                            ppath.display()
                        )));
                    }
                }
                if parent.virtual_size != cur.virtual_size
                    || parent.layer.logical_sector != cur.layer.logical_sector
                {
                    return Err(bad("parent disk geometry does not match child"));
                }
                Some(parent)
            } else {
                None
            };
            layers.push(cur.layer);
            match next {
                Some(p) => cur = p,
                None => break,
            }
        }
        let mut info = info;
        info.chain = layers.iter().map(|l| l.path.clone()).collect();
        Ok(Vhdx { layers, info })
    }

    pub fn info(&self) -> &VhdxInfo {
        &self.info
    }

    /// Fill `buf` (which lies inside one block) from layer `li` and below.
    fn read_block_part(&self, li: usize, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let Some(l) = self.layers.get(li) else {
            buf.fill(0);
            return Ok(());
        };
        let block = offset / l.block_size;
        let entry = l.bat[(block + block / l.chunk_ratio) as usize];
        let state = (entry & 7) as u8;
        let file_off = (entry >> 20) * MIB;
        let within = offset % l.block_size;
        match state {
            PAYLOAD_FULLY_PRESENT => l.file.read_at(file_off + within, buf),
            PAYLOAD_PARTIALLY_PRESENT if l.has_parent => {
                let chunk = block / l.chunk_ratio;
                let sb = l.bat[(chunk * (l.chunk_ratio + 1) + l.chunk_ratio) as usize];
                if (sb & 7) as u8 != SB_PRESENT {
                    return Err(bad("partially present block without a sector bitmap"));
                }
                let sb_off = (sb >> 20) * MIB;
                let ss = l.logical_sector;
                // Bitmap bits covering this request (it lies in one block,
                // so in one chunk and one bitmap block).
                let first = offset / ss;
                let last = (offset + buf.len() as u64 - 1) / ss;
                let (b0, b1) = ((first % (1 << 23)) / 8, (last % (1 << 23)) / 8);
                let mut bits = vec![0u8; (b1 - b0 + 1) as usize];
                l.file.read_at(sb_off + b0, &mut bits)?;
                let present = |sector: u64| {
                    let i = sector % (1 << 23);
                    bits[(i / 8 - b0) as usize] & (1 << (i % 8)) != 0
                };
                // Walk runs of sectors with the same presence.
                let mut pos = 0usize;
                while pos < buf.len() {
                    let abs = offset + pos as u64;
                    let here = present(abs / ss);
                    let mut run_end = ((abs / ss) + 1) * ss;
                    while run_end < offset + buf.len() as u64 && present(run_end / ss) == here {
                        run_end += ss;
                    }
                    let n = (run_end.min(offset + buf.len() as u64) - abs) as usize;
                    if here {
                        l.file
                            .read_at(file_off + abs % l.block_size, &mut buf[pos..pos + n])?;
                    } else {
                        self.read_block_part(li + 1, abs, &mut buf[pos..pos + n])?;
                    }
                    pos += n;
                }
                Ok(())
            }
            PAYLOAD_NOT_PRESENT | PAYLOAD_UNDEFINED if l.has_parent => {
                self.read_block_part(li + 1, offset, buf)
            }
            PAYLOAD_NOT_PRESENT | PAYLOAD_UNDEFINED | PAYLOAD_ZERO | PAYLOAD_UNMAPPED => {
                buf.fill(0);
                Ok(())
            }
            s => Err(bad(format!(
                "{}: invalid BAT state {s} for block {block}",
                l.path.display()
            ))),
        }
    }

    /// Virtual byte ranges that hold data in any layer (block granularity).
    pub fn allocated(&self) -> Vec<Extent> {
        let size = self.info.virtual_size;
        let mut out = Vec::new();
        for l in &self.layers {
            let blocks = size.div_ceil(l.block_size);
            for b in 0..blocks {
                let state = (l.bat[(b + b / l.chunk_ratio) as usize] & 7) as u8;
                if state == PAYLOAD_FULLY_PRESENT || state == PAYLOAD_PARTIALLY_PRESENT {
                    let start = b * l.block_size;
                    out.push(Extent(start, l.block_size.min(size - start)));
                }
            }
        }
        extent::normalize(out)
    }
}

impl ReadAt for Vhdx {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| bad("read overflow"))?;
        if end > self.info.virtual_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let bs = self.info.block_size as u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            let abs = offset + pos as u64;
            // Layers may have different block sizes; split at the smallest.
            let min_bs = self.layers.iter().map(|l| l.block_size).min().unwrap_or(bs);
            let n = ((min_bs - abs % min_bs) as usize).min(buf.len() - pos);
            self.read_block_part(0, abs, &mut buf[pos..pos + n])?;
            pos += n;
        }
        Ok(())
    }
}
