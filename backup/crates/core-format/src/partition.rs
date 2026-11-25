//! GPT and MBR partition table parsing (UEFI specification 2.10, ch. 5;
//! the classic IBM PC MBR layout). Read-only: this module never writes.
//!
//! Besides the parsed entries, the parser records the exact byte regions
//! that make up the table so that backup always captures them and restore
//! can reproduce them byte-for-byte.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::b64;
use crate::error::{Error, Result};
use crate::extent::Extent;
use crate::io::ReadAt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Gpt,
    Mbr,
    /// No recognised partition table (e.g. a whole-disk filesystem).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    Esp,
    Msr,
    Recovery,
    BiosBoot,
    Data,
    Swap,
    Lvm,
    Extended,
    Unknown,
}

impl PartitionRole {
    /// Partitions that make a disk boot. Always imaged in full.
    pub fn is_boot_critical(&self) -> bool {
        matches!(
            self,
            PartitionRole::Esp
                | PartitionRole::Msr
                | PartitionRole::Recovery
                | PartitionRole::BiosBoot
        )
    }
}

pub mod gpt_types {
    use uuid::{uuid, Uuid};
    pub const ESP: Uuid = uuid!("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    pub const MSR: Uuid = uuid!("E3C9E316-0B5C-4DB8-817D-F92DF00215AE");
    pub const WINDOWS_RECOVERY: Uuid = uuid!("DE94BBA4-06D1-4D40-A16A-BFD50179D6AC");
    pub const BASIC_DATA: Uuid = uuid!("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    pub const BIOS_BOOT: Uuid = uuid!("21686148-6449-6E6F-744E-656564454649");
    pub const LINUX_FS: Uuid = uuid!("0FC63DAF-8483-4772-8E79-3D69D8477DE4");
    pub const LINUX_ROOT_X86_64: Uuid = uuid!("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
    pub const LINUX_SWAP: Uuid = uuid!("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F");
    pub const LINUX_LVM: Uuid = uuid!("E6D6D379-F507-44C2-A23C-238F2A3DF928");
    pub const LINUX_XBOOTLDR: Uuid = uuid!("BC13C2FF-59E6-4262-A352-B275FD6F7172");
}

pub fn role_for_gpt_type(t: &Uuid) -> PartitionRole {
    use gpt_types::*;
    match *t {
        x if x == ESP => PartitionRole::Esp,
        x if x == MSR => PartitionRole::Msr,
        x if x == WINDOWS_RECOVERY => PartitionRole::Recovery,
        x if x == BIOS_BOOT => PartitionRole::BiosBoot,
        x if x == LINUX_SWAP => PartitionRole::Swap,
        x if x == LINUX_LVM => PartitionRole::Lvm,
        x if x == BASIC_DATA || x == LINUX_FS || x == LINUX_ROOT_X86_64 || x == LINUX_XBOOTLDR => {
            PartitionRole::Data
        }
        _ => PartitionRole::Unknown,
    }
}

pub fn role_for_mbr_type(t: u8) -> PartitionRole {
    match t {
        0xEF => PartitionRole::Esp,
        0x27 => PartitionRole::Recovery,
        0x82 => PartitionRole::Swap,
        0x8E => PartitionRole::Lvm,
        0x05 | 0x0F | 0x85 => PartitionRole::Extended,
        0x01 | 0x04 | 0x06 | 0x07 | 0x0B | 0x0C | 0x0E | 0x83 => PartitionRole::Data,
        _ => PartitionRole::Unknown,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEntry {
    /// 1-based. GPT: entry index + 1. MBR: 1–4 primary, 5+ logical.
    pub number: u32,
    /// Byte offset from the start of the disk.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_guid: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_guid: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbr_type: Option<u8>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub attributes: u64,
    #[serde(default)]
    pub bootable: bool,
    pub role: PartitionRole,
}

impl PartitionEntry {
    pub fn extent(&self) -> Extent {
        Extent(self.start, self.length)
    }
}

/// Exact bytes of part of the partition table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRegion {
    pub offset: u64,
    #[serde(with = "b64::serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTable {
    pub scheme: Scheme,
    pub sector_size: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_guid: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbr_signature: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_usable_lba: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_usable_lba: Option<u64>,
    /// False if the GPT backup header/entries were missing or invalid.
    #[serde(default = "yes")]
    pub backup_table_valid: bool,
    pub partitions: Vec<PartitionEntry>,
    pub raw_regions: Vec<RawRegion>,
}

fn yes() -> bool {
    true
}

impl PartitionTable {
    pub fn raw_extents(&self) -> Vec<Extent> {
        self.raw_regions
            .iter()
            .map(|r| Extent(r.offset, r.data.len() as u64))
            .collect()
    }
}

const MAX_GPT_ENTRIES: u32 = 16_384;
const MAX_EBR_CHAIN: usize = 256;

/// Guess the logical sector size of a raw image from where the GPT header is.
pub fn detect_sector_size(src: &dyn ReadAt, disk_size: u64) -> u32 {
    for ss in [512u32, 4096] {
        let mut sig = [0u8; 8];
        if disk_size >= 2 * ss as u64
            && src.read_at(ss as u64, &mut sig).is_ok()
            && &sig == b"EFI PART"
        {
            return ss;
        }
    }
    512
}

/// Parse the partition table of a disk.
pub fn read_table(src: &dyn ReadAt, disk_size: u64, sector_size: u32) -> Result<PartitionTable> {
    if !(512..=65536).contains(&sector_size) || !sector_size.is_power_of_two() {
        return Err(Error::InvalidArgument(format!(
            "bad sector size {sector_size}"
        )));
    }
    let ss = sector_size as u64;
    if disk_size < ss {
        return Ok(empty_table(sector_size));
    }
    let mut mbr = vec![0u8; ss as usize];
    src.read_at(0, &mut mbr)?;
    let has_mbr_sig = mbr[510] == 0x55 && mbr[511] == 0xAA;
    let protective = has_mbr_sig && (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xEE);
    if protective {
        return read_gpt(src, disk_size, sector_size, mbr);
    }
    // Some tools write GPT without a protective MBR; accept a valid header.
    if disk_size >= 2 * ss {
        let mut sig = [0u8; 8];
        src.read_at(ss, &mut sig)?;
        if &sig == b"EFI PART" {
            return read_gpt(src, disk_size, sector_size, mbr);
        }
    }
    if has_mbr_sig && looks_like_mbr_partition_table(&mbr, disk_size, ss) {
        return read_mbr(src, disk_size, sector_size, mbr);
    }
    Ok(empty_table(sector_size))
}

fn empty_table(sector_size: u32) -> PartitionTable {
    PartitionTable {
        scheme: Scheme::None,
        sector_size,
        disk_guid: None,
        mbr_signature: None,
        first_usable_lba: None,
        last_usable_lba: None,
        backup_table_valid: true,
        partitions: vec![],
        raw_regions: vec![],
    }
}

/// A FAT/NTFS boot sector also ends in 55AA; only treat sector 0 as an MBR
/// if its entries are plausible.
fn looks_like_mbr_partition_table(mbr: &[u8], disk_size: u64, ss: u64) -> bool {
    let mut any = false;
    for i in 0..4 {
        let e = &mbr[446 + i * 16..446 + i * 16 + 16];
        let status = e[0];
        let ptype = e[4];
        if status != 0 && status != 0x80 {
            return false;
        }
        if ptype == 0 {
            continue;
        }
        let lba = u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64;
        let count = u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64;
        if lba == 0 || count == 0 || (lba + count) * ss > disk_size.max(ss) + ss * 2048 {
            return false;
        }
        any = true;
    }
    any
}

struct GptHeader {
    my_lba: u64,
    alt_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: Uuid,
    entries_lba: u64,
    num_entries: u32,
    entry_size: u32,
    entries_crc: u32,
}

fn parse_gpt_header(sector: &[u8], expected_lba: u64) -> Result<GptHeader> {
    if &sector[0..8] != b"EFI PART" {
        return Err(Error::malformed("GPT signature missing"));
    }
    let hsize = u32::from_le_bytes(sector[12..16].try_into().unwrap()) as usize;
    if !(92..=sector.len()).contains(&hsize) {
        return Err(Error::malformed("GPT header size out of range"));
    }
    let crc = u32::from_le_bytes(sector[16..20].try_into().unwrap());
    let mut h = sector[..hsize].to_vec();
    h[16..20].fill(0);
    if crc32fast::hash(&h) != crc {
        return Err(Error::malformed("GPT header CRC mismatch"));
    }
    let r = |o: usize| u64::from_le_bytes(sector[o..o + 8].try_into().unwrap());
    let hdr = GptHeader {
        my_lba: r(24),
        alt_lba: r(32),
        first_usable: r(40),
        last_usable: r(48),
        disk_guid: Uuid::from_bytes_le(sector[56..72].try_into().unwrap()),
        entries_lba: r(72),
        num_entries: u32::from_le_bytes(sector[80..84].try_into().unwrap()),
        entry_size: u32::from_le_bytes(sector[84..88].try_into().unwrap()),
        entries_crc: u32::from_le_bytes(sector[88..92].try_into().unwrap()),
    };
    if hdr.my_lba != expected_lba {
        return Err(Error::malformed("GPT header MyLBA mismatch"));
    }
    if hdr.num_entries == 0 || hdr.num_entries > MAX_GPT_ENTRIES {
        return Err(Error::malformed("GPT entry count out of range"));
    }
    if hdr.entry_size < 128 || hdr.entry_size > 4096 || hdr.entry_size % 128 != 0 {
        return Err(Error::malformed("GPT entry size invalid"));
    }
    Ok(hdr)
}

fn read_gpt_entries(src: &dyn ReadAt, hdr: &GptHeader, ss: u64, disk_size: u64) -> Result<Vec<u8>> {
    let bytes = hdr.num_entries as u64 * hdr.entry_size as u64;
    let padded = bytes.div_ceil(ss) * ss;
    let off = hdr
        .entries_lba
        .checked_mul(ss)
        .ok_or_else(|| Error::malformed("GPT entries LBA overflow"))?;
    if off.checked_add(padded).is_none_or(|e| e > disk_size) {
        return Err(Error::malformed("GPT entries beyond end of disk"));
    }
    let mut buf = vec![0u8; padded as usize];
    src.read_at(off, &mut buf)?;
    if crc32fast::hash(&buf[..bytes as usize]) != hdr.entries_crc {
        return Err(Error::malformed("GPT entries CRC mismatch"));
    }
    Ok(buf)
}

fn read_gpt(
    src: &dyn ReadAt,
    disk_size: u64,
    sector_size: u32,
    mbr: Vec<u8>,
) -> Result<PartitionTable> {
    let ss = sector_size as u64;
    let last_lba = disk_size / ss - 1;
    let mut sec = vec![0u8; ss as usize];
    src.read_at(ss, &mut sec)?;

    let mut regions = vec![RawRegion {
        offset: 0,
        data: mbr,
    }];

    // Prefer the primary header; fall back to the backup at the last LBA.
    let primary = parse_gpt_header(&sec, 1)
        .and_then(|h| read_gpt_entries(src, &h, ss, disk_size).map(|e| (h, e)));
    let (hdr, entries, from_primary) = match primary {
        Ok((h, e)) => (h, e, true),
        Err(primary_err) => {
            let mut bsec = vec![0u8; ss as usize];
            src.read_at(last_lba * ss, &mut bsec)?;
            match parse_gpt_header(&bsec, last_lba)
                .and_then(|h| read_gpt_entries(src, &h, ss, disk_size).map(|e| (h, e)))
            {
                Ok((h, e)) => (h, e, false),
                Err(_) => return Err(primary_err),
            }
        }
    };

    if from_primary {
        // Primary: LBA1 header followed by entries (normally at LBA 2).
        regions.push(RawRegion {
            offset: ss,
            data: sec.clone(),
        });
        regions.push(RawRegion {
            offset: hdr.entries_lba * ss,
            data: entries.clone(),
        });
    }

    // Backup header and entries.
    let alt_lba = if from_primary {
        hdr.alt_lba
    } else {
        hdr.my_lba
    };
    let mut backup_valid = false;
    if alt_lba <= last_lba && alt_lba > 1 {
        let mut bsec = vec![0u8; ss as usize];
        src.read_at(alt_lba * ss, &mut bsec)?;
        if let Ok(bh) = parse_gpt_header(&bsec, alt_lba) {
            if let Ok(be) = read_gpt_entries(src, &bh, ss, disk_size) {
                regions.push(RawRegion {
                    offset: bh.entries_lba * ss,
                    data: be,
                });
                regions.push(RawRegion {
                    offset: alt_lba * ss,
                    data: bsec,
                });
                backup_valid = true;
            }
        }
    }

    let mut parts = Vec::new();
    for i in 0..hdr.num_entries as usize {
        let e = &entries[i * hdr.entry_size as usize..i * hdr.entry_size as usize + 128];
        let type_guid = Uuid::from_bytes_le(e[0..16].try_into().unwrap());
        if type_guid.is_nil() {
            continue;
        }
        let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
        let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
        if last < first || last > last_lba {
            return Err(Error::malformed(format!(
                "GPT entry {} has invalid LBA range",
                i + 1
            )));
        }
        let name_u16: Vec<u16> = e[56..128]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        parts.push(PartitionEntry {
            number: i as u32 + 1,
            start: first * ss,
            length: (last - first + 1) * ss,
            type_guid: Some(type_guid),
            unique_guid: Some(Uuid::from_bytes_le(e[16..32].try_into().unwrap())),
            mbr_type: None,
            name: String::from_utf16_lossy(&name_u16),
            attributes: u64::from_le_bytes(e[48..56].try_into().unwrap()),
            bootable: false,
            role: role_for_gpt_type(&type_guid),
        });
    }
    Ok(PartitionTable {
        scheme: Scheme::Gpt,
        sector_size,
        disk_guid: Some(hdr.disk_guid),
        mbr_signature: None,
        first_usable_lba: Some(hdr.first_usable),
        last_usable_lba: Some(hdr.last_usable),
        backup_table_valid: backup_valid && from_primary,
        partitions: parts,
        raw_regions: regions,
    })
}

fn mbr_entry(e: &[u8]) -> (bool, u8, u64, u64) {
    (
        e[0] == 0x80,
        e[4],
        u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64,
        u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64,
    )
}

fn read_mbr(
    src: &dyn ReadAt,
    disk_size: u64,
    sector_size: u32,
    mbr: Vec<u8>,
) -> Result<PartitionTable> {
    let ss = sector_size as u64;
    let sig = u32::from_le_bytes(mbr[440..444].try_into().unwrap());
    let mut parts = Vec::new();
    let mut regions = vec![RawRegion {
        offset: 0,
        data: mbr.clone(),
    }];
    let mut extended_base = None;
    for i in 0..4 {
        let (boot, t, lba, count) = mbr_entry(&mbr[446 + i * 16..462 + i * 16]);
        if t == 0 || count == 0 {
            continue;
        }
        let role = role_for_mbr_type(t);
        if role == PartitionRole::Extended {
            extended_base = Some(lba);
        }
        parts.push(PartitionEntry {
            number: i as u32 + 1,
            start: lba * ss,
            length: count * ss,
            type_guid: None,
            unique_guid: None,
            mbr_type: Some(t),
            name: String::new(),
            attributes: 0,
            bootable: boot,
            role,
        });
    }
    if let Some(base) = extended_base {
        let mut ebr_lba = base;
        let mut number = 5;
        for _ in 0..MAX_EBR_CHAIN {
            if (ebr_lba + 1) * ss > disk_size {
                return Err(Error::malformed("EBR beyond end of disk"));
            }
            let mut ebr = vec![0u8; ss as usize];
            src.read_at(ebr_lba * ss, &mut ebr)?;
            if ebr[510] != 0x55 || ebr[511] != 0xAA {
                return Err(Error::malformed("EBR signature missing"));
            }
            regions.push(RawRegion {
                offset: ebr_lba * ss,
                data: ebr.clone(),
            });
            let (boot, t, rel, count) = mbr_entry(&ebr[446..462]);
            if t != 0 && count != 0 {
                parts.push(PartitionEntry {
                    number,
                    start: (ebr_lba + rel) * ss,
                    length: count * ss,
                    type_guid: None,
                    unique_guid: None,
                    mbr_type: Some(t),
                    name: String::new(),
                    attributes: 0,
                    bootable: boot,
                    role: role_for_mbr_type(t),
                });
                number += 1;
            }
            let (_, nt, next_rel, _) = mbr_entry(&ebr[462..478]);
            if nt == 0 || next_rel == 0 {
                break;
            }
            ebr_lba = base + next_rel;
        }
    }
    for p in &parts {
        if p.start + p.length > disk_size {
            return Err(Error::malformed(format!(
                "MBR partition {} extends beyond end of disk",
                p.number
            )));
        }
    }
    Ok(PartitionTable {
        scheme: Scheme::Mbr,
        sector_size,
        disk_guid: None,
        mbr_signature: Some(sig),
        first_usable_lba: None,
        last_usable_lba: None,
        backup_table_valid: true,
        partitions: parts,
        raw_regions: regions,
    })
}

/// Builders for synthetic disks used in tests across the workspace.
#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use super::*;

    pub struct GptPart {
        pub type_guid: Uuid,
        pub first_lba: u64,
        pub last_lba: u64,
        pub name: &'static str,
    }

    /// Write a valid GPT (protective MBR, primary and backup) into `disk`.
    pub fn write_gpt(disk: &mut [u8], ss: usize, disk_guid: Uuid, parts: &[GptPart]) {
        let n_entries = 128usize;
        let esz = 128usize;
        let total_lba = (disk.len() / ss) as u64;
        let last = total_lba - 1;
        let entries_sectors = (n_entries * esz).div_ceil(ss) as u64;

        let mut entries = vec![0u8; n_entries * esz];
        for (i, p) in parts.iter().enumerate() {
            let e = &mut entries[i * esz..(i + 1) * esz];
            e[0..16].copy_from_slice(&p.type_guid.to_bytes_le());
            e[16..32].copy_from_slice(&Uuid::from_u128(0x1000 + i as u128).to_bytes_le());
            e[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
            e[40..48].copy_from_slice(&p.last_lba.to_le_bytes());
            for (j, c) in p.name.encode_utf16().enumerate() {
                e[56 + j * 2..58 + j * 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        let ecrc = crc32fast::hash(&entries);

        let header = |my: u64, alt: u64, elba: u64| {
            let mut h = vec![0u8; ss];
            h[0..8].copy_from_slice(b"EFI PART");
            h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            h[12..16].copy_from_slice(&92u32.to_le_bytes());
            h[24..32].copy_from_slice(&my.to_le_bytes());
            h[32..40].copy_from_slice(&alt.to_le_bytes());
            h[40..48].copy_from_slice(&(2 + entries_sectors).to_le_bytes());
            h[48..56].copy_from_slice(&(last - 1 - entries_sectors).to_le_bytes());
            h[56..72].copy_from_slice(&disk_guid.to_bytes_le());
            h[72..80].copy_from_slice(&elba.to_le_bytes());
            h[80..84].copy_from_slice(&(n_entries as u32).to_le_bytes());
            h[84..88].copy_from_slice(&(esz as u32).to_le_bytes());
            h[88..92].copy_from_slice(&ecrc.to_le_bytes());
            let c = crc32fast::hash(&h[..92]);
            h[16..20].copy_from_slice(&c.to_le_bytes());
            h
        };

        // Protective MBR.
        let m = &mut disk[0..ss];
        m.fill(0);
        m[446 + 4] = 0xEE;
        m[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        m[446 + 12..446 + 16]
            .copy_from_slice(&((total_lba - 1).min(u32::MAX as u64) as u32).to_le_bytes());
        m[510] = 0x55;
        m[511] = 0xAA;

        let backup_elba = last - entries_sectors;
        disk[ss..2 * ss].copy_from_slice(&header(1, last, 2));
        disk[2 * ss..2 * ss + entries.len()].copy_from_slice(&entries);
        let bo = backup_elba as usize * ss;
        disk[bo..bo + entries.len()].copy_from_slice(&entries);
        disk[last as usize * ss..].copy_from_slice(&header(last, 1, backup_elba));
    }

    /// Write a classic MBR with up to four primary partitions.
    pub fn write_mbr(disk: &mut [u8], signature: u32, parts: &[(u8, u32, u32, bool)]) {
        let m = &mut disk[0..512];
        m[446..510].fill(0);
        m[440..444].copy_from_slice(&signature.to_le_bytes());
        for (i, &(t, lba, count, boot)) in parts.iter().enumerate() {
            let e = &mut m[446 + i * 16..462 + i * 16];
            e[0] = if boot { 0x80 } else { 0 };
            e[4] = t;
            e[8..12].copy_from_slice(&lba.to_le_bytes());
            e[12..16].copy_from_slice(&count.to_le_bytes());
        }
        m[510] = 0x55;
        m[511] = 0xAA;
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn gpt_disk(ss: usize) -> Vec<u8> {
        let mut d = vec![0u8; 64 * 1024 * 1024];
        let lba = |bytes: u64| bytes / ss as u64;
        write_gpt(
            &mut d,
            ss,
            Uuid::from_u128(42),
            &[
                GptPart {
                    type_guid: gpt_types::ESP,
                    first_lba: lba(1 << 20),
                    last_lba: lba(9 << 20) - 1,
                    name: "EFI system partition",
                },
                GptPart {
                    type_guid: gpt_types::MSR,
                    first_lba: lba(9 << 20),
                    last_lba: lba(10 << 20) - 1,
                    name: "Microsoft reserved partition",
                },
                GptPart {
                    type_guid: gpt_types::BASIC_DATA,
                    first_lba: lba(10 << 20),
                    last_lba: lba(60 << 20) - 1,
                    name: "Basic data partition",
                },
            ],
        );
        d
    }

    #[test]
    fn parses_gpt_512_and_4k() {
        for ss in [512usize, 4096] {
            let d = gpt_disk(ss);
            assert_eq!(detect_sector_size(&d, d.len() as u64), ss as u32);
            let t = read_table(&d, d.len() as u64, ss as u32).unwrap();
            assert_eq!(t.scheme, Scheme::Gpt);
            assert_eq!(t.disk_guid, Some(Uuid::from_u128(42)));
            assert!(t.backup_table_valid);
            assert_eq!(t.partitions.len(), 3);
            assert_eq!(t.partitions[0].role, PartitionRole::Esp);
            assert_eq!(t.partitions[0].name, "EFI system partition");
            assert_eq!(t.partitions[1].role, PartitionRole::Msr);
            assert_eq!(t.partitions[2].start, 10 << 20);
            assert_eq!(t.partitions[2].length, 50 << 20);
            // MBR + primary header + entries + backup entries + backup header.
            assert_eq!(t.raw_regions.len(), 5);
            let last = t
                .raw_regions
                .iter()
                .map(|r| r.offset + r.data.len() as u64)
                .max()
                .unwrap();
            assert_eq!(last, d.len() as u64);
        }
    }

    #[test]
    fn gpt_falls_back_to_backup_header() {
        let mut d = gpt_disk(512);
        d[512 + 30] ^= 0xFF; // corrupt primary header
        let t = read_table(&d, d.len() as u64, 512).unwrap();
        assert_eq!(t.partitions.len(), 3);
        assert!(!t.backup_table_valid);
    }

    #[test]
    fn gpt_entry_crc_checked() {
        let mut d = gpt_disk(512);
        d[1024 + 33] ^= 1; // primary entries
        let n = d.len();
        d[n - 512 - 32 * 512 + 33] ^= 1; // backup entries
        assert!(read_table(&d, d.len() as u64, 512).is_err());
    }

    #[test]
    fn parses_mbr() {
        let mut d = vec![0u8; 16 * 1024 * 1024];
        write_mbr(
            &mut d,
            0xDEADBEEF,
            &[(0x07, 2048, 4096, true), (0x83, 8192, 8192, false)],
        );
        let t = read_table(&d, d.len() as u64, 512).unwrap();
        assert_eq!(t.scheme, Scheme::Mbr);
        assert_eq!(t.mbr_signature, Some(0xDEADBEEF));
        assert_eq!(t.partitions.len(), 2);
        assert!(t.partitions[0].bootable);
        assert_eq!(t.partitions[1].start, 8192 * 512);
    }

    #[test]
    fn parses_mbr_logical_partitions() {
        let mut d = vec![0u8; 16 * 1024 * 1024];
        write_mbr(
            &mut d,
            1,
            &[(0x07, 2048, 2048, false), (0x05, 4096, 20000, false)],
        );
        // EBR 1 at 4096: logical at +2048, next EBR at base+8192.
        let mut ebr = |at: usize, rel: u32, cnt: u32, next: u32| {
            let o = at * 512;
            d[o + 446 + 4] = 0x83;
            d[o + 446 + 8..o + 446 + 12].copy_from_slice(&rel.to_le_bytes());
            d[o + 446 + 12..o + 446 + 16].copy_from_slice(&cnt.to_le_bytes());
            if next != 0 {
                d[o + 462 + 4] = 0x05;
                d[o + 462 + 8..o + 462 + 12].copy_from_slice(&next.to_le_bytes());
                d[o + 462 + 12..o + 462 + 16].copy_from_slice(&4096u32.to_le_bytes());
            }
            d[o + 510] = 0x55;
            d[o + 511] = 0xAA;
        };
        ebr(4096, 2048, 2048, 8192);
        ebr(4096 + 8192, 2048, 1024, 0);
        let t = read_table(&d, d.len() as u64, 512).unwrap();
        let nums: Vec<u32> = t.partitions.iter().map(|p| p.number).collect();
        assert_eq!(nums, vec![1, 2, 5, 6]);
        assert_eq!(t.partitions[3].start, (4096 + 8192 + 2048) * 512);
        assert_eq!(t.raw_regions.len(), 3);
    }

    #[test]
    fn ebr_loop_is_bounded() {
        let mut d = vec![0u8; 4 * 1024 * 1024];
        write_mbr(&mut d, 1, &[(0x05, 2048, 4096, false)]);
        let o = 2048 * 512;
        d[o + 462 + 4] = 0x05;
        d[o + 462 + 8..o + 462 + 12].copy_from_slice(&0u32.to_le_bytes()); // points to itself? 0 ends chain
        d[o + 510] = 0x55;
        d[o + 511] = 0xAA;
        assert!(read_table(&d, d.len() as u64, 512).is_ok());
    }

    #[test]
    fn random_and_mutated_input_never_panics() {
        let mut x = 0x2545F4914F6CDD1Du64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let base = gpt_disk(512);
        for i in 0..400 {
            let mut d = if i % 50 != 0 {
                base[..(1 << 20)].to_vec()
            } else {
                base.clone()
            };
            for _ in 0..(1 + rnd() % 64) {
                let pos = (rnd() % 40_000) as usize;
                let len = d.len();
                d[pos % len] = rnd() as u8;
            }
            let _ = read_table(&d, d.len() as u64, 512);
            let _ = read_table(&d, d.len() as u64 * 4, 4096); // claims larger than data
        }
    }

    #[test]
    fn unpartitioned_disk() {
        let d = vec![0u8; 1024 * 1024];
        assert_eq!(
            read_table(&d, d.len() as u64, 512).unwrap().scheme,
            Scheme::None
        );
    }

    #[test]
    fn fat_boot_sector_is_not_mbr() {
        let mut d = vec![0u8; 1024 * 1024];
        d[0] = 0xEB;
        d[3..11].copy_from_slice(b"MSDOS5.0");
        // Garbage in the entry area as a FAT boot sector would have.
        d[446..510].fill(0x41);
        d[510] = 0x55;
        d[511] = 0xAA;
        assert_eq!(
            read_table(&d, d.len() as u64, 512).unwrap().scheme,
            Scheme::None
        );
    }
}
