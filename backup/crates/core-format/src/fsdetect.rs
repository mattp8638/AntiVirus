//! Identify a filesystem from its on-disk superblock signature.
//! Signatures are taken from the public specifications / kernel headers of
//! each filesystem; only magic numbers are checked, nothing is mounted.

use serde::{Deserialize, Serialize};

use crate::io::ReadAt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsType {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    Exfat,
    Ext,
    Xfs,
    Btrfs,
    Swap,
    Luks,
    Bitlocker,
    LvmPv,
    Refs,
    Unknown,
}

fn at(src: &dyn ReadAt, offset: u64, len: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; len];
    src.read_at(offset, &mut b).ok().map(|_| b)
}

/// `base` is the partition's byte offset in `src`; `len` its length.
pub fn detect(src: &dyn ReadAt, base: u64, len: u64) -> FsType {
    let Some(s0) = (len >= 512).then(|| at(src, base, 512)).flatten() else {
        return FsType::Unknown;
    };
    if &s0[3..11] == b"-FVE-FS-" {
        return FsType::Bitlocker;
    }
    if &s0[3..11] == b"NTFS    " {
        return FsType::Ntfs;
    }
    if &s0[3..11] == b"EXFAT   " {
        return FsType::Exfat;
    }
    if &s0[3..11] == b"ReFS\0\0\0\0" {
        return FsType::Refs;
    }
    if &s0[0..6] == b"LUKS\xba\xbe" {
        return FsType::Luks;
    }
    if &s0[0..4] == b"XFSB" {
        return FsType::Xfs;
    }
    if s0[510] == 0x55 && s0[511] == 0xAA {
        if &s0[82..87] == b"FAT32" {
            return FsType::Fat32;
        }
        if &s0[54..59] == b"FAT16" {
            return FsType::Fat16;
        }
        if &s0[54..59] == b"FAT12" {
            return FsType::Fat12;
        }
    }
    if len >= 2048 {
        if let Some(s1) = at(src, base + 512, 512) {
            if &s1[0..8] == b"LABELONE" && &s1[24..32] == b"LVM2 001" {
                return FsType::LvmPv;
            }
        }
        if let Some(sb) = at(src, base + 1024 + 56, 2) {
            if sb == [0x53, 0xEF] {
                return FsType::Ext;
            }
        }
    }
    if len >= 4096 {
        if let Some(sw) = at(src, base + 4096 - 10, 10) {
            if &sw == b"SWAPSPACE2" || &sw[..] == b"SWAP-SPACE" {
                return FsType::Swap;
            }
        }
    }
    if len >= 0x10040 + 8 {
        if let Some(b) = at(src, base + 0x10040, 8) {
            if &b == b"_BHRfS_M" {
                return FsType::Btrfs;
            }
        }
    }
    FsType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_signatures() {
        let mut d = vec![0u8; 0x20000];
        d[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(detect(&d, 0, d.len() as u64), FsType::Ntfs);

        let mut d = vec![0u8; 0x20000];
        d[82..87].copy_from_slice(b"FAT32");
        d[510] = 0x55;
        d[511] = 0xAA;
        assert_eq!(detect(&d, 0, d.len() as u64), FsType::Fat32);

        let mut d = vec![0u8; 0x20000];
        d[1024 + 56] = 0x53;
        d[1024 + 57] = 0xEF;
        assert_eq!(detect(&d, 0, d.len() as u64), FsType::Ext);

        let mut d = vec![0u8; 0x20000];
        d[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
        assert_eq!(detect(&d, 0, d.len() as u64), FsType::Btrfs);

        let d = vec![0u8; 0x20000];
        assert_eq!(detect(&d, 0, d.len() as u64), FsType::Unknown);
        // Truncated source.
        assert_eq!(detect(&d, 0x1FF00, 512), FsType::Unknown);
    }
}
