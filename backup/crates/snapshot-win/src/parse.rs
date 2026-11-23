//! Platform-independent parsing of Windows structures, kept separate from
//! the FFI so it can be unit-tested anywhere.

use core_format::extent::{self, Extent};

/// Convert an NTFS volume bitmap (bit set = cluster in use, LSB first) into
/// absolute disk byte extents. `volume_offset` is the partition's start on
/// the disk.
pub fn bitmap_to_extents(
    bits: &[u8],
    start_lcn: u64,
    clusters: u64,
    cluster_size: u64,
    volume_offset: u64,
) -> Vec<Extent> {
    let mut out = Vec::new();
    let mut run_start: Option<u64> = None;
    for i in 0..clusters {
        let byte = bits.get((i / 8) as usize).copied().unwrap_or(0);
        let used = byte & (1 << (i % 8)) != 0;
        match (used, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(s)) => {
                out.push(Extent(
                    volume_offset + (start_lcn + s) * cluster_size,
                    (i - s) * cluster_size,
                ));
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = run_start {
        out.push(Extent(
            volume_offset + (start_lcn + s) * cluster_size,
            (clusters - s) * cluster_size,
        ));
    }
    extent::normalize(out)
}

/// Parse the header of a VOLUME_BITMAP_BUFFER: (StartingLcn, BitmapSize).
pub fn parse_bitmap_header(buf: &[u8]) -> Option<(i64, i64)> {
    Some((
        i64::from_le_bytes(buf.get(0..8)?.try_into().ok()?),
        i64::from_le_bytes(buf.get(8..16)?.try_into().ok()?),
    ))
}

/// Parse a RETRIEVAL_POINTERS_BUFFER into (starting VCN, [(next_vcn, lcn)]).
pub fn parse_retrieval_pointers(
    buf: &[u8],
    bytes_returned: usize,
) -> Option<(i64, Vec<(i64, i64)>)> {
    let buf = buf.get(..bytes_returned)?;
    let count = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    let start_vcn = i64::from_le_bytes(buf.get(8..16)?.try_into().ok()?);
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let o = 16 + i * 16;
        let next = i64::from_le_bytes(buf.get(o..o + 8)?.try_into().ok()?);
        let lcn = i64::from_le_bytes(buf.get(o + 8..o + 16)?.try_into().ok()?);
        v.push((next, lcn));
    }
    Some((start_vcn, v))
}

/// File runs (from retrieval pointers) to absolute disk extents. LCN -1
/// marks a sparse/compressed run with no clusters on disk.
pub fn runs_to_extents(
    start_vcn: i64,
    runs: &[(i64, i64)],
    cluster_size: u64,
    volume_offset: u64,
) -> Vec<Extent> {
    let mut out = Vec::new();
    let mut vcn = start_vcn;
    for &(next, lcn) in runs {
        if lcn >= 0 && next > vcn {
            out.push(Extent(
                volume_offset + lcn as u64 * cluster_size,
                (next - vcn) as u64 * cluster_size,
            ));
        }
        vcn = next;
    }
    out
}

/// Parse VOLUME_DISK_EXTENTS: [(disk_number, starting_offset, length)].
pub fn parse_disk_extents(buf: &[u8]) -> Option<Vec<(u32, u64, u64)>> {
    let n = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    // DISK_EXTENT is 24 bytes, array 8-byte aligned at offset 8.
    (0..n)
        .map(|i| {
            let o = 8 + i * 24;
            Some((
                u32::from_le_bytes(buf.get(o..o + 4)?.try_into().ok()?),
                i64::from_le_bytes(buf.get(o + 8..o + 16)?.try_into().ok()?) as u64,
                i64::from_le_bytes(buf.get(o + 16..o + 24)?.try_into().ok()?) as u64,
            ))
        })
        .collect()
}

/// Read a NUL-terminated ASCII string at `offset` in a descriptor buffer
/// (STORAGE_DEVICE_DESCRIPTOR); offset 0 means absent.
pub fn descriptor_string(buf: &[u8], offset: u32) -> String {
    if offset == 0 || offset as usize >= buf.len() {
        return String::new();
    }
    let s = &buf[offset as usize..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

/// A UEFI `Boot####` variable (EFI_LOAD_OPTION, UEFI spec 3.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    pub device_path_hex: String,
}

pub fn parse_load_option(buf: &[u8]) -> Option<LoadOption> {
    let attributes = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?);
    let dp_len = u16::from_le_bytes(buf.get(4..6)?.try_into().ok()?) as usize;
    let mut i = 6;
    let mut desc = Vec::new();
    loop {
        let c = u16::from_le_bytes(buf.get(i..i + 2)?.try_into().ok()?);
        i += 2;
        if c == 0 {
            break;
        }
        desc.push(c);
    }
    let dp = buf.get(i..i + dp_len)?;
    Some(LoadOption {
        attributes,
        description: String::from_utf16_lossy(&desc),
        device_path_hex: hex_encode(dp),
    })
}

/// UEFI `BootOrder`: array of u16 → "Boot0001" names.
pub fn parse_boot_order(buf: &[u8]) -> Vec<String> {
    buf.chunks_exact(2)
        .map(|c| format!("Boot{:04X}", u16::from_le_bytes([c[0], c[1]])))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Readable size of an NTFS volume from an NTFS_VOLUME_DATA_BUFFER:
/// TotalClusters × BytesPerCluster. A volume device serves whole clusters
/// only; the sectors after the last cluster (and the backup boot sector)
/// are outside it even though NumberSectors counts some of them.
pub fn ntfs_readable_bytes(buf: &[u8]) -> Option<u64> {
    if buf.len() < 48 {
        return None;
    }
    let sectors = i64::from_le_bytes(buf[8..16].try_into().ok()?);
    let clusters = i64::from_le_bytes(buf[16..24].try_into().ok()?);
    let bps = u32::from_le_bytes(buf[40..44].try_into().ok()?) as u64;
    let bpc = u32::from_le_bytes(buf[44..48].try_into().ok()?) as u64;
    if sectors <= 0 || clusters <= 0 || bps == 0 || bpc == 0 {
        return None;
    }
    Some((clusters as u64 * bpc).min(sectors as u64 * bps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_runs() {
        // clusters 0,1 used; 2..8 free; 8..12 used; 12 free; 13..16 used
        let bits = [0b0000_0011u8, 0b1110_1111];
        let e = bitmap_to_extents(&bits, 0, 16, 4096, 1 << 20);
        assert_eq!(
            e,
            vec![
                Extent(1 << 20, 8192),
                Extent((1 << 20) + 8 * 4096, 4 * 4096),
                Extent((1 << 20) + 13 * 4096, 3 * 4096)
            ]
        );
        // Bits past `clusters` are ignored.
        assert_eq!(
            bitmap_to_extents(&[0xFF], 0, 3, 512, 0),
            vec![Extent(0, 1536)]
        );
        // Non-zero starting LCN.
        assert_eq!(
            bitmap_to_extents(&[0x01], 100, 8, 512, 0),
            vec![Extent(51200, 512)]
        );
    }

    #[test]
    fn retrieval_pointers() {
        let mut b = vec![0u8; 16 + 3 * 16];
        b[0] = 3;
        b[8..16].copy_from_slice(&0i64.to_le_bytes());
        let runs = [(4i64, 100i64), (6, -1), (10, 200)];
        for (i, (n, l)) in runs.iter().enumerate() {
            b[16 + i * 16..24 + i * 16].copy_from_slice(&n.to_le_bytes());
            b[24 + i * 16..32 + i * 16].copy_from_slice(&l.to_le_bytes());
        }
        let (vcn, r) = parse_retrieval_pointers(&b, b.len()).unwrap();
        assert_eq!(r, runs.to_vec());
        assert_eq!(
            runs_to_extents(vcn, &r, 4096, 0),
            vec![Extent(100 * 4096, 4 * 4096), Extent(200 * 4096, 4 * 4096)]
        );
        assert!(parse_retrieval_pointers(&b, 20).is_none());
    }

    #[test]
    fn disk_extents() {
        let mut b = vec![0u8; 8 + 24];
        b[0] = 1;
        b[8..12].copy_from_slice(&2u32.to_le_bytes());
        b[16..24].copy_from_slice(&(1i64 << 20).to_le_bytes());
        b[24..32].copy_from_slice(&(5i64 << 20).to_le_bytes());
        assert_eq!(parse_disk_extents(&b).unwrap(), vec![(2, 1 << 20, 5 << 20)]);
    }

    #[test]
    fn load_option() {
        let mut b = vec![1, 0, 0, 0, 4, 0];
        for c in "Windows Boot Manager".encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0, 0x7f, 0xff, 0x04, 0x00]);
        let o = parse_load_option(&b).unwrap();
        assert_eq!(o.attributes, 1);
        assert_eq!(o.description, "Windows Boot Manager");
        assert_eq!(o.device_path_hex, "7fff0400");
        assert!(parse_load_option(&b[..10]).is_none());
        assert_eq!(
            parse_boot_order(&[1, 0, 0x10, 0]),
            vec!["Boot0001", "Boot0010"]
        );
    }

    #[test]
    fn descriptor_strings() {
        let mut b = vec![0u8; 64];
        b[40..47].copy_from_slice(b"Samsung");
        assert_eq!(descriptor_string(&b, 40), "Samsung");
        assert_eq!(descriptor_string(&b, 0), "");
        assert_eq!(descriptor_string(&b, 1000), "");
    }

    #[test]
    fn ntfs_readable_size_is_whole_clusters() {
        // Numbers from the Windows CI runner's C: drive: partition
        // 160939621888 bytes, NumberSectors = partition - 1 sector, 4 KiB
        // clusters; Windows reports the volume as 160939618304 bytes.
        let mut b = vec![0u8; 96];
        b[8..16].copy_from_slice(&(160939621376i64 / 512).to_le_bytes());
        b[16..24].copy_from_slice(&(160939618304i64 / 4096).to_le_bytes());
        b[40..44].copy_from_slice(&512u32.to_le_bytes());
        b[44..48].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(ntfs_readable_bytes(&b), Some(160939618304));
        assert_eq!(ntfs_readable_bytes(&b[..40]), None);
        b[44..48].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(ntfs_readable_bytes(&b), None);
    }
}
