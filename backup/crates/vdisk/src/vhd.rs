//! The 512-byte footer of a fixed VHD (Microsoft Virtual Hard Disk Image
//! Format Specification): the disk's bytes followed by this footer. Azure
//! creates managed disks from fixed VHDs whose size is a whole number of MiB.

/// Size rounded up to a whole MiB, as Azure requires of a VHD's disk.
pub fn azure_size(size: u64) -> u64 {
    size.div_ceil(1 << 20) * (1 << 20)
}

/// CHS geometry as the specification computes it.
fn geometry(size: u64) -> (u16, u8, u8) {
    let mut total = size / 512;
    if total > 65535 * 16 * 255 {
        total = 65535 * 16 * 255;
    }
    let (spt, heads, cth);
    if total >= 65535 * 16 * 63 {
        spt = 255u64;
        heads = 16u64;
        cth = total / spt;
    } else {
        let mut s = 17u64;
        let mut c = total / s;
        let mut h = c.div_ceil(1024);
        if h < 4 {
            h = 4;
        }
        if c >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            c = total / s;
        }
        if c >= h * 1024 {
            s = 63;
            h = 16;
            c = total / s;
        }
        spt = s;
        heads = h;
        cth = c;
    }
    ((cth / heads) as u16, heads as u8, spt as u8)
}

/// The footer of a fixed VHD holding `size` bytes (a multiple of 512).
pub fn fixed_footer(size: u64, unique_id: [u8; 16], now_unix: i64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(b"conectix");
    f[8..12].copy_from_slice(&2u32.to_be_bytes()); // features: reserved bit
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // version 1.0
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes()); // no dynamic header
    let since_2000 = (now_unix - 946_684_800).max(0) as u32;
    f[24..28].copy_from_slice(&since_2000.to_be_bytes());
    f[28..32].copy_from_slice(b"fnrr");
    f[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    f[36..40].copy_from_slice(b"Wi2k");
    f[40..48].copy_from_slice(&size.to_be_bytes()); // original size
    f[48..56].copy_from_slice(&size.to_be_bytes()); // current size
    let (c, h, s) = geometry(size);
    f[56..58].copy_from_slice(&c.to_be_bytes());
    f[58] = h;
    f[59] = s;
    f[60..64].copy_from_slice(&2u32.to_be_bytes()); // fixed hard disk
    f[68..84].copy_from_slice(&unique_id);
    let sum: u32 = f.iter().map(|&b| b as u32).sum();
    f[64..68].copy_from_slice(&(!sum).to_be_bytes());
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_fields_and_checksum() {
        let f = fixed_footer(64 << 20, [7; 16], 1_790_000_000);
        assert_eq!(&f[0..8], b"conectix");
        assert_eq!(u64::from_be_bytes(f[48..56].try_into().unwrap()), 64 << 20);
        assert_eq!(u32::from_be_bytes(f[60..64].try_into().unwrap()), 2);
        let stored = u32::from_be_bytes(f[64..68].try_into().unwrap());
        let mut g = f;
        g[64..68].fill(0);
        let sum: u32 = g.iter().map(|&b| b as u32).sum();
        assert_eq!(stored, !sum);
        assert_eq!(azure_size(1), 1 << 20);
        assert_eq!(azure_size(3 << 20), 3 << 20);
        // Geometry from the specification's algorithm (64 MiB: 131072 sectors,
        // 17 per track, 7710 cylinder-heads over 8 heads).
        assert_eq!(geometry(64 << 20), (963, 8, 17));
        // Large disks: 255 sectors per track and 16 heads, capped.
        assert_eq!(geometry(2 << 40), (65535, 16, 255));
    }

    #[test]
    fn qemu_reads_a_fixed_vhd() {
        let Ok(o) = std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
        else {
            return;
        };
        if !o.status.success() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("disk.vhd");
        let size = 32u64 << 20;
        let mut data = vec![0u8; size as usize];
        data[5 << 20..(5 << 20) + 4].copy_from_slice(b"FNRR");
        data.extend_from_slice(&fixed_footer(size, [1; 16], 1_790_000_000));
        std::fs::write(&p, &data).unwrap();
        let info = std::process::Command::new("qemu-img")
            .args(["info", "--output=json", "-f", "vpc", "-o", "force_size=on"])
            .arg(&p)
            .output()
            .unwrap();
        // Older qemu-img versions take force_size only with --image-opts.
        let info = if info.status.success() {
            info
        } else {
            std::process::Command::new("qemu-img")
                .args(["info", "--output=json", "--image-opts"])
                .arg(format!(
                    "driver=vpc,force_size_calc=current_size,file.filename={}",
                    p.display()
                ))
                .output()
                .unwrap()
        };
        assert!(
            info.status.success(),
            "{}",
            String::from_utf8_lossy(&info.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(v["virtual-size"].as_u64(), Some(size), "{v}");
        assert_eq!(v["format"], "vpc");
    }
}
