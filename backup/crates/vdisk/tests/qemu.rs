//! Interoperability with an independent VHDX implementation (qemu-img).
//! Skipped when qemu-img is not installed.

use std::process::Command;

use core_format::io::ReadAt;
use vdisk::vhdx::Vhdx;
use vdisk::writer::VhdxWriter;

const MIB: u64 = 1024 * 1024;

fn qemu() -> bool {
    let ok = Command::new("qemu-img")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("qemu-img not installed; skipping");
    }
    ok
}

fn sample(size: u64) -> Vec<u8> {
    let mut d = vec![0u8; size as usize];
    for (i, b) in d[..5 * MIB as usize].iter_mut().enumerate() {
        *b = (i * 7 % 253) as u8;
    }
    let tail = d.len() - 8192;
    d[tail..].fill(0xA5);
    d[40 * MIB as usize..41 * MIB as usize].fill(0x11);
    d
}

#[test]
fn qemu_accepts_and_reads_our_vhdx() {
    if !qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // qemu supports only 512-byte logical sectors in VHDX; 4Kn output is
    // covered by our own round-trip test.
    for (logical, size) in [(512u32, 100 * MIB + 8192), (512, 64 * MIB)] {
        let data = sample(size);
        let p = dir.path().join(format!("ours-{logical}-{size}.vhdx"));
        let w = VhdxWriter::create(&p, size, logical, 4096, 32 * MIB).unwrap();
        for off in (0..size).step_by(MIB as usize) {
            let end = (off + MIB).min(size);
            w.write_at(off, &data[off as usize..end as usize]).unwrap();
        }
        w.finish().unwrap();
        let check = Command::new("qemu-img")
            .args(["check", "-f", "vhdx"])
            .arg(&p)
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "qemu-img check: {}{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
        let info = Command::new("qemu-img")
            .args(["info", "--output=json", "-f", "vhdx"])
            .arg(&p)
            .output()
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(info["virtual-size"].as_u64(), Some(size));
        let raw = dir.path().join(format!("ours-{logical}-{size}.raw"));
        let conv = Command::new("qemu-img")
            .args(["convert", "-f", "vhdx", "-O", "raw"])
            .arg(&p)
            .arg(&raw)
            .output()
            .unwrap();
        assert!(
            conv.status.success(),
            "{}",
            String::from_utf8_lossy(&conv.stderr)
        );
        assert!(
            std::fs::read(&raw).unwrap() == data,
            "qemu reads back exactly what we wrote ({logical})"
        );
    }
}

#[test]
fn we_read_vhdx_written_by_qemu() {
    if !qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let size = 96 * MIB;
    let data = sample(size);
    let raw = dir.path().join("in.raw");
    std::fs::write(&raw, &data).unwrap();
    for sub in ["dynamic", "fixed"] {
        let p = dir.path().join(format!("qemu-{sub}.vhdx"));
        let o = Command::new("qemu-img")
            .args([
                "convert",
                "-f",
                "raw",
                "-O",
                "vhdx",
                "-o",
                &format!("subformat={sub}"),
            ])
            .arg(&raw)
            .arg(&p)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v = Vhdx::open(&p).unwrap();
        assert_eq!(v.info().virtual_size, size);
        let mut got = vec![0u8; size as usize];
        v.read_at(0, &mut got).unwrap();
        assert!(got == data, "our reader matches qemu's {sub} VHDX");
    }
}
