//! Image exports read by an independent NBD client (qemu-img / qemu-io).
//! Skipped when QEMU tools are missing.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use nbd_server::{Export, ImageExport, NbdServer};

const MIB: usize = 1 << 20;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn setup(dir: &std::path::Path) -> (Repository, core_format::ManifestBody, Vec<u8>) {
    let mut disk = vec![0u8; 20 * MIB + 4096];
    for (i, b) in disk[..9 * MIB].iter_mut().enumerate() {
        *b = (i * 13 % 241) as u8;
    }
    let n = disk.len();
    disk[n - 4096..].fill(0x5A);
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.join("repo")).unwrap());
    let (repo, _) = Repository::init(
        b,
        b"pw",
        InitOptions {
            chunk_size: 1 << 20,
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        },
    )
    .unwrap();
    let src = engine::ReadAtSource {
        inner: disk.clone(),
        info: engine::DiskInfo {
            size: disk.len() as u64,
            logical_sector_size: 512,
            ..Default::default()
        },
    };
    let meta = engine::ImageMeta {
        machine: core_format::manifest::MachineInfo {
            machine_id: "m".into(),
            hostname: "h".into(),
        },
        consistency: core_format::manifest::Consistency::Offline,
        os: Default::default(),
        boot: Default::default(),
        drivers: vec![],
        label: None,
        warnings: vec![],
        vm: None,
        applications: vec![],
    };
    let r = engine::backup(
        &repo,
        &[&src as &dyn engine::DiskSource],
        meta,
        &Default::default(),
        &engine::JobControl::new(),
        &|_| {},
    )
    .unwrap();
    let m = repo.load_manifest(&r.image_id).unwrap();
    (repo, m, disk)
}

#[test]
fn qemu_reads_an_image_export_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, m, disk) = setup(dir.path());
    let ex = ImageExport::new(&repo, &m, 0, 4 << 20).unwrap();
    assert_eq!(ex.size(), disk.len() as u64);
    // Direct reads across chunk boundaries and into absent (zero) chunks.
    let mut b = vec![0u8; 3 * MIB];
    ex.read_at((MIB - 100) as u64, &mut b).unwrap();
    assert_eq!(&b[..], &disk[MIB - 100..4 * MIB - 100]);
    let mut b = vec![1u8; 4096];
    ex.read_at((12 * MIB) as u64, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0));

    if !have("qemu-img") {
        eprintln!("qemu-img missing; skipping the independent-client part");
        return;
    }
    let mut exports: BTreeMap<String, Arc<dyn Export>> = BTreeMap::new();
    exports.insert("disk0".into(), Arc::new(ex));
    let srv = NbdServer::start(exports).unwrap();
    let out = dir.path().join("out.raw");
    let o = Command::new("qemu-img")
        .args(["convert", "-f", "raw", &srv.url("disk0")])
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        std::fs::read(&out).unwrap() == disk,
        "qemu-img read the export exactly"
    );

    if have("qemu-io") {
        let o = Command::new("qemu-io")
            .args(["-f", "raw", "-c", "write -P 0x11 0 512", &srv.url("disk0")])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            !o.status.success()
                || text.to_lowercase().contains("read-only")
                || text.contains("Operation not permitted"),
            "write must fail: {text}"
        );
        let o = Command::new("qemu-io")
            .args([
                "-r",
                "-f",
                "raw",
                "-c",
                "read -P 0x5a 20971520 4096",
                &srv.url("disk0"),
            ])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&o.stdout).contains("read 4096/4096"),
            "{}",
            String::from_utf8_lossy(&o.stdout)
        );
    }
    // The backup itself is unchanged.
    assert!(
        engine::verify(
            &repo,
            None,
            engine::VerifyLevel::Full,
            &engine::JobControl::new(),
            2
        )
        .unwrap()
        .ok
    );
}

#[test]
fn export_blocks_prune_while_open() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, m, _) = setup(dir.path());
    let ex = ImageExport::new(&repo, &m, 0, 4 << 20).unwrap();
    let e = engine::retention::prune(&repo, false, &engine::JobControl::new()).unwrap_err();
    assert!(e.to_string().contains("busy"), "{e}");
    drop(ex);
    engine::retention::prune(&repo, false, &engine::JobControl::new()).unwrap();
}
