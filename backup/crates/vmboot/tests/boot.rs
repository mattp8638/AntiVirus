#![cfg(unix)]
//! Boot images straight from a repository under QEMU.
//!
//! * `blank_disk_is_not_verified` runs wherever QEMU is installed.
//! * `cirros_boots_from_backup` needs a bootable raw image in
//!   `FENRIR_TEST_BOOT_IMAGE` (CI downloads CirrOS); skipped otherwise.

use std::sync::Arc;
use std::time::Duration;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use vmboot::{BootOptions, Outcome};

fn backup(dir: &std::path::Path, disk: Vec<u8>) -> (Repository, core_format::ManifestBody) {
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.join("repo")).unwrap());
    let (repo, _) = Repository::init(
        b,
        b"pw",
        InitOptions {
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        },
    )
    .unwrap();
    let src = engine::ReadAtSource {
        info: engine::DiskInfo {
            size: disk.len() as u64,
            logical_sector_size: 512,
            ..Default::default()
        },
        inner: disk,
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
    (repo, m)
}

fn host() -> Option<vmboot::HostSupport> {
    let h = vmboot::detect();
    if !h.usable() {
        eprintln!("skipped: QEMU is not installed");
        return None;
    }
    Some(h)
}

#[test]
fn blank_disk_is_not_verified() {
    let Some(h) = host() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (repo, m) = backup(dir.path(), vec![0u8; 8 << 20]);
    let mut o = BootOptions::for_host(&h);
    o.memory_mb = 256;
    o.cpus = 1;
    o.timeout = Duration::from_secs(120);
    o.min_boot = Duration::from_secs(20);
    o.stable_for = Duration::from_secs(15);
    let (r, s) = vmboot::boot_check(&repo, &m, &h, &o, &|| false, &|_| {}).unwrap();
    eprintln!("{r:?}");
    assert!(s.is_none());
    assert_ne!(r.outcome, Outcome::Verified);
    assert_eq!(r.outcome, Outcome::Failed, "{}", r.message);
    assert_eq!(r.firmware, "bios");
}

#[test]
fn cirros_boots_from_backup() {
    let Some(h) = host() else { return };
    let Some(path) = std::env::var_os("FENRIR_TEST_BOOT_IMAGE") else {
        eprintln!("skipped: FENRIR_TEST_BOOT_IMAGE not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let original = std::fs::read(path).unwrap();
    let (repo, m) = backup(dir.path(), original.clone());
    let mut o = BootOptions::for_host(&h);
    o.memory_mb = 512;
    o.cpus = 1;
    o.timeout = Duration::from_secs(if h.kvm { 300 } else { 900 });
    let (r, s) = vmboot::boot_check(&repo, &m, &h, &o, &|| false, &|p| eprintln!("{p}")).unwrap();
    eprintln!("{r:?}");
    assert!(s.is_none());
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.message);
    let png = r.screenshot_png.expect("screenshot");
    assert!(png.starts_with(b"\x89PNG"), "PNG screenshot");
    // The guest wrote to its overlay; the backup is untouched.
    let rep = engine::verify(
        &repo,
        Some(&[m.image_id]),
        engine::VerifyLevel::Full,
        &engine::JobControl::new(),
        2,
    )
    .unwrap();
    assert!(rep.ok, "{rep:?}");
    let ex = nbd_server::ImageExport::new(&repo, &m, 0, 8 << 20).unwrap();
    let mut back = vec![0u8; original.len()];
    nbd_server::Export::read_at(&ex, 0, &mut back).unwrap();
    assert!(back == original, "image content changed");
}

/// A restore test: the image restored in full to a raw file (read back and
/// matched to the backup), the VM booted from that file, and the file left
/// as restored (the guest writes to an overlay), ready to be deleted.
#[test]
fn cirros_boots_from_a_full_restore() {
    let Some(h) = host() else { return };
    let Some(path) = std::env::var_os("FENRIR_TEST_BOOT_IMAGE") else {
        eprintln!("skipped: FENRIR_TEST_BOOT_IMAGE not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let original = std::fs::read(path).unwrap();
    let (repo, m) = backup(dir.path(), original.clone());
    let raw = dir.path().join("restored").join("disk0.raw");
    std::fs::create_dir_all(raw.parent().unwrap()).unwrap();
    let c = engine::DestructiveConfirmation::confirmed_by_user(&raw);
    let t = engine::FileTarget::open(&raw, m.disks[0].size, true, &c).unwrap();
    let report = engine::restore_disk(
        &repo,
        &m,
        0,
        &t,
        &engine::RestoreOptions {
            workers: 2,
            zero_fill: false,
            fit: false,
            grow: false,
            verify: true,
        },
        &engine::JobControl::new(),
        &|_, _| {},
    )
    .unwrap();
    drop(t);
    let v = report.verification.expect("verified");
    assert!(
        v.supported && v.chunks_checked > 0 && v.mismatches == 0,
        "{v:?}"
    );

    let mut o = BootOptions::for_host(&h);
    o.memory_mb = 512;
    o.cpus = 1;
    o.timeout = Duration::from_secs(if h.kvm { 300 } else { 900 });
    o.disk_files = vec![raw.clone()];
    let (r, s) = vmboot::boot_check(&repo, &m, &h, &o, &|| false, &|p| eprintln!("{p}")).unwrap();
    eprintln!("{r:?}");
    assert!(s.is_none());
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.message);
    assert!(r
        .screenshot_png
        .expect("screenshot")
        .starts_with(b"\x89PNG"));
    assert!(
        std::fs::read(&raw).unwrap()[..original.len()] == original[..],
        "the restored disk is untouched"
    );
    std::fs::remove_dir_all(raw.parent().unwrap()).unwrap();
    assert!(!raw.exists());

    // A file per disk is required.
    o.disk_files = vec![raw.clone(), raw];
    assert!(vmboot::boot_check(&repo, &m, &h, &o, &|| false, &|_| {}).is_err());
}
