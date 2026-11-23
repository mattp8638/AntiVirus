//! A GPT disk with an NTFS and an ext4 volume is backed up with the real
//! engine into an encrypted repository; files are then listed and restored
//! from the backup without restoring the disk.

use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::fsdetect::FsType;
use core_format::partition::gpt_types;
use core_format::partition::testutil::{write_gpt, GptPart};
use core_format::{InitOptions, Repository};
use filebrowse::{Conflict, EntryKind, RestoreOptions};
use nbd_server::ImageExport;

const MIB: u64 = 1 << 20;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    zstd::decode_all(std::fs::File::open(p).unwrap()).unwrap()
}

fn big() -> Vec<u8> {
    (0..3 * MIB as usize)
        .map(|i| ((i * 31 + i / 4096) % 251) as u8)
        .collect()
}

/// 40 MiB disk: NTFS at 1–17 MiB, ext4 at 18–34 MiB.
fn backed_up(dir: &std::path::Path) -> (Repository, core_format::ManifestBody) {
    let mut disk = vec![0u8; (40 * MIB) as usize];
    let lba = |b: u64| b / 512;
    write_gpt(
        &mut disk,
        512,
        uuid::Uuid::from_u128(9),
        &[
            GptPart {
                type_guid: gpt_types::BASIC_DATA,
                first_lba: lba(MIB),
                last_lba: lba(17 * MIB) - 1,
                name: "Windows",
            },
            GptPart {
                type_guid: gpt_types::LINUX_FS,
                first_lba: lba(18 * MIB),
                last_lba: lba(34 * MIB) - 1,
                name: "home",
            },
        ],
    );
    let n = fixture("ntfs.img.zst");
    let e = fixture("ext4.img.zst");
    disk[MIB as usize..MIB as usize + n.len()].copy_from_slice(&n);
    disk[18 * MIB as usize..18 * MIB as usize + e.len()].copy_from_slice(&e);

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

fn check_volume(
    repo: &Repository,
    m: &core_format::ManifestBody,
    partition: u32,
    out: &std::path::Path,
) {
    let disk: Arc<dyn filebrowse::Disk> = Arc::new(ImageExport::new(repo, m, 0, 8 << 20).unwrap());
    let mut fs = filebrowse::open(m, disk, 0, partition).unwrap();

    let root = filebrowse::list(fs.as_mut(), "/", 1000).unwrap();
    assert!(
        root.entries
            .iter()
            .any(|e| e.name == "Users" && e.kind == EntryKind::Dir),
        "{root:?}"
    );
    assert!(
        !root.entries.iter().any(|e| e.name.starts_with('$')),
        "NTFS metadata files are hidden"
    );

    // Case-insensitive on NTFS, exact on ext.
    let docs = filebrowse::list(fs.as_mut(), "/Users/anna/Documents", 1000).unwrap();
    let names: Vec<_> = docs.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names[0], "Sub Folder", "folders first: {names:?}");
    assert!(
        names.contains(&"report.txt") && names.contains(&"Ünïcode ✓.txt"),
        "{names:?}"
    );
    let report = docs
        .entries
        .iter()
        .find(|e| e.name == "report.txt")
        .unwrap();
    assert_eq!(report.size, 17);
    assert_eq!(
        report.modified,
        Some(1_772_600_767),
        "2026-03-04 05:06:07 UTC"
    );
    assert!(filebrowse::list(fs.as_mut(), "/Users/../etc", 10).is_err());

    // Restore a file and a folder, keeping the folder structure.
    let opts = RestoreOptions {
        target: out.to_path_buf(),
        keep_structure: true,
        conflict: Conflict::Rename,
    };
    let paths = vec![
        "/Users/anna/Documents/report.txt".to_string(),
        "/Users/anna/Pictures".to_string(),
        "/Users/anna/Documents/Sub Folder".to_string(),
    ];
    let r = filebrowse::restore(fs.as_mut(), &paths, &opts, &|| false, &|_, _| {}).unwrap();
    assert_eq!(r.failed, vec![], "{r:?}");
    assert_eq!(r.files, 3);
    let d = out.join("Users/anna");
    assert_eq!(
        std::fs::read(d.join("Documents/report.txt")).unwrap(),
        b"quarterly report\n"
    );
    assert_eq!(
        std::fs::read(d.join("Documents/Sub Folder/notes.md")).unwrap(),
        b"# notes\nremember the milk\n"
    );
    assert_eq!(std::fs::read(d.join("Pictures/big.bin")).unwrap(), big());
    let mtime = std::fs::metadata(d.join("Documents/report.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_772_600_767
    );

    // Again: the existing file is kept and the backup copy written beside it.
    std::fs::write(d.join("Documents/report.txt"), b"edited since").unwrap();
    let r = filebrowse::restore(fs.as_mut(), &paths[..1], &opts, &|| false, &|_, _| {}).unwrap();
    assert_eq!((r.files, r.renamed), (1, 1));
    assert_eq!(
        std::fs::read(d.join("Documents/report.txt")).unwrap(),
        b"edited since"
    );
    assert_eq!(
        std::fs::read(d.join("Documents/report (restored).txt")).unwrap(),
        b"quarterly report\n"
    );
    // Skip leaves it; overwrite replaces it.
    let skip = RestoreOptions {
        conflict: Conflict::Skip,
        ..opts.clone()
    };
    assert_eq!(
        filebrowse::restore(fs.as_mut(), &paths[..1], &skip, &|| false, &|_, _| {})
            .unwrap()
            .skipped,
        1
    );
    let over = RestoreOptions {
        conflict: Conflict::Overwrite,
        ..opts.clone()
    };
    filebrowse::restore(fs.as_mut(), &paths[..1], &over, &|| false, &|_, _| {}).unwrap();
    assert_eq!(
        std::fs::read(d.join("Documents/report.txt")).unwrap(),
        b"quarterly report\n"
    );

    // Flat: straight into the target; cancellation stops and leaves no partial file.
    let flat = out.join("flat");
    let o = RestoreOptions {
        target: flat.clone(),
        keep_structure: false,
        conflict: Conflict::Rename,
    };
    filebrowse::restore(fs.as_mut(), &paths[1..2], &o, &|| false, &|_, _| {}).unwrap();
    assert!(flat.join("Pictures/big.bin").is_file());
    let c = out.join("cancelled");
    let o = RestoreOptions {
        target: c.clone(),
        ..o
    };
    assert!(matches!(
        filebrowse::restore(fs.as_mut(), &paths[1..2], &o, &|| true, &|_, _| {}),
        Err(filebrowse::Error::Cancelled)
    ));
    assert!(!c.join("Pictures/big.bin").exists());
}

#[test]
fn browse_and_restore_files_from_ntfs_and_ext4_backups() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, m) = backed_up(dir.path());
    let vols = filebrowse::volumes(&m);
    let fs: Vec<_> = vols
        .iter()
        .map(|v| (v.partition, v.filesystem, v.browsable))
        .collect();
    assert_eq!(fs, vec![(1, FsType::Ntfs, true), (2, FsType::Ext, true)]);

    check_volume(&repo, &m, 1, &dir.path().join("out-ntfs"));
    check_volume(&repo, &m, 2, &dir.path().join("out-ext"));

    // ext: the symlink is shown as a link and never followed or restored.
    let disk: Arc<dyn filebrowse::Disk> =
        Arc::new(ImageExport::new(&repo, &m, 0, 8 << 20).unwrap());
    let mut ext = filebrowse::open(&m, disk.clone(), 0, 2).unwrap();
    let anna = filebrowse::list(ext.as_mut(), "/Users/anna", 100).unwrap();
    assert_eq!(
        anna.entries.iter().find(|e| e.name == "link").unwrap().kind,
        EntryKind::Link
    );
    // NTFS lookups ignore case.
    let mut ntfs = filebrowse::open(&m, disk, 0, 1).unwrap();
    assert_eq!(
        filebrowse::list(ntfs.as_mut(), "/users/ANNA/documents", 100)
            .unwrap()
            .total,
        3
    );
    let out = dir.path().join("ci");
    let r = filebrowse::restore(
        ntfs.as_mut(),
        &["/USERS/anna/documents/REPORT.TXT".into()],
        &RestoreOptions {
            target: out.clone(),
            keep_structure: false,
            conflict: Conflict::Rename,
        },
        &|| false,
        &|_, _| {},
    )
    .unwrap();
    assert_eq!(r.files, 1);
}
