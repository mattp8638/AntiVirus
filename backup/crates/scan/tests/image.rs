//! A real backup (GPT disk with the NTFS and ext4 test volumes, backed up
//! with the engine into an encrypted repository) scanned through the image.

use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::partition::gpt_types;
use core_format::partition::testutil::{write_gpt, GptPart};
use core_format::{InitOptions, Repository};
use nbd_server::ImageExport;

const MIB: u64 = 1 << 20;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../filebrowse/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    zstd::decode_all(std::fs::File::open(p).unwrap()).unwrap()
}

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

#[test]
fn files_inside_ntfs_and_ext4_backups_are_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, m) = backed_up(dir.path());
    let disk: Arc<dyn filebrowse::Disk> =
        Arc::new(ImageExport::new(&repo, &m, 0, 8 << 20).unwrap());

    // What report.txt holds, read through the image.
    let mut ntfs = filebrowse::open(&m, disk.clone(), 0, 1).unwrap();
    let mut content = Vec::new();
    ntfs.copy("/Users/anna/Documents/report.txt", &mut content, &|| false)
        .unwrap();
    assert_eq!(content.len(), 17);
    let pattern: String = content[..8].iter().map(|b| format!("{b:02X} ")).collect();
    let rules = vec![scan::RuleSource {
        name: "fixture.yar".into(),
        source: format!("rule Report_Text {{ strings: $a = {{ {pattern} }} condition: $a }}"),
    }];

    let mut cache = scan::Cache::default();
    let opts = scan::Options {
        selection: scan::Selection::All,
        ..Default::default()
    };
    let mut report = scan::Report::default();
    // First pass without indicators finds the YARA match and learns hashes.
    let scanner = scan::Scanner::new(&[], &rules);
    for (part, label) in [(1u32, "C:\\"), (2, "/home")] {
        let mut fs = filebrowse::open(&m, disk.clone(), 0, part).unwrap();
        scan::scan_volume(
            fs.as_mut(),
            label,
            &scanner,
            &rules,
            &opts,
            &mut cache,
            &mut report,
            &mut |_, _| {},
            &|| false,
        )
        .unwrap();
    }
    let hits: Vec<&scan::Finding> = report
        .findings
        .iter()
        .filter(|f| f.path.ends_with("report.txt"))
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "both volumes hold report.txt: {:?}",
        report.findings
    );
    assert!(hits.iter().all(|f| f
        .detections
        .iter()
        .any(|d| d.name == "fixture.yar:Report_Text")));
    assert!(report.files_scanned > 2 && report.bytes_scanned > 0);

    // Its SHA-256 as an indicator, without the rule: found from the cache.
    let sha = hits[0].sha256.clone();
    let scanner = scan::Scanner::new(&[sha], &rules);
    let mut again = scan::Report::default();
    for (part, label) in [(1u32, "C:\\"), (2, "/home")] {
        let mut fs = filebrowse::open(&m, disk.clone(), 0, part).unwrap();
        scan::scan_volume(
            fs.as_mut(),
            label,
            &scanner,
            &rules,
            &opts,
            &mut cache,
            &mut again,
            &mut |_, _| {},
            &|| false,
        )
        .unwrap();
    }
    assert_eq!(again.bytes_scanned, 0, "nothing read again");
    assert!(again
        .findings
        .iter()
        .filter(|f| f.path.ends_with("report.txt"))
        .all(|f| f.detections.iter().any(|d| d.kind == "hash")));
}

#[test]
fn ntfs_and_ext4_backups_are_catalogued_and_searched() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, m) = backed_up(dir.path());
    let disk: Arc<dyn filebrowse::Disk> =
        Arc::new(ImageExport::new(&repo, &m, 0, 8 << 20).unwrap());
    let mut c = catalog::Catalogue::new();
    for (part, label) in [(1u32, "C:\\"), (2, "/home")] {
        let mut fs = filebrowse::open(&m, disk.clone(), 0, part).unwrap();
        c.add_volume(
            catalog::VolumeRef {
                label: label.into(),
                disk: 0,
                partition: part,
            },
            fs.as_mut(),
            &|| false,
        )
        .unwrap();
    }
    let q = catalog::Query::parse("report.txt").unwrap();
    let (hits, more) = catalog::search(&c, &q, 10);
    assert!(!more);
    assert_eq!(hits.len(), 2, "{hits:?}");
    assert!(hits
        .iter()
        .all(|h| h.path == "/Users/anna/Documents/report.txt" && h.size == 17));
    assert_eq!(
        hits.iter().map(|h| h.volume.partition).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(hits[0].modified, Some(1_772_600_767));
    let (folders, _) = catalog::search(&c, &catalog::Query::parse("anna/pictures").unwrap(), 10);
    assert!(folders.iter().any(|h| h.folder));
    assert!(!c
        .entries
        .iter()
        .any(|e| e.p.contains("/./") || e.p.ends_with("/.")));
}
