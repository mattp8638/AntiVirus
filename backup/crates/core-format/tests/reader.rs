//! The reference reader must reconstruct a disk from a repository written
//! through the library API, independent of the engine.

use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::extent::Extent;
use core_format::manifest::*;
use core_format::partition::{PartitionTable, Scheme};
use core_format::{InitOptions, Repository};

#[test]
fn reader_exports_sparse_disk() {
    let dir = tempfile::tempdir().unwrap();
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("r")).unwrap());
    let cs = 64 * 1024u32;
    let (repo, _) = Repository::init(
        b,
        b"pw",
        InitOptions {
            chunk_size: cs,
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        },
    )
    .unwrap();

    let size = 5 * cs as u64 + 1000; // last chunk is short
    let c1 = vec![1u8; cs as usize];
    let c4 = vec![4u8; 1000];
    let (i1, i4) = (repo.chunk_id(&c1), repo.chunk_id(&c4));
    repo.put_chunk(&i1, &c1).unwrap();
    repo.put_chunk(&i4, &c4).unwrap();
    let body = ManifestBody {
        format: BODY_FORMAT.into(),
        version: BODY_VERSION,
        image_id: uuid::Uuid::new_v4(),
        repo_id: repo.config().repo_id,
        created: "2026-11-20T00:00:00Z".into(),
        created_unix: 0,
        kind: ImageKind::Full,
        parent: None,
        label: None,
        machine: MachineInfo {
            machine_id: "m".into(),
            hostname: "h".into(),
        },
        consistency: Consistency::Offline,
        chunk_size: cs,
        hash: "blake3-keyed".into(),
        compression: "zstd".into(),
        encryption: "xchacha20poly1305".into(),
        disks: vec![DiskImage {
            index: 0,
            size,
            logical_sector_size: 512,
            physical_sector_size: 512,
            model: String::new(),
            serial: String::new(),
            device: String::new(),
            partition_table: PartitionTable {
                scheme: Scheme::None,
                sector_size: 512,
                disk_guid: None,
                mbr_signature: None,
                first_usable_lba: None,
                last_usable_lba: None,
                backup_table_valid: true,
                partitions: vec![],
                raw_regions: vec![],
            },
            partitions: vec![],
            used_extents: vec![Extent(0, size)],
            chunks: vec![ChunkRef(1, i1), ChunkRef(5, i4)],
        }],
        boot: BootConfig::default(),
        os: OsInfo::default(),
        drivers: vec![],
        excluded: vec![],
        warnings: vec![],
        stats: ImageStats::default(),
        vm: None,
        applications: vec![],
    };
    let signer = repo.signer_for_machine("m").unwrap();
    repo.store_manifest(&body, &signer).unwrap();

    let out = dir.path().join("disk.raw");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_fenrir-reader"))
        .args([
            dir.path().join("r").to_str().unwrap(),
            "export",
            &body.image_id.to_string(),
            "0",
            out.to_str().unwrap(),
        ])
        .env("FENRIR_PASSPHRASE", "pw")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let d = std::fs::read(&out).unwrap();
    let cs = cs as usize;
    assert_eq!(d.len() as u64, size);
    assert!(d[..cs].iter().all(|&b| b == 0));
    assert!(d[cs..2 * cs].iter().all(|&b| b == 1));
    assert!(d[2 * cs..5 * cs].iter().all(|&b| b == 0));
    assert!(d[5 * cs..].iter().all(|&b| b == 4));

    // Refuses to overwrite.
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_fenrir-reader"))
        .args([
            dir.path().join("r").to_str().unwrap(),
            "export",
            &body.image_id.to_string(),
            "0",
            out.to_str().unwrap(),
        ])
        .env("FENRIR_PASSPHRASE", "pw")
        .output()
        .unwrap();
    assert!(!o.status.success());
}
