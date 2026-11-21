use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::io::ReadAt;
use core_format::{InitOptions, Repository};
use vdisk::testutil::{Block, Builder};
use vdisk::{Vhdx, VhdxSource};

const MIB: u64 = 1024 * 1024;

fn pat(seed: u8, len: u64) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn read_all(v: &Vhdx) -> Vec<u8> {
    let mut b = vec![0u8; v.info().virtual_size as usize];
    v.read_at(0, &mut b).unwrap();
    b
}

#[test]
fn dynamic_disk_reads_and_reports_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("d.vhdx");
    let mut b = Builder::new(8 * MIB + 512 * 3, MIB); // size not block-aligned
    b.blocks.insert(0, Block::Full(pat(1, MIB)));
    b.blocks.insert(3, Block::Zero);
    b.blocks.insert(8, Block::Full(pat(2, MIB)));
    b.write(&p);
    let v = Vhdx::open(&p).unwrap();
    assert_eq!(v.info().virtual_size, 8 * MIB + 1536);
    assert_eq!(v.info().chain.len(), 1);
    let d = read_all(&v);
    assert_eq!(&d[..MIB as usize], &pat(1, MIB)[..]);
    assert!(d[MIB as usize..8 * MIB as usize].iter().all(|&x| x == 0));
    assert_eq!(&d[8 * MIB as usize..], &pat(2, MIB)[..1536]);
    assert_eq!(
        v.allocated(),
        vec![
            core_format::Extent(0, MIB),
            core_format::Extent(8 * MIB, 1536)
        ]
    );
    // Unaligned read across a block boundary.
    let mut x = vec![0u8; 100];
    v.read_at(MIB - 50, &mut x).unwrap();
    assert_eq!(&x[..50], &pat(1, MIB)[MIB as usize - 50..]);
    assert!(x[50..].iter().all(|&b| b == 0));
    assert!(v.read_at(8 * MIB + 1500, &mut x).is_err());
}

fn chain(dir: &std::path::Path) -> (Vec<u8>, std::path::PathBuf, Builder) {
    let parent = dir.join("base.vhdx");
    let mut pb = Builder::new(4 * MIB, MIB);
    pb.blocks.insert(0, Block::Full(pat(10, MIB)));
    pb.blocks.insert(1, Block::Full(pat(11, MIB)));
    pb.write(&parent);

    let child = dir.join("child.avhdx");
    let mut cb = Builder::new(4 * MIB, MIB);
    cb.parent = Some((".\\base.vhdx".into(), pb.data_write_guid));
    // Block 1: sectors 0..8 and 100 from the child, rest from parent.
    let mut present = vec![false; (MIB / 512) as usize];
    for s in (0..8).chain([100]) {
        present[s] = true;
    }
    cb.blocks.insert(
        1,
        Block::Partial {
            data: pat(20, MIB),
            present,
        },
    );
    cb.blocks.insert(2, Block::Full(pat(21, MIB)));
    cb.write(&child);

    let mut expect = vec![0u8; 4 * MIB as usize];
    expect[..MIB as usize].copy_from_slice(&pat(10, MIB));
    expect[MIB as usize..2 * MIB as usize].copy_from_slice(&pat(11, MIB));
    let c = pat(20, MIB);
    for s in (0..8usize).chain([100]) {
        let o = MIB as usize + s * 512;
        expect[o..o + 512].copy_from_slice(&c[s * 512..s * 512 + 512]);
    }
    expect[2 * MIB as usize..3 * MIB as usize].copy_from_slice(&pat(21, MIB));
    (expect, child, pb)
}

#[test]
fn differencing_chain_merges_layers() {
    let dir = tempfile::tempdir().unwrap();
    let (expect, child, _) = chain(dir.path());
    let v = Vhdx::open(&child).unwrap();
    assert_eq!(v.info().chain.len(), 2);
    assert_eq!(read_all(&v), expect);
    assert_eq!(v.allocated(), vec![core_format::Extent(0, 3 * MIB)]);
}

#[test]
fn parent_changed_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_, child, mut pb) = chain(dir.path());
    pb.data_write_guid = uuid::Uuid::new_v4(); // parent rewritten after child was made
    pb.write(&dir.path().join("base.vhdx"));
    let e = Vhdx::open(&child).err().unwrap();
    assert!(e.to_string().contains("linkage"), "{e}");
}

#[test]
fn damaged_and_dirty_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("d.vhdx");
    let mut b = Builder::new(2 * MIB, MIB);
    b.blocks.insert(0, Block::Full(pat(3, MIB)));
    b.write(&p);
    // One header damaged: the other is used.
    let mut raw = std::fs::read(&p).unwrap();
    raw[128 * 1024 + 20] ^= 1;
    std::fs::write(&p, &raw).unwrap();
    assert!(Vhdx::open(&p).is_ok());
    raw[64 * 1024 + 20] ^= 1;
    std::fs::write(&p, &raw).unwrap();
    assert!(Vhdx::open(&p).is_err());

    b.log_guid = uuid::Uuid::new_v4();
    b.write(&p);
    assert!(Vhdx::open(&p).err().unwrap().to_string().contains("log"));

    std::fs::write(&p, vec![0u8; 2 * MIB as usize]).unwrap();
    assert!(Vhdx::open(&p).is_err());
}

#[test]
fn random_corruption_never_panics() {
    let dir = tempfile::tempdir().unwrap();
    let (_, child, _) = chain(dir.path());
    let orig = std::fs::read(&child).unwrap();
    let mut x = 88172645463325252u64;
    for _ in 0..200 {
        let mut d = orig.clone();
        for _ in 0..8 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Bias toward the metadata structures in the first 3 MiB.
            let i = (x % (3 * MIB)) as usize;
            d[i] ^= (x >> 32) as u8 | 1;
        }
        std::fs::write(&child, &d).unwrap();
        if let Ok(v) = Vhdx::open(&child) {
            let mut b = vec![0u8; 4096];
            let _ = v.read_at(MIB, &mut b);
        }
    }
}

#[test]
fn engine_backs_up_only_allocated_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let (expect, child, _) = chain(dir.path());
    let src = VhdxSource::open(&child, "vm disk 0").unwrap();
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("repo")).unwrap());
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
    let meta = engine::ImageMeta {
        machine: core_format::manifest::MachineInfo {
            machine_id: "hyperv-vm:x".into(),
            hostname: "vm".into(),
        },
        consistency: core_format::manifest::Consistency::Application,
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
    assert_eq!(
        r.stats.bytes_read,
        3 * MIB,
        "unallocated block 3 never read"
    );
    let m = repo.load_manifest(&r.image_id).unwrap();
    let out = dir.path().join("out.img");
    let c = engine::DestructiveConfirmation::confirmed_by_user(&out);
    let t = engine::FileTarget::open(&out, m.disks[0].size, true, &c).unwrap();
    engine::restore_disk(
        &repo,
        &m,
        0,
        &t,
        &Default::default(),
        &engine::JobControl::new(),
        &|_, _| {},
    )
    .unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), expect);
}

#[test]
fn restore_image_as_vhdx() {
    let dir = tempfile::tempdir().unwrap();
    let (expect, child, _) = chain(dir.path());
    let src = VhdxSource::open(&child, "vm disk").unwrap();
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("repo")).unwrap());
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
    let meta = engine::ImageMeta {
        machine: core_format::manifest::MachineInfo {
            machine_id: "m".into(),
            hostname: "vm".into(),
        },
        consistency: core_format::manifest::Consistency::Application,
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
    let d = &m.disks[0];
    let out = dir.path().join("restored.vhdx");
    let t = vdisk::VhdxTarget::create(
        &out,
        d.size,
        d.logical_sector_size,
        d.physical_sector_size,
        m.chunk_size,
    )
    .unwrap();
    engine::restore_disk(
        &repo,
        &m,
        0,
        &t,
        &engine::RestoreOptions {
            workers: 3,
            zero_fill: false,
        },
        &engine::JobControl::new(),
        &|_, _| {},
    )
    .unwrap();
    t.finish().unwrap();
    assert_eq!(read_all(&Vhdx::open(&out).unwrap()), expect);
    // Only the 3 MiB of data is allocated (one 32 MiB block), not the whole disk.
    assert!(std::fs::metadata(&out).unwrap().len() < 40 * MIB);
}
