use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use core_format::backend::{Backend, LocalBackend, PutOutcome};
use core_format::crypto::KdfParams;
use core_format::extent::Extent;
use core_format::manifest::{
    BootConfig, CaptureMethod, Consistency, ImageKind, MachineInfo, OsInfo,
};
use core_format::partition::testutil::{write_gpt, write_mbr, GptPart};
use core_format::partition::{gpt_types, PartitionTable};
use core_format::{InitOptions, Repository};
use engine::*;
use uuid::Uuid;

const MIB: u64 = 1024 * 1024;
const CS: u32 = 1024 * 1024;

/// In-memory disk whose data partition (number 3) reports a used-block map,
/// as a VSS/bitmap source would.
struct MemDisk {
    data: RwLock<Vec<u8>>,
    used_in_data: Option<Vec<Extent>>,
}

impl DiskSource for MemDisk {
    fn info(&self) -> DiskInfo {
        DiskInfo {
            size: self.data.read().unwrap().len() as u64,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            ..Default::default()
        }
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        core_format::io::ReadAt::read_at(&*self.data.read().unwrap(), offset, buf)
    }
    fn capture_plan(&self, _t: &PartitionTable) -> io::Result<CapturePlan> {
        Ok(CapturePlan {
            partitions: vec![PartitionPlan {
                number: 3,
                used: self.used_in_data.clone(),
                capture: CaptureMethod::SnapshotBitmap,
                filesystem: None,
                volume: Some("vol3".into()),
                mount_points: vec!["C:\\".into()],
                encryption: None,
            }],
            ..Default::default()
        })
    }
}

fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// 32 MiB GPT disk: ESP 1–5 MiB, MSR 5–6 MiB, data 6–30 MiB.
/// Data partition used ranges: 6–10 MiB and 20–21.5 MiB; the rest of the
/// partition holds "deleted file" garbage that must not be stored.
fn make_disk() -> MemDisk {
    let mut d = pattern(1, (32 * MIB) as usize); // garbage everywhere
    let lba = |b: u64| b / 512;
    write_gpt(
        &mut d,
        512,
        Uuid::from_u128(7),
        &[
            GptPart {
                type_guid: gpt_types::ESP,
                first_lba: lba(MIB),
                last_lba: lba(5 * MIB) - 1,
                name: "EFI",
            },
            GptPart {
                type_guid: gpt_types::MSR,
                first_lba: lba(5 * MIB),
                last_lba: lba(6 * MIB) - 1,
                name: "MSR",
            },
            GptPart {
                type_guid: gpt_types::BASIC_DATA,
                first_lba: lba(6 * MIB),
                last_lba: lba(30 * MIB) - 1,
                name: "Windows",
            },
        ],
    );
    d[(6 * MIB) as usize + 3..(6 * MIB) as usize + 11].copy_from_slice(b"NTFS    ");
    MemDisk {
        data: RwLock::new(d),
        used_in_data: Some(vec![
            Extent(6 * MIB, 4 * MIB),
            Extent(20 * MIB, 3 * MIB / 2),
        ]),
    }
}

fn meta() -> ImageMeta {
    ImageMeta {
        machine: MachineInfo {
            machine_id: "test-machine".into(),
            hostname: "t".into(),
        },
        consistency: Consistency::Application,
        os: OsInfo {
            family: "windows".into(),
            ..Default::default()
        },
        boot: BootConfig::default(),
        drivers: vec![],
        label: None,
        warnings: vec![],
        vm: None,
        applications: vec![],
    }
}

fn new_repo(dir: &std::path::Path) -> Repository {
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.join("repo")).unwrap());
    Repository::init(
        b,
        b"pw",
        InitOptions {
            chunk_size: CS,
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        },
    )
    .unwrap()
    .0
}

fn run_backup(repo: &Repository, disk: &MemDisk) -> engine::Result<BackupReport> {
    backup(
        repo,
        &[disk as &dyn DiskSource],
        meta(),
        &BackupOptions {
            workers: 3,
            rate_limit: 0,
        },
        &JobControl::new(),
        &|_| {},
    )
}

fn restore_to(repo: &Repository, id: Uuid, path: &std::path::Path) -> RestoreReport {
    let m = repo.load_manifest(&id).unwrap();
    let c = DestructiveConfirmation::confirmed_by_user(path);
    let t = FileTarget::open(path, m.disks[0].size, true, &c).unwrap();
    restore_disk(
        repo,
        &m,
        0,
        &t,
        &RestoreOptions::default(),
        &JobControl::new(),
        &|_, _| {},
    )
    .unwrap()
}

fn in_extents(off: u64, ex: &[Extent]) -> bool {
    ex.iter().any(|e| off >= e.0 && off < e.end())
}

#[test]
fn backup_restore_roundtrip_is_exact_on_used_ranges() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let rep = run_backup(&repo, &disk).unwrap();
    assert_eq!(rep.kind, ImageKind::Full);

    let m = repo.load_manifest(&rep.image_id).unwrap();
    let d0 = &m.disks[0];
    assert_eq!(d0.partition_table.partitions.len(), 3);
    assert_eq!(d0.partitions[2].capture, CaptureMethod::SnapshotBitmap);
    assert_eq!(
        d0.partitions[2].filesystem,
        core_format::fsdetect::FsType::Ntfs
    );
    // ESP and MSR captured in full even though the source offered no plan.
    assert_eq!(d0.partitions[0].captured_bytes, 4 * MIB);
    assert_eq!(d0.partitions[1].captured_bytes, MIB);

    let out = dir.path().join("restored.img");
    restore_to(&repo, rep.image_id, &out);
    let restored = std::fs::read(&out).unwrap();
    let orig = disk.data.read().unwrap();
    assert_eq!(restored.len(), orig.len());
    for off in (0..orig.len() as u64).step_by(512) {
        let a = &orig[off as usize..off as usize + 512];
        let b = &restored[off as usize..off as usize + 512];
        if in_extents(off, &d0.used_extents) {
            assert_eq!(a, b, "used data differs at {off}");
        } else {
            assert!(b.iter().all(|&x| x == 0), "unused region at {off} not zero");
        }
    }
    // Partition table is byte-exact, including the backup GPT at the end.
    assert_eq!(&restored[..34 * 512], &orig[..34 * 512]);
    let n = orig.len();
    assert_eq!(&restored[n - 33 * 512..], &orig[n - 33 * 512..]);
    // Restored disk parses to the same table.
    let t = core_format::partition::read_table(&restored, n as u64, 512).unwrap();
    assert_eq!(t, d0.partition_table);
}

#[test]
fn second_backup_stores_only_changed_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let first = run_backup(&repo, &disk).unwrap();

    // Change one 4 KiB block inside a used range.
    disk.data.write().unwrap()[(7 * MIB) as usize..(7 * MIB) as usize + 4096].fill(0xAB);
    // Change "free space" garbage: must not cause any upload.
    disk.data.write().unwrap()[(15 * MIB) as usize..(16 * MIB) as usize].fill(0xCD);

    let second = run_backup(&repo, &disk).unwrap();
    assert_eq!(second.kind, ImageKind::Incremental);
    assert_eq!(second.parent, Some(first.image_id));
    assert_eq!(second.stats.chunks_new, 1, "only the modified chunk is new");
    assert!(second.stats.chunks_total > 1);

    let out = dir.path().join("r2.img");
    restore_to(&repo, second.image_id, &out);
    let restored = std::fs::read(&out).unwrap();
    assert!(restored[(7 * MIB) as usize..(7 * MIB) as usize + 4096]
        .iter()
        .all(|&b| b == 0xAB));
    assert!(restored[(15 * MIB) as usize..(16 * MIB) as usize]
        .iter()
        .all(|&b| b == 0));

    // The first image still restores to its own content.
    let out1 = dir.path().join("r1.img");
    restore_to(&repo, first.image_id, &out1);
    assert!(
        !std::fs::read(&out1).unwrap()[(7 * MIB) as usize..(7 * MIB) as usize + 4096]
            .iter()
            .all(|&b| b == 0xAB)
    );
}

#[test]
fn zero_chunks_are_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    disk.data.write().unwrap()[(20 * MIB) as usize..(22 * MIB) as usize].fill(0);
    let r = run_backup(&repo, &disk).unwrap();
    let m = repo.load_manifest(&r.image_id).unwrap();
    assert!(!m.disks[0].chunks.iter().any(|c| c.0 == 20 || c.0 == 21));
    // A used disk as target: zero-fill must clear those ranges.
    let out = dir.path().join("dirty.img");
    std::fs::write(&out, vec![0xEEu8; (32 * MIB) as usize]).unwrap();
    restore_to(&repo, r.image_id, &out);
    let restored = std::fs::read(&out).unwrap();
    assert!(restored[(20 * MIB) as usize..(21 * MIB + MIB / 2) as usize]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn verify_detects_corrupt_and_missing_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let r = run_backup(&repo, &disk).unwrap();
    let ctl = JobControl::new();
    assert!(verify(&repo, None, VerifyLevel::Full, &ctl, 2).unwrap().ok);

    let m = repo.load_manifest(&r.image_id).unwrap();
    let victim = m.disks[0].chunks[3].1;
    let path = dir.path().join("repo").join(victim.object_key());
    let mut raw = std::fs::read(&path).unwrap();
    let n = raw.len();
    raw[n / 2] ^= 0x01;
    std::fs::write(&path, &raw).unwrap();

    let quick = verify(&repo, None, VerifyLevel::Quick, &ctl, 2).unwrap();
    assert!(quick.ok, "quick verify does not read chunk contents");
    let full = verify(&repo, None, VerifyLevel::Full, &ctl, 2).unwrap();
    assert!(!full.ok);
    assert_eq!(full.corrupt_chunks.len(), 1);
    assert_eq!(full.corrupt_chunks[0].chunk, victim.to_hex());
    assert_eq!(full.corrupt_chunks[0].images, vec![r.image_id]);

    // Restore must fail loudly, not write corrupt data silently.
    let out = dir.path().join("x.img");
    let c = DestructiveConfirmation::confirmed_by_user(&out);
    let t = FileTarget::open(&out, m.disks[0].size, true, &c).unwrap();
    assert!(restore_disk(
        &repo,
        &m,
        0,
        &t,
        &RestoreOptions::default(),
        &JobControl::new(),
        &|_, _| {}
    )
    .is_err());

    std::fs::remove_file(&path).unwrap();
    let quick = verify(&repo, None, VerifyLevel::Quick, &ctl, 2).unwrap();
    assert!(!quick.ok);
    assert_eq!(quick.missing_chunks.len(), 1);
}

/// Backend that fails every chunk upload after `fail_after` successes,
/// simulating a dropped network or a killed agent.
struct FlakyBackend {
    inner: LocalBackend,
    puts: AtomicUsize,
    fail_after: usize,
}

impl Backend for FlakyBackend {
    fn put(&self, key: &str, data: &[u8]) -> core_format::Result<PutOutcome> {
        if key.starts_with("chunks/") && self.puts.fetch_add(1, Ordering::SeqCst) >= self.fail_after
        {
            return Err(core_format::Error::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected network failure",
            )));
        }
        self.inner.put(key, data)
    }
    fn get(&self, key: &str) -> core_format::Result<Vec<u8>> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> core_format::Result<bool> {
        self.inner.exists(key)
    }
    fn list(&self, prefix: &str) -> core_format::Result<Vec<String>> {
        self.inner.list(prefix)
    }
    fn delete(&self, key: &str) -> core_format::Result<()> {
        self.inner.delete(key)
    }
    fn describe(&self) -> String {
        "flaky".into()
    }
}

#[test]
fn interrupted_backup_leaves_no_manifest_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let flaky: Arc<dyn Backend> = Arc::new(FlakyBackend {
        inner: LocalBackend::open(dir.path().join("repo")).unwrap(),
        puts: AtomicUsize::new(0),
        fail_after: 4,
    });
    let flaky_repo = Repository::unlock_with_passphrase(flaky, b"pw").unwrap();
    let err = run_backup(&flaky_repo, &disk).unwrap_err();
    assert!(err.to_string().contains("injected"), "{err}");
    assert!(
        repo.list_image_ids().unwrap().is_empty(),
        "no manifest after failure"
    );
    let stored_before = repo.backend().list("chunks").unwrap().len();
    assert!(stored_before >= 4);

    let r = run_backup(&repo, &disk).unwrap();
    assert_eq!(
        r.stats.chunks_new as usize + stored_before,
        r.stats.chunks_total as usize
    );
    assert!(
        verify(&repo, None, VerifyLevel::Full, &JobControl::new(), 2)
            .unwrap()
            .ok
    );
}

#[test]
fn cancelled_backup_writes_no_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let ctl = JobControl::new();
    ctl.cancel();
    let e = backup(
        &repo,
        &[&disk as &dyn DiskSource],
        meta(),
        &BackupOptions::default(),
        &ctl,
        &|_| {},
    )
    .unwrap_err();
    assert!(matches!(e, EngineError::Cancelled));
    assert!(repo.list_image_ids().unwrap().is_empty());
}

#[test]
fn restore_refuses_mismatched_confirmation_and_small_target() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let r = run_backup(&repo, &disk).unwrap();
    let m = repo.load_manifest(&r.image_id).unwrap();

    let a = dir.path().join("a.img");
    let b = dir.path().join("b.img");
    let c = DestructiveConfirmation::confirmed_by_user(&a);
    assert!(matches!(
        FileTarget::open(&b, 1, true, &c),
        Err(EngineError::Safety(_))
    ));
    assert!(!b.exists(), "nothing created on refusal");

    struct Small;
    impl WriteTarget for Small {
        fn size(&self) -> u64 {
            MIB
        }
        fn write_at(&self, _: u64, _: &[u8]) -> io::Result<()> {
            panic!("must not write")
        }
        fn sync(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "small".into()
        }
    }
    let e = restore_disk(
        &repo,
        &m,
        0,
        &Small,
        &RestoreOptions::default(),
        &JobControl::new(),
        &|_, _| {},
    )
    .unwrap_err();
    assert!(matches!(e, EngineError::Safety(_)));
}

#[test]
fn mbr_disk_without_plan_is_captured_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let mut d = pattern(9, (16 * MIB) as usize);
    // Sectors 2048.. : one partition 1–9 MiB; 9–16 MiB unpartitioned.
    write_mbr(&mut d, 0x1234_5678, &[(0x83, 2048, 16384, true)]);
    let src = ReadAtSource {
        inner: d.clone(),
        info: DiskInfo {
            size: d.len() as u64,
            logical_sector_size: 512,
            ..Default::default()
        },
    };
    let r = backup(
        &repo,
        &[&src as &dyn DiskSource],
        meta(),
        &BackupOptions::default(),
        &JobControl::new(),
        &|_| {},
    )
    .unwrap();
    let m = repo.load_manifest(&r.image_id).unwrap();
    assert_eq!(
        m.disks[0].used_extents,
        vec![Extent(0, 9 * MIB)],
        "MBR gap + partition, not the unpartitioned tail"
    );
    let out = dir.path().join("mbr.img");
    restore_to(&repo, r.image_id, &out);
    assert_eq!(
        &std::fs::read(&out).unwrap()[..(9 * MIB) as usize],
        &d[..(9 * MIB) as usize]
    );
}

#[test]
fn image_with_two_disks() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let a = make_disk();
    let b = ReadAtSource {
        inner: pattern(3, (4 * MIB) as usize),
        info: DiskInfo {
            size: 4 * MIB,
            logical_sector_size: 512,
            ..Default::default()
        },
    };
    let r = backup(
        &repo,
        &[&a as &dyn DiskSource, &b],
        meta(),
        &BackupOptions::default(),
        &JobControl::new(),
        &|_| {},
    )
    .unwrap();
    let m = repo.load_manifest(&r.image_id).unwrap();
    assert_eq!(m.disks.len(), 2);
    assert_eq!(
        m.disks[1].used_extents,
        vec![Extent(0, 4 * MIB)],
        "unpartitioned disk captured whole"
    );
}

// ---------- retention, prune and locks ----------

#[test]
fn forget_and_prune_free_space_but_keep_retained_images_intact() {
    use engine::retention::{forget, prune, RetentionPolicy};
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let mut ids = vec![];
    for round in 0..3u8 {
        // Each round rewrites a different used megabyte with new content.
        let off = ((6 + round as u64) * MIB) as usize;
        disk.data.write().unwrap()[off..off + MIB as usize]
            .copy_from_slice(&pattern(100 + round as u64, MIB as usize));
        ids.push(run_backup(&repo, &disk).unwrap().image_id);
    }
    let before = repo.backend().list("chunks").unwrap().len();
    let latest_disk = disk.data.read().unwrap().clone();

    let r = forget(
        &repo,
        &[],
        &RetentionPolicy {
            keep_last: 1,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(r.removed.len(), 2);
    assert_eq!(repo.list_image_ids().unwrap(), vec![ids[2]]);

    let dry = prune(&repo, true, &JobControl::new()).unwrap();
    assert!(
        dry.chunks_deleted >= 2,
        "chunks unique to forgotten images: {dry:?}"
    );
    assert_eq!(
        repo.backend().list("chunks").unwrap().len(),
        before,
        "dry run deletes nothing"
    );

    let p = prune(&repo, false, &JobControl::new()).unwrap();
    assert_eq!(p.chunks_deleted, dry.chunks_deleted);
    assert!(p.bytes_deleted > 0);
    assert_eq!(
        repo.backend().list("chunks").unwrap().len(),
        before - p.chunks_deleted
    );

    // The retained image is complete: full verify and a byte-exact restore.
    assert!(
        verify(&repo, None, VerifyLevel::Full, &JobControl::new(), 2)
            .unwrap()
            .ok
    );
    let out = dir.path().join("latest.img");
    restore_to(&repo, ids[2], &out);
    let m = repo.load_manifest(&ids[2]).unwrap();
    let restored = std::fs::read(&out).unwrap();
    for e in &m.disks[0].used_extents {
        assert_eq!(
            &restored[e.0 as usize..e.end() as usize],
            &latest_disk[e.0 as usize..e.end() as usize]
        );
    }
    // Nothing left to prune.
    assert_eq!(
        prune(&repo, false, &JobControl::new())
            .unwrap()
            .chunks_deleted,
        0
    );
}

#[test]
fn prune_refuses_when_a_manifest_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    let id = run_backup(&repo, &disk).unwrap().image_id;
    // A chunk nobody references, and a damaged manifest.
    let orphan = vec![9u8; 4096];
    repo.put_chunk(&repo.chunk_id(&orphan), &orphan).unwrap();
    let mpath = dir
        .path()
        .join("repo")
        .join("manifests")
        .join(id.to_string());
    let mut raw = std::fs::read(&mpath).unwrap();
    let n = raw.len();
    raw[n - 3] ^= 1;
    std::fs::write(&mpath, raw).unwrap();
    let before = repo.backend().list("chunks").unwrap().len();
    let e = engine::retention::prune(&repo, false, &JobControl::new()).unwrap_err();
    assert!(matches!(e, EngineError::Safety(_)), "{e}");
    assert_eq!(
        repo.backend().list("chunks").unwrap().len(),
        before,
        "nothing deleted"
    );
}

#[test]
fn prune_and_backup_exclude_each_other() {
    use core_format::lock::LockKind;
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    {
        let _backup_running = repo.lock(LockKind::Shared).unwrap();
        let e = engine::retention::prune(&repo, false, &JobControl::new()).unwrap_err();
        assert!(e.to_string().contains("busy"), "{e}");
    }
    {
        let _prune_running = repo.lock(LockKind::Exclusive).unwrap();
        let e = run_backup(&repo, &disk).unwrap_err();
        assert!(e.to_string().contains("pruned"), "{e}");
        assert!(repo.list_image_ids().unwrap().is_empty());
    }
    // Locks were released: both work now.
    run_backup(&repo, &disk).unwrap();
    engine::retention::prune(&repo, false, &JobControl::new()).unwrap();
    assert!(core_format::lock::list_locks(&**repo.backend())
        .unwrap()
        .is_empty());
}

#[test]
fn stats_record_raw_and_stored_bytes_of_new_data() {
    let dir = tempfile::tempdir().unwrap();
    let repo = new_repo(dir.path());
    let disk = make_disk();
    // Highly compressible content in one used range.
    disk.data.write().unwrap()[(20 * MIB) as usize..(21 * MIB) as usize].fill(0x41);
    let r = run_backup(&repo, &disk).unwrap();
    assert_eq!(r.stats.bytes_new_raw, r.stats.chunks_new * MIB);
    assert!(r.stats.bytes_new_stored < r.stats.bytes_new_raw);
}

/// Storage with object locks (S3 Object Lock): deletes of locked objects
/// are refused, locks are extended.
struct LockedBackend {
    inner: LocalBackend,
    locked: std::sync::Mutex<std::collections::HashSet<String>>,
    extended: std::sync::Mutex<Vec<String>>,
}

impl Backend for LockedBackend {
    fn put(&self, key: &str, data: &[u8]) -> core_format::Result<PutOutcome> {
        if !key.starts_with("locks/") {
            self.locked.lock().unwrap().insert(key.to_string());
        }
        self.inner.put(key, data)
    }
    fn get(&self, key: &str) -> core_format::Result<Vec<u8>> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> core_format::Result<bool> {
        self.inner.exists(key)
    }
    fn list(&self, prefix: &str) -> core_format::Result<Vec<String>> {
        self.inner.list(prefix)
    }
    fn delete(&self, key: &str) -> core_format::Result<()> {
        if self.locked.lock().unwrap().contains(key) {
            return Err(core_format::Error::Retained(key.to_string()));
        }
        self.inner.delete(key)
    }
    fn describe(&self) -> String {
        "locked".into()
    }
    fn lock_days(&self) -> Option<u32> {
        Some(30)
    }
    fn extend_lock(&self, key: &str) -> core_format::Result<bool> {
        self.extended.lock().unwrap().push(key.to_string());
        Ok(true)
    }
}

#[test]
fn object_locks_keep_objects_until_they_expire_and_are_extended() {
    use engine::retention::{forget, prune, RetentionPolicy};
    let dir = tempfile::tempdir().unwrap();
    drop(new_repo(dir.path()));
    let lb = Arc::new(LockedBackend {
        inner: LocalBackend::open(dir.path().join("repo")).unwrap(),
        locked: Default::default(),
        extended: Default::default(),
    });
    let b: Arc<dyn Backend> = lb.clone();
    let repo = Repository::unlock_with_passphrase(b, b"pw").unwrap();
    let disk = make_disk();
    let mut ids = vec![];
    for round in 0..2u8 {
        let off = ((6 + round as u64) * MIB) as usize;
        disk.data.write().unwrap()[off..off + MIB as usize]
            .copy_from_slice(&pattern(200 + round as u64, MIB as usize));
        ids.push(run_backup(&repo, &disk).unwrap().image_id);
    }
    let keep_last = RetentionPolicy {
        keep_last: 1,
        ..Default::default()
    };
    // Every object was written by this backend, so every one is locked.
    let r = forget(&repo, &[], &keep_last, false).unwrap();
    assert!(r.removed.is_empty());
    assert_eq!(
        r.retained,
        vec![ids[0]],
        "the old image stays until its lock expires"
    );
    assert_eq!(repo.list_image_ids().unwrap().len(), 2);

    // The lock expires: the next run removes it.
    lb.locked.lock().unwrap().clear();
    let r = forget(&repo, &[], &keep_last, false).unwrap();
    assert_eq!(r.removed, vec![ids[0]]);

    // Chunks only the old image used: kept while locked, and everything
    // still used gets its lock extended.
    for k in repo.backend().list("chunks").unwrap() {
        lb.locked.lock().unwrap().insert(k);
    }
    let p = prune(&repo, false, &JobControl::new()).unwrap();
    assert_eq!(p.chunks_deleted, 0);
    assert!(p.chunks_retained >= 1, "{p:?}");
    let ext = lb.extended.lock().unwrap().clone();
    assert!(ext.contains(&"config.json".to_string()));
    assert!(ext.contains(&format!("manifests/{}", ids[1])));
    let m = repo.load_manifest(&ids[1]).unwrap();
    for c in m.chunk_ids() {
        assert!(
            ext.contains(&c.object_key()),
            "chunk {} in use is extended",
            c.object_key()
        );
    }
    assert_eq!(p.locks_extended, ext.len());
    // A dry run neither deletes nor extends.
    lb.extended.lock().unwrap().clear();
    prune(&repo, true, &JobControl::new()).unwrap();
    assert!(lb.extended.lock().unwrap().is_empty());
    // Expired: now reclaimed, and the remaining image is intact.
    lb.locked.lock().unwrap().clear();
    let p = prune(&repo, false, &JobControl::new()).unwrap();
    assert!(p.chunks_deleted >= 1 && p.chunks_retained == 0);
    assert!(
        verify(&repo, None, VerifyLevel::Full, &JobControl::new(), 2)
            .unwrap()
            .ok
    );
}

#[test]
fn copy_to_another_repository_restores_identically() {
    let dir = tempfile::tempdir().unwrap();
    let src = new_repo(&dir.path().join("a"));
    let dst = new_repo(&dir.path().join("b"));
    let disk = make_disk();
    let first = run_backup(&src, &disk).unwrap();
    disk.data.write().unwrap()[(7 * MIB) as usize..(7 * MIB) as usize + 4096].fill(0xAB);
    let second = run_backup(&src, &disk).unwrap();
    // A copy has its own ID in each destination, derived from the source image.
    let id_in = |r: &Repository, id: Uuid| engine::copy::copy_id(r.config().repo_id, id);

    let r =
        engine::copy::copy_images(&src, &dst, None, true, &JobControl::new(), &|_, _| {}).unwrap();
    assert_eq!(
        r.copied,
        vec![id_in(&dst, first.image_id), id_in(&dst, second.image_id)],
        "oldest first"
    );
    assert!(r.verified);
    let total: usize = src
        .load_manifest(&second.image_id)
        .unwrap()
        .disks
        .iter()
        .map(|d| d.chunks.len())
        .sum();
    assert!(
        r.chunks_written > 0 && (r.chunks_written as usize) < 2 * total,
        "shared chunks once"
    );
    // The copy keeps the chain and restores to the same bytes as the source.
    let copied = dst.load_manifest(&id_in(&dst, second.image_id)).unwrap();
    assert_eq!(copied.parent, Some(id_in(&dst, first.image_id)));
    assert_eq!(copied.repo_id, dst.config().repo_id);
    let (a, b) = (
        dir.path().join("from-src.img"),
        dir.path().join("from-dst.img"),
    );
    restore_to(&src, second.image_id, &a);
    restore_to(&dst, id_in(&dst, second.image_id), &b);
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    // Different keys: the destination's chunk objects are not the source's.
    let names = |r: &Repository| -> std::collections::HashSet<String> {
        r.backend().list("chunks/").unwrap().into_iter().collect()
    };
    assert!(names(&src).is_disjoint(&names(&dst)));

    // Again: nothing to do.
    let r =
        engine::copy::copy_images(&src, &dst, None, false, &JobControl::new(), &|_, _| {}).unwrap();
    assert!(r.copied.is_empty() && r.already_there == 2 && r.chunks_written == 0);
    // Only the newest, into a third repository: it stands alone there.
    let third = new_repo(&dir.path().join("c"));
    let r = engine::copy::copy_images(
        &src,
        &third,
        Some(&[second.image_id]),
        false,
        &JobControl::new(),
        &|_, _| {},
    )
    .unwrap();
    assert_eq!(r.copied, vec![id_in(&third, second.image_id)]);
    let alone = third
        .load_manifest(&id_in(&third, second.image_id))
        .unwrap();
    assert_eq!((alone.parent, alone.kind), (None, ImageKind::Full));
    // Not into itself.
    assert!(
        engine::copy::copy_images(&src, &src, None, false, &JobControl::new(), &|_, _| {}).is_err()
    );
}
