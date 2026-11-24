//! Image backup: read used blocks, chunk, dedupe, store, write manifest.

use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use core_format::backend::PutOutcome;
use core_format::chunk::ChunkId;
use core_format::extent::{self, Extent};
use core_format::manifest::{
    BootConfig, ChunkRef, Consistency, DiskImage, DriverInfo, ImageKind, ImageStats, MachineInfo,
    ManifestBody, OsInfo, BODY_FORMAT, BODY_VERSION,
};
use core_format::partition;
use core_format::{timefmt, Repository};
use serde::Serialize;
use uuid::Uuid;

use crate::control::{JobControl, Throttle};
use crate::layout::{plan_disk, DiskLayout};
use crate::source::SourceReader;
use crate::{DiskSource, EngineError, Result};

/// Facts about the machine that the engine cannot discover itself.
#[derive(Debug, Clone)]
pub struct ImageMeta {
    pub machine: MachineInfo,
    pub consistency: Consistency,
    pub os: OsInfo,
    pub boot: BootConfig,
    pub drivers: Vec<DriverInfo>,
    pub label: Option<String>,
    pub warnings: Vec<String>,
    /// Set when imaging a VM from its host.
    pub vm: Option<core_format::manifest::VmInfo>,
    /// Application components coordinated with the snapshot (VSS writers).
    pub applications: Vec<core_format::manifest::ApplicationInfo>,
}

#[derive(Debug, Clone)]
pub struct BackupOptions {
    /// Hash/compress/encrypt worker threads.
    pub workers: usize,
    /// Read rate limit in bytes per second; 0 = unlimited.
    pub rate_limit: u64,
    /// Changed-block tracking: what changed since an earlier image of the
    /// same machine. Chunks with no changed byte are taken from that image
    /// instead of being read (docs/design/frequent-backups.md §3).
    pub changed: Option<ChangedSince>,
}

/// The ranges written on each disk since `base_image` was taken, as reported
/// by a change tracker the caller trusts to record every write (Hyper-V
/// Resilient Change Tracking). A chunk is reused from the base image only if
/// none of its bytes changed and its used ranges are the same as in the base
/// image; everything else is read. When the base image cannot be used (gone,
/// another machine, another chunk size) every disk is read in full.
#[derive(Debug, Clone)]
pub struct ChangedSince {
    pub base_image: Uuid,
    /// One entry per source disk, in the same order. `None` reads that disk
    /// in full (no tracking for it, or a disk the base image does not have).
    pub disks: Vec<Option<Vec<Extent>>>,
    /// Read about one in this many chunks reported unchanged anyway and
    /// check they match the base image; a mismatch fails the backup with
    /// [`EngineError::ChangeTrackingMissed`]. 0 = no checks.
    pub spot_check_one_in: u32,
}

impl Default for BackupOptions {
    fn default() -> Self {
        BackupOptions {
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .clamp(1, 8),
            rate_limit: 0,
            changed: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub disk: u32,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub chunks_new: u64,
    /// New data written to the repository so far (compressed, encrypted).
    pub bytes_stored: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub image_id: Uuid,
    pub parent: Option<Uuid>,
    pub kind: ImageKind,
    pub stats: ImageStats,
    pub warnings: Vec<String>,
    /// How the disks were read: "full", or "changed_blocks" when unchanged
    /// chunks were taken from `changed_base` without reading them.
    pub read_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_base: Option<Uuid>,
    /// Used bytes taken from the base image without reading them.
    pub bytes_unchanged: u64,
    /// Why change tracking was asked for but not used, if it was not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_read_reason: Option<String>,
}

/// The base image's view of one disk, for reusing its unchanged chunks.
struct Reuse<'a> {
    spot_check_one_in: u32,
    changed: &'a [Extent],
    base_used: &'a [Extent],
    base_chunks: std::collections::HashMap<u64, ChunkId>,
}

struct Work {
    index: u64,
    data: Vec<u8>,
}

enum Done {
    /// Taken from the base image without reading (changed-block tracking).
    Reused {
        index: u64,
        id: ChunkId,
    },
    Stored {
        index: u64,
        id: ChunkId,
        new: bool,
        stored: u64,
    },
    Zero,
}

/// Back up `sources` (one per disk) as a single image.
///
/// The manifest is written only after every chunk is stored. If the job is
/// killed or cancelled, nothing references the chunks already written and
/// the next run reuses them.
pub fn backup(
    repo: &Repository,
    sources: &[&dyn DiskSource],
    meta: ImageMeta,
    opts: &BackupOptions,
    ctl: &JobControl,
    progress: &(dyn Fn(&Progress) + Sync),
) -> Result<BackupReport> {
    if sources.is_empty() {
        return Err(EngineError::InvalidInput("no disks to back up".into()));
    }
    // Shared lock: a prune (exclusive) cannot delete chunks this backup
    // finds already stored and reuses.
    let _lock = repo.lock(core_format::lock::LockKind::Shared)?;
    let started = Instant::now();
    ctl.set_rate_limit(opts.rate_limit);
    let cs = repo.chunk_size() as u64;
    let mut stats = ImageStats::default();
    let mut disks = Vec::new();
    let mut warnings = meta.warnings.clone();
    let mut excluded = Vec::new();
    let mut bytes_unchanged = 0u64;
    let (base, mut full_read_reason) = match &opts.changed {
        None => (None, None),
        Some(c) => match usable_base(repo, c, &meta.machine.machine_id, sources.len()) {
            Ok(m) => (Some((c, m)), None),
            Err(why) => (None, Some(why)),
        },
    };
    let changed_lists: Vec<Option<Vec<Extent>>> = match &base {
        Some((c, _)) => c
            .disks
            .iter()
            .map(|d| d.clone().map(extent::normalize))
            .collect(),
        None => vec![],
    };

    for (di, src) in sources.iter().enumerate() {
        let PlannedDisk {
            info,
            sector_size: ss,
            table,
            layout,
            plan,
        } = plan_one(*src, di)?;
        if table.scheme == partition::Scheme::Gpt && !table.backup_table_valid {
            warnings.push(format!(
                "disk {di}: GPT backup header or entries are damaged; image keeps them as found"
            ));
        }
        warnings.extend(plan.warnings.iter().cloned());
        excluded.extend(plan.excluded.iter().cloned());
        let total = extent::total_len(&layout.used);

        let reuse = base.as_ref().and_then(|(c, m)| {
            let changed = changed_lists.get(di)?.as_deref()?;
            let d = m.disks.iter().find(|d| d.index == di as u32)?;
            if d.size != info.size {
                return None;
            }
            Some(Reuse {
                spot_check_one_in: c.spot_check_one_in,
                changed,
                base_used: &d.used_extents,
                base_chunks: d.chunks.iter().map(|c| (c.0, c.1)).collect(),
            })
        });
        let chunks = run_pipeline(
            repo,
            *src,
            di as u32,
            info.size,
            cs,
            &layout.used,
            total,
            opts,
            ctl,
            progress,
            &mut stats,
            reuse.as_ref(),
            &mut bytes_unchanged,
        )?;

        disks.push(DiskImage {
            index: di as u32,
            size: info.size,
            logical_sector_size: ss,
            physical_sector_size: if info.physical_sector_size == 0 {
                ss
            } else {
                info.physical_sector_size
            },
            model: info.model,
            serial: info.serial,
            device: info.device,
            partition_table: table,
            partitions: layout.partitions,
            used_extents: layout.used,
            chunks,
        });
    }

    // Parent = most recent image of the same machine. Every image is
    // self-contained (it lists every chunk); `parent` records lineage for
    // retention and change-ratio anomaly checks.
    let parent = latest_image_for_machine(repo, &meta.machine.machine_id)?;
    let now = timefmt::now_unix();
    stats.duration_ms = started.elapsed().as_millis() as u64;
    let body = ManifestBody {
        format: BODY_FORMAT.into(),
        version: BODY_VERSION,
        image_id: Uuid::new_v4(),
        repo_id: repo.config().repo_id,
        created: timefmt::rfc3339_utc(now),
        created_unix: now,
        kind: if parent.is_some() {
            ImageKind::Incremental
        } else {
            ImageKind::Full
        },
        parent,
        label: meta.label,
        machine: meta.machine.clone(),
        consistency: meta.consistency,
        chunk_size: repo.chunk_size(),
        hash: repo.config().hash.clone(),
        compression: "zstd".into(),
        encryption: repo.config().encryption.clone(),
        disks,
        boot: meta.boot,
        os: meta.os,
        drivers: meta.drivers,
        excluded,
        warnings: warnings.clone(),
        stats: stats.clone(),
        vm: meta.vm,
        applications: meta.applications,
    };
    if ctl.is_cancelled() {
        return Err(EngineError::Cancelled);
    }
    let signer = repo.signer_for_machine(&meta.machine.machine_id)?;
    repo.store_manifest(&body, &signer)?;
    let used_base = base.is_some() && changed_lists.iter().any(|d| d.is_some());
    if base.is_some() && !used_base {
        full_read_reason = Some("no disk had change tracking".into());
    }
    Ok(BackupReport {
        image_id: body.image_id,
        parent,
        kind: body.kind,
        stats,
        warnings,
        read_mode: if used_base { "changed_blocks" } else { "full" },
        changed_base: base
            .as_ref()
            .filter(|_| used_base)
            .map(|(c, _)| c.base_image),
        bytes_unchanged,
        full_read_reason,
    })
}

/// Whether to read a chunk reported unchanged anyway, to check the tracker:
/// a fixed, evenly spread choice of about one chunk in `one_in`.
fn spot_check(index: u64, one_in: u32) -> bool {
    one_in > 0 && index.wrapping_mul(0x9E37_79B9_7F4A_7C15) % one_in as u64 == 0
}

/// The base image, if its chunks may stand in for unchanged ones: it must
/// still exist (the shared lock held by the caller keeps it and its chunks
/// from being pruned), be of the same machine and use this chunk size.
fn usable_base(
    repo: &Repository,
    c: &ChangedSince,
    machine_id: &str,
    disks: usize,
) -> std::result::Result<ManifestBody, String> {
    if c.disks.len() != disks {
        return Err(format!(
            "change tracking covers {} disks, the backup has {disks}",
            c.disks.len()
        ));
    }
    let m = repo
        .load_manifest(&c.base_image)
        .map_err(|e| format!("the previous image {} cannot be used: {e}", c.base_image))?;
    if m.machine.machine_id != machine_id {
        return Err("the previous image is of another machine".into());
    }
    if m.chunk_size != repo.chunk_size() {
        return Err("the previous image uses another chunk size".into());
    }
    Ok(m)
}

/// What a backup of one disk would capture.
pub struct PlannedDisk {
    pub info: crate::DiskInfo,
    pub sector_size: u32,
    pub table: partition::PartitionTable,
    pub layout: DiskLayout,
    pub plan: crate::CapturePlan,
}

fn plan_one(src: &dyn DiskSource, di: usize) -> Result<PlannedDisk> {
    let info = src.info();
    if info.size == 0 {
        return Err(EngineError::InvalidInput(format!("disk {di} has size 0")));
    }
    let ss = if info.logical_sector_size == 0 {
        partition::detect_sector_size(&SourceReader(src), info.size)
    } else {
        info.logical_sector_size
    };
    let table = partition::read_table(&SourceReader(src), info.size, ss)?;
    let plan = src.capture_plan(&table)?;
    let layout = plan_disk(src, info.size, &table, &plan)?;
    Ok(PlannedDisk {
        info,
        sector_size: ss,
        table,
        layout,
        plan,
    })
}

/// Plan a backup without reading data or touching a repository: partition
/// tables, capture methods and the bytes each partition would contribute.
pub fn plan_image(sources: &[&dyn DiskSource]) -> Result<Vec<PlannedDisk>> {
    sources
        .iter()
        .enumerate()
        .map(|(i, s)| plan_one(*s, i))
        .collect()
}

/// Read the first 1 MiB and last 64 KiB of every captured partition range,
/// to check that a source (e.g. a VSS shadow device) is readable before a
/// long backup. Returns bytes read.
pub fn probe_reads(src: &dyn DiskSource, planned: &PlannedDisk) -> Result<u64> {
    let mut total = 0u64;
    for p in &planned.layout.partitions {
        let ranges = extent::clip(&planned.layout.used, p.entry.extent());
        let (Some(first), Some(last)) = (ranges.first(), ranges.last()) else {
            continue;
        };
        for (off, len) in [
            (first.0, first.1.min(1 << 20)),
            (last.end() - last.1.min(64 << 10), last.1.min(64 << 10)),
        ] {
            let mut buf = vec![0u8; len as usize];
            src.read_at(off, &mut buf).map_err(|e| {
                EngineError::Io(std::io::Error::new(
                    e.kind(),
                    format!("probe read of partition {} at {off}: {e}", p.entry.number),
                ))
            })?;
            total += len;
        }
    }
    Ok(total)
}

fn latest_image_for_machine(repo: &Repository, machine_id: &str) -> Result<Option<Uuid>> {
    let (all, _bad) = repo.load_all_manifests()?;
    let mine: Vec<_> = all
        .iter()
        .filter(|m| m.machine.machine_id == machine_id)
        .collect();
    let order = crate::retention::newest_first(&mine, |m| (m.image_id, m.created_unix, m.parent));
    Ok(order.first().map(|&i| mine[i].image_id))
}

#[allow(clippy::too_many_arguments)]
fn run_pipeline(
    repo: &Repository,
    src: &dyn DiskSource,
    disk_index: u32,
    size: u64,
    cs: u64,
    used: &[Extent],
    total: u64,
    opts: &BackupOptions,
    ctl: &JobControl,
    progress: &(dyn Fn(&Progress) + Sync),
    stats: &mut ImageStats,
    reuse: Option<&Reuse>,
    bytes_unchanged: &mut u64,
) -> Result<Vec<ChunkRef>> {
    let workers = opts.workers.max(1);
    let (work_tx, work_rx): (SyncSender<Work>, Receiver<Work>) = mpsc::sync_channel(workers * 2);
    let work_rx = Arc::new(Mutex::new(work_rx));
    let (done_tx, done_rx) = mpsc::channel::<Result<Done>>();
    let first_error: Mutex<Option<EngineError>> = Mutex::new(None);

    let n_chunks = size.div_ceil(cs);
    let mut refs = Vec::new();
    let mut bytes_done = 0u64;

    std::thread::scope(|s| -> Result<()> {
        for _ in 0..workers {
            let rx = Arc::clone(&work_rx);
            let tx = done_tx.clone();
            s.spawn(move || loop {
                let job = { rx.lock().unwrap().recv() };
                let Ok(job) = job else { break };
                let r = process_chunk(repo, job);
                if tx.send(r).is_err() {
                    break;
                }
            });
        }
        let reused_tx = done_tx.clone();
        drop(done_tx);

        // Reader.
        let reader = s.spawn(|| -> Result<()> {
            let mut throttle = Throttle::new();
            for index in 0..n_chunks {
                if !ctl.checkpoint() {
                    return Err(EngineError::Cancelled);
                }
                if first_error.lock().unwrap().is_some() {
                    break;
                }
                let start = index * cs;
                let range = Extent(start, cs.min(size - start));
                let parts = extent::clip(used, range);
                if parts.is_empty() {
                    continue;
                }
                // Nothing written here since the base image, and the same
                // bytes in use: the base image's chunk (or its absence, for
                // an all-zero chunk) is this chunk.
                // Spot-checked chunks are read anyway and compared with it.
                let mut check: Option<Option<ChunkId>> = None;
                if let Some(r) = reuse {
                    if extent::clip(r.changed, range).is_empty()
                        && extent::clip(r.base_used, range) == parts
                    {
                        let base_id = r.base_chunks.get(&index).copied();
                        if spot_check(index, r.spot_check_one_in) {
                            check = Some(base_id);
                        } else {
                            if let Some(id) = base_id {
                                if reused_tx.send(Ok(Done::Reused { index, id })).is_err() {
                                    break;
                                }
                            }
                            continue;
                        }
                    }
                }
                // Unused bytes stay zero: free-space contents are never stored.
                let mut data = vec![0u8; range.1 as usize];
                for e in &parts {
                    let o = (e.0 - start) as usize;
                    src.read_at(e.0, &mut data[o..o + e.1 as usize])
                        .map_err(|err| {
                            EngineError::Io(std::io::Error::new(
                                err.kind(),
                                format!("reading disk {disk_index} at offset {}: {err}", e.0),
                            ))
                        })?;
                    throttle.account(e.1, ctl);
                }
                if let Some(base_id) = check {
                    let same = match base_id {
                        Some(id) => repo.chunk_id(&data) == id,
                        None => data.iter().all(|&b| b == 0),
                    };
                    if !same {
                        return Err(EngineError::ChangeTrackingMissed(format!(
                            "disk {disk_index}: the chunk at offset {start} was reported unchanged but differs from the previous image"
                        )));
                    }
                }
                if work_tx.send(Work { index, data }).is_err() {
                    break;
                }
            }
            drop(work_tx);
            drop(reused_tx);
            Ok(())
        });

        // Collector (this thread).
        for r in done_rx.iter() {
            match r {
                Ok(Done::Reused { index, id }) => {
                    refs.push(ChunkRef(index, id));
                    stats.chunks_total += 1;
                    let len = extent::total_len(&extent::clip(
                        used,
                        Extent(index * cs, cs.min(size - index * cs)),
                    ));
                    *bytes_unchanged += len;
                    bytes_done += len;
                }
                Ok(Done::Stored {
                    index,
                    id,
                    new,
                    stored,
                }) => {
                    refs.push(ChunkRef(index, id));
                    stats.chunks_total += 1;
                    let len = cs.min(size - index * cs);
                    if new {
                        stats.chunks_new += 1;
                        stats.bytes_new_stored += stored;
                        stats.bytes_new_raw += len;
                    }
                    stats.bytes_read += len;
                    bytes_done += len;
                }
                Ok(Done::Zero) => {}
                Err(e) => {
                    ctl.cancel();
                    let mut fe = first_error.lock().unwrap();
                    if fe.is_none() {
                        *fe = Some(e);
                    }
                    continue;
                }
            }
            progress(&Progress {
                disk: disk_index,
                bytes_done: bytes_done.min(total),
                bytes_total: total,
                chunks_new: stats.chunks_new,
                bytes_stored: stats.bytes_new_stored,
            });
        }
        let reader_result = reader.join().expect("reader thread panicked");
        if let Some(e) = first_error.lock().unwrap().take() {
            return Err(e);
        }
        reader_result
    })?;

    refs.sort_by_key(|r| r.0);
    Ok(refs)
}

fn process_chunk(repo: &Repository, job: Work) -> Result<Done> {
    if job.data.iter().all(|&b| b == 0) {
        return Ok(Done::Zero);
    }
    let id = repo.chunk_id(&job.data);
    if repo.has_chunk(&id)? {
        return Ok(Done::Stored {
            index: job.index,
            id,
            new: false,
            stored: 0,
        });
    }
    let (outcome, stored) = repo.put_chunk(&id, &job.data)?;
    Ok(Done::Stored {
        index: job.index,
        id,
        new: outcome == PutOutcome::Created,
        stored,
    })
}
