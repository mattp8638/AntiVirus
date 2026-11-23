//! Live images of a running Linux system (docs/design/phase-6.md).
//!
//! Each disk is the raw device with overlays: LVM snapshots mapped back onto
//! the extents of their physical volume, PV metadata read before any
//! snapshot existed, small non-LVM file systems copied while frozen, swap
//! reduced to its header, and our snapshots' copy-on-write space as zeros.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use core_format::extent::Extent;
use core_format::manifest::{BootConfig, CaptureMethod, Consistency, Firmware, OsInfo};
use engine::composite::{CompositeDisk, HeadThenZeros, Overlay, SharedReader};
use engine::{CapturePlan, DiskInfo, DiskSource, PartitionPlan};

use crate::blk::{self, Node};
use crate::lvm::{self, Pv, Segment};

/// Non-LVM partitions up to this size are copied while frozen.
pub const FREEZE_COPY_MAX: u64 = 4 << 30;
const SNAP_PREFIX: &str = "fenrir-snap-";
const RECORD: &str = "linux-snapshots.json";

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct LiveOptions {
    /// Disks to image; empty = every disk holding a system mount.
    pub disks: Vec<PathBuf>,
    /// Read what cannot be snapshotted live and mark the image inconsistent,
    /// instead of failing.
    pub allow_inconsistent: bool,
    /// Where snapshot names are recorded (removed after a crash).
    pub state_dir: PathBuf,
    /// Where frozen partitions are copied. Must not be on one of them.
    pub temp_dir: PathBuf,
    /// Disks holding these paths (the repository) are left out when chosen
    /// automatically.
    pub exclude_paths: Vec<PathBuf>,
}

pub struct LiveBackup {
    pub sources: Vec<CompositeDisk>,
    pub consistency: Consistency,
    pub warnings: Vec<String>,
    pub os: OsInfo,
    pub boot: BootConfig,
    /// "vg/lv" of the snapshots we created.
    snapshots: Vec<String>,
    temps: Vec<PathBuf>,
    state_dir: PathBuf,
}

impl LiveBackup {
    pub fn sources(&self) -> Vec<&dyn DiskSource> {
        self.sources.iter().map(|s| s as &dyn DiskSource).collect()
    }

    /// Remove the snapshots and copies. Also done on drop; this reports errors.
    pub fn finish(mut self) -> Result<(), String> {
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<(), String> {
        self.sources.clear(); // close the snapshot devices first
        let mut errs = Vec::new();
        for t in self.temps.drain(..) {
            let _ = std::fs::remove_file(t);
        }
        for s in std::mem::take(&mut self.snapshots) {
            match remove_snapshot(&s) {
                Ok(()) => record(&self.state_dir, |v| v.retain(|x| x != &s)),
                Err(e) => errs.push(format!("{s}: {e}")),
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(format!("could not remove snapshot(s): {}", errs.join("; ")))
        }
    }
}

impl Drop for LiveBackup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .env("LVM_SUPPRESS_FD_WARNINGS", "1")
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn lvm_report(cmd: &str, fields: &str, extra: &[&str]) -> Result<String, String> {
    let mut a = vec![
        "--reportformat",
        "json",
        "--units",
        "b",
        "--nosuffix",
        "-o",
        fields,
    ];
    a.extend_from_slice(extra);
    run(cmd, &a)
}

fn segments() -> Result<Vec<Segment>, String> {
    lvm::parse_segments(&lvm_report(
        "lvs",
        lvm::SEGMENT_FIELDS,
        &["-a", "--segments"],
    )?)
}

fn record(dir: &Path, f: impl FnOnce(&mut Vec<String>)) {
    let p = dir.join(RECORD);
    let mut v: Vec<String> = std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    f(&mut v);
    if v.is_empty() {
        let _ = std::fs::remove_file(&p);
    } else if let Ok(b) = serde_json::to_vec(&v) {
        // Written before the snapshot is created and synced, so a crash
        // right after lvcreate still leaves the record.
        if let Ok(mut f) = File::create(&p) {
            let _ = f.write_all(&b);
            let _ = f.sync_all();
        }
    }
}

fn remove_snapshot(vg_lv: &str) -> Result<(), String> {
    let (_, lv) = vg_lv.split_once('/').unwrap_or(("", vg_lv));
    if !lv.starts_with(SNAP_PREFIX) {
        return Err(format!("{vg_lv} is not a Fenrir-Backup snapshot"));
    }
    let mut last = String::new();
    // A reader that has just closed the device can keep it busy briefly.
    for _ in 0..5 {
        match run("lvremove", &["-f", "-y", vg_lv]) {
            Ok(_) => return Ok(()),
            Err(e) if e.contains("not found") || e.contains("Failed to find") => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(last)
}

/// Remove snapshots a crashed backup left behind (only those it recorded).
pub fn remove_leftover_snapshots(state_dir: &Path) -> Vec<String> {
    let mut names = vec![];
    record(state_dir, |v| names = v.clone());
    let mut log = vec![];
    for n in names {
        match remove_snapshot(&n) {
            Ok(()) => {
                record(state_dir, |v| v.retain(|x| x != &n));
                log.push(format!("removed leftover snapshot {n}"));
            }
            Err(e) => log.push(format!("could not remove leftover snapshot {n}: {e}")),
        }
    }
    log
}

fn canon(p: &str) -> String {
    std::fs::canonicalize(p)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| p.to_string())
}

fn sysfs_block(dev: &str) -> PathBuf {
    let name = Path::new(&canon(dev))
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    PathBuf::from("/sys/class/block").join(name)
}

fn sysfs_u64(dir: &Path, f: &str) -> Option<u64> {
    std::fs::read_to_string(dir.join(f))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Byte offset, length and number of a partition device on its disk.
fn partition_geometry(dev: &str) -> Result<(u64, u64, u32), String> {
    let d = sysfs_block(dev);
    match (
        sysfs_u64(&d, "start"),
        sysfs_u64(&d, "size"),
        sysfs_u64(&d, "partition"),
    ) {
        (Some(s), Some(l), Some(n)) => Ok((s * 512, l * 512, n as u32)),
        _ => Err(format!("{dev}: no partition geometry in {}", d.display())),
    }
}

/// One region of a disk that LVM or a file system uses: a partition, or the
/// whole disk.
struct Region<'a> {
    node: &'a Node,
    start: u64,
    len: u64,
    number: Option<u32>,
}

/// What we will do with an LV that has extents on a PV we image.
enum LvAction {
    Snapshot,
    Swap,
    Raw,
}

struct Pending {
    disk: usize,
    vg: String,
    lv: String,
    lv_size: u64,
    /// Overlays to add once the snapshot device exists: (disk offset, PV range).
    ranges: Vec<(u64, lvm::PvRange)>,
    pv_start: u64,
    pv: Pv,
}

/// Prepare a live image of the running system (or of `opts.disks`).
pub fn prepare(opts: &LiveOptions) -> Result<LiveBackup, Error> {
    let tree = blk::parse(&run("lsblk", &["--json", "-b", "-p", "-o", blk::COLUMNS])?)?;
    let mut warnings = Vec::new();
    let disks: Vec<&Node> = if opts.disks.is_empty() {
        let mut d = blk::system_disks(&tree);
        if d.is_empty() {
            return Err("no disk holds a mounted system file system".into());
        }
        let repo_mounts: Vec<String> = opts
            .exclude_paths
            .iter()
            .filter_map(|p| mount_of(p))
            .collect();
        d.retain(|disk| {
            let m = disk.mounts();
            let holds_repo = m.iter().any(|x| repo_mounts.iter().any(|r| r == x));
            let holds_root = m.contains(&"/");
            if holds_repo && !holds_root {
                warnings.push(format!(
                    "{} is not imaged: it holds the backup repository",
                    disk.name
                ));
            }
            !holds_repo || holds_root
        });
        d
    } else {
        opts.disks
            .iter()
            .map(|p| {
                let want = canon(&p.display().to_string());
                tree.iter()
                    .find(|n| canon(&n.name) == want)
                    .ok_or_else(|| format!("{} is not a whole disk", p.display()))
            })
            .collect::<Result<_, _>>()?
    };

    let has_lvm = disks
        .iter()
        .flat_map(|d| d.walk())
        .any(|n| n.fstype == "LVM2_member");
    let (pvs, segs, vgs) = if has_lvm {
        (
            lvm::parse_pvs(&lvm_report(
                "pvs",
                "pv_name,vg_name,pe_start,pv_pe_count",
                &[],
            )?)?,
            segments()?,
            lvm::parse_vgs(&lvm_report("vgs", "vg_name,vg_free,vg_extent_size", &[])?)?,
        )
    } else {
        (vec![], vec![], vec![])
    };
    // Swap in use, by device-mapper path of the LV or partition path.
    let swaps: Vec<String> = disks
        .iter()
        .flat_map(|d| d.walk())
        .filter(|n| n.is_swap())
        .map(|n| canon(&n.name))
        .collect();
    let temp_dev = std::fs::metadata(&opts.temp_dir)
        .map_err(|e| format!("{}: {e}", opts.temp_dir.display()))?
        .dev();

    let mut live = LiveBackup {
        sources: vec![],
        consistency: Consistency::Offline,
        warnings: vec![],
        os: os_info(),
        boot: boot_config(),
        snapshots: vec![],
        temps: vec![],
        state_dir: opts.state_dir.clone(),
    };
    let mut snapped = false;
    let mut inconsistent = false;
    let mut problems: Vec<String> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut built: Vec<(DiskInfo, SharedReader, Vec<Overlay>, CapturePlan)> = Vec::new();
    let mut needed: BTreeMap<String, u64> = BTreeMap::new();
    let mut freezes: Vec<(usize, u64, u64, String, String)> = Vec::new();

    for (di, disk) in disks.iter().enumerate() {
        let f = File::open(&disk.name).map_err(|e| format!("{}: {e}", disk.name))?;
        let raw: SharedReader = Arc::new(f);
        let mut info = DiskInfo {
            size: disk.size,
            device: disk.name.clone(),
            ..Default::default()
        };
        if let Ok(f) = File::open(&disk.name) {
            (info.logical_sector_size, info.physical_sector_size) =
                crate::linux::sector_sizes(&f).unwrap_or((512, 512));
        }
        (info.model, info.serial) = crate::linux::model_serial(Path::new(&disk.name));
        let mut overlays: Vec<Overlay> = Vec::new();
        let mut plan = CapturePlan::default();

        let mut regions = Vec::new();
        if disk.fstype == "LVM2_member" || disk.mounted() || disk.is_swap() {
            regions.push(Region {
                node: disk,
                start: 0,
                len: disk.size,
                number: None,
            });
        }
        for c in disk.children.iter().filter(|c| c.kind == "part") {
            let (start, len, number) = partition_geometry(&c.name)?;
            regions.push(Region {
                node: c,
                start,
                len,
                number: Some(number),
            });
        }

        for r in &regions {
            let n = r.node;
            let mut pp = PartitionPlan {
                number: r.number.unwrap_or(0),
                used: None,
                capture: CaptureMethod::RawFull,
                filesystem: None,
                volume: Some(n.name.clone()),
                mount_points: n.mounts().iter().map(|s| s.to_string()).collect(),
                encryption: (n.fstype == "crypto_LUKS").then(|| "luks".to_string()),
            };
            let live_below = n.walk().iter().any(|x| x.mounted() || x.is_swap());

            if n.fstype == "LVM2_member" {
                let Some(pv) = pvs.iter().find(|p| canon(&p.name) == canon(&n.name)) else {
                    problems.push(format!(
                        "{}: LVM physical volume not reported by pvs",
                        n.name
                    ));
                    continue;
                };
                let ext = vgs
                    .iter()
                    .find(|v| v.name == pv.vg)
                    .map(|v| v.extent_size)
                    .unwrap_or(4 << 20);
                // Metadata areas: read now, before any snapshot changes them.
                let data_end = (pv.pe_start + pv.pe_count * ext).min(r.len);
                let mut head = vec![0u8; pv.pe_start.min(r.len) as usize];
                raw.read_at(r.start, &mut head)?;
                let mut used = vec![Extent(r.start, head.len() as u64)];
                overlays.push(Overlay {
                    start: r.start,
                    len: head.len() as u64,
                    device_len: head.len() as u64,
                    device: Arc::new(HeadThenZeros(head)),
                    device_base: 0,
                    decrypted: false,
                });
                if data_end < r.len {
                    let mut tail = vec![0u8; (r.len - data_end) as usize];
                    raw.read_at(r.start + data_end, &mut tail)?;
                    used.push(Extent(r.start + data_end, tail.len() as u64));
                    overlays.push(Overlay {
                        start: r.start + data_end,
                        len: tail.len() as u64,
                        device_len: tail.len() as u64,
                        device: Arc::new(HeadThenZeros(tail)),
                        device_base: 0,
                        decrypted: false,
                    });
                }
                // Each LV with extents here.
                let mut lvs: Vec<&str> = segs
                    .iter()
                    .filter(|s| s.vg == pv.vg && lvm::touches(s, pv))
                    .map(|s| s.lv.as_str())
                    .collect();
                lvs.sort_unstable();
                lvs.dedup();
                for lv in lvs {
                    let lsegs: Vec<&Segment> = segs
                        .iter()
                        .filter(|s| s.vg == pv.vg && s.lv == lv)
                        .collect();
                    let s0 = lsegs[0];
                    if s0.is_snapshot() {
                        warnings.push(format!(
                            "{}/{lv} is a snapshot: it is not imaged and will be invalid after a restore; remove it then (lvremove)",
                            pv.vg
                        ));
                        continue;
                    }
                    let here: Vec<lvm::PvRange> =
                        lsegs.iter().filter_map(|s| lvm::on_pv(s, pv)).collect();
                    let all_linear = lsegs.iter().all(|s| s.linear().is_some());
                    for h in &here {
                        used.push(Extent(r.start + h.pv_offset, h.len));
                    }
                    let action = if swaps.contains(&canon(&s0.dm_path)) {
                        LvAction::Swap
                    } else if !s0.active() {
                        LvAction::Raw
                    } else if !all_linear || s0.hidden() {
                        let why = format!(
                            "{}/{lv} ({}) is active and cannot be snapshotted (only linear logical volumes can)",
                            pv.vg, s0.segtype
                        );
                        if !opts.allow_inconsistent {
                            problems.push(why);
                            continue;
                        }
                        warnings.push(format!("{why}: read live, the image may be inconsistent"));
                        inconsistent = true;
                        // Every segment of the LV is captured from the disk.
                        for s in lsegs.iter().filter(|s| lvm::touches(s, pv)) {
                            for (name, a, b) in &s.pe_ranges {
                                if name == &pv.name {
                                    used.push(Extent(
                                        r.start + pv.pe_start + a * ext,
                                        (b - a + 1) * ext,
                                    ));
                                }
                            }
                        }
                        LvAction::Raw
                    } else {
                        LvAction::Snapshot
                    };
                    match action {
                        LvAction::Raw => {}
                        LvAction::Swap => {
                            // Header page from the disk, the rest zeros.
                            let mut first = true;
                            let mut sorted = here.clone();
                            sorted.sort_by_key(|h| h.lv_offset);
                            for h in sorted {
                                let mut keep = vec![];
                                if first && h.lv_offset == 0 {
                                    keep = vec![0u8; 4096.min(h.len as usize)];
                                    raw.read_at(r.start + h.pv_offset, &mut keep)?;
                                }
                                first = false;
                                overlays.push(Overlay {
                                    start: r.start + h.pv_offset,
                                    len: h.len,
                                    device_len: h.len,
                                    device: Arc::new(HeadThenZeros(keep)),
                                    device_base: 0,
                                    decrypted: false,
                                });
                            }
                        }
                        LvAction::Snapshot => {
                            if let Some(p) = pending.iter_mut().find(|p| {
                                p.vg == pv.vg && p.lv == lv && p.disk == di && p.pv == *pv
                            }) {
                                p.ranges.extend(here.iter().map(|h| (r.start, *h)));
                            } else {
                                if !pending.iter().any(|p| p.vg == pv.vg && p.lv == lv) {
                                    *needed.entry(pv.vg.clone()).or_default() +=
                                        lvm::snapshot_size(s0.lv_size, ext);
                                }
                                pending.push(Pending {
                                    disk: di,
                                    vg: pv.vg.clone(),
                                    lv: lv.to_string(),
                                    lv_size: s0.lv_size,
                                    ranges: here.iter().map(|h| (r.start, *h)).collect(),
                                    pv_start: r.start,
                                    pv: pv.clone(),
                                });
                            }
                        }
                    }
                }
                pp.used = Some(used);
                pp.capture = CaptureMethod::SnapshotFull;
            } else if n.is_swap() {
                let mut keep = vec![0u8; 4096.min(r.len as usize)];
                raw.read_at(r.start, &mut keep)?;
                overlays.push(Overlay {
                    start: r.start,
                    len: r.len,
                    device_len: r.len,
                    device: Arc::new(HeadThenZeros(keep)),
                    device_base: 0,
                    decrypted: false,
                });
            } else if n.mounted() && n.children.is_empty() {
                let mp = n.mountpoint.clone();
                let same_fs = std::fs::metadata(&mp).map(|m| m.dev()).ok() == Some(temp_dev);
                if r.len > FREEZE_COPY_MAX || same_fs {
                    let why = if same_fs {
                        format!("{} ({mp}) holds the temporary folder {}, so it cannot be frozen while copied", n.name, opts.temp_dir.display())
                    } else {
                        format!("{} ({mp}, {} GiB) is mounted and not on LVM, so it cannot be snapshotted", n.name, r.len >> 30)
                    };
                    if !opts.allow_inconsistent {
                        problems.push(why);
                        continue;
                    }
                    warnings.push(format!("{why}: read live, the image may be inconsistent"));
                    inconsistent = true;
                } else {
                    // Copied after every check has passed (below).
                    freezes.push((di, r.start, r.len, mp, n.fstype.clone()));
                    pp.capture = CaptureMethod::SnapshotFull;
                }
            } else if live_below {
                // A mounted file system inside something else (LUKS, RAID...).
                let why = format!(
                    "{} ({}) holds mounted file systems ({}) that cannot be snapshotted on the disk",
                    n.name,
                    if n.fstype.is_empty() { &n.kind } else { &n.fstype },
                    n.mounts().join(", ")
                );
                if !opts.allow_inconsistent {
                    problems.push(why);
                    continue;
                }
                warnings.push(format!("{why}: read live, the image may be inconsistent"));
                inconsistent = true;
            }
            if r.number.is_some() {
                plan.partitions.push(pp);
            }
        }
        built.push((info, raw, overlays, plan));
    }

    if !problems.is_empty() {
        return Err(format!(
            "this system cannot be imaged consistently while running:\n  {}\n\
             Back it up from the recovery media, or allow an inconsistent image.",
            problems.join("\n  ")
        )
        .into());
    }
    for (vg, need) in &needed {
        let free = vgs
            .iter()
            .find(|v| &v.name == vg)
            .map(|v| v.free)
            .unwrap_or(0);
        if *need > free {
            return Err(format!(
                "volume group {vg} needs {} MiB free for snapshots during the backup and has {} MiB; \
                 free space in it (or add a disk to it)",
                need >> 20,
                free >> 20
            )
            .into());
        }
    }

    for (di, start, len, mp, fstype) in freezes {
        let (path, frozen) = freeze_copy(&built[di].1, start, len, &mp, &opts.temp_dir)?;
        live.temps.push(path.clone());
        if !frozen {
            warnings.push(format!(
                "{mp} could not be frozen ({fstype}); it was copied as is"
            ));
        }
        built[di].2.push(Overlay {
            start,
            len,
            device_len: len,
            device: Arc::new(File::open(&path)?),
            device_base: 0,
            decrypted: false,
        });
        snapped = true;
    }

    // Snapshots: one per LV, LVM freezes its file system while creating it.
    let mut created: BTreeMap<(String, String), String> = BTreeMap::new();
    for p in &pending {
        let key = (p.vg.clone(), p.lv.clone());
        if created.contains_key(&key) {
            continue;
        }
        let name = snapshot_name(&p.lv);
        let full = format!("{}/{name}", p.vg);
        record(&opts.state_dir, |v| v.push(full.clone()));
        live.snapshots.push(full.clone());
        let ext = vgs
            .iter()
            .find(|v| v.name == p.vg)
            .map(|v| v.extent_size)
            .unwrap_or(4 << 20);
        let size = format!("{}b", lvm::snapshot_size(p.lv_size, ext));
        run(
            "lvcreate",
            &[
                "-s",
                "-y",
                "-L",
                &size,
                "-n",
                &name,
                &format!("{}/{}", p.vg, p.lv),
            ],
        )
        .map_err(|e| format!("creating a snapshot of {}/{}: {e}", p.vg, p.lv))?;
        created.insert(key, name);
        snapped = true;
    }
    if !created.is_empty() {
        let now = segments()?;
        for p in &pending {
            let name = &created[&(p.vg.clone(), p.lv.clone())];
            let snap = now
                .iter()
                .find(|s| s.vg == p.vg && &s.lv == name)
                .ok_or_else(|| format!("snapshot {}/{name} not found after creating it", p.vg))?;
            if !snap.active() {
                return Err(format!("snapshot {}/{name} is not active", p.vg).into());
            }
            let dev: SharedReader =
                Arc::new(File::open(&snap.dm_path).map_err(|e| format!("{}: {e}", snap.dm_path))?);
            let ov = &mut built[p.disk].2;
            for (pv_start, h) in &p.ranges {
                ov.push(Overlay {
                    start: pv_start + h.pv_offset,
                    len: h.len,
                    device_len: h.len,
                    device: dev.clone(),
                    device_base: h.lv_offset,
                    decrypted: false,
                });
            }
            // The snapshot's own extents on this PV: free space in the
            // captured metadata. Zeros, not whatever it copied.
            for s in now.iter().filter(|s| s.vg == p.vg && &s.lv == name) {
                if let Some(h) = lvm::on_pv(s, &p.pv) {
                    let start = p.pv_start + h.pv_offset;
                    if !ov.iter().any(|o| o.start == start) {
                        ov.push(Overlay {
                            start,
                            len: h.len,
                            device_len: h.len,
                            device: Arc::new(HeadThenZeros(vec![])),
                            device_base: 0,
                            decrypted: false,
                        });
                    }
                }
            }
        }
    }

    for (info, raw, overlays, plan) in built {
        live.sources
            .push(CompositeDisk::new(info, raw, overlays, plan)?);
    }
    live.consistency = if inconsistent {
        Consistency::Inconsistent
    } else if snapped {
        Consistency::Crash
    } else {
        Consistency::Offline
    };
    warnings.append(&mut live.warnings);
    live.warnings = warnings;
    Ok(live)
}

fn snapshot_name(lv: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let tag = format!(
        "{:08x}",
        (t.as_nanos() as u64 ^ (std::process::id() as u64) << 32) as u32
    );
    let base: String = lv
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(40)
        .collect();
    format!("{SNAP_PREFIX}{base}-{tag}")
}

/// The mount point holding `p` (longest prefix in /proc/self/mounts).
fn mount_of(p: &Path) -> Option<String> {
    let p = std::fs::canonicalize(p).ok()?;
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    mounts
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|m| m.replace("\\040", " "))
        .filter(|m| p.starts_with(m))
        .max_by_key(|m| m.len())
}

/// Copy a partition to a file in `dir` while its file system is frozen.
/// Returns the file and whether the freeze worked.
fn freeze_copy(
    raw: &SharedReader,
    start: u64,
    len: u64,
    mountpoint: &str,
    dir: &Path,
) -> Result<(PathBuf, bool), Error> {
    struct Thaw<'a>(&'a str, bool);
    impl Drop for Thaw<'_> {
        fn drop(&mut self) {
            if self.1 {
                let _ = run("fsfreeze", &["-u", self.0]);
            }
        }
    }
    let path = dir.join(format!(
        "fenrir-frozen-{}-{}.img",
        std::process::id(),
        start
    ));
    let mut out = File::create(&path)?;
    let frozen = run("fsfreeze", &["-f", mountpoint]).is_ok();
    let _thaw = Thaw(mountpoint, frozen);
    let mut buf = vec![0u8; 4 << 20];
    let mut pos = 0;
    while pos < len {
        let n = (len - pos).min(buf.len() as u64) as usize;
        raw.read_at(start + pos, &mut buf[..n])?;
        out.write_all(&buf[..n])?;
        pos += n as u64;
    }
    out.sync_all()?;
    Ok((path, frozen))
}

pub fn os_info() -> OsInfo {
    let rel = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |k: &str| {
        rel.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default()
    };
    OsInfo {
        family: "linux".into(),
        name: get("PRETTY_NAME"),
        version: get("VERSION_ID"),
        build: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        arch: std::env::consts::ARCH.into(),
    }
}

pub fn boot_config() -> BootConfig {
    let uefi = Path::new("/sys/firmware/efi").exists();
    let mut b = BootConfig {
        firmware: if uefi { Firmware::Uefi } else { Firmware::Bios },
        ..Default::default()
    };
    if uefi {
        // SecureBoot-8be4df61-...: 4 attribute bytes, then the value.
        if let Ok(rd) = std::fs::read_dir("/sys/firmware/efi/efivars") {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("SecureBoot-") {
                    if let Ok(v) = std::fs::read(e.path()) {
                        b.secure_boot = v.get(4).map(|x| *x == 1);
                    }
                }
            }
        }
    }
    for g in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"] {
        if Path::new(g).exists() {
            b.grub = Some(g.into());
        }
    }
    b
}
