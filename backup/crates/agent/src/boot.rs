//! Boot checks: start an image as an isolated VM and see whether it boots.
//!
//! * Linux hosts with QEMU: straight from the repository (`vmboot`), no
//!   copy. Optionally left running; such sessions live in this process,
//!   are listed in the inventory and stop after `MAX_SESSION`.
//! * Hyper-V hosts (installed as one, or any machine with Hyper-V): the image
//!   is written as VHDX into a folder, booted with its network disconnected
//!   and checked by heartbeat. Then removed again, or kept as a VM to log in
//!   to and inspect until it is stopped (remembered across agent restarts).
//! * Restore tests (`full_restore`, docs/design/restore-tests.md): the whole
//!   image is restored first (raw files read back and matched to the backup
//!   on KVM hosts, VHDX on Hyper-V), the VM boots from the restored disks,
//!   and the VM and its disks are deleted afterwards; the job says whether
//!   that deletion succeeded.

#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use anyhow::anyhow;
use anyhow::bail;
use base64::Engine;
use core_format::Repository;
use protocol::{BootCheckResult, JobState, JobUpdate, RestoreTest, RunningVm};

use crate::jobs::{Ctx, Reporter};

/// VMs kept running are powered off after this long.
#[cfg(unix)]
pub const MAX_SESSION: Duration = Duration::from_secs(8 * 3600);

#[cfg(unix)]
struct Held {
    info: RunningVm,
    vm: vmboot::VmSession,
}

#[cfg(unix)]
static SESSIONS: Mutex<Vec<Held>> = Mutex::new(Vec::new());

/// Hyper-V VMs kept after a boot check: they outlive this process, so they
/// are remembered in the agent's state folder.
#[cfg(not(unix))]
mod kept {
    use protocol::RunningVm;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct Kept {
        pub info: RunningVm,
        pub name: String,
        pub dir: std::path::PathBuf,
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn file() -> std::path::PathBuf {
        crate::config::state_dir().join("kept-vms.json")
    }

    pub fn load() -> Vec<Kept> {
        std::fs::read(file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(v: &[Kept]) {
        if let Ok(b) = serde_json::to_vec_pretty(v) {
            let _ = std::fs::write(file(), b);
        }
    }

    pub fn add(k: Kept) {
        let _g = LOCK.lock().unwrap();
        let mut v = load();
        v.push(k);
        save(&v);
    }

    /// Turn off and delete the VM and its disks.
    pub fn stop(id: uuid::Uuid) -> anyhow::Result<()> {
        let _g = LOCK.lock().unwrap();
        let mut v = load();
        let i = v
            .iter()
            .position(|k| k.info.session_id == id)
            .ok_or_else(|| {
                anyhow::anyhow!("no kept VM {id} on this host (it may have been removed already)")
            })?;
        let k = v.remove(i);
        save(&v);
        if let Err(e) = crate::hyperv::remove_vm(&k.name) {
            crate::log::warn(&format!(
                "removing VM {}: {e:#} (it may have been deleted in Hyper-V Manager)",
                k.name
            ));
        }
        let _ = std::fs::remove_dir_all(&k.dir);
        Ok(())
    }
}

/// Can this host boot images as VMs? ("boot_kvm" / "boot_hyperv")
pub fn capability(role: &str) -> Option<&'static str> {
    if crate::hyperv::is_host(role) {
        return Some("boot_hyperv");
    }
    #[cfg(unix)]
    {
        static HOST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *HOST.get_or_init(|| vmboot::detect().usable()) {
            return Some("boot_kvm");
        }
    }
    None
}

/// Running sessions; also stops those that exited or ran too long.
pub fn running_vms() -> Vec<RunningVm> {
    #[cfg(unix)]
    {
        let mut g = SESSIONS.lock().unwrap();
        g.retain_mut(|h| {
            let keep = h.vm.running() && h.vm.uptime() < MAX_SESSION;
            if !keep {
                crate::log::info(&format!("VM session {} ended", h.info.session_id));
            }
            keep
        });
        g.iter().map(|h| h.info.clone()).collect()
    }
    #[cfg(not(unix))]
    {
        kept::load().into_iter().map(|k| k.info).collect()
    }
}

pub fn stop_vm(id: uuid::Uuid) -> anyhow::Result<JobUpdate> {
    #[cfg(unix)]
    {
        let mut g = SESSIONS.lock().unwrap();
        let i = g
            .iter()
            .position(|h| h.info.session_id == id)
            .ok_or_else(|| {
                anyhow!("no VM session {id} runs on this host (it may have stopped already)")
            })?;
        let mut h = g.remove(i);
        drop(g);
        h.vm.stop();
    }
    #[cfg(not(unix))]
    kept::stop(id)?;
    #[allow(unreachable_code)]
    Ok(crate::jobs::finished(JobState::Succeeded))
}

/// Stop every session (agent shutdown).
pub fn stop_all() {
    #[cfg(unix)]
    SESSIONS.lock().unwrap().clear();
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn update_for(r: BootCheckResult) -> anyhow::Result<JobUpdate> {
    let mut u = crate::jobs::finished(match r.outcome.as_str() {
        "verified" => JobState::Succeeded,
        "screen" => JobState::Warning,
        _ => JobState::Failed,
    });
    if r.outcome == "screen" {
        u.warnings.push(r.message.clone());
    }
    if r.outcome == "failed" {
        u.error = Some(format!("the image did not boot: {}", r.message));
    }
    let mut v = serde_json::to_value(&r)?;
    v["screenshot_png"] = serde_json::Value::Null;
    u.result = Some(v);
    u.boot_check = Some(r);
    Ok(u)
}

/// A restore test's facts from the restore reports of its disks.
fn restore_facts(format: &str, reports: &[engine::RestoreReport], seconds: u64) -> RestoreTest {
    let v = reports.iter().filter_map(|r| r.verification.as_ref());
    RestoreTest {
        format: format.into(),
        bytes_restored: reports.iter().map(|r| r.bytes_written).sum(),
        restore_seconds: seconds,
        chunks_checked: v.clone().map(|v| v.chunks_checked).sum(),
        mismatches: v.map(|v| v.mismatches).sum(),
        ..Default::default()
    }
}

/// Record the deletion of a restore test's VM and disks.
fn removed(t: &mut RestoreTest, result: anyhow::Result<()>) {
    t.removed_unix = now_unix();
    match result {
        Ok(()) => t.vm_removed = true,
        Err(e) => t.removal_error = format!("{e:#}"),
    }
}

/// A restore test whose disks did not read back as written fails, whatever
/// the boot showed.
fn apply_restore_test(out: &mut BootCheckResult, t: RestoreTest) {
    if t.mismatches > 0 {
        out.outcome = "failed".into();
        out.message = format!(
            "{} chunk(s) of the restored disks did not read back as written; {}",
            t.mismatches, out.message
        );
    } else if !t.vm_removed {
        out.message = format!(
            "{} The test VM or its disks could not be deleted: {}",
            out.message, t.removal_error
        );
    }
    out.restore_test = Some(t);
}

/// Restore every disk of `m` as a raw file in `dir` (new, the agent's own
/// folder), read back and matched to the backup. Returns the files in disk
/// order and the reports.
#[cfg(unix)]
fn restore_raw(
    ctx: &Ctx,
    repo: &Repository,
    m: &core_format::manifest::ManifestBody,
    dir: &std::path::Path,
    rep: &Reporter,
) -> anyhow::Result<(Vec<std::path::PathBuf>, Vec<engine::RestoreReport>)> {
    std::fs::create_dir_all(dir)?;
    let dir = dir.canonicalize()?;
    let total: u64 = m.disks.iter().map(|d| d.size).sum();
    let (mut files, mut reports, mut base) = (Vec::new(), Vec::new(), 0u64);
    for d in &m.disks {
        let path = dir.join(format!("disk{}.raw", d.index));
        // A new file in the agent's own restore-test folder, never a disk.
        let c = engine::DestructiveConfirmation::confirmed_by_user(&path);
        let t = engine::FileTarget::open(&path, d.size, true, &c)?;
        let label = format!("restore test: disk {}", d.index);
        let cb = |done: u64, _t: u64| rep.progress("restoring", base + done, total, &label);
        let r = engine::restore_disk(
            repo,
            m,
            d.index,
            &t,
            &engine::RestoreOptions {
                workers: 4,
                zero_fill: false,
                fit: false,
                grow: false,
                verify: true,
            },
            &ctx.ctl,
            &cb,
        )?;
        base += d.size;
        files.push(path);
        reports.push(r);
    }
    Ok((files, reports))
}

pub struct BootRequest {
    pub image_id: uuid::Uuid,
    pub keep_running: bool,
    pub memory_mb: Option<u64>,
    pub cpus: Option<u32>,
    /// Hyper-V: folder for the VM's disks.
    pub directory: Option<String>,
    /// Restore the image fully first, boot from it, delete everything after.
    pub full_restore: bool,
}

pub fn run(
    ctx: &Ctx,
    repo: &Repository,
    req: &BootRequest,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    match capability(&ctx.cfg.role) {
        Some("boot_kvm") => kvm(ctx, repo, req, rep),
        Some("boot_hyperv") => hyperv(ctx, repo, req, rep),
        _ => bail!("this host cannot boot VMs: install QEMU (qemu-system-x86, qemu-utils, ovmf) or use a Hyper-V host"),
    }
}

#[cfg(unix)]
fn kvm(
    ctx: &Ctx,
    repo: &Repository,
    req: &BootRequest,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m = repo.load_manifest(&req.image_id)?;
    let host = vmboot::detect();
    let mut o = vmboot::BootOptions::for_host(&host);
    let vm = m.vm.clone().unwrap_or_default();
    o.memory_mb = req
        .memory_mb
        .unwrap_or(if vm.memory_mb >= 512 {
            vm.memory_mb
        } else {
            4096
        })
        .clamp(256, 65536);
    o.cpus = req.cpus.unwrap_or(vm.cpu_count.max(2)).clamp(1, 16);
    o.keep_running = req.keep_running && !req.full_restore;
    let test_dir = ctx
        .state_dir
        .join("restore-tests")
        .join(req.image_id.simple().to_string());
    let mut test = None;
    if req.full_restore {
        let _ = std::fs::remove_dir_all(&test_dir); // an interrupted test's leftovers
        let started = std::time::Instant::now();
        match restore_raw(ctx, repo, &m, &test_dir, rep) {
            Ok((files, reports)) => {
                o.disk_files = files;
                test = Some(restore_facts("raw", &reports, started.elapsed().as_secs()));
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&test_dir);
                return Err(e.context("restoring the image for the restore test"));
            }
        }
    }
    rep.progress("starting", 0, 1, "starting the VM");
    let timeout = o.timeout.as_secs();
    let progress = |msg: &str| rep.progress("booting", 0, timeout, msg);
    let ctl = ctx.ctl.clone();
    let booted = vmboot::boot_check(repo, &m, &host, &o, &|| ctl.is_cancelled(), &progress);
    if let Some(t) = test.as_mut() {
        // The VM has stopped (boot_check drops it): delete its restored disks.
        removed(
            t,
            std::fs::remove_dir_all(&test_dir).map_err(|e| anyhow!("{}: {e}", test_dir.display())),
        );
    }
    let (r, session) = booted.map_err(|e| anyhow!("{e}"))?;
    let mut out = BootCheckResult {
        image_id: req.image_id,
        outcome: serde_json::to_value(r.outcome)?
            .as_str()
            .unwrap_or("failed")
            .to_string(),
        method: r.method.clone(),
        seconds: r.seconds,
        firmware: r.firmware.clone(),
        accel: r.accel.clone(),
        message: r.message.clone(),
        screenshot_png: r.screenshot_png.as_deref().map(b64),
        session: None,
        restore_test: None,
    };
    if let Some(t) = test {
        apply_restore_test(&mut out, t);
    }
    if let Some(vm) = session {
        let info = RunningVm {
            session_id: uuid::Uuid::new_v4(),
            image_id: req.image_id,
            started_unix: now_unix() - vm.uptime().as_secs() as i64,
            vnc_port: vm.access.vnc_port,
            forwards: vm.access.forwards.clone(),
        };
        out.session = Some(info.clone());
        SESSIONS.lock().unwrap().push(Held { info, vm });
    }
    update_for(out)
}

#[cfg(not(unix))]
fn kvm(_: &Ctx, _: &Repository, _: &BootRequest, _: &Reporter) -> anyhow::Result<JobUpdate> {
    bail!("QEMU boot checks run on Linux hosts")
}

fn hyperv(
    ctx: &Ctx,
    repo: &Repository,
    req: &BootRequest,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m = repo.load_manifest(&req.image_id)?;
    let keep_running = req.keep_running && !req.full_restore;
    let session_id = uuid::Uuid::new_v4();
    let short = &req.image_id.simple().to_string()[..8];
    // A kept VM gets a name of its own; a plain check reuses one, clearing an interrupted run's leftovers.
    let name = if keep_running {
        format!(
            "Fenrir check {} {} {}",
            m.machine.hostname,
            &m.created[..10.min(m.created.len())],
            &session_id.simple().to_string()[..6]
        )
    } else {
        format!("fenrir-check-{short}")
    };
    let base = match req
        .directory
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(d) => {
            let p = std::path::PathBuf::from(d);
            if !p.is_absolute() {
                bail!(
                    "the folder for the VM must be a full path on the host, e.g. D:\\Fenrir checks"
                );
            }
            p
        }
        None => ctx.state_dir.join("boot-checks"),
    };
    let dir = base.join(crate::restore::safe_name(&name));
    if !keep_running {
        let _ = crate::hyperv::remove_vm(&name);
        let _ = std::fs::remove_dir_all(&dir);
    }
    let mut test: Option<RestoreTest> = None;
    let result = (|| -> anyhow::Result<BootCheckResult> {
        let started = std::time::Instant::now();
        let written = crate::restore::write_disk_files_reported(
            ctx,
            repo,
            &m,
            &[],
            &dir,
            vdisk::Format::Vhdx,
            rep,
        )?;
        if req.full_restore {
            let reports: Vec<engine::RestoreReport> =
                written.iter().map(|(_, _, r)| r.clone()).collect();
            test = Some(restore_facts("vhdx", &reports, started.elapsed().as_secs()));
        }
        let files: Vec<(u32, std::path::PathBuf)> =
            written.into_iter().map(|(i, p, _)| (i, p)).collect();
        let mut spec = crate::restore::vm_spec(&m, &name, &dir, &files, None, false);
        spec.switch = None;
        if let Some(mb) = req.memory_mb {
            spec.memory_mb = mb.clamp(512, 65536);
        }
        if let Some(c) = req.cpus {
            spec.cpu_count = c.clamp(1, 16);
        }
        rep.progress("booting", 0, 1, "starting the VM (network disconnected)");
        crate::hyperv::run_ps(&crate::hyperv::new_vm_script(&spec)?)?;
        let r = crate::hyperv::boot_check_vm(&name, 600)?;
        let (shot, blank) = match r
            .thumb
            .as_deref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
        {
            Some(raw) => {
                let rgb = vmboot::png::rgb565_to_rgb(&raw);
                let (w, h) = (crate::hyperv::THUMB_W, crate::hyperv::THUMB_H);
                let blank = vmboot::probe::summarise_ppm(&vmboot::png::ppm(w, h, &rgb))
                    .is_none_or(|s| s.is_blank());
                (vmboot::png::encode_rgb(w, h, &rgb).map(|p| b64(&p)), blank)
            }
            None => (None, true),
        };
        let (outcome, method) = match r.outcome.as_str() {
            "heartbeat" => ("verified", "heartbeat"),
            "timeout" if !blank => ("screen", "screen"),
            "timeout" => ("failed", "timeout"),
            _ => ("failed", "vm state"),
        };
        let message = if outcome == "screen" {
            "the VM is running but its heartbeat service did not answer (integration services missing?); check the screenshot".to_string()
        } else {
            r.message
        };
        Ok(BootCheckResult {
            image_id: req.image_id,
            outcome: outcome.into(),
            method: method.into(),
            seconds: r.seconds,
            firmware: if spec.generation == 2 { "uefi" } else { "bios" }.into(),
            accel: "hyperv".into(),
            message,
            screenshot_png: shot,
            session: None,
            restore_test: None,
        })
    })();
    let keep = keep_running && result.is_ok();
    if keep {
        // Left for an administrator to log in to; its network stays disconnected. Stop it from the console.
        let info = RunningVm {
            session_id,
            image_id: req.image_id,
            started_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            vnc_port: 0,
            forwards: Default::default(),
        };
        #[cfg(not(unix))]
        kept::add(kept::Kept {
            info: info.clone(),
            name: name.clone(),
            dir: dir.clone(),
        });
        crate::log::info(&format!("kept boot-check VM '{name}' in {}", dir.display()));
        let mut r = result?;
        r.session = Some(info);
        r.message = format!("{} The VM is kept in Hyper-V Manager as '{name}' (network disconnected) until you stop it.", r.message);
        return update_for(r);
    }
    let vm = crate::hyperv::remove_vm(&name);
    if let Err(e) = &vm {
        crate::log::warn(&format!("could not remove boot-check VM {name}: {e:#}"));
    }
    let files = std::fs::remove_dir_all(&dir);
    let mut out = result?;
    if let Some(mut t) = test {
        removed(
            &mut t,
            vm.and(files.or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("{}: {e}", dir.display()))
                }
            })),
        );
        apply_restore_test(&mut out, t);
    }
    update_for(out)
}

#[cfg(test)]
mod restore_test_tests {
    use super::*;

    fn result() -> BootCheckResult {
        BootCheckResult {
            image_id: uuid::Uuid::nil(),
            outcome: "verified".into(),
            method: "ssh".into(),
            seconds: 40,
            firmware: "uefi".into(),
            accel: "kvm".into(),
            message: "the guest answered".into(),
            screenshot_png: None,
            session: None,
            restore_test: None,
        }
    }

    #[test]
    fn a_restore_test_records_the_restore_and_the_deletion() {
        let mut t = RestoreTest {
            format: "raw".into(),
            chunks_checked: 12,
            ..Default::default()
        };
        removed(&mut t, Ok(()));
        assert!(t.vm_removed && t.removed_unix > 0 && t.removal_error.is_empty());
        let mut r = result();
        apply_restore_test(&mut r, t);
        assert_eq!(r.outcome, "verified");
        assert_eq!(r.restore_test.unwrap().chunks_checked, 12);
    }

    #[test]
    fn a_mismatch_fails_and_a_failed_deletion_is_said() {
        let mut r = result();
        apply_restore_test(
            &mut r,
            RestoreTest {
                mismatches: 2,
                vm_removed: true,
                ..Default::default()
            },
        );
        assert_eq!(r.outcome, "failed");
        assert!(r.message.starts_with("2 chunk(s)"));

        let mut t = RestoreTest::default();
        removed(&mut t, Err(anyhow::anyhow!("access denied")));
        assert!(!t.vm_removed && t.removal_error.contains("access denied"));
        let mut r = result();
        apply_restore_test(&mut r, t);
        assert_eq!(r.outcome, "verified");
        assert!(r.message.contains("could not be deleted: access denied"));
        let u = update_for(r).unwrap();
        assert_eq!(u.result.unwrap()["restore_test"]["vm_removed"], false);
    }
}
