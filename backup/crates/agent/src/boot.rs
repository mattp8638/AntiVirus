//! Boot checks: start an image as an isolated VM and see whether it boots.
//!
//! * Linux hosts with QEMU: straight from the repository (`vmboot`), no
//!   copy. Optionally left running; such sessions live in this process,
//!   are listed in the inventory and stop after `MAX_SESSION`.
//! * Hyper-V hosts: the image is written as VHDX into a scratch folder,
//!   booted with its network disconnected, checked by heartbeat, and
//!   removed again.

use std::sync::Mutex;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use anyhow::anyhow;
use anyhow::bail;
use base64::Engine;
use core_format::Repository;
use protocol::{BootCheckResult, JobState, JobUpdate, RunningVm};

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

#[cfg(not(unix))]
static SESSIONS: Mutex<Vec<RunningVm>> = Mutex::new(Vec::new());

/// Can this host boot images as VMs? ("boot_kvm" / "boot_hyperv")
pub fn capability(role: &str) -> Option<&'static str> {
    if cfg!(windows) && role == "hyperv" {
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
        SESSIONS.lock().unwrap().clone()
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
    bail!("no VM session {id} runs on this host");
    #[allow(unreachable_code)]
    Ok(crate::jobs::finished(JobState::Succeeded))
}

/// Stop every session (agent shutdown).
pub fn stop_all() {
    #[cfg(unix)]
    SESSIONS.lock().unwrap().clear();
}

#[cfg(unix)]
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

pub struct BootRequest {
    pub image_id: uuid::Uuid,
    pub keep_running: bool,
    pub memory_mb: Option<u64>,
    pub cpus: Option<u32>,
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
    o.keep_running = req.keep_running;
    rep.progress("starting", 0, 1, "starting the VM");
    let timeout = o.timeout.as_secs();
    let progress = |msg: &str| rep.progress("booting", 0, timeout, msg);
    let ctl = ctx.ctl.clone();
    let (r, session) = vmboot::boot_check(repo, &m, &host, &o, &|| ctl.is_cancelled(), &progress)
        .map_err(|e| anyhow!("{e}"))?;
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
    };
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
    let name = format!("fenrir-check-{}", &req.image_id.simple().to_string()[..8]);
    let dir = ctx.state_dir.join("boot-checks").join(&name);
    // Leftovers of an interrupted check.
    let _ = crate::hyperv::remove_vm(&name);
    let _ = std::fs::remove_dir_all(&dir);
    let result = (|| -> anyhow::Result<BootCheckResult> {
        let files = crate::restore::write_vhdx(ctx, repo, &m, &[], &dir, rep)?;
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
        })
    })();
    if let Err(e) = crate::hyperv::remove_vm(&name) {
        crate::log::warn(&format!("could not remove boot-check VM {name}: {e:#}"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    if req.keep_running {
        crate::log::info("keep-running is not available on Hyper-V hosts; the VM was removed");
    }
    update_for(result?)
}
