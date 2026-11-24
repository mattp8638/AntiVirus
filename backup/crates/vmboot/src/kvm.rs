//! QEMU/KVM boot and health check (Unix hosts).

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use core_format::manifest::Firmware;
use core_format::partition::PartitionRole;
use core_format::{ManifestBody, Repository};
use nbd_server::{Export, ImageExport, NbdServer};
use serde::{Deserialize, Serialize};

use crate::probe::{self, ScreenSummary, Service};
use crate::qmp;

#[derive(Debug)]
pub struct BootError(pub String);

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for BootError {}

fn err(m: impl Into<String>) -> BootError {
    BootError(m.into())
}

pub type Result<T> = std::result::Result<T, BootError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The guest answered: guest agent, or a service on the network.
    Verified,
    /// Reached a stable, non-blank screen; look at the screenshot.
    Screen,
    Failed,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BootReport {
    pub outcome: Outcome,
    /// What decided it: "guest agent", "SSH", "screen", "firmware", ...
    pub method: String,
    pub seconds: u64,
    /// "uefi" or "bios".
    pub firmware: String,
    /// "kvm" or "tcg" (software emulation).
    pub accel: String,
    pub message: String,
    #[serde(skip)]
    pub screenshot_png: Option<Vec<u8>>,
}

impl std::fmt::Debug for BootReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootReport")
            .field("outcome", &self.outcome)
            .field("method", &self.method)
            .field("seconds", &self.seconds)
            .field("firmware", &self.firmware)
            .field("accel", &self.accel)
            .field("message", &self.message)
            .field(
                "screenshot_png",
                &self.screenshot_png.as_ref().map(|p| p.len()),
            )
            .finish()
    }
}

/// What this host can do.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostSupport {
    pub qemu: Option<PathBuf>,
    pub qemu_img: Option<PathBuf>,
    pub kvm: bool,
    pub ovmf: Option<(PathBuf, PathBuf)>,
}

impl HostSupport {
    pub fn usable(&self) -> bool {
        self.qemu.is_some() && self.qemu_img.is_some()
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

pub fn detect() -> HostSupport {
    let ovmf_pairs = [
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ),
        (
            "/usr/share/qemu/ovmf-x86_64-code.bin",
            "/usr/share/qemu/ovmf-x86_64-vars.bin",
        ),
    ];
    HostSupport {
        qemu: which("qemu-system-x86_64"),
        qemu_img: which("qemu-img"),
        kvm: std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
        ovmf: ovmf_pairs
            .iter()
            .find(|(c, v)| Path::new(c).is_file() && Path::new(v).is_file())
            .map(|(c, v)| (PathBuf::from(c), PathBuf::from(v))),
    }
}

/// UEFI if the image says so or has an EFI system partition.
pub fn firmware_of(m: &ManifestBody) -> Firmware {
    if let Some(vm) = &m.vm {
        if vm.generation == 2 {
            return Firmware::Uefi;
        }
        if vm.generation == 1 {
            return Firmware::Bios;
        }
    }
    match m.boot.firmware {
        Firmware::Unknown => {
            if m.disks.iter().any(|d| {
                d.partitions
                    .iter()
                    .any(|p| p.entry.role == PartitionRole::Esp)
            }) {
                Firmware::Uefi
            } else {
                Firmware::Bios
            }
        }
        f => f,
    }
}

#[derive(Debug, Clone)]
pub struct BootOptions {
    pub memory_mb: u64,
    pub cpus: u32,
    /// Overall time limit for a verdict.
    pub timeout: Duration,
    /// Earliest time a "stable screen" counts.
    pub min_boot: Duration,
    /// How long the screen must stay unchanged.
    pub stable_for: Duration,
    /// Keep the VM after the verdict (VNC + forwards on loopback).
    pub keep_running: bool,
    /// Override firmware detection.
    pub firmware: Option<Firmware>,
}

impl BootOptions {
    pub fn for_host(h: &HostSupport) -> Self {
        BootOptions {
            memory_mb: 4096,
            cpus: 2,
            timeout: Duration::from_secs(if h.kvm { 600 } else { 1200 }),
            min_boot: Duration::from_secs(45),
            stable_for: Duration::from_secs(30),
            keep_running: false,
            firmware: None,
        }
    }
}

/// Connection details of a running VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Access {
    /// Loopback VNC port on the host.
    pub vnc_port: u16,
    /// Guest service → loopback host port.
    pub forwards: BTreeMap<String, u16>,
}

/// A running VM. Killed and cleaned up on drop.
pub struct VmSession {
    child: Child,
    qmp: Option<qmp::Qmp>,
    _nbd: NbdServer,
    dir: tempfile::TempDir,
    pub access: Access,
    pub firmware: Firmware,
    pub accel: String,
    started: Instant,
    forward_addrs: Vec<(Service, SocketAddr)>,
}

fn free_port() -> Result<u16> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| err(format!("no free port: {e}")))
}

impl VmSession {
    /// Start `image` as a VM. Returns once QEMU is running.
    pub fn start(
        repo: &Repository,
        image: &ManifestBody,
        host: &HostSupport,
        opts: &BootOptions,
    ) -> Result<VmSession> {
        let qemu = host
            .qemu
            .clone()
            .ok_or_else(|| err("qemu-system-x86_64 is not installed on this host"))?;
        let qemu_img = host
            .qemu_img
            .clone()
            .ok_or_else(|| err("qemu-img is not installed on this host"))?;
        if image.disks.is_empty() {
            return Err(err("the image has no disks"));
        }
        let firmware = opts.firmware.unwrap_or_else(|| firmware_of(image));
        if firmware == Firmware::Uefi && host.ovmf.is_none() {
            return Err(err(
                "the image needs UEFI firmware; install OVMF (package ovmf / edk2-ovmf)",
            ));
        }
        let dir = tempfile::Builder::new()
            .prefix("fenrir-vm-")
            .tempdir()
            .map_err(|e| err(format!("temp dir: {e}")))?;

        let mut exports: BTreeMap<String, Arc<dyn Export>> = BTreeMap::new();
        for d in &image.disks {
            let e = ImageExport::new(repo, image, d.index, 256 << 20)
                .map_err(|e| err(e.to_string()))?;
            exports.insert(format!("disk{}", d.index), Arc::new(e));
        }
        let nbd = NbdServer::start(exports).map_err(|e| err(format!("NBD server: {e}")))?;

        let accel = if host.kvm { "kvm" } else { "tcg" }.to_string();
        let uefi = firmware == Firmware::Uefi;
        let mut args: Vec<String> = vec![
            "-name".into(),
            format!("fenrir-{}", &image.image_id.to_string()[..8]),
            "-machine".into(),
            format!("{},accel={accel}", if uefi { "q35" } else { "pc" }),
            "-cpu".into(),
            if host.kvm {
                "host".into()
            } else {
                "max".into()
            },
            "-m".into(),
            opts.memory_mb.to_string(),
            "-smp".into(),
            opts.cpus.to_string(),
            "-nodefaults".into(),
            "-vga".into(),
            "std".into(),
            "-display".into(),
            "none".into(),
        ];
        if uefi {
            let (code, vars) = host.ovmf.clone().expect("checked");
            let vars_copy = dir.path().join("OVMF_VARS.fd");
            std::fs::copy(&vars, &vars_copy).map_err(|e| err(format!("copying OVMF vars: {e}")))?;
            args.extend([
                "-drive".into(),
                format!("if=pflash,format=raw,readonly=on,file={}", code.display()),
                "-drive".into(),
                format!("if=pflash,format=raw,file={}", vars_copy.display()),
            ]);
        }
        for (i, d) in image.disks.iter().enumerate() {
            let overlay = dir.path().join(format!("disk{}.qcow2", d.index));
            let o = Command::new(&qemu_img)
                .args([
                    "create",
                    "-q",
                    "-f",
                    "qcow2",
                    "-F",
                    "raw",
                    "-b",
                    &nbd.url(&format!("disk{}", d.index)),
                ])
                .arg(&overlay)
                .output()
                .map_err(|e| err(format!("qemu-img: {e}")))?;
            if !o.status.success() {
                return Err(err(format!(
                    "creating the overlay: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )));
            }
            let bus = if uefi {
                format!("ide.{i}")
            } else {
                format!("ide.{}", i / 2)
            };
            let unit = if uefi {
                String::new()
            } else {
                format!(",unit={}", i % 2)
            };
            if !uefi && i >= 4 || uefi && i >= 6 {
                return Err(err("too many disks for the emulated controller"));
            }
            args.extend([
                "-drive".into(),
                format!(
                    "file={},format=qcow2,if=none,id=d{i},cache=unsafe",
                    overlay.display()
                ),
                "-device".into(),
                format!(
                    "ide-hd,drive=d{i},bus={bus}{unit}{}",
                    if i == 0 { ",bootindex=0" } else { "" }
                ),
            ]);
        }
        let mut forwards = BTreeMap::new();
        let mut forward_addrs = vec![];
        let mut hostfwd = String::new();
        for s in probe::SERVICES {
            let p = free_port()?;
            hostfwd.push_str(&format!(",hostfwd=tcp:127.0.0.1:{p}-:{}", s.guest_port()));
            forwards.insert(s.name().to_string(), p);
            forward_addrs.push((s, SocketAddr::from(([127, 0, 0, 1], p))));
        }
        // VNC display numbers count from port 5900.
        let vnc_port = (5901..5999)
            .find(|p| TcpListener::bind(("127.0.0.1", *p)).is_ok())
            .ok_or_else(|| err("no free VNC port"))?;
        let qmp_path = dir.path().join("qmp.sock");
        let qga_path = dir.path().join("qga.sock");
        args.extend([
            "-netdev".into(),
            format!("user,id=n0,restrict=on{hostfwd}"),
            "-device".into(),
            "e1000,netdev=n0".into(),
            "-chardev".into(),
            format!(
                "socket,id=qmp,path={},server=on,wait=off",
                qmp_path.display()
            ),
            "-mon".into(),
            "chardev=qmp,mode=control".into(),
            "-chardev".into(),
            format!(
                "socket,id=qga0,path={},server=on,wait=off",
                qga_path.display()
            ),
            "-device".into(),
            "virtio-serial".into(),
            "-device".into(),
            "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".into(),
            "-device".into(),
            "pvpanic".into(),
            "-serial".into(),
            format!("file:{}", dir.path().join("serial.log").display()),
            "-debugcon".into(),
            format!("file:{}", dir.path().join("firmware.log").display()),
            "-global".into(),
            "isa-debugcon.iobase=0x402".into(),
            "-vnc".into(),
            format!("127.0.0.1:{}", vnc_port - 5900),
        ]);
        let child = Command::new(&qemu)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                std::fs::File::create(dir.path().join("qemu.log"))
                    .map_err(|e| err(e.to_string()))?,
            )
            .spawn()
            .map_err(|e| err(format!("starting QEMU: {e}")))?;
        let mut s = VmSession {
            child,
            qmp: None,
            _nbd: nbd,
            dir,
            access: Access { vnc_port, forwards },
            firmware,
            accel,
            started: Instant::now(),
            forward_addrs,
        };
        // QEMU creates the control socket at start-up.
        for _ in 0..100 {
            if let Some(code) = s.child.try_wait().ok().flatten() {
                return Err(err(format!(
                    "QEMU exited at start ({code}): {}",
                    s.log_tail("qemu.log", 600)
                )));
            }
            if let Ok(q) = qmp::Qmp::connect(&qmp_path) {
                s.qmp = Some(q);
                return Ok(s);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(err("QEMU did not open its control socket"))
    }

    pub fn log_tail(&self, name: &str, max: usize) -> String {
        let b = std::fs::read(self.dir.path().join(name)).unwrap_or_default();
        String::from_utf8_lossy(&b[b.len().saturating_sub(max)..])
            .trim()
            .to_string()
    }

    fn firmware_text(&self) -> String {
        format!(
            "{}\n{}",
            self.log_tail("firmware.log", 20_000),
            self.log_tail("serial.log", 20_000)
        )
    }

    pub fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn screenshot(&mut self, format: &str) -> Option<Vec<u8>> {
        let path = self.dir.path().join(format!("shot.{format}"));
        let _ = std::fs::remove_file(&path);
        let q = self.qmp.as_mut()?;
        let mut args = serde_json::json!({ "filename": path.display().to_string() });
        if format == "png" {
            args["format"] = "png".into();
        }
        q.execute("screendump", args).ok()?;
        std::fs::read(&path).ok()
    }

    fn guest_agent_alive(&self) -> bool {
        qmp::guest_ping(&self.dir.path().join("qga.sock"))
    }

    /// Watch the VM until it proves it booted, fails, or time runs out.
    pub fn check(
        &mut self,
        opts: &BootOptions,
        cancelled: &dyn Fn() -> bool,
        progress: &dyn Fn(&str),
    ) -> BootReport {
        let fw = match self.firmware {
            Firmware::Uefi => "uefi",
            _ => "bios",
        }
        .to_string();
        let mut last: Option<(ScreenSummary, Instant)> = None;
        let mut early: Option<ScreenSummary> = None;
        let report = |s: &mut Self, outcome, method: &str, message: String| BootReport {
            outcome,
            method: method.into(),
            seconds: s.started.elapsed().as_secs(),
            firmware: fw.clone(),
            accel: s.accel.clone(),
            message,
            screenshot_png: s.screenshot("png"),
        };
        loop {
            let t = self.started.elapsed();
            if cancelled() {
                return report(self, Outcome::Failed, "cancelled", "cancelled".into());
            }
            if !self.running() {
                return BootReport {
                    outcome: Outcome::Failed,
                    method: "vm exited".into(),
                    seconds: t.as_secs(),
                    firmware: fw.clone(),
                    accel: self.accel.clone(),
                    message: format!("QEMU exited: {}", self.log_tail("qemu.log", 600)),
                    screenshot_png: None,
                };
            }
            if let Some(q) = self.qmp.as_mut() {
                if let Ok(st) = q.execute("query-status", serde_json::json!({})) {
                    let status = st["status"].as_str().unwrap_or("").to_string();
                    if ["guest-panicked", "internal-error", "shutdown", "io-error"]
                        .contains(&status.as_str())
                    {
                        return report(
                            self,
                            Outcome::Failed,
                            "vm state",
                            format!("the VM entered state '{status}'"),
                        );
                    }
                }
            }
            if let Some(f) = probe::firmware_failure(&self.firmware_text()) {
                return report(
                    self,
                    Outcome::Failed,
                    "firmware",
                    format!("the firmware reported: {f}"),
                );
            }
            if self.guest_agent_alive() {
                return report(
                    self,
                    Outcome::Verified,
                    "guest agent",
                    "the QEMU guest agent inside the VM answered".into(),
                );
            }
            for (s, a) in self.forward_addrs.clone() {
                if probe::probe(a, s) {
                    return report(
                        self,
                        Outcome::Verified,
                        s.name(),
                        format!(
                            "the guest's {} service answered on the isolated network",
                            s.name()
                        ),
                    );
                }
            }
            if let Some(sum) = self
                .screenshot("ppm")
                .as_deref()
                .and_then(probe::summarise_ppm)
            {
                if t < Duration::from_secs(8) && early.is_none() && !sum.is_blank() {
                    early = Some(sum.clone());
                }
                match &last {
                    Some((prev, since)) if prev.same_as(&sum) => {
                        let firmware_screen = early.as_ref().is_some_and(|e| e.same_as(&sum));
                        if t >= opts.min_boot
                            && since.elapsed() >= opts.stable_for
                            && !sum.is_blank()
                            && !firmware_screen
                        {
                            return report(
                                self,
                                Outcome::Screen,
                                "screen",
                                "the VM reached a stable screen but did not answer on the network; check the screenshot".into(),
                            );
                        }
                    }
                    _ => last = Some((sum, Instant::now())),
                }
            }
            if t >= opts.timeout {
                let blank = last.as_ref().is_none_or(|(s, _)| s.is_blank());
                return report(
                    self,
                    Outcome::Failed,
                    "timeout",
                    if blank {
                        "the screen stayed blank".into()
                    } else {
                        "no stable screen and no answer before the time limit".into()
                    },
                );
            }
            progress(&format!("booting ({}s, {})", t.as_secs(), self.accel));
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    /// Stop QEMU (power off) and wait for it.
    pub fn stop(&mut self) {
        if let Some(q) = self.qmp.as_mut() {
            let _ = q.execute("quit", serde_json::json!({}));
        }
        for _ in 0..50 {
            if !self.running() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for VmSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Boot `image`, check it, and (unless `keep_running`) shut it down.
pub fn boot_check(
    repo: &Repository,
    image: &ManifestBody,
    host: &HostSupport,
    opts: &BootOptions,
    cancelled: &dyn Fn() -> bool,
    progress: &dyn Fn(&str),
) -> Result<(BootReport, Option<VmSession>)> {
    let mut s = VmSession::start(repo, image, host, opts)?;
    let r = s.check(opts, cancelled, progress);
    if opts.keep_running && r.outcome != Outcome::Failed && s.running() {
        Ok((r, Some(s)))
    } else {
        drop(s);
        Ok((r, None))
    }
}
