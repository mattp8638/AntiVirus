//! fenrir-backup-agent: enrolls with a Fenrir-Backup server, then runs the jobs it
//! is given (backups, Hyper-V VM backups, verification).

mod apprestore;
mod boot;
mod browse;
mod client;
mod cloudrestore;
mod config;
mod discover;
mod download;
mod export;
mod folders;
mod gateway;
mod hwfix;
mod hyperv;
mod inventory;
mod jobs;
mod linuxfix;
mod localrec;
mod log;
#[cfg(target_os = "macos")]
mod macsnap;
mod malware;
mod names;
mod rct;
mod recovery;
mod restore;
mod search;
mod setup;
mod share;
mod update;
mod vmdef;
#[cfg(windows)]
mod winsvc;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::{Parser, Subcommand};
use protocol::{
    AgentRole, EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse, PROTOCOL_VERSION,
};

use crate::client::Client;
use crate::config::{AgentConfig, Secrets};

#[derive(Parser)]
#[command(name = "fenrir-backup-agent", version, about = "Fenrir-Backup agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register this machine with a server (run by the installer).
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        /// SHA-256 of the server certificate (hex) for self-signed servers.
        #[arg(long, default_value = "")]
        pin: String,
        #[arg(long, default_value = "server")]
        role: String,
    },
    /// Run in the foreground (systemd, launchd, or by hand).
    Run,
    /// Recovery media: find the server settings, enrol this machine for
    /// restores (state in RAM) and serve jobs until stopped.
    Recovery {
        /// Settings file (default: search the recovery medium and sticks).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Recovery media: after a Windows disk was restored to DEVICE, make it
    /// start on this machine's storage controller (offline registry; prints
    /// what changed as JSON).
    PrepareWindows {
        #[arg(long)]
        device: String,
    },
    /// The local recovery partition, by hand (normally a job from the
    /// server): `install` (repartitions VOLUME's disk: needs --yes) or
    /// `remove`. Prints the result as JSON.
    LocalRecovery {
        /// install | remove
        action: String,
        /// Recovery settings file (server, enrolment code), for install.
        #[arg(long)]
        settings: Option<std::path::PathBuf>,
        #[arg(long, default_value = "C")]
        volume: String,
        #[arg(long, default_value_t = 0)]
        size_mb: u32,
        #[arg(long)]
        auto_start: bool,
        /// Build from this Windows PE image instead of the machine's Windows RE.
        #[arg(long)]
        base_wim: Option<std::path::PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Windows service entry point.
    Service,
    /// Show enrollment and connectivity.
    Status,
    /// Windows: install (or update) the agent as the FenrirBackupAgent service and
    /// enrol it. Asks for administrator rights if needed.
    Install {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "")]
        pin: String,
        #[arg(long, default_value = "server")]
        role: String,
    },
    /// Windows: remove the service, the program and this machine's agent
    /// identity. Backups already stored are kept.
    Uninstall {
        /// Confirm without asking.
        #[arg(long)]
        yes: bool,
    },
}

fn main() {
    // Fenrir-Backup-Setup.exe: the agent with its settings appended. Started by
    // double-click (no arguments) or with /quiet, it installs itself.
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || (args.len() == 2 && setup::is_quiet_flag(&args[1])) {
        if let Some((cfg, exe)) = setup::embedded() {
            let quiet = args.len() == 2;
            let r = setup::install(&cfg, Some(exe), Some(if quiet { "/quiet" } else { "" }));
            let relaunched = matches!(r, Ok(false));
            let code = match r {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("\nSetup failed: {e:#}");
                    1
                }
            };
            // Started by double-click: keep the window open to read it. An
            // elevated copy was started instead when `relaunched`.
            if !quiet && !relaunched {
                println!("\nPress Enter to close this window.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
            std::process::exit(code);
        }
    }
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Enroll {
            server,
            token,
            pin,
            role,
        } => enroll(&server, &token, &pin, &role),
        Cmd::Run => match run_loop(stop_on_signal()) {
            // systemd (Restart=always) and launchd (KeepAlive) start the new build.
            Ok(LoopExit::Restart) => std::process::exit(75),
            Ok(LoopExit::Stopped) => Ok(()),
            Err(e) => Err(e),
        },
        Cmd::Recovery { config } => recovery::run(config),
        Cmd::PrepareWindows { device } => hwfix::adapt_restored_disk(&device).map(|r| {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }),
        Cmd::LocalRecovery {
            action,
            settings,
            volume,
            size_mb,
            auto_start,
            base_wim,
            yes,
        } => local_recovery_cli(
            &action, settings, &volume, size_mb, auto_start, base_wim, yes,
        ),
        Cmd::Service => service(),
        Cmd::Status => status(),
        Cmd::Install {
            server,
            token,
            pin,
            role,
        } => {
            let cfg = protocol::setup::SetupConfig {
                server,
                pin,
                token,
                role,
            };
            setup::install(&cfg, None, None).map(|_| ())
        }
        Cmd::Uninstall { yes } => {
            if !yes {
                print!("Remove the Fenrir-Backup agent from this machine? Type yes: ");
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let mut a = String::new();
                let _ = std::io::stdin().read_line(&mut a);
                if a.trim() != "yes" {
                    eprintln!("not removed");
                    std::process::exit(2);
                }
            }
            setup::uninstall()
        }
    };
    if let Err(e) = r {
        eprintln!("fenrir-backup-agent: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn service() -> anyhow::Result<()> {
    winsvc::run()
}

#[cfg(not(windows))]
fn service() -> anyhow::Result<()> {
    anyhow::bail!("`service` is the Windows service entry point; use `run` on this platform")
}

fn stop_on_signal() -> Arc<AtomicBool> {
    // The service manager stops us with SIGTERM; the default action ends the
    // process, which is safe: a killed backup leaves no partial manifest.
    Arc::new(AtomicBool::new(false))
}

fn enroll(server: &str, token: &str, pin: &str, role: &str) -> anyhow::Result<()> {
    enroll_as(server, token, pin, role, None)
}

/// Enrol; `identity` overrides (hostname, machine id), for recovery media.
pub fn enroll_as(
    server: &str,
    token: &str,
    pin: &str,
    role: &str,
    identity: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    let server = config::validate_server_url(server)?;
    let detected;
    let role = if role == "auto" {
        detected = inventory::detect_role();
        detected.as_str()
    } else {
        role
    };
    let role =
        AgentRole::parse(role).context("role must be workstation, server, hyperv or auto")?;
    if role == AgentRole::Recovery && identity.is_none() {
        anyhow::bail!(
            "the recovery role is for recovery media: use `fenrir-backup-agent recovery`"
        );
    }
    let dir = config::state_dir();
    config::ensure_private_dir(&dir)?;
    // Keep an existing key pair so repository access survives reinstalls.
    let key = config::load_secrets(&dir)
        .ok()
        .flatten()
        .map(|s| s.key)
        .unwrap_or_else(protocol::seal::AgentKey::generate);
    let machine_id = match identity {
        Some((_, m)) => m.to_string(),
        None => inventory::machine_id()?,
    };
    let client = Client::new(&server, pin, None)?;
    let req = EnrollRequest {
        protocol: PROTOCOL_VERSION,
        token: token.to_string(),
        hostname: identity.map_or_else(inventory::hostname, |(h, _)| h.to_string()),
        machine_id: machine_id.clone(),
        os: inventory::os(),
        role,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        public_key: key.public_b64(),
    };
    let resp: EnrollResponse = client.post("/api/agent/enroll", &req)?;
    config::save_secrets(
        &dir,
        &Secrets {
            agent_token: resp.agent_token,
            key,
        },
    )?;
    AgentConfig {
        server: server.clone(),
        pin: pin.to_string(),
        agent_id: resp.agent_id.to_string(),
        role: role.as_str().into(),
        machine_id,
    }
    .save(&dir)?;
    println!("Enrolled with {server} as agent {}.", resp.agent_id);
    Ok(())
}

fn status() -> anyhow::Result<()> {
    let dir = config::state_dir();
    let cfg = AgentConfig::load(&dir)?;
    println!(
        "server:    {}\nagent id:  {}\nrole:      {}\nmachine:   {}",
        cfg.server, cfg.agent_id, cfg.role, cfg.machine_id
    );
    let s = config::load_secrets(&dir)?.context("secrets missing: enroll again")?;
    let client = Client::new(&cfg.server, &cfg.pin, Some(s.agent_token))?;
    let inv = inventory::collect(&cfg.role, vec![], vec![]);
    let r: HeartbeatResponse = client.post(
        "/api/agent/heartbeat",
        &HeartbeatRequest {
            inventory: inv,
            running_job: None,
        },
    )?;
    println!("server:    reachable ({} job(s) waiting)", r.jobs.len());
    Ok(())
}

/// When the VM list was read, the VMs, and any problem listing them.
type VmCache = (Option<Instant>, Vec<protocol::VmSummary>, Vec<String>);

struct Running {
    id: uuid::Uuid,
    ctl: Arc<engine::JobControl>,
    handle: std::thread::JoinHandle<()>,
}

/// Main loop: heartbeat, take at most one job, keep heartbeating while it
/// runs, honour cancellations.
/// Why the main loop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum LoopExit {
    Stopped,
    /// A new agent build was installed; restart to run it.
    Restart,
}

pub fn run_loop(stop: Arc<AtomicBool>) -> anyhow::Result<LoopExit> {
    let dir = config::state_dir();
    log::init(&dir);
    let cfg = AgentConfig::load(&dir)?;
    let secrets = config::load_secrets(&dir)?.context("secrets missing: enroll again")?;
    let client = Client::new(&cfg.server, &cfg.pin, Some(secrets.agent_token.clone()))?;
    let key = Arc::new(secrets.key);
    log::info(&format!(
        "agent {} starting; server {}",
        cfg.agent_id, cfg.server
    ));
    if hyperv::is_host(&cfg.role) {
        jobs::cleanup_leftover_checkpoints(&dir);
    }
    #[cfg(target_os = "linux")]
    jobs::cleanup_leftover_snapshots(&dir);
    update::cleanup_old();
    let mut failed_update: Option<(String, Instant)> = None;

    let mut backoff = 5u64;
    let mut running: Option<Running> = None;
    let mut inv_cache: Option<(Instant, protocol::Inventory)> = None;
    let gw = gateway::Gateway::new(key.clone(), client.clone());
    let vms: Arc<Mutex<VmCache>> = Arc::new(Mutex::new((None, vec![], vec![])));

    while !stop.load(Ordering::SeqCst) {
        if running.as_ref().is_some_and(|r| r.handle.is_finished()) {
            running = None;
        }
        // Close an image left open for browsing, and its network share.
        if running.is_none()
            && browse::expire()
            && boot::running_vms().is_empty()
            && !gateway::serving()
        {
            share::release_all();
        }
        // Hyper-V inventory is slow (PowerShell); refresh every 5 minutes.
        if hyperv::is_host(&cfg.role) {
            let mut g = vms.lock().unwrap();
            if g.0.is_none_or(|t| t.elapsed() > Duration::from_secs(300)) {
                match hyperv::list_vms() {
                    Ok(v) => *g = (Some(Instant::now()), v, vec![]),
                    Err(e) => {
                        *g = (
                            Some(Instant::now()),
                            vec![],
                            vec![format!("Could not list Hyper-V VMs: {e:#}")],
                        )
                    }
                }
            }
        }
        let (vm_list, notes) = {
            let g = vms.lock().unwrap();
            (g.1.clone(), g.2.clone())
        };
        // While polling fast (file browsing), the inventory is reused for 20 s.
        let inventory = match &inv_cache {
            Some((t, inv)) if t.elapsed() < Duration::from_secs(20) => inv.clone(),
            _ => {
                let inv = inventory::collect(&cfg.role, vm_list, notes);
                inv_cache = Some((Instant::now(), inv.clone()));
                inv
            }
        };
        let mut inventory = inventory;
        inventory.gateway_addresses = gw.addresses();
        let req = HeartbeatRequest {
            inventory,
            running_job: running.as_ref().map(|r| r.id),
        };
        match client.post::<_, HeartbeatResponse>("/api/agent/heartbeat", &req) {
            Ok(hb) => {
                backoff = 5;
                // The server asks for 1-second polling while someone browses files.
                let poll = hb.poll_seconds.clamp(1, 300) as u64;
                gw.apply(hb.gateway.as_ref());
                if let Some(r) = &running {
                    if hb.cancel.contains(&r.id) {
                        log::info(&format!("job {} cancelled by the server", r.id));
                        r.ctl.cancel();
                    }
                }
                if running.is_none() {
                    if let Some(spec) = hb.jobs.into_iter().next() {
                        log::info(&format!("starting job {} ({})", spec.id, spec.kind.label()));
                        let ctl = Arc::new(engine::JobControl::new());
                        let (c2, k2, cfg2, dir2, ctl2) = (
                            client.clone(),
                            key.clone(),
                            cfg.clone(),
                            dir.clone(),
                            ctl.clone(),
                        );
                        let id = spec.id;
                        let handle = std::thread::spawn(move || {
                            let ctx = jobs::Ctx {
                                cfg: &cfg2,
                                state_dir: &dir2,
                                client: &c2,
                                key: &k2,
                                ctl: ctl2,
                            };
                            let outcome = jobs::run(&ctx, &spec);
                            log::info(&format!(
                                "job {} finished: {:?} {}",
                                spec.id,
                                outcome.state,
                                outcome.error.clone().unwrap_or_default()
                            ));
                            if let Err(e) = jobs::Reporter::new(&c2, spec.id).finish(&outcome) {
                                log::error(&format!(
                                    "could not report the result of job {}: {e:#}",
                                    spec.id
                                ));
                            }
                        });
                        running = Some(Running { id, ctl, handle });
                    }
                }
                // Update only between jobs, and do not retry a failing
                // build more than hourly.
                if let (None, Some(u), true) = (
                    &running,
                    &hb.update,
                    req.inventory.running_vms.is_empty() && cfg.role != "recovery",
                ) {
                    let recently_failed = failed_update.as_ref().is_some_and(|(sha, t)| {
                        sha == &u.sha256 && t.elapsed() < Duration::from_secs(3600)
                    });
                    if !u.sha256.eq_ignore_ascii_case(&update::self_sha256()) && !recently_failed {
                        log::info(&format!(
                            "updating agent to build {}",
                            &u.sha256[..12.min(u.sha256.len())]
                        ));
                        match update::apply(&client, u) {
                            Ok(()) => {
                                log::info("agent updated; restarting");
                                return Ok(LoopExit::Restart);
                            }
                            Err(e) => {
                                log::warn(&format!("agent update failed: {e:#}"));
                                failed_update = Some((u.sha256.clone(), Instant::now()));
                            }
                        }
                    }
                }
                sleep_unless(&stop, poll);
            }
            Err(e) => {
                if let Some(r) = e.downcast_ref::<client::ServerRefused>() {
                    if r.code == 401 || r.code == 403 {
                        log::error(&format!("{r}. This machine must be enrolled again."));
                    }
                }
                log::warn(&format!("heartbeat failed: {e:#}"));
                backoff = (backoff * 2).min(300);
                sleep_unless(&stop, backoff);
            }
        }
    }
    if let Some(r) = running {
        r.ctl.cancel();
        let _ = r.handle.join();
    }
    boot::stop_all();
    log::info("agent stopped");
    Ok(LoopExit::Stopped)
}

fn sleep_unless(stop: &AtomicBool, secs: u64) {
    for _ in 0..secs {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(windows)]
fn local_recovery_cli(
    action: &str,
    settings: Option<std::path::PathBuf>,
    volume: &str,
    size_mb: u32,
    auto_start: bool,
    base_wim: Option<std::path::PathBuf>,
    yes: bool,
) -> anyhow::Result<()> {
    if !yes {
        anyhow::bail!("this repartitions the system disk: add --yes");
    }
    match action {
        "install" => {
            let path = settings.ok_or_else(|| anyhow::anyhow!("--settings is required"))?;
            let cfg = protocol::recovery::parse(&std::fs::read(&path)?)
                .map_err(|e| anyhow::anyhow!(e))?
                .ok_or_else(|| anyhow::anyhow!("{} holds no settings", path.display()))?;
            let host = inventory::hostname();
            let (st, notes) = localrec::install(&localrec::Options {
                volume,
                size_mb,
                auto_start,
                settings: &cfg,
                base_wim: base_wim.as_deref(),
                machine: &host,
            })?;
            println!("{}", serde_json::json!({ "state": st, "notes": notes }));
        }
        "remove" => println!("{}", serde_json::json!({ "notes": localrec::remove()? })),
        other => anyhow::bail!("unknown action {other}: install or remove"),
    }
    Ok(())
}

#[cfg(not(windows))]
fn local_recovery_cli(
    _: &str,
    _: Option<std::path::PathBuf>,
    _: &str,
    _: u32,
    _: bool,
    _: Option<std::path::PathBuf>,
    _: bool,
) -> anyhow::Result<()> {
    anyhow::bail!("local recovery partitions are for Windows")
}
