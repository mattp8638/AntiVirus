//! `fenrir-backup` — command-line interface.
//!
//! Every command supports `--json`: one JSON document on stdout, progress
//! and messages on stderr. Exit codes are stable (see `ExitCode` and
//! docs/CLI.md) so RMM tools can act on them.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use core_format::backend::{Backend, LocalBackend};
use core_format::manifest::{MachineInfo, ManifestBody};
use core_format::repo::{InitOptions, Repository};
use core_format::{crypto::KdfParams, RecoveryKey};
use engine::{
    BackupOptions, DestructiveConfirmation, FileTarget, JobControl, RestoreOptions, VerifyLevel,
};
use serde::Serialize;
use serde_json::json;

mod exit;
use exit::{CliError, ExitCode};

#[derive(Parser)]
#[command(
    name = "fenrir-backup",
    version,
    about = "Fenrir-Backup: disk imaging and recovery"
)]
struct Cli {
    /// Print one JSON document on stdout instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Repository location (local path).
    #[arg(long, global = true, env = "FENRIR_REPO")]
    repo: Option<PathBuf>,

    /// Read the passphrase from this file (first line). Otherwise
    /// FENRIR_PASSPHRASE, otherwise prompt.
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,

    /// Unlock with a recovery key file instead of the passphrase.
    #[arg(long, global = true)]
    recovery_key: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Repository management.
    #[command(subcommand)]
    Repo(RepoCmd),
    /// Passphrases and recovery keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Create an image.
    #[command(subcommand)]
    Backup(BackupCmd),
    /// List and inspect images.
    #[command(subcommand)]
    Image(ImageCmd),
    /// Check images and chunks.
    Verify(VerifyArgs),
    /// Restore an image.
    #[command(subcommand)]
    Restore(RestoreCmd),
}

#[derive(Subcommand)]
enum RepoCmd {
    /// Create a new, empty, encrypted repository.
    Init {
        /// Where to write the recovery key. Keep it offline; it unlocks the
        /// repository if the passphrase is lost. Must not already exist.
        #[arg(long)]
        recovery_key_out: PathBuf,
        /// Chunk size in KiB (power of two, 64..65536).
        #[arg(long, default_value_t = 4096)]
        chunk_size_kib: u32,
        /// zstd compression level (1..19).
        #[arg(long, default_value_t = 3)]
        zstd_level: i32,
    },
    /// Show repository parameters and usage.
    Info,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Add another passphrase (read from FENRIR_NEW_PASSPHRASE or prompted).
    AddPassphrase,
    /// Create an additional recovery key.
    AddRecovery {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args, Clone)]
struct CommonBackup {
    /// Free-text label stored in the manifest.
    #[arg(long)]
    label: Option<String>,
    /// Read rate limit in MiB/s (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    rate_limit_mib: u64,
    /// Worker threads for hashing, compression and encryption.
    #[arg(long)]
    workers: Option<usize>,
    /// Plan only: read partition tables (and, for `system`, take and
    /// release a VSS snapshot), probe-read each partition, report what
    /// would be captured. Writes nothing; needs no repository.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Image the running Windows system (VSS, application-consistent).
    System {
        #[command(flatten)]
        common: CommonBackup,
        /// Also include this physical disk number. Repeatable.
        #[arg(long = "include-disk")]
        include_disk: Vec<u32>,
        /// Use the VSS FULL backup type (writers may truncate logs).
        /// Default is COPY, which leaves other backup tools' chains intact.
        #[arg(long)]
        vss_full: bool,
    },
    /// Image block devices or raw image files that are not in use.
    Disk {
        #[command(flatten)]
        common: CommonBackup,
        /// Devices or image files, one per disk in the image.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Allow imaging a mounted device without a snapshot.
        #[arg(long)]
        allow_inconsistent: bool,
        /// Machine ID to record (default: this machine's).
        #[arg(long)]
        machine_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum ImageCmd {
    /// List images, oldest first.
    List,
    /// Show one image's manifest.
    Show {
        /// Image ID or unique prefix.
        image: String,
    },
}

#[derive(Args)]
struct VerifyArgs {
    /// Image(s) to verify (ID or prefix). Default: all.
    #[arg(long)]
    image: Vec<String>,
    /// Decrypt and re-hash this percentage of chunks.
    #[arg(long, conflicts_with = "full")]
    sample: Option<f64>,
    /// Decrypt and re-hash every chunk.
    #[arg(long)]
    full: bool,
    #[arg(long, default_value_t = 4)]
    workers: usize,
}

#[derive(Subcommand)]
enum RestoreCmd {
    /// Write one disk of an image to a target device or file.
    Disk {
        /// Image ID or unique prefix.
        #[arg(long)]
        image: String,
        /// Disk index within the image.
        #[arg(long, default_value_t = 0)]
        disk: u32,
        /// Target block device or image file. Everything on it is overwritten.
        #[arg(long)]
        target: PathBuf,
        /// Confirm overwriting the target. Required.
        #[arg(long)]
        yes: bool,
        /// Skip writing zeros where the image has none (only for empty targets).
        #[arg(long)]
        no_zero_fill: bool,
        /// Fit the image onto a disk of a different size: move the GPT to
        /// the end of a larger disk, or use a smaller disk if every
        /// partition fits.
        #[arg(long)]
        fit: bool,
        /// Afterwards, add the fallback UEFI boot loader on the restored
        /// EFI system partition if it is missing (for new hardware).
        #[arg(long)]
        boot_fixup: bool,
        #[arg(long, default_value_t = 4)]
        workers: usize,
    },
}

struct Ctx {
    json: bool,
    repo: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    recovery_key: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let ctx = Ctx {
        json: cli.json,
        repo: cli.repo,
        passphrase_file: cli.passphrase_file,
        recovery_key: cli.recovery_key,
    };
    let result = run(&ctx, cli.cmd);
    let code = match result {
        Ok(Outcome {
            value,
            human,
            warnings,
        }) => {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({ "ok": true, "result": value, "warnings": warnings })
                    )
                    .unwrap()
                );
            } else {
                print!("{human}");
                for w in &warnings {
                    eprintln!("warning: {w}");
                }
            }
            if warnings.is_empty() {
                ExitCode::Ok
            } else {
                ExitCode::OkWithWarnings
            }
        }
        Err(e) => {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": { "kind": e.code.name(), "message": e.message }, "exit_code": e.code as i32 }))
                        .unwrap()
                );
            } else {
                eprintln!("error: {}", e.message);
            }
            e.code
        }
    };
    std::process::exit(code as i32);
}

struct Outcome {
    value: serde_json::Value,
    human: String,
    warnings: Vec<String>,
}

impl Outcome {
    fn new(value: impl Serialize, human: String) -> Self {
        Outcome {
            value: serde_json::to_value(value).unwrap(),
            human,
            warnings: vec![],
        }
    }
    fn with_warnings(mut self, w: Vec<String>) -> Self {
        self.warnings = w;
        self
    }
}

type R<T> = Result<T, CliError>;

fn run(ctx: &Ctx, cmd: Cmd) -> R<Outcome> {
    match cmd {
        Cmd::Repo(RepoCmd::Init {
            recovery_key_out,
            chunk_size_kib,
            zstd_level,
        }) => repo_init(ctx, &recovery_key_out, chunk_size_kib, zstd_level),
        Cmd::Repo(RepoCmd::Info) => repo_info(ctx),
        Cmd::Key(KeyCmd::AddPassphrase) => {
            let repo = open_repo(ctx)?;
            let p = new_passphrase("FENRIR_NEW_PASSPHRASE")?;
            let slot = repo.add_passphrase(p.as_bytes(), KdfParams::DEFAULT)?;
            Ok(Outcome::new(
                json!({ "slot_id": slot }),
                format!("Added passphrase (key slot {slot}).\n"),
            ))
        }
        Cmd::Key(KeyCmd::AddRecovery { out }) => {
            let repo = open_repo(ctx)?;
            ensure_new_file(&out)?;
            let rk = repo.add_recovery_key()?;
            write_secret_file(&out, &rk.to_file_contents())?;
            Ok(Outcome::new(
                json!({ "slot_id": rk.slot_id, "path": out }),
                format!(
                    "Recovery key written to {}. Store it offline.\n",
                    out.display()
                ),
            ))
        }
        Cmd::Backup(BackupCmd::Disk {
            common,
            paths,
            allow_inconsistent,
            machine_id,
        }) => backup_disk(ctx, common, paths, allow_inconsistent, machine_id),
        Cmd::Backup(BackupCmd::System {
            common,
            include_disk,
            vss_full,
        }) => backup_system(ctx, common, include_disk, vss_full),
        Cmd::Image(ImageCmd::List) => image_list(ctx),
        Cmd::Image(ImageCmd::Show { image }) => {
            let repo = open_repo(ctx)?;
            let id = repo.resolve_image_id(&image)?;
            let m = repo.load_manifest(&id)?;
            let human = serde_json::to_string_pretty(&m).unwrap() + "\n";
            Ok(Outcome::new(&m, human))
        }
        Cmd::Verify(a) => verify(ctx, a),
        Cmd::Restore(RestoreCmd::Disk {
            image,
            disk,
            target,
            yes,
            no_zero_fill,
            fit,
            boot_fixup,
            workers,
        }) => restore(
            ctx,
            &image,
            disk,
            &target,
            yes,
            RestoreFlags {
                zero_fill: !no_zero_fill,
                fit,
                boot_fixup,
            },
            workers,
        ),
    }
}

// ---------- repository access ----------

fn repo_path(ctx: &Ctx) -> R<&Path> {
    ctx.repo
        .as_deref()
        .ok_or_else(|| CliError::usage("no repository given: use --repo or FENRIR_REPO"))
}

fn read_passphrase(ctx: &Ctx, prompt: &str) -> R<String> {
    if let Some(p) = &ctx.passphrase_file {
        let s = std::fs::read_to_string(p).map_err(|e| {
            CliError::new(
                ExitCode::Usage,
                format!("passphrase file {}: {e}", p.display()),
            )
        })?;
        return Ok(s.lines().next().unwrap_or("").to_string());
    }
    if let Ok(p) = std::env::var("FENRIR_PASSPHRASE") {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            ExitCode::KeyError,
            "no passphrase: use --passphrase-file, FENRIR_PASSPHRASE or a terminal",
        ));
    }
    rpassword::prompt_password(prompt)
        .map_err(|e| CliError::new(ExitCode::KeyError, format!("reading passphrase: {e}")))
}

fn new_passphrase(env: &str) -> R<String> {
    if let Ok(p) = std::env::var(env) {
        if p.is_empty() {
            return Err(CliError::usage("passphrase must not be empty"));
        }
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            ExitCode::KeyError,
            format!("no new passphrase: set {env} or use a terminal"),
        ));
    }
    let a = rpassword::prompt_password("New passphrase: ")
        .map_err(|e| CliError::new(ExitCode::KeyError, e.to_string()))?;
    let b = rpassword::prompt_password("Repeat passphrase: ")
        .map_err(|e| CliError::new(ExitCode::KeyError, e.to_string()))?;
    if a != b {
        return Err(CliError::new(
            ExitCode::KeyError,
            "passphrases do not match",
        ));
    }
    if a.chars().count() < 8 {
        return Err(CliError::usage("passphrase must be at least 8 characters"));
    }
    Ok(a)
}

fn open_repo(ctx: &Ctx) -> R<Repository> {
    let path = repo_path(ctx)?;
    let backend: Arc<dyn Backend> = Arc::new(LocalBackend::open(path)?);
    if let Some(rkp) = &ctx.recovery_key {
        let s = std::fs::read_to_string(rkp).map_err(|e| {
            CliError::new(
                ExitCode::KeyError,
                format!("recovery key {}: {e}", rkp.display()),
            )
        })?;
        let rk = RecoveryKey::from_file_contents(&s)?;
        return Ok(Repository::unlock_with_recovery_key(backend, &rk)?);
    }
    // Fail fast on a bad path before prompting.
    Repository::read_config(&*backend)?;
    let p = read_passphrase(ctx, "Repository passphrase: ")?;
    Ok(Repository::unlock_with_passphrase(backend, p.as_bytes())?)
}

fn ensure_new_file(p: &Path) -> R<()> {
    if p.exists() {
        return Err(CliError::usage(format!(
            "{} already exists; refusing to overwrite",
            p.display()
        )));
    }
    Ok(())
}

fn write_secret_file(p: &Path, contents: &str) -> R<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o
        .open(p)
        .map_err(|e| CliError::new(ExitCode::Error, format!("{}: {e}", p.display())))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn repo_init(ctx: &Ctx, rk_out: &Path, chunk_kib: u32, zstd_level: i32) -> R<Outcome> {
    let path = repo_path(ctx)?;
    ensure_new_file(rk_out)?;
    if !(1..=19).contains(&zstd_level) {
        return Err(CliError::usage("zstd level must be 1..19"));
    }
    let chunk_size = chunk_kib
        .checked_mul(1024)
        .ok_or_else(|| CliError::usage("chunk size too large"))?;
    core_format::chunk::check_chunk_size(chunk_size)?;
    let pass = match (&ctx.passphrase_file, std::env::var("FENRIR_PASSPHRASE")) {
        (Some(_), _) | (None, Ok(_)) => read_passphrase(ctx, "")?,
        _ => new_passphrase("FENRIR_PASSPHRASE")?,
    };
    if pass.is_empty() {
        return Err(CliError::usage("passphrase must not be empty"));
    }
    let backend: Arc<dyn Backend> = Arc::new(LocalBackend::create(path)?);
    let (repo, rk) = Repository::init(
        backend,
        pass.as_bytes(),
        InitOptions {
            chunk_size,
            zstd_level,
            kdf: KdfParams::DEFAULT,
        },
    )?;
    write_secret_file(rk_out, &rk.to_file_contents())?;
    let c = repo.config();
    Ok(Outcome::new(
        json!({ "repo_id": c.repo_id, "path": path, "chunk_size": c.chunk_size, "recovery_key": rk_out }),
        format!(
            "Created repository {} at {}\nRecovery key written to {} — store it offline, away from this machine.\n",
            c.repo_id,
            path.display(),
            rk_out.display()
        ),
    ))
}

#[derive(Serialize)]
struct RepoInfo {
    repo_id: uuid::Uuid,
    location: String,
    created: String,
    chunk_size: u32,
    zstd_level: i32,
    images: usize,
    chunks: usize,
    stored_bytes: u64,
}

fn repo_info(ctx: &Ctx) -> R<Outcome> {
    let repo = open_repo(ctx)?;
    let c = repo.config();
    let chunks = repo.backend().list("chunks")?;
    let path = repo_path(ctx)?;
    let stored: u64 = chunks
        .iter()
        .filter_map(|k| {
            std::fs::metadata(k.split('/').fold(path.to_path_buf(), |p, s| p.join(s))).ok()
        })
        .map(|m| m.len())
        .sum();
    let info = RepoInfo {
        repo_id: c.repo_id,
        location: repo.backend().describe(),
        created: c.created.clone(),
        chunk_size: c.chunk_size,
        zstd_level: c.zstd_level,
        images: repo.list_image_ids()?.len(),
        chunks: chunks.len(),
        stored_bytes: stored,
    };
    let human = format!(
        "Repository {}\n  location:   {}\n  created:    {}\n  chunk size: {}\n  images:     {}\n  chunks:     {} ({})\n",
        info.repo_id,
        info.location,
        info.created,
        human_bytes(info.chunk_size as u64),
        info.images,
        info.chunks,
        human_bytes(info.stored_bytes)
    );
    Ok(Outcome::new(info, human))
}

// ---------- backup ----------

fn progress_printer(json: bool) -> impl Fn(&engine::Progress) + Sync {
    let last = std::sync::Mutex::new(Instant::now() - Duration::from_secs(10));
    let tty = std::io::stderr().is_terminal();
    move |p: &engine::Progress| {
        if json {
            return;
        }
        let mut l = last.lock().unwrap();
        if l.elapsed() < Duration::from_millis(if tty { 250 } else { 10_000 })
            && p.bytes_done < p.bytes_total
        {
            return;
        }
        *l = Instant::now();
        let pct = if p.bytes_total == 0 {
            100.0
        } else {
            p.bytes_done as f64 * 100.0 / p.bytes_total as f64
        };
        let line = format!(
            "disk {}: {:5.1}%  {} / {}  new chunks: {}",
            p.disk,
            pct,
            human_bytes(p.bytes_done),
            human_bytes(p.bytes_total),
            p.chunks_new
        );
        if tty {
            eprint!("\r{line}   ");
            if p.bytes_done >= p.bytes_total {
                eprintln!();
            }
        } else {
            eprintln!("{line}");
        }
    }
}

fn backup_options(c: &CommonBackup) -> BackupOptions {
    let mut o = BackupOptions {
        rate_limit: c.rate_limit_mib.saturating_mul(1024 * 1024),
        ..Default::default()
    };
    if let Some(w) = c.workers {
        o.workers = w.max(1);
    }
    o
}

fn report_outcome(r: engine::BackupReport) -> Outcome {
    let human = format!(
        "Image {} created ({:?}{}).\n  read {}, {} chunks, {} new ({} stored), {:.1}s\n",
        r.image_id,
        r.kind,
        r.parent
            .map(|p| format!(", parent {p}"))
            .unwrap_or_default(),
        human_bytes(r.stats.bytes_read),
        r.stats.chunks_total,
        r.stats.chunks_new,
        human_bytes(r.stats.bytes_new_stored),
        r.stats.duration_ms as f64 / 1000.0
    );
    let w = r.warnings.clone();
    Outcome::new(&r, human).with_warnings(w)
}

fn backup_disk(
    ctx: &Ctx,
    common: CommonBackup,
    paths: Vec<PathBuf>,
    allow_inconsistent: bool,
    machine_id: Option<String>,
) -> R<Outcome> {
    let mut opened = Vec::new();
    for p in &paths {
        opened.push(
            snapshot_linux::open_disk(p, allow_inconsistent).map_err(|e| {
                CliError::new(
                    if e.is::<snapshot_linux::InUse>() {
                        ExitCode::Safety
                    } else {
                        ExitCode::Error
                    },
                    e.to_string(),
                )
            })?,
        );
    }
    let mut warnings: Vec<String> = opened.iter().flat_map(|o| o.warnings.clone()).collect();
    let consistency = if opened
        .iter()
        .any(|o| o.consistency == core_format::manifest::Consistency::Inconsistent)
    {
        core_format::manifest::Consistency::Inconsistent
    } else {
        core_format::manifest::Consistency::Offline
    };
    if common.dry_run {
        let sources: Vec<&dyn engine::DiskSource> = opened
            .iter()
            .map(|o| &o.source as &dyn engine::DiskSource)
            .collect();
        return dry_run(&sources).map(|o| o.with_warnings(warnings));
    }
    let repo = open_repo(ctx)?;
    let machine_id = match machine_id {
        Some(m) => m,
        None => local_machine_id(),
    };
    if machine_id.is_empty() {
        return Err(CliError::usage(
            "could not determine a machine ID; pass --machine-id",
        ));
    }
    let meta = engine::ImageMeta {
        machine: MachineInfo {
            machine_id,
            hostname: hostname(),
        },
        consistency,
        os: Default::default(),
        boot: Default::default(),
        drivers: vec![],
        label: common.label.clone(),
        warnings: std::mem::take(&mut warnings),
        vm: None,
    };
    let sources: Vec<&dyn engine::DiskSource> = opened
        .iter()
        .map(|o| &o.source as &dyn engine::DiskSource)
        .collect();
    let pr = progress_printer(ctx.json);
    let r = engine::backup(
        &repo,
        &sources,
        meta,
        &backup_options(&common),
        &JobControl::new(),
        &pr,
    )?;
    Ok(report_outcome(r))
}

#[cfg(windows)]
fn backup_system(
    ctx: &Ctx,
    common: CommonBackup,
    include_disk: Vec<u32>,
    vss_full: bool,
) -> R<Outcome> {
    let repo = if common.dry_run {
        None
    } else {
        Some(open_repo(ctx)?)
    };
    if !ctx.json {
        eprintln!("Creating VSS snapshot set...");
    }
    let sb = snapshot_win::prepare_system_backup(&snapshot_win::VssOptions {
        full_backup_type: vss_full,
        extra_disks: include_disk,
    })
    .map_err(|e| CliError::new(ExitCode::Error, e.to_string()))?;
    if common.dry_run {
        let r = dry_run(&sb.sources());
        let vss_warnings = sb.meta.warnings.clone();
        // Abort: writers are told no backup happened.
        let finish = sb.finish(false);
        let mut out = r?;
        out.warnings.splice(0..0, vss_warnings);
        if let Err(e) = finish {
            out.warnings.push(format!("VSS abort reported: {e}"));
        }
        return Ok(out);
    }
    let repo = repo.expect("opened when not a dry run");
    let mut meta = sb.meta.clone();
    meta.label = common.label.clone();
    let pr = progress_printer(ctx.json);
    let result = engine::backup(
        &repo,
        &sb.sources(),
        meta,
        &backup_options(&common),
        &JobControl::new(),
        &pr,
    );
    let finish = sb.finish(result.is_ok());
    let r = result?;
    let mut out = report_outcome(r);
    if let Err(e) = finish {
        out.warnings.push(format!(
            "image stored, but VSS BackupComplete reported: {e}"
        ));
    }
    Ok(out)
}

#[cfg(not(windows))]
fn backup_system(_ctx: &Ctx, _c: CommonBackup, _d: Vec<u32>, _f: bool) -> R<Outcome> {
    Err(CliError::usage(
        "`backup system` uses VSS and runs on Windows. On Linux, image unmounted disks with `backup disk` (live Linux snapshots arrive in a later release).",
    ))
}

#[derive(Serialize)]
struct PlannedPartitionOut {
    number: u32,
    role: core_format::partition::PartitionRole,
    filesystem: core_format::fsdetect::FsType,
    capture: core_format::manifest::CaptureMethod,
    start: u64,
    length: u64,
    captured_bytes: u64,
    volume: Option<String>,
    mount_points: Vec<String>,
    encryption: Option<String>,
}

#[derive(Serialize)]
struct PlannedDiskOut {
    index: usize,
    device: String,
    model: String,
    size: u64,
    logical_sector_size: u32,
    scheme: core_format::partition::Scheme,
    captured_bytes: u64,
    probe_bytes_read: u64,
    partitions: Vec<PlannedPartitionOut>,
    excluded: Vec<core_format::manifest::ExcludedFile>,
}

fn dry_run(sources: &[&dyn engine::DiskSource]) -> R<Outcome> {
    let planned = engine::plan_image(sources)?;
    let mut out = Vec::new();
    let mut human = String::from("Dry run: nothing was written.\n");
    let mut warnings = Vec::new();
    for (i, (p, src)) in planned.iter().zip(sources).enumerate() {
        let probe = engine::probe_reads(*src, p)?;
        warnings.extend(p.plan.warnings.iter().cloned());
        let captured = core_format::extent::total_len(&p.layout.used);
        human += &format!(
            "disk {i}: {} {} ({}, {:?}), would capture {}\n",
            p.info.device,
            p.info.model,
            human_bytes(p.info.size),
            p.table.scheme,
            human_bytes(captured)
        );
        for r in &p.layout.partitions {
            human += &format!(
                "  #{:<2} {:<9} {:<10} {:<16} {:>10} of {:>10}  {}\n",
                r.entry.number,
                format!("{:?}", r.entry.role).to_lowercase(),
                format!("{:?}", r.filesystem).to_lowercase(),
                format!("{:?}", r.capture).to_lowercase(),
                human_bytes(r.captured_bytes),
                human_bytes(r.entry.length),
                r.mount_points.join(" ")
            );
        }
        for x in &p.plan.excluded {
            human += &format!("  excluded: {} ({})\n", x.path, human_bytes(x.bytes));
        }
        out.push(PlannedDiskOut {
            index: i,
            device: p.info.device.clone(),
            model: p.info.model.clone(),
            size: p.info.size,
            logical_sector_size: p.sector_size,
            scheme: p.table.scheme,
            captured_bytes: captured,
            probe_bytes_read: probe,
            partitions: p
                .layout
                .partitions
                .iter()
                .map(|r| PlannedPartitionOut {
                    number: r.entry.number,
                    role: r.entry.role,
                    filesystem: r.filesystem,
                    capture: r.capture,
                    start: r.entry.start,
                    length: r.entry.length,
                    captured_bytes: r.captured_bytes,
                    volume: r.volume.clone(),
                    mount_points: r.mount_points.clone(),
                    encryption: r.encryption.clone(),
                })
                .collect(),
            excluded: p.plan.excluded.clone(),
        });
    }
    Ok(Outcome::new(json!({ "dry_run": true, "disks": out }), human).with_warnings(warnings))
}

fn local_machine_id() -> String {
    #[cfg(windows)]
    {
        snapshot_win_machine_id()
    }
    #[cfg(not(windows))]
    {
        snapshot_linux::machine_id().unwrap_or_default()
    }
}

#[cfg(windows)]
fn snapshot_win_machine_id() -> String {
    snapshot_win::win::system::machine_id()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_default()
}

// ---------- images ----------

#[derive(Serialize)]
struct ImageSummary {
    image_id: uuid::Uuid,
    created: String,
    hostname: String,
    machine_id: String,
    kind: core_format::manifest::ImageKind,
    consistency: core_format::manifest::Consistency,
    label: Option<String>,
    disks: Vec<u64>,
    captured_bytes: u64,
    chunks: usize,
}

fn summarize(m: &ManifestBody) -> ImageSummary {
    ImageSummary {
        image_id: m.image_id,
        created: m.created.clone(),
        hostname: m.machine.hostname.clone(),
        machine_id: m.machine.machine_id.clone(),
        kind: m.kind,
        consistency: m.consistency,
        label: m.label.clone(),
        disks: m.disks.iter().map(|d| d.size).collect(),
        captured_bytes: m
            .disks
            .iter()
            .map(|d| core_format::extent::total_len(&d.used_extents))
            .sum(),
        chunks: m.chunk_ids().len(),
    }
}

fn image_list(ctx: &Ctx) -> R<Outcome> {
    let repo = open_repo(ctx)?;
    let (ok, bad) = repo.load_all_manifests()?;
    let list: Vec<ImageSummary> = ok.iter().map(summarize).collect();
    let mut human = String::new();
    for s in &list {
        human += &format!(
            "{}  {}  {:<15} {:<11} {:<13} {:>10}  {}\n",
            s.image_id,
            s.created,
            s.hostname,
            format!("{:?}", s.kind).to_lowercase(),
            format!("{:?}", s.consistency).to_lowercase(),
            human_bytes(s.captured_bytes),
            s.label.clone().unwrap_or_default()
        );
    }
    if list.is_empty() {
        human = "No images.\n".into();
    }
    let warnings = bad
        .iter()
        .map(|(id, e)| format!("image {id} could not be read: {e}"))
        .collect();
    Ok(Outcome::new(&list, human).with_warnings(warnings))
}

// ---------- verify ----------

fn verify(ctx: &Ctx, a: VerifyArgs) -> R<Outcome> {
    let repo = open_repo(ctx)?;
    let ids = a
        .image
        .iter()
        .map(|s| repo.resolve_image_id(s))
        .collect::<Result<Vec<_>, _>>()?;
    let level = match (a.full, a.sample) {
        (true, _) => VerifyLevel::Full,
        (false, Some(p)) => {
            if !(0.0..=100.0).contains(&p) {
                return Err(CliError::usage("--sample must be 0..100"));
            }
            VerifyLevel::Sample(p)
        }
        _ => VerifyLevel::Quick,
    };
    let r = engine::verify(
        &repo,
        (!ids.is_empty()).then_some(&ids[..]),
        level,
        &JobControl::new(),
        a.workers,
    )?;
    let mut human = format!(
        "Verified {} image(s), {} referenced chunks, {} read and re-hashed: {}\n",
        r.images_checked,
        r.chunks_referenced,
        r.chunks_read,
        if r.ok { "OK" } else { "PROBLEMS FOUND" }
    );
    for m in &r.bad_manifests {
        human += &format!("  manifest {}: {}\n", m.image_id, m.problem);
    }
    for c in r.missing_chunks.iter().chain(&r.corrupt_chunks) {
        human += &format!(
            "  chunk {}: {} (used by {} image(s))\n",
            c.chunk,
            c.problem,
            c.images.len()
        );
    }
    if !r.ok {
        if ctx.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "ok": false, "result": r, "exit_code": ExitCode::VerifyFailed as i32 })
                )
                .unwrap()
            );
            std::process::exit(ExitCode::VerifyFailed as i32);
        }
        return Err(CliError::new(
            ExitCode::VerifyFailed,
            human.trim_end().to_string(),
        ));
    }
    Ok(Outcome::new(&r, human))
}

// ---------- restore ----------

struct RestoreFlags {
    zero_fill: bool,
    fit: bool,
    boot_fixup: bool,
}

#[derive(serde::Serialize)]
struct RestoreOutput {
    #[serde(flatten)]
    report: engine::RestoreReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot: Option<engine::bootfix::BootFix>,
}

fn restore(
    ctx: &Ctx,
    image: &str,
    disk: u32,
    target: &Path,
    yes: bool,
    flags: RestoreFlags,
    workers: usize,
) -> R<Outcome> {
    let RestoreFlags {
        zero_fill,
        fit,
        boot_fixup,
    } = flags;
    let repo = open_repo(ctx)?;
    let id = repo.resolve_image_id(image)?;
    let m = repo.load_manifest(&id)?;
    let d = m
        .disks
        .iter()
        .find(|d| d.index == disk)
        .ok_or_else(|| CliError::usage(format!("image has no disk {disk}")))?;
    if !yes {
        return Err(CliError::new(
            ExitCode::ConfirmationRequired,
            format!(
                "this will overwrite {} with disk {} of image {} ({}). Re-run with --yes to confirm.",
                target.display(),
                disk,
                id,
                human_bytes(d.size)
            ),
        ));
    }
    let confirm = DestructiveConfirmation::confirmed_by_user(target);
    let min = if fit {
        engine::fit::min_size(d)
    } else {
        d.size
    };
    // Windows: a physical disk is taken over first (volumes locked and
    // dismounted, the system disk refused).
    #[cfg(windows)]
    let (t, lock) = if engine::target::is_windows_device_path(&target.to_string_lossy()) {
        let (t, l) = snapshot_win::win::disks::take_over(&target.to_string_lossy(), &confirm)?;
        (t, Some(l))
    } else {
        (FileTarget::open(target, min, true, &confirm)?, None)
    };
    #[cfg(not(windows))]
    let t = FileTarget::open(target, min, true, &confirm)?;
    let tty = std::io::stderr().is_terminal() && !ctx.json;
    let last = std::sync::Mutex::new(Instant::now());
    let pr = |done: u64, total: u64| {
        if tty {
            let mut l = last.lock().unwrap();
            if l.elapsed() > Duration::from_millis(250) {
                *l = Instant::now();
                eprint!(
                    "\rrestoring: {} / {}   ",
                    human_bytes(done),
                    human_bytes(total)
                );
            }
        }
    };
    let r = engine::restore_disk(
        &repo,
        &m,
        disk,
        &t,
        &RestoreOptions {
            workers,
            zero_fill: zero_fill || t.is_block_device,
            fit,
        },
        &JobControl::new(),
        &pr,
    )?;
    if tty {
        eprintln!();
    }
    drop(t);
    let mut human = format!(
        "Restored disk {} of image {} to {} ({} written).\n",
        disk,
        id,
        r.target,
        human_bytes(r.bytes_written)
    );
    let boot = if boot_fixup {
        let b = engine::bootfix::fix_restored_disk(target, d)?;
        match &b {
            Some(b) if !b.added.is_empty() => {
                human += &format!("Added the fallback boot loader: {}.\n", b.added.join(", "))
            }
            Some(_) => human += "The restored disk already has a fallback boot loader.\n",
            None => human += "No EFI system partition on this disk; nothing to fix.\n",
        }
        b
    } else {
        None
    };
    #[cfg(windows)]
    if let Some(l) = lock {
        if let Err(e) = l.finish() {
            human += &format!(
                "Windows did not re-read the restored disk ({e}); restart before using it.\n"
            );
        }
    }
    Ok(Outcome::new(&RestoreOutput { report: r, boot }, human))
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
