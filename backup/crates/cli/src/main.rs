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
    /// Kubernetes: back up and restore the objects of namespaces.
    #[command(subcommand)]
    K8s(K8sCmd),
    /// Microsoft 365, Google Workspace and Salesforce data.
    #[command(subcommand)]
    Saas(SaasCmd),
    /// Continuous data protection of Linux volumes (any second restorable).
    #[command(subcommand)]
    Cdp(CdpCmd),
    /// Changed-block tracking of Linux volumes: backups read only what changed.
    #[command(subcommand)]
    Cbt(CbtCmd),
    /// Copy a disk straight onto another (no repository).
    Clone(CloneArgs),
    /// Copy images to another repository (an off-site copy): re-encrypted
    /// for it, then verified there.
    Copy(CopyArgs),
}

#[derive(Args)]
struct CopyArgs {
    /// The destination repository (a folder, s3:// or azure://).
    #[arg(long)]
    to: PathBuf,
    /// The destination's passphrase, first line of this file. Otherwise
    /// FENRIR_TO_PASSPHRASE.
    #[arg(long)]
    to_passphrase_file: Option<PathBuf>,
    /// Image ID (or unique prefix) to copy. Repeatable. Default: every image
    /// the destination does not have.
    #[arg(long = "image")]
    images: Vec<String>,
    /// Re-read every copied chunk in the destination (default: check the
    /// manifests and that every chunk is there).
    #[arg(long)]
    full_verify: bool,
}

#[derive(Args)]
struct CloneArgs {
    /// Disk to copy: a block device or image file not in use (or with --live).
    #[arg(long)]
    source: PathBuf,
    /// Disk to overwrite. Everything on it is lost.
    #[arg(long)]
    target: PathBuf,
    /// Confirm overwriting the target. Required.
    #[arg(long)]
    yes: bool,
    /// The target may be a different size (GPT moved to its end; a smaller
    /// disk when the partitions fit).
    #[arg(long)]
    fit: bool,
    /// Give a larger target's extra space to the last partition and grow its
    /// file system (implies --fit).
    #[arg(long)]
    grow: bool,
    /// Add the fallback UEFI boot loader on the copy if it is missing.
    #[arg(long)]
    boot_fixup: bool,
    /// The source is in use: read it through a snapshot (Linux: LVM;
    /// Windows: VSS, the system disk).
    #[arg(long)]
    live: bool,
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
        /// Dedup group (repositories sharing one chunk store): `new` starts a
        /// group in --repo; a member's path (`<group>/repos/<id>`) adds a
        /// repository to its group (that member's passphrase from
        /// FENRIR_GROUP_PASSPHRASE, or prompted). The new repository is
        /// `<group>/repos/<its id>`: use that as --repo from then on.
        #[arg(long)]
        dedup_group: Option<String>,
    },
    /// Show repository parameters and usage.
    Info,
}

/// Changed-block tracking of a Linux logical volume with device-mapper
/// `era` (docs/design/cbt-physical.md).
#[derive(Subcommand)]
enum CbtCmd {
    /// Start tracking an unmounted logical volume; mount the device it
    /// prints from then on.
    Enable {
        #[arg(long)]
        name: String,
        #[arg(long)]
        volume: String,
        /// Tracking granularity in KiB (a power of two, 4 to 1024).
        #[arg(long, default_value_t = 64)]
        block_kib: u64,
    },
    /// Back the volume up, reading only the blocks written since the
    /// previous backup (the first reads everything).
    Backup {
        #[arg(long)]
        name: String,
        #[arg(long)]
        label: Option<String>,
        /// Read everything this time (and check the tracking).
        #[arg(long)]
        full: bool,
    },
    /// The tracking state and the current era.
    Status {
        #[arg(long)]
        name: String,
    },
    /// Stop tracking (unmount first); the volume is left as it is.
    Disable {
        #[arg(long)]
        name: String,
    },
}

/// Continuous data protection of a Linux logical volume.
#[derive(Subcommand)]
enum CdpCmd {
    /// Journal every write of an unmounted logical volume (then mount
    /// /dev/mapper/fenrir-cdp-NAME instead of it).
    Enable {
        #[arg(long)]
        name: String,
        /// The logical volume, e.g. /dev/vg0/data.
        #[arg(long)]
        volume: String,
        /// Size of each of the two journal volumes.
        #[arg(long, default_value_t = 1024)]
        journal_mb: u64,
    },
    /// Mark, swap and ship journals to the repository, with base images.
    Run {
        #[arg(long)]
        name: String,
        /// Seconds between timestamp marks (the restore granularity).
        #[arg(long, default_value_t = 5)]
        mark_every: u64,
        /// Seconds between journal swaps (shipped then).
        #[arg(long, default_value_t = 60)]
        rotate_every: u64,
        /// Seconds between base images.
        #[arg(long, default_value_t = 86_400)]
        base_every: u64,
        /// Stop after this many seconds (default: run until stopped).
        #[arg(long)]
        r#for: Option<u64>,
    },
    /// The times a volume can be restored to.
    Points {
        #[arg(long)]
        name: String,
    },
    /// Restore a volume as it was at a moment (to the second it was marked).
    Restore {
        #[arg(long)]
        name: String,
        /// Unix seconds, or YYYY-MM-DDTHH:MM:SSZ.
        #[arg(long)]
        at: String,
        /// A device or image file to write it to.
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    /// Stop journaling (unmount the device first).
    Disable {
        #[arg(long)]
        name: String,
        #[arg(long)]
        remove_journals: bool,
    },
}

/// Which SaaS service and its credentials (secrets come from files).
#[derive(clap::Args, Clone)]
struct SaasService {
    /// m365 | google | salesforce | quickbooks
    #[arg(long)]
    service: String,
    /// Microsoft 365: directory (tenant) ID or domain. Google: the Workspace
    /// domain. Salesforce: a name for the org. QuickBooks: the company
    /// (realm) ID.
    #[arg(long)]
    tenant: String,
    /// Microsoft 365 / Salesforce: the app registration's or connected app's client ID.
    #[arg(long)]
    client_id: Option<String>,
    /// Microsoft 365 / Salesforce: a file holding the client secret.
    /// QuickBooks: a JSON file {"client_secret": ..., "refresh_token": ...};
    /// the newest refresh token is kept beside it.
    #[arg(long)]
    secret_file: Option<PathBuf>,
    /// Google: the service account's JSON key file.
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// Google: a Workspace administrator (to list users).
    #[arg(long)]
    admin: Option<String>,
    /// Salesforce: https://<my-domain>.my.salesforce.com. QuickBooks: the
    /// API address (default production; https://sandbox-quickbooks.api.intuit.com).
    #[arg(long)]
    domain_url: Option<String>,
}

#[derive(Subcommand)]
enum SaasCmd {
    /// Back up (only what changed since the last backup is downloaded).
    Backup {
        #[command(flatten)]
        svc: SaasService,
        /// Users (Microsoft 365, Google) to back up; default: all.
        #[arg(long = "user")]
        users: Vec<String>,
        /// Salesforce objects; default: the standard ones and every custom object.
        #[arg(long = "object")]
        objects: Vec<String>,
        /// Leave mail out (Microsoft 365, Google).
        #[arg(long)]
        no_mail: bool,
        /// Leave files out (OneDrive, Google Drive).
        #[arg(long)]
        no_files: bool,
        /// Microsoft 365: SharePoint sites' document libraries (Sites.ReadWrite.All).
        #[arg(long)]
        sites: bool,
        /// Microsoft 365: Teams channel messages (ChannelMessage.Read.All).
        #[arg(long)]
        teams: bool,
        /// Microsoft 365: Entra ID objects and Conditional Access policies
        /// (Directory.Read.All, Policy.Read.All).
        #[arg(long)]
        directory: bool,
        #[arg(long)]
        label: Option<String>,
    },
    /// The items in a SaaS backup.
    List {
        image: String,
        #[arg(long)]
        account: Option<String>,
    },
    /// Write items to a folder (mail as .eml, files as files, records as JSON).
    Export {
        #[arg(long)]
        image: String,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        account: Option<String>,
        /// Only items whose path starts with this.
        #[arg(long)]
        path: Option<String>,
    },
    /// Put items back into the service.
    Restore {
        #[command(flatten)]
        svc: SaasService,
        #[arg(long)]
        image: String,
        /// The user (or org) whose items to restore.
        #[arg(long)]
        account: String,
        /// Into another user's mailbox and drive.
        #[arg(long)]
        to_account: Option<String>,
        #[arg(long)]
        path: Option<String>,
        /// mail | file | record (default: all).
        #[arg(long)]
        kind: Option<String>,
        /// Salesforce: update records that still exist (default: leave them).
        #[arg(long)]
        overwrite: bool,
    },
}

/// How to reach the Kubernetes API (default: the pod's service account).
#[derive(clap::Args, Clone)]
struct K8sConnect {
    /// API server, e.g. https://10.0.0.1:6443.
    #[arg(long)]
    api_server: Option<String>,
    /// File holding a bearer token (a service account's).
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// The cluster's CA certificate (PEM).
    #[arg(long)]
    ca_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum K8sCmd {
    /// Back up the objects of namespaces (not their volumes' data).
    Backup {
        #[command(flatten)]
        connect: K8sConnect,
        /// Namespace to back up (repeat for several).
        #[arg(long = "namespace", required = true)]
        namespaces: Vec<String>,
        /// Name of the cluster in the repository (its machine).
        #[arg(long, default_value = "kubernetes")]
        cluster: String,
        #[arg(long)]
        label: Option<String>,
        /// Also back up the data of the namespaces' claims, read by pods
        /// running this image (the Fenrir-Backup CLI image).
        #[arg(long)]
        volume_image: Option<String>,
    },
    /// What a Kubernetes backup holds.
    Show { image: String },
    /// Create a backup's objects again.
    Restore {
        #[command(flatten)]
        connect: K8sConnect,
        #[arg(long)]
        image: String,
        /// Only this namespace of the backup (default: all).
        #[arg(long)]
        namespace: Option<String>,
        /// Into this namespace instead (with --namespace).
        #[arg(long)]
        to_namespace: Option<String>,
        /// Replace objects that exist (default: leave them).
        #[arg(long)]
        replace: bool,
        /// Write the claims' data back with pods running this image.
        #[arg(long)]
        volume_image: Option<String>,
    },
    /// In a pod: serve a volume's files to a backup, or receive them on
    /// restore (started by backup and restore; not for direct use).
    #[command(hide = true)]
    VolumeServer {
        #[arg(long)]
        dir: PathBuf,
        /// read | write
        #[arg(long)]
        mode: String,
    },
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
    /// Image the running system: Windows through VSS (application-consistent),
    /// Linux through LVM snapshots and frozen copies (crash-consistent).
    System {
        #[command(flatten)]
        common: CommonBackup,
        /// Windows: also include this physical disk number. Repeatable.
        #[arg(long = "include-disk")]
        include_disk: Vec<u32>,
        /// Use the VSS FULL backup type (writers may truncate logs).
        /// Default is COPY, which leaves other backup tools' chains intact.
        #[arg(long)]
        vss_full: bool,
        /// Windows: image only the --include-disk disks, not the system disk
        /// (a server's data disks, coordinated with its applications).
        #[arg(long)]
        data_disks_only: bool,
        /// Linux: image these whole disks instead of the ones holding the
        /// system's mounts. Repeatable.
        #[arg(long = "disk")]
        disks: Vec<PathBuf>,
        /// Linux: read what cannot be snapshotted live (a large non-LVM
        /// root, LUKS, RAID) and mark the image inconsistent, instead of
        /// refusing.
        #[arg(long)]
        allow_inconsistent: bool,
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
        /// On a larger target, give the extra space to the last partition
        /// and grow its file system (implies --fit).
        #[arg(long)]
        grow: bool,
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
            dedup_group,
        }) => repo_init(
            ctx,
            &recovery_key_out,
            chunk_size_kib,
            zstd_level,
            dedup_group.as_deref(),
        ),
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
            data_disks_only,
            disks,
            allow_inconsistent,
        }) => {
            if cfg!(windows) && (!disks.is_empty() || allow_inconsistent) {
                return Err(CliError::usage(
                    "--disk and --allow-inconsistent are for Linux; on Windows use --include-disk",
                ));
            }
            if !cfg!(windows) && (!include_disk.is_empty() || vss_full || data_disks_only) {
                return Err(CliError::usage(
                    "--include-disk, --vss-full and --data-disks-only are for Windows; on Linux use --disk",
                ));
            }
            backup_system(
                ctx,
                common,
                SystemFlags {
                    include_disk,
                    vss_full,
                    data_disks_only,
                    disks,
                    allow_inconsistent,
                },
            )
        }
        Cmd::Image(ImageCmd::List) => image_list(ctx),
        Cmd::Image(ImageCmd::Show { image }) => {
            let repo = open_repo(ctx)?;
            let id = repo.resolve_image_id(&image)?;
            let m = repo.load_manifest(&id)?;
            let human = serde_json::to_string_pretty(&m).unwrap() + "\n";
            Ok(Outcome::new(&m, human))
        }
        Cmd::Verify(a) => verify(ctx, a),
        Cmd::Clone(a) => clone(ctx, a),
        Cmd::Copy(a) => copy(ctx, a),
        Cmd::K8s(k) => k8s_cmd(ctx, k),
        Cmd::Saas(c) => saas_cmd(ctx, c),
        Cmd::Cdp(c) => cdp_cmd(ctx, c),
        Cmd::Cbt(c) => cbt_cmd(ctx, c),
        Cmd::Restore(RestoreCmd::Disk {
            image,
            disk,
            target,
            yes,
            no_zero_fill,
            fit,
            boot_fixup,
            grow,
            workers,
        }) => restore(
            ctx,
            &image,
            disk,
            &target,
            yes,
            RestoreFlags {
                zero_fill: !no_zero_fill,
                fit: fit || grow,
                boot_fixup,
                grow,
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

/// `--repo s3://bucket/prefix`: S3-compatible storage configured from the
/// environment (FENRIR_S3_ENDPOINT, FENRIR_S3_REGION, FENRIR_S3_PATH_STYLE,
/// FENRIR_S3_LOCK=compliance:30, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).
fn s3_from_env(url: &str) -> R<s3store::S3Backend> {
    let (bucket, prefix) = s3store::parse_url(url)
        .ok_or_else(|| CliError::usage(format!("{url}: expected s3://bucket/prefix")))?;
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let need = |k: &str| {
        var(k).ok_or_else(|| CliError::usage(format!("{k} is needed for an s3:// repository")))
    };
    let lock = match var("FENRIR_S3_LOCK") {
        None => None,
        Some(l) => {
            let (m, d) = l.split_once(':').unwrap_or((&l, ""));
            Some(s3store::Lock {
                mode: s3store::LockMode::parse(m).ok_or_else(|| {
                    CliError::usage("FENRIR_S3_LOCK is governance:DAYS or compliance:DAYS")
                })?,
                days: d.parse().map_err(|_| {
                    CliError::usage("FENRIR_S3_LOCK is governance:DAYS or compliance:DAYS")
                })?,
            })
        }
    };
    Ok(s3store::S3Backend::new(s3store::S3Config {
        endpoint: need("FENRIR_S3_ENDPOINT")?,
        region: var("FENRIR_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
        bucket,
        prefix,
        path_style: var("FENRIR_S3_PATH_STYLE")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        access_key: need("AWS_ACCESS_KEY_ID")?,
        secret_key: need("AWS_SECRET_ACCESS_KEY")?,
        lock,
        // Archive tier for chunks (STANDARD_IA, GLACIER_IR, ...).
        storage_class: var("FENRIR_S3_STORAGE_CLASS").filter(|c| !c.is_empty()),
    })?)
}

/// `--repo azure://container/prefix`: Azure Blob Storage configured from the
/// environment (FENRIR_AZURE_ACCOUNT, FENRIR_AZURE_KEY or FENRIR_AZURE_SAS,
/// FENRIR_AZURE_ENDPOINT (default https://ACCOUNT.blob.core.windows.net),
/// FENRIR_AZURE_LOCK=locked:30 or unlocked:30).
fn azure_from_env(url: &str) -> R<azstore::AzureBackend> {
    let (container, prefix) = azstore::parse_url(url)
        .ok_or_else(|| CliError::usage(format!("{url}: expected azure://container/prefix")))?;
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let account = var("FENRIR_AZURE_ACCOUNT").ok_or_else(|| {
        CliError::usage("FENRIR_AZURE_ACCOUNT is needed for an azure:// repository")
    })?;
    let credential = match (var("FENRIR_AZURE_KEY"), var("FENRIR_AZURE_SAS")) {
        (Some(k), _) => azstore::Credential::AccountKey(k),
        (None, Some(s)) => azstore::credential_from(&s),
        _ => {
            return Err(CliError::usage(
                "FENRIR_AZURE_KEY (the account key) or FENRIR_AZURE_SAS is needed",
            ))
        }
    };
    let lock = match var("FENRIR_AZURE_LOCK") {
        None => None,
        Some(l) => {
            let bad = || CliError::usage("FENRIR_AZURE_LOCK is locked:DAYS or unlocked:DAYS");
            let (m, d) = l.split_once(':').unwrap_or((&l, ""));
            Some(azstore::Lock {
                mode: azstore::LockMode::parse(m).ok_or_else(bad)?,
                days: d.parse().map_err(|_| bad())?,
            })
        }
    };
    Ok(azstore::AzureBackend::new(azstore::AzureConfig {
        endpoint: var("FENRIR_AZURE_ENDPOINT")
            .unwrap_or_else(|| format!("https://{account}.blob.core.windows.net")),
        account,
        container,
        prefix,
        credential,
        lock,
        // Archive tier for chunks (Cool, Cold).
        access_tier: var("FENRIR_AZURE_TIER").filter(|c| !c.is_empty()),
    })?)
}

/// The repository's storage: a folder, S3 for `s3://` locations, Azure Blob
/// for `azure://`; a dedup group member (`<group>/repos/<id>`) with the
/// group's shared store.
fn backend(path: &Path, create: bool) -> R<Arc<dyn Backend>> {
    let s = path.to_string_lossy();
    if let Some((root, _)) = core_format::group::split_member_path(&s) {
        let member = location(path, create)?;
        let shared = location(Path::new(&root), false)?;
        return Ok(Arc::new(core_format::group::GroupBackend {
            member,
            shared,
        }));
    }
    location(path, create)
}

fn location(path: &Path, create: bool) -> R<Arc<dyn Backend>> {
    let s = path.to_string_lossy();
    if s.starts_with("azure://") {
        let b = azure_from_env(&s)?;
        if create {
            b.ensure_container()?;
        }
        if create && !b.is_empty()? {
            return Err(CliError::usage(format!(
                "{s} already holds data: choose an empty container or another folder in it"
            )));
        }
        return Ok(Arc::new(b));
    }
    if s.starts_with("s3://") {
        let b = s3_from_env(&s)?;
        if create {
            b.ensure_bucket()?;
        }
        if create && !b.is_empty()? {
            return Err(CliError::usage(format!(
                "{s} already holds data: choose an empty bucket or prefix"
            )));
        }
        return Ok(Arc::new(b));
    }
    Ok(if create {
        Arc::new(LocalBackend::create(path)?)
    } else {
        Arc::new(LocalBackend::open(path)?)
    })
}

fn open_repo(ctx: &Ctx) -> R<Repository> {
    let path = repo_path(ctx)?;
    let backend = backend(path, false)?;
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

fn repo_init(
    ctx: &Ctx,
    rk_out: &Path,
    chunk_kib: u32,
    zstd_level: i32,
    dedup_group: Option<&str>,
) -> R<Outcome> {
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
    let opts = InitOptions {
        chunk_size,
        zstd_level,
        kdf: KdfParams::DEFAULT,
    };
    let (repo, rk, path) = match dedup_group {
        None => {
            let backend = backend(path, true)?;
            let (repo, rk) = Repository::init(backend, pass.as_bytes(), opts)?;
            (repo, rk, path.to_path_buf())
        }
        Some(g) => init_in_group(path, g, &pass, opts)?,
    };
    let path = path.as_path();
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

/// A new member of a dedup group: a new group in `path` (`new`), or the
/// group of the member at `group`.
fn init_in_group(
    path: &Path,
    group: &str,
    pass: &str,
    opts: InitOptions,
) -> R<(Repository, core_format::RecoveryKey, PathBuf)> {
    use core_format::group;
    let (root, key, info) = if group == "new" {
        let root = path.to_string_lossy().to_string();
        let shared = backend(path, true)?;
        let info = group::create(&*shared, opts.chunk_size)?;
        (root, core_format::crypto::SecretKey::generate()?, info)
    } else {
        let (root, _) = group::split_member_path(group).ok_or_else(|| {
            CliError::usage("--dedup-group takes `new` or the path of a repository in a group (<group>/repos/<id>)")
        })?;
        let other_pass = match std::env::var("FENRIR_GROUP_PASSPHRASE") {
            Ok(p) => p,
            Err(_) => {
                rpassword::prompt_password(format!("Passphrase of {group}: ")).map_err(|e| {
                    CliError::new(ExitCode::KeyError, format!("reading passphrase: {e}"))
                })?
            }
        };
        let other = Repository::unlock_with_passphrase(
            backend(Path::new(group), false)?,
            other_pass.as_bytes(),
        )?;
        let key = other
            .group_key()
            .cloned()
            .ok_or_else(|| CliError::usage(format!("{group} is not in a dedup group")))?;
        let info = group::read_info(&*backend(Path::new(&root), false)?)?;
        (root, key, info)
    };
    let rk = core_format::RecoveryKey::generate(uuid::Uuid::new_v4())?;
    let member = PathBuf::from(group::member_path(&root, &rk.repo_id));
    let b = backend(&member, true)?;
    let repo = Repository::init_member(b, pass.as_bytes(), opts, &rk, &info, &key)?;
    Ok((repo, rk, member))
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
        applications: vec![],
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

/// What `backup system` was asked for (some of it per platform).
struct SystemFlags {
    #[cfg_attr(not(windows), allow(dead_code))]
    include_disk: Vec<u32>,
    #[cfg_attr(not(windows), allow(dead_code))]
    vss_full: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    data_disks_only: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    disks: Vec<PathBuf>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    allow_inconsistent: bool,
}

#[cfg(windows)]
fn backup_system(ctx: &Ctx, common: CommonBackup, f: SystemFlags) -> R<Outcome> {
    let SystemFlags {
        include_disk,
        vss_full,
        data_disks_only,
        ..
    } = f;
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
        data_disks_only,
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

#[cfg(target_os = "linux")]
fn backup_system(ctx: &Ctx, common: CommonBackup, f: SystemFlags) -> R<Outcome> {
    use snapshot_linux::live;
    let SystemFlags {
        disks,
        allow_inconsistent,
        ..
    } = f;
    let state = PathBuf::from("/var/lib/fenrir-backup");
    let _ = std::fs::create_dir_all(&state);
    for l in live::remove_leftover_snapshots(&state) {
        eprintln!("{l}");
    }
    let repo = if common.dry_run {
        None
    } else {
        Some(open_repo(ctx)?)
    };
    if !ctx.json {
        eprintln!("Taking snapshots...");
    }
    let temp = if Path::new("/var/tmp").is_dir() {
        PathBuf::from("/var/tmp")
    } else {
        std::env::temp_dir()
    };
    let lb = live::prepare(&live::LiveOptions {
        disks,
        allow_inconsistent,
        state_dir: state,
        temp_dir: temp,
        exclude_paths: ctx.repo.iter().filter(|p| p.is_dir()).cloned().collect(),
        hooks_dir: Some(hooks_dir()),
    })
    .map_err(|e| CliError::new(ExitCode::Safety, e.to_string()))?;
    if common.dry_run {
        let out = dry_run(&lb.sources());
        let w = lb.warnings.clone();
        let finish = lb.finish();
        let mut out = out?;
        out.warnings.splice(0..0, w);
        if let Err(e) = finish {
            out.warnings.push(e);
        }
        return Ok(out);
    }
    let repo = repo.expect("opened when not a dry run");
    let machine_id = local_machine_id();
    if machine_id.is_empty() {
        return Err(CliError::usage(
            "could not determine a machine ID (/etc/machine-id)",
        ));
    }
    let meta = engine::ImageMeta {
        machine: MachineInfo {
            machine_id,
            hostname: hostname(),
        },
        consistency: lb.consistency,
        os: lb.os.clone(),
        boot: lb.boot.clone(),
        drivers: vec![],
        label: common.label.clone(),
        warnings: lb.warnings.clone(),
        vm: None,
        applications: lb.applications.clone(),
    };
    let pr = progress_printer(ctx.json);
    let result = engine::backup(
        &repo,
        &lb.sources(),
        meta,
        &backup_options(&common),
        &JobControl::new(),
        &pr,
    );
    let finish = lb.finish();
    let mut out = report_outcome(result?);
    if let Err(e) = finish {
        out.warnings.push(format!("image stored, but {e}"));
    }
    Ok(out)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn backup_system(_ctx: &Ctx, _c: CommonBackup, _f: SystemFlags) -> R<Outcome> {
    Err(CliError::usage(
        "`backup system` runs on Windows (VSS) and Linux (LVM snapshots). Here, image unmounted disks with `backup disk`.",
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
    grow: bool,
}

#[derive(serde::Serialize)]
struct RestoreOutput<R: serde::Serialize> {
    #[serde(flatten)]
    report: R,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot: Option<engine::bootfix::BootFix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grow: Option<engine::grow::GrowReport>,
}

/// After a disk was written: fallback boot loader, Windows re-reading the
/// disk, the grown file system. Appends to `human` and `warnings`.
#[allow(clippy::too_many_arguments)]
fn after_write(
    target: &Path,
    d: &core_format::manifest::DiskImage,
    boot_fixup: bool,
    grown: Option<&engine::fit::Grown>,
    #[cfg(windows)] lock: Option<snapshot_win::win::disks::DiskLock>,
    human: &mut String,
    warnings: &mut Vec<String>,
) -> R<(
    Option<engine::bootfix::BootFix>,
    Option<engine::grow::GrowReport>,
)> {
    let boot = if boot_fixup {
        let b = engine::bootfix::fix_restored_disk(target, d)?;
        match &b {
            Some(b) if !b.added.is_empty() => {
                *human += &format!("Added the fallback boot loader: {}.\n", b.added.join(", "))
            }
            Some(_) => *human += "The disk already has a fallback boot loader.\n",
            None => *human += "No EFI system partition on this disk; nothing to fix.\n",
        }
        b
    } else {
        None
    };
    #[cfg(windows)]
    if let Some(l) = lock {
        if let Err(e) = l.finish() {
            *human +=
                &format!("Windows did not re-read the disk ({e}); restart before using it.\n");
        }
    }
    let grow = grown.map(|g| {
        let r = engine::grow::grow_filesystem(target, g);
        for n in &r.notes {
            *human += &format!("{n}.\n");
        }
        if r.filesystem_grown {
            *human += "Its file system fills the partition.\n";
        } else {
            warnings.extend(r.notes.iter().skip(1).cloned());
        }
        r
    });
    Ok((boot, grow))
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
        grow,
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
            grow,
            verify: true,
        },
        &JobControl::new(),
        &pr,
    )?;
    if tty {
        eprintln!();
    }
    drop(t);
    if let Some(v) = &r.verification {
        if v.mismatches > 0 {
            eprintln!(
                "WARNING: {} restored chunk(s) did not read back as written; do not rely on {}",
                v.mismatches, r.target
            );
        }
    }
    let mut human = format!(
        "Restored disk {} of image {} to {} ({} written).\n",
        disk,
        id,
        r.target,
        human_bytes(r.bytes_written)
    );
    let mut warnings = r.notes.clone();
    let (boot, grow) = after_write(
        target,
        d,
        boot_fixup,
        r.grown.as_ref(),
        #[cfg(windows)]
        lock,
        &mut human,
        &mut warnings,
    )?;
    Ok(Outcome::new(
        &RestoreOutput {
            report: r,
            boot,
            grow,
        },
        human,
    )
    .with_warnings(warnings))
}

fn copy(ctx: &Ctx, a: CopyArgs) -> R<Outcome> {
    let src = open_repo(ctx)?;
    let pass = match &a.to_passphrase_file {
        Some(f) => std::fs::read_to_string(f)
            .map_err(|e| CliError::usage(format!("{}: {e}", f.display())))?
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
        None => std::env::var("FENRIR_TO_PASSPHRASE").map_err(|_| {
            CliError::new(
                ExitCode::KeyError,
                "the destination's passphrase: --to-passphrase-file or FENRIR_TO_PASSPHRASE",
            )
        })?,
    };
    let dst = Repository::unlock_with_passphrase(backend(&a.to, false)?, pass.as_bytes())?;
    let ids = a
        .images
        .iter()
        .map(|i| src.resolve_image_id(i))
        .collect::<Result<Vec<_>, _>>()?;
    let tty = std::io::stderr().is_terminal() && !ctx.json;
    let pr = |done: u64, total: u64| {
        if tty {
            eprint!("\rcopying: {done} / {total} chunks   ");
        }
    };
    let r = engine::copy::copy_images(
        &src,
        &dst,
        (!ids.is_empty()).then_some(ids.as_slice()),
        a.full_verify,
        &JobControl::new(),
        &pr,
    )?;
    if tty {
        eprintln!();
    }
    let human = format!(
        "Copied {} image(s) to {} ({} already there): {} chunks written ({}), {} already there. Verified.\n",
        r.copied.len(),
        a.to.display(),
        r.already_there,
        r.chunks_written,
        human_bytes(r.bytes_stored),
        r.chunks_present
    );
    Ok(Outcome::new(&r, human))
}

fn same_disk(a: &Path, b: &Path) -> bool {
    let c = |p: &Path| {
        std::fs::canonicalize(p)
            .map(|x| x.display().to_string())
            .unwrap_or_else(|_| p.display().to_string())
            .to_ascii_lowercase()
    };
    c(a) == c(b)
}

/// Something to undo after a live copy (release a snapshot); returns an error text.
type Release = Box<dyn FnOnce() -> Option<String>>;

/// An in-use disk through a snapshot: LVM on Linux.
/// Freeze/thaw hooks for live Linux backups (FENRIR_HOOKS_DIR overrides).
#[cfg(target_os = "linux")]
fn hooks_dir() -> PathBuf {
    std::env::var_os("FENRIR_HOOKS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(snapshot_linux::apps::HOOKS_DIR))
}

#[cfg(target_os = "linux")]
fn live_source(
    disk: &Path,
    warnings: &mut Vec<String>,
    release: &mut Vec<Release>,
) -> R<Box<dyn engine::DiskSource>> {
    let state = PathBuf::from("/var/lib/fenrir-backup");
    let _ = std::fs::create_dir_all(&state);
    let mut lb = snapshot_linux::live::prepare(&snapshot_linux::live::LiveOptions {
        disks: vec![disk.to_path_buf()],
        allow_inconsistent: false,
        state_dir: state,
        temp_dir: PathBuf::from("/var/tmp"),
        exclude_paths: vec![],
        hooks_dir: None,
    })
    .map_err(|e| CliError::new(ExitCode::Safety, e.to_string()))?;
    warnings.extend(lb.warnings.clone());
    let src = lb.sources.remove(0);
    release.push(Box::new(move || lb.finish().err()));
    Ok(Box::new(src))
}

/// An in-use disk through a snapshot: VSS on Windows (the system disk).
#[cfg(windows)]
fn live_source(
    disk: &Path,
    _warnings: &mut Vec<String>,
    release: &mut Vec<Release>,
) -> R<Box<dyn engine::DiskSource>> {
    let mut sb = snapshot_win::prepare_system_backup(&snapshot_win::VssOptions {
        data_disks_only: false,
        full_backup_type: false,
        extra_disks: vec![],
    })
    .map_err(|e| CliError::new(ExitCode::Error, e.to_string()))?;
    let want = disk.to_string_lossy().to_ascii_lowercase();
    let i = sb
        .disks
        .iter()
        .position(|d| d.info.device.to_ascii_lowercase() == want)
        .ok_or_else(|| {
            CliError::usage(format!(
                "{} is not the system disk; --live copies the disk Windows runs from",
                disk.display()
            ))
        })?;
    let src = sb.disks.remove(i);
    release.push(Box::new(move || {
        sb.finish(true).err().map(|e| e.to_string())
    }));
    Ok(Box::new(src))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn live_source(
    _disk: &Path,
    _warnings: &mut Vec<String>,
    _release: &mut Vec<Release>,
) -> R<Box<dyn engine::DiskSource>> {
    Err(CliError::usage("--live works on Linux and Windows"))
}

fn clone(ctx: &Ctx, a: CloneArgs) -> R<Outcome> {
    if same_disk(&a.source, &a.target) {
        return Err(CliError::usage(
            "the source and the target are the same disk",
        ));
    }
    if !a.yes {
        return Err(CliError::new(
            ExitCode::ConfirmationRequired,
            format!(
                "this will overwrite {} with a copy of {}. Re-run with --yes to confirm.",
                a.target.display(),
                a.source.display()
            ),
        ));
    }
    // The source, plus whatever must be released afterwards.
    let mut release: Vec<Release> = Vec::new();
    let mut warnings = Vec::new();
    let source: Box<dyn engine::DiskSource> = if a.live {
        live_source(&a.source, &mut warnings, &mut release)?
    } else {
        let o = snapshot_linux::open_disk(&a.source, false).map_err(|e| {
            CliError::new(
                if e.is::<snapshot_linux::InUse>() {
                    ExitCode::Safety
                } else {
                    ExitCode::Error
                },
                format!("{e} (or copy it with --live)"),
            )
        })?;
        Box::new(o.source)
    };
    let fit = a.fit || a.grow;
    let confirm = DestructiveConfirmation::confirmed_by_user(&a.target);
    let src_size = source.info().size;
    #[cfg(windows)]
    let (t, lock) = if engine::target::is_windows_device_path(&a.target.to_string_lossy()) {
        let (t, l) = snapshot_win::win::disks::take_over(&a.target.to_string_lossy(), &confirm)?;
        (t, Some(l))
    } else {
        (
            FileTarget::open(&a.target, if fit { 1 } else { src_size }, true, &confirm)?,
            None,
        )
    };
    #[cfg(not(windows))]
    let t = FileTarget::open(&a.target, if fit { 1 } else { src_size }, true, &confirm)?;
    let tty = std::io::stderr().is_terminal() && !ctx.json;
    let last = std::sync::Mutex::new(Instant::now());
    let pr = |done: u64, total: u64| {
        if tty {
            let mut l = last.lock().unwrap();
            if l.elapsed() > Duration::from_millis(250) {
                *l = Instant::now();
                eprint!(
                    "\rcopying: {} / {}   ",
                    human_bytes(done),
                    human_bytes(total)
                );
            }
        }
    };
    let result = engine::clone::clone_disk(
        source.as_ref(),
        &t,
        &engine::clone::CloneOptions { fit, grow: a.grow },
        &JobControl::new(),
        &pr,
    );
    if tty {
        eprintln!();
    }
    drop(t);
    drop(source);
    for r in release {
        if let Some(e) = r() {
            warnings.push(format!("releasing the snapshot: {e}"));
        }
    }
    let (r, d) = result?;
    let mut human = format!(
        "Copied {} to {} ({} copied).\n",
        a.source.display(),
        a.target.display(),
        human_bytes(r.bytes_copied)
    );
    warnings.extend(r.notes.iter().cloned());
    let (boot, grow) = after_write(
        &a.target,
        &d,
        a.boot_fixup,
        r.grown.as_ref(),
        #[cfg(windows)]
        lock,
        &mut human,
        &mut warnings,
    )?;
    Ok(Outcome::new(
        &RestoreOutput {
            report: r,
            boot,
            grow,
        },
        human,
    )
    .with_warnings(warnings))
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

// ---------------------------------------------------------------- Kubernetes (docs/design/kubernetes.md)

fn k8s_client(c: &K8sConnect) -> R<k8s::Client> {
    let conn = match &c.api_server {
        None => k8s::Connect::in_cluster().map_err(|e| CliError::usage(e.to_string()))?,
        Some(server) => {
            let read = |p: &Option<PathBuf>, what: &str| -> R<String> {
                let p = p.as_ref().ok_or_else(|| {
                    CliError::usage(format!("--{what} is needed with --api-server"))
                })?;
                std::fs::read_to_string(p)
                    .map_err(|e| CliError::usage(format!("{}: {e}", p.display())))
            };
            k8s::Connect {
                server: server.clone(),
                token: read(&c.token_file, "token-file")?.trim().to_string(),
                ca_pem: read(&c.ca_file, "ca-file")?,
            }
        }
    };
    k8s::Client::new(&conn).map_err(|e| CliError::usage(e.to_string()))
}

fn k8s_e(e: k8s::Error) -> CliError {
    CliError::new(ExitCode::Error, e.0)
}

/// A Kubernetes backup's archive, read back from the repository.
fn k8s_archive(
    repo: &Repository,
    image: &str,
) -> R<(core_format::ManifestBody, k8s::archive::Archive)> {
    let m = repo.load_manifest(&repo.resolve_image_id(image)?)?;
    let a = k8s::repo::archive(repo, &m).map_err(|e| CliError::usage(e.0))?;
    Ok((m, a))
}

fn k8s_cmd(ctx: &Ctx, k: K8sCmd) -> R<Outcome> {
    match k {
        K8sCmd::Backup {
            connect,
            namespaces,
            cluster,
            label,
            volume_image,
        } => {
            let c = k8s_client(&connect)?;
            let quiet = ctx.json;
            let repo = open_repo(ctx)?;
            let r = k8s::repo::backup(
                &repo,
                &c,
                &cluster,
                &namespaces,
                label,
                volume_image.as_deref(),
                &JobControl::new(),
                &|s: &str| {
                    if !quiet {
                        eprintln!("  {s}")
                    }
                },
            )
            .map_err(k8s_e)?;
            let out = Outcome::new(
                json!({ "image_id": r.image_id, "namespaces": namespaces, "objects": r.objects, "kinds": r.kinds, "volumes": r.volumes, "warnings": r.warnings }),
                format!(
                    "Backed up {} objects and {} volumes of {} as image {}\n",
                    r.objects,
                    r.volumes.len(),
                    namespaces.join(", "),
                    r.image_id
                ),
            );
            Ok(if r.warnings.is_empty() {
                out
            } else {
                out.with_warnings(r.warnings.clone())
            })
        }
        K8sCmd::Show { image } => {
            let repo = open_repo(ctx)?;
            let (m, a) = k8s_archive(&repo, &image)?;
            let names: Vec<String> = a
                .objects
                .iter()
                .map(|o| {
                    format!(
                        "{}/{} {}",
                        o.namespace,
                        o.resource.kind,
                        o.object["metadata"]["name"].as_str().unwrap_or("")
                    )
                })
                .collect();
            Ok(Outcome::new(
                json!({ "image_id": m.image_id, "cluster": m.machine.hostname, "namespaces": a.namespaces.iter().map(|n| &n.name).collect::<Vec<_>>(), "kinds": a.summary(), "objects": names }),
                format!("{}\n", names.join("\n")),
            ))
        }
        K8sCmd::Restore {
            connect,
            image,
            namespace,
            to_namespace,
            replace,
            volume_image,
        } => {
            if to_namespace.is_some() && namespace.is_none() {
                return Err(CliError::usage(
                    "--to-namespace needs --namespace (the one to restore under the new name)",
                ));
            }
            let repo = open_repo(ctx)?;
            let m = repo.load_manifest(&repo.resolve_image_id(&image)?)?;
            let c = k8s_client(&connect)?;
            let only: Vec<String> = namespace.iter().cloned().collect();
            let map: Vec<(String, String)> = namespace
                .iter()
                .cloned()
                .zip(to_namespace.iter().cloned())
                .collect();
            let rep =
                k8s::repo::restore(&repo, &c, &m, &only, &map, replace, volume_image.as_deref())
                    .map_err(k8s_e)?;
            let warnings = rep.failed.clone();
            let text = format!(
                "Restored into {}: {} created, {} already there, {} volumes{}\n",
                rep.namespaces.join(", "),
                rep.created,
                rep.existing,
                rep.volumes.len(),
                if rep.failed.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", {} failed:\n  {}",
                        rep.failed.len(),
                        rep.failed.join("\n  ")
                    )
                }
            );
            let out = Outcome::new(serde_json::to_value(&rep).unwrap_or_default(), text);
            Ok(if warnings.is_empty() {
                out
            } else {
                out.with_warnings(warnings)
            })
        }
        K8sCmd::VolumeServer { dir, mode } => {
            k8s::volumes::serve(&dir, mode == "write")?;
            Ok(Outcome::new(json!({ "served": true }), String::new()))
        }
    }
}

#[cfg(target_os = "linux")]
/// Disk `disk` of an image, written to `file` (its first `len` bytes).
fn k8s_disk_to(
    repo: &Repository,
    m: &core_format::ManifestBody,
    disk: u32,
    file: &Path,
    len: u64,
) -> R<()> {
    k8s::repo::disk_to(repo, m, disk, file, len).map_err(k8s_e)
}

#[cfg(target_os = "linux")]
fn tempfile_dir() -> R<PathBuf> {
    let d = std::env::temp_dir().join(format!("fenrir-k8s-{}", std::process::id()));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

// ---------------------------------------------------------------- SaaS (docs/design/saas.md)

fn saas_conn(s: &SaasService) -> R<(saas::run::Settings, saas::run::Conn)> {
    let file = s
        .key_file
        .as_ref()
        .or(s.secret_file.as_ref())
        .ok_or_else(|| {
            CliError::usage(if s.service == "google" {
                "--key-file is needed for google"
            } else {
                "--secret-file is needed"
            })
        })?;
    let secret = std::fs::read_to_string(file)
        .map_err(|e| CliError::usage(format!("{}: {e}", file.display())))?;
    let settings = saas::run::Settings {
        service: s.service.clone(),
        tenant: s.tenant.clone(),
        client_id: s.client_id.clone().unwrap_or_default(),
        domain_url: s.domain_url.clone().unwrap_or_default(),
        admin: s.admin.clone().unwrap_or_default(),
    };
    // Rotating refresh tokens (QuickBooks) are kept next to the secret file.
    let state = file.parent().map(|p| p.to_path_buf());
    let conn = saas::run::connect_in(&settings, &secret, state.as_deref())
        .map_err(|e| CliError::usage(e.0))?;
    Ok((settings, conn))
}

fn saas_err(e: saas::Error) -> CliError {
    CliError::new(ExitCode::Error, e.0)
}

/// A safe relative path for an exported item.
fn saas_rel(it: &saas::store::Item) -> PathBuf {
    let clean = |s: &str| -> String {
        let t: String = s
            .chars()
            .map(|c| {
                if c.is_control() || "<>:\"\\|?*".contains(c) {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        let t = t.trim().trim_matches('.').to_string();
        if t.is_empty() {
            "_".into()
        } else {
            t.chars().take(120).collect()
        }
    };
    let mut p = PathBuf::from(clean(&it.account)).join(&it.kind);
    let parts: Vec<&str> = it
        .path
        .split('/')
        .filter(|x| !x.is_empty() && *x != "." && *x != "..")
        .collect();
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        p.push(if last && it.kind == "mail" {
            format!(
                "{} [{}].eml",
                clean(part),
                clean(&it.id).chars().take(16).collect::<String>()
            )
        } else if last && it.kind == "record" {
            format!("{}.json", clean(part))
        } else {
            clean(part)
        });
    }
    p
}

fn saas_cmd(ctx: &Ctx, c: SaasCmd) -> R<Outcome> {
    match c {
        SaasCmd::Backup {
            svc,
            users,
            objects,
            no_mail,
            no_files,
            sites,
            teams,
            directory,
            label,
        } => {
            let (settings, conn) = saas_conn(&svc)?;
            let repo = open_repo(ctx)?;
            let quiet = ctx.json;
            let r = saas::run::backup(
                &repo,
                &conn,
                &settings,
                &saas::run::Scope {
                    users,
                    objects,
                    mail: !no_mail,
                    files: !no_files,
                    sites,
                    teams,
                    directory,
                },
                label,
                &|s: &str| {
                    if !quiet {
                        eprintln!("  {s}")
                    }
                },
            )
            .map_err(saas_err)?;
            let out = Outcome::new(
                json!({ "image_id": r.image_id, "service": svc.service, "tenant": svc.tenant, "items": r.items, "chunks_new": r.chunks_new, "warnings": r.warnings }),
                format!(
                    "Backed up {} items of {} {} as image {}\n",
                    r.items, svc.service, svc.tenant, r.image_id
                ),
            );
            Ok(if r.warnings.is_empty() {
                out
            } else {
                out.with_warnings(r.warnings.clone())
            })
        }
        SaasCmd::List { image, account } => {
            let repo = open_repo(ctx)?;
            let m = repo.load_manifest(&repo.resolve_image_id(&image)?)?;
            let idx = saas::store::read_index(&repo, &m)?;
            let items: Vec<&saas::store::Item> = idx
                .items
                .iter()
                .filter(|i| account.as_ref().is_none_or(|a| &i.account == a))
                .collect();
            let text: Vec<String> = items
                .iter()
                .map(|i| format!("{}\t{}\t{}\t{}", i.account, i.kind, i.size, i.path))
                .collect();
            Ok(Outcome::new(
                json!({ "service": idx.service, "tenant": idx.tenant, "items": items.iter().map(|i| json!({ "account": i.account, "kind": i.kind, "id": i.id, "path": i.path, "size": i.size, "modified": i.modified })).collect::<Vec<_>>() }),
                format!("{}\n", text.join("\n")),
            ))
        }
        SaasCmd::Export {
            image,
            to,
            account,
            path,
        } => {
            let repo = open_repo(ctx)?;
            let m = repo.load_manifest(&repo.resolve_image_id(&image)?)?;
            let idx = saas::store::read_index(&repo, &m)?;
            let (mut n, mut bytes) = (0u64, 0u64);
            for it in idx.items.iter().filter(|i| {
                account.as_ref().is_none_or(|a| &i.account == a)
                    && path.as_ref().is_none_or(|p| i.path.starts_with(p.as_str()))
            }) {
                let data = saas::store::read_item(&repo, it)?;
                let dst = to.join(saas_rel(it));
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dst, &data)?;
                n += 1;
                bytes += data.len() as u64;
            }
            Ok(Outcome::new(
                json!({ "items": n, "bytes": bytes, "to": to }),
                format!("Exported {n} items ({bytes} bytes) to {}\n", to.display()),
            ))
        }
        SaasCmd::Restore {
            svc,
            image,
            account,
            to_account,
            path,
            kind,
            overwrite,
        } => {
            let (_, conn) = saas_conn(&svc)?;
            let repo = open_repo(ctx)?;
            let m = repo.load_manifest(&repo.resolve_image_id(&image)?)?;
            let r = saas::run::restore(
                &repo,
                &conn,
                &m,
                &saas::run::Selection {
                    account,
                    to_account,
                    kind,
                    path,
                    overwrite,
                },
            )
            .map_err(saas_err)?;
            let out = Outcome::new(
                serde_json::to_value(&r).unwrap_or_default(),
                format!("Restored {} items to {} ({})\n", r.restored, r.to, r.folder),
            );
            Ok(if r.failed.is_empty() {
                out
            } else {
                out.with_warnings(r.failed)
            })
        }
    }
}

// ---------------------------------------------------------------- CDP (docs/design/cdp.md)

#[cfg(target_os = "linux")]
fn cdp_state_dir() -> PathBuf {
    std::env::var_os("FENRIR_CDP_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fenrir-backup"))
}

/// A CDP image's details (base or journal), kept in its OS version field.
#[cfg(target_os = "linux")]
fn cdp_meta(m: &core_format::ManifestBody) -> serde_json::Value {
    serde_json::from_str(&m.os.version).unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn cdp_store(
    ctx: &Ctx,
    name: &str,
    path: &Path,
    kind: &str,
    meta: serde_json::Value,
) -> R<uuid::Uuid> {
    let repo = open_repo(ctx)?;
    let src = snapshot_linux::open_disk(path, false)
        .map_err(|e| CliError::new(ExitCode::Error, e.to_string()))?;
    let m = engine::ImageMeta {
        machine: MachineInfo {
            machine_id: format!("cdp:{}:{name}", hostname()),
            hostname: format!("{} ({name})", hostname()),
        },
        consistency: core_format::manifest::Consistency::Crash,
        os: core_format::manifest::OsInfo {
            family: kind.into(),
            name: name.into(),
            version: meta.to_string(),
            ..Default::default()
        },
        boot: Default::default(),
        drivers: vec![],
        label: Some(format!("{kind} {name}")),
        warnings: vec![],
        vm: None,
        applications: vec![],
    };
    let r = engine::backup(
        &repo,
        &[&src.source as &dyn engine::DiskSource],
        m,
        &engine::BackupOptions {
            workers: 2,
            ..Default::default()
        },
        &JobControl::new(),
        &|_| {},
    )?;
    Ok(r.image_id)
}

/// Swap journals (with a base image when due) and ship the finished journal.
#[cfg(target_os = "linux")]
fn cdp_cycle(ctx: &Ctx, st: &mut cdp::control::State, base: bool) -> R<serde_json::Value> {
    let dir = cdp_state_dir();
    let err = |e: String| CliError::new(ExitCode::Error, e);
    let snap = format!("{}-fenrir-cdp-base", st.lv);
    let (journal, seq, base_mark) =
        cdp::control::rotate(&dir, st, base.then_some(snap.as_str())).map_err(err)?;
    let mut out = json!({ "journal_seq": seq });
    if base {
        let snap_path = PathBuf::from(format!("/dev/{}/{snap}", st.vg));
        // Valid from its mark on (see cdp::control::rotate).
        let t = base_mark.unwrap_or_else(cdp::control::now);
        let r = cdp_store(
            ctx,
            &st.name,
            &snap_path,
            "cdp-base",
            json!({ "seq": st.seq, "unix": t }),
        );
        // Its output must not reach stdout (the --json document).
        let _ = std::process::Command::new("lvremove")
            .args(["-q", "-y"])
            .arg(&snap_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let id = r?;
        st.base_image = Some(id.to_string());
        st.base_seq = st.seq;
        st.base_unix = t;
        cdp::control::save(&dir, st).map_err(err)?;
        out["base_image"] = json!(id);
    }
    // The finished journal: only the part in use.
    let mut f = std::fs::File::open(&journal)?;
    let used = cdp::control::used_bytes(&mut f)?;
    let (_, list) = cdp::journal::entries(&mut f)?;
    let times: Vec<i64> = list
        .iter()
        .filter_map(|e| {
            if let cdp::journal::Entry::Mark(m) = e {
                cdp::journal::mark_time(m)
            } else {
                None
            }
        })
        .collect();
    let tmp = tempfile_dir()?.join(format!("journal-{seq}.img"));
    {
        use std::io::{Read, Seek, SeekFrom};
        f.seek(SeekFrom::Start(0))?;
        let mut o = std::fs::File::create(&tmp)?;
        std::io::copy(&mut (&mut f).take(used), &mut o)?;
        o.set_len(used.div_ceil(4096) * 4096)?;
    }
    let id = cdp_store(
        ctx,
        &st.name,
        &tmp,
        "cdp-journal",
        json!({ "seq": seq, "bytes": used, "first": times.first(), "last": times.last(), "entries": list.len() }),
    );
    let _ = std::fs::remove_file(&tmp);
    out["journal_image"] = json!(id?);
    out["marks"] = json!([times.first(), times.last()]);
    Ok(out)
}

#[cfg(target_os = "linux")]
fn cdp_cmd(ctx: &Ctx, c: CdpCmd) -> R<Outcome> {
    let dir = cdp_state_dir();
    let err = |e: String| CliError::new(ExitCode::Error, e);
    match c {
        CdpCmd::Enable {
            name,
            volume,
            journal_mb,
        } => {
            let st = cdp::control::enable(&dir, &name, &volume, journal_mb).map_err(err)?;
            let dev = cdp::control::device(&name);
            Ok(Outcome::new(json!({ "device": dev, "state": st }), format!("CDP enabled for {volume}: mount {} instead of it from now on (and in /etc/fstab).\n", dev.display())))
        }
        CdpCmd::Run {
            name,
            mark_every,
            rotate_every,
            base_every,
            r#for,
        } => {
            let mut st = cdp::control::load(&dir, &name).map_err(err)?;
            let started = Instant::now();
            let mut cycles = Vec::new();
            let mut last_rotate = Instant::now();
            let base_due = |st: &cdp::control::State| {
                st.base_image.is_none() || cdp::control::now() - st.base_unix >= base_every as i64
            };
            // First a base, so that every journal from here replays onto it.
            if base_due(&st) {
                cycles.push(cdp_cycle(ctx, &mut st, true)?);
                last_rotate = Instant::now();
            }
            loop {
                std::thread::sleep(Duration::from_secs(mark_every.max(1)));
                cdp::control::mark(&name, &cdp::journal::time_mark(cdp::control::now()))
                    .map_err(err)?;
                let (_, hi, disabled) = cdp::control::usage(&name).map_err(err)?;
                let size = std::fs::metadata(&st.journals[st.active])
                    .map(|_| ())
                    .ok()
                    .and_then(|_| {
                        std::process::Command::new("blockdev")
                            .arg("--getsz")
                            .arg(&st.journals[st.active])
                            .output()
                            .ok()
                            .and_then(|o| {
                                String::from_utf8_lossy(&o.stdout)
                                    .trim()
                                    .parse::<u64>()
                                    .ok()
                            })
                    })
                    .unwrap_or(u64::MAX);
                let done = r#for.is_some_and(|f| started.elapsed().as_secs() >= f);
                if disabled
                    || hi > size / 10 * 7
                    || last_rotate.elapsed().as_secs() >= rotate_every
                    || done
                {
                    let due = base_due(&st);
                    cycles.push(cdp_cycle(ctx, &mut st, due)?);
                    last_rotate = Instant::now();
                }
                if done {
                    break;
                }
            }
            Ok(Outcome::new(
                json!({ "cycles": cycles }),
                format!("{} journal swaps shipped\n", cycles.len()),
            ))
        }
        CdpCmd::Points { name } => {
            let repo = open_repo(ctx)?;
            let (all, _) = repo.load_all_manifests()?;
            let mid = format!("cdp:{}:{name}", hostname());
            let mut rows: Vec<serde_json::Value> = all.iter().filter(|m| m.machine.machine_id == mid).map(|m| {
                let meta = cdp_meta(m);
                json!({ "image_id": m.image_id, "kind": m.os.family, "seq": meta["seq"], "from": meta["first"], "to": meta["last"], "base_unix": meta["unix"] })
            }).collect();
            rows.sort_by_key(|r| (r["seq"].as_u64().unwrap_or(0), r["kind"] != "cdp-base"));
            let first = rows
                .iter()
                .find(|r| r["kind"] == "cdp-base")
                .and_then(|r| r["base_unix"].as_i64());
            let last = rows.iter().filter_map(|r| r["to"].as_i64()).max();
            Ok(Outcome::new(
                json!({ "points": rows, "earliest": first, "latest": last }),
                format!(
                    "Restorable from {} to {} (unix seconds), to the second of each mark\n",
                    first.unwrap_or(0),
                    last.unwrap_or(0)
                ),
            ))
        }
        CdpCmd::Restore {
            name,
            at,
            target,
            yes,
        } => {
            let at: i64 =
                at.parse().ok().or_else(|| parse_utc(&at)).ok_or_else(|| {
                    CliError::usage("--at is unix seconds or YYYY-MM-DDTHH:MM:SSZ")
                })?;
            if !yes {
                return Err(CliError::new(
                    ExitCode::ConfirmationRequired,
                    format!("this overwrites {}: add --yes", target.display()),
                ));
            }
            let repo = open_repo(ctx)?;
            let (all, _) = repo.load_all_manifests()?;
            let mid = format!("cdp:{}:{name}", hostname());
            let mine: Vec<&core_format::ManifestBody> =
                all.iter().filter(|m| m.machine.machine_id == mid).collect();
            let base = mine
                .iter()
                .filter(|m| {
                    m.os.family == "cdp-base"
                        && cdp_meta(m)["unix"].as_i64().is_some_and(|u| u <= at)
                })
                .max_by_key(|m| cdp_meta(m)["seq"].as_u64().unwrap_or(0))
                .ok_or_else(|| CliError::usage("no base image from before that moment"))?;
            let base_seq = cdp_meta(base)["seq"].as_u64().unwrap_or(0);
            let mut journals: Vec<&&core_format::ManifestBody> = mine
                .iter()
                .filter(|m| {
                    m.os.family == "cdp-journal"
                        && cdp_meta(m)["seq"].as_u64().is_some_and(|s| s >= base_seq)
                })
                .collect();
            journals.sort_by_key(|m| cdp_meta(m)["seq"].as_u64().unwrap_or(0));
            let d = &base.disks[0];
            let confirm = DestructiveConfirmation::confirmed_by_user(&target);
            let t = FileTarget::open(&target, d.size, true, &confirm)?;
            engine::restore_disk(
                &repo,
                base,
                0,
                &t,
                &RestoreOptions {
                    workers: 4,
                    zero_fill: true,
                    fit: false,
                    grow: false,
                    verify: true,
                },
                &JobControl::new(),
                &|_, _| {},
            )?;
            drop(t);
            let dir = tempfile_dir()?;
            let mut out = std::fs::OpenOptions::new().write(true).open(&target)?;
            let (mut applied, mut last_mark, mut writes) = (0, None, 0u64);
            for (expected, j) in (base_seq..).zip(journals) {
                let meta = cdp_meta(j);
                let seq = meta["seq"].as_u64().unwrap_or(0);
                if seq != expected {
                    return Err(CliError::new(ExitCode::Error, format!("journal {expected} is missing (pruned or not shipped): the volume can only be restored to before it")));
                }
                let file = dir.join(format!("j{seq}"));
                k8s_disk_to(&repo, j, 0, &file, meta["bytes"].as_u64().unwrap_or(0))?;
                let (r, past) =
                    cdp::journal::replay_until(&mut std::fs::File::open(&file)?, &mut out, at)?;
                let _ = std::fs::remove_file(&file);
                applied += 1;
                writes += r.writes;
                if r.last_mark.is_some() {
                    last_mark = r.last_mark.clone();
                }
                if past {
                    break;
                }
            }
            out.sync_all()?;
            let _ = std::fs::remove_dir_all(&dir);
            let reached = last_mark.as_deref().and_then(cdp::journal::mark_time);
            Ok(Outcome::new(
                json!({ "base_image": base.image_id, "journals": applied, "writes": writes, "restored_to": reached }),
                format!("Restored {name} to {} (base image {}, {applied} journals, {writes} writes replayed)\n", reached.map(core_format::timefmt::rfc3339_utc).unwrap_or_else(|| "its base image".into()), base.image_id),
            ))
        }
        CdpCmd::Disable {
            name,
            remove_journals,
        } => {
            cdp::control::disable(&dir, &name, remove_journals).map_err(err)?;
            Ok(Outcome::new(
                json!({ "disabled": name }),
                format!("CDP stopped for {name}: mount the logical volume itself again.\n"),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn cbt_cmd(ctx: &Ctx, c: CbtCmd) -> R<Outcome> {
    use cdp::era;
    let dir = cdp_state_dir();
    let err = |e: String| CliError::new(ExitCode::Error, e);
    match c {
        CbtCmd::Enable {
            name,
            volume,
            block_kib,
        } => {
            let st = era::enable(&dir, &name, &volume, block_kib).map_err(err)?;
            let dev = era::device(&name);
            Ok(Outcome::new(
                json!({ "device": dev, "state": st }),
                format!("Change tracking enabled for {volume}: mount {} instead of it from now on (and in /etc/fstab).\n", dev.display()),
            ))
        }
        CbtCmd::Status { name } => {
            let st = era::load(&dir, &name).map_err(err)?;
            let era_now = era::current_era(&name).map_err(err)?;
            Ok(Outcome::new(
                json!({ "state": st, "current_era": era_now }),
                format!(
                    "{name}: era {era_now}, last image {}\n",
                    st.last_image.as_deref().unwrap_or("none")
                ),
            ))
        }
        CbtCmd::Disable { name } => {
            era::disable(&dir, &name).map_err(err)?;
            Ok(Outcome::new(
                json!({ "disabled": name }),
                format!(
                    "Change tracking stopped for {name}: mount the logical volume itself again.\n"
                ),
            ))
        }
        CbtCmd::Backup { name, label, full } => {
            let mut st = era::load(&dir, &name).map_err(err)?;
            let snap = format!("{}-fenrir-cbt", st.lv);
            let (snap_path, era_now) = era::snapshot(&st, &snap).map_err(err)?;
            let remove = || {
                let _ = std::process::Command::new("lvremove")
                    .args(["-q", "-y", &snap_path])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            };
            let r = (|| -> R<engine::BackupReport> {
                let changed = match (&st.last_image, st.since_era, full) {
                    (Some(base), Some(since), false) => {
                        let ranges = era::written_since(&st, since).map_err(err)?;
                        Some(engine::ChangedSince {
                            base_image: base
                                .parse()
                                .map_err(|_| CliError::usage("bad base image in the state"))?,
                            disks: vec![Some(
                                ranges
                                    .into_iter()
                                    .map(|(o, l)| core_format::extent::Extent(o, l))
                                    .collect(),
                            )],
                            spot_check_one_in: 64,
                        })
                    }
                    _ => None,
                };
                let repo = open_repo(ctx)?;
                let src = snapshot_linux::open_disk(Path::new(&snap_path), false)
                    .map_err(|e| CliError::new(ExitCode::Error, e.to_string()))?;
                let m = engine::ImageMeta {
                    machine: MachineInfo {
                        machine_id: format!("cbt:{}:{name}", hostname()),
                        hostname: format!("{} ({name})", hostname()),
                    },
                    consistency: core_format::manifest::Consistency::Crash,
                    os: Default::default(),
                    boot: Default::default(),
                    drivers: vec![],
                    label: label.clone().or_else(|| Some(format!("volume {name}"))),
                    warnings: vec![],
                    vm: None,
                    applications: vec![],
                };
                Ok(engine::backup(
                    &repo,
                    &[&src.source as &dyn engine::DiskSource],
                    m,
                    &engine::BackupOptions {
                        changed,
                        ..Default::default()
                    },
                    &JobControl::new(),
                    &|_| {},
                )?)
            })();
            remove();
            let r = r?;
            st.last_image = Some(r.image_id.to_string());
            st.since_era = Some(era_now);
            era::save(&dir, &st).map_err(err)?;
            Ok(Outcome::new(
                json!({ "image_id": r.image_id, "read_mode": r.read_mode, "bytes_unchanged": r.bytes_unchanged,
                        "full_read_reason": r.full_read_reason, "era": era_now }),
                format!("Backed up {name} as image {} ({}; {} bytes taken from the previous image unread)\n",
                    r.image_id, r.read_mode, r.bytes_unchanged),
            ))
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn cbt_cmd(_: &Ctx, _: CbtCmd) -> R<Outcome> {
    Err(CliError::usage(
        "changed-block tracking with dm-era is for Linux logical volumes; Hyper-V VMs use RCT",
    ))
}

#[cfg(not(target_os = "linux"))]
fn cdp_cmd(_: &Ctx, _: CdpCmd) -> R<Outcome> {
    Err(CliError::usage(
        "continuous data protection is for Linux logical volumes",
    ))
}

#[cfg(target_os = "linux")]
/// `YYYY-MM-DDTHH:MM:SSZ` (UTC) to unix seconds.
fn parse_utc(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (d, t) = s.split_once(['T', ' '])?;
    let d: Vec<&str> = d.split('-').collect();
    let t: Vec<&str> = t.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let (y, mo, da) = (d[0].parse().ok()?, d[1].parse().ok()?, d[2].parse().ok()?);
    let (h, mi, se): (i64, i64, i64) = (t[0].parse().ok()?, t[1].parse().ok()?, t[2].parse().ok()?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(core_format::timefmt::days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + se)
}

#[cfg(all(test, target_os = "linux"))]
mod parse_utc_tests {
    #[test]
    fn utc_times() {
        assert_eq!(super::parse_utc("1970-01-02T00:00:01Z"), Some(86401));
        assert_eq!(
            super::parse_utc("2026-11-24T10:00:00Z")
                .map(core_format::timefmt::rfc3339_utc)
                .as_deref(),
            Some("2026-11-24T10:00:00Z")
        );
        assert_eq!(super::parse_utc("yesterday"), None);
    }
}

#[cfg(test)]
mod saas_paths {
    use super::*;

    fn item(kind: &str, path: &str) -> saas::store::Item {
        saas::store::Item {
            account: "ann@contoso.com".into(),
            kind: kind.into(),
            id: "AAMkADEyN2FhYzUwLTI".into(),
            path: path.into(),
            modified: String::new(),
            size: 0,
            hash: String::new(),
            meta: serde_json::Value::Null,
            chunks: vec![],
        }
    }

    #[test]
    fn exported_paths_stay_inside_the_folder() {
        assert_eq!(
            saas_rel(&item("mail", "Inbox/Re: plan?")),
            PathBuf::from("ann@contoso.com/mail/Inbox/Re_ plan_ [AAMkADEyN2FhYzUw].eml")
        );
        assert_eq!(
            saas_rel(&item("file", "../../etc/passwd")),
            PathBuf::from("ann@contoso.com/file/etc/passwd")
        );
        assert_eq!(
            saas_rel(&item("record", "Account/001A")),
            PathBuf::from("ann@contoso.com/record/Account/001A.json")
        );
        assert!(!saas_rel(&item("file", "/abs/x")).is_absolute());
    }
}
