//! Wire protocol between `fenrir-server` and `fenrir-backup-agent`, plus the
//! sealing scheme the browser uses to hand repository secrets to agents
//! without the server being able to read them.
//!
//! All messages are JSON over HTTPS. Agents always initiate.

#![forbid(unsafe_code)]

pub mod gateway;
pub mod net;
pub mod recovery;
pub mod seal;
pub mod setup;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    /// Desktop or laptop.
    Workstation,
    /// Physical or virtual server backing itself up.
    Server,
    /// Hyper-V host backing up its VMs.
    Hyperv,
    /// A machine booted from recovery media: restores only, state in RAM.
    Recovery,
}

impl AgentRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "workstation" => Some(Self::Workstation),
            "server" => Some(Self::Server),
            "hyperv" => Some(Self::Hyperv),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workstation => "workstation",
            Self::Server => "server",
            Self::Hyperv => "hyperv",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSummary {
    /// "windows", "linux", "macos".
    pub family: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub protocol: u32,
    pub token: String,
    pub hostname: String,
    pub machine_id: String,
    pub os: OsSummary,
    pub role: AgentRole,
    pub agent_version: String,
    /// X25519 public key, base64. Repository secrets are sealed to it.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    /// Bearer token for all later requests. Shown once; the server keeps
    /// only its hash.
    pub agent_token: String,
    pub poll_seconds: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiskSummary {
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub system: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    /// Logical sector size in bytes (0 = unknown).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub sector_size: u32,
    /// A partition of it is mounted or in use (e.g. the recovery medium):
    /// never offered as a restore target.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_use: bool,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VmSummary {
    pub id: String,
    pub name: String,
    /// "running", "off", "saved", "paused", ...
    pub state: String,
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub disk_bytes: u64,
    #[serde(default)]
    pub disks: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub hostname: String,
    pub os: OsSummary,
    pub agent_version: String,
    /// What this agent can do: "backup_system", "backup_disks",
    /// "backup_hyperv", "verify".
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub disks: Vec<DiskSummary>,
    #[serde(default)]
    pub vms: Vec<VmSummary>,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Rust target triple the agent was built for (auto-update).
    #[serde(default)]
    pub agent_target: String,
    /// SHA-256 of the running agent executable (auto-update).
    #[serde(default)]
    pub agent_sha256: String,
    /// VMs this host runs from backups (boot checks kept running).
    #[serde(default)]
    pub running_vms: Vec<RunningVm>,
    /// Addresses ("ip:port") where this agent serves repositories as a
    /// gateway, when it listens for direct connections.
    #[serde(default)]
    pub gateway_addresses: Vec<String>,
    /// How this machine booted: "uefi" or "bios" (recovery media reports it
    /// so the UI can warn before restoring an image that needs the other).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunningVm {
    pub session_id: Uuid,
    pub image_id: Uuid,
    pub started_unix: i64,
    /// Loopback VNC port on the host (KVM); 0 if none.
    #[serde(default)]
    pub vnc_port: u16,
    /// Guest service name → loopback port on the host.
    #[serde(default)]
    pub forwards: std::collections::BTreeMap<String, u16>,
}

/// Outcome of a boot check, reported with the job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootCheckResult {
    pub image_id: Uuid,
    /// "verified", "screen" or "failed".
    pub outcome: String,
    pub method: String,
    pub seconds: u64,
    pub firmware: String,
    /// "kvm", "tcg" or "hyperv".
    pub accel: String,
    pub message: String,
    /// PNG, base64.
    #[serde(default)]
    pub screenshot_png: Option<String>,
    /// Set when the VM was left running.
    #[serde(default)]
    pub session: Option<RunningVm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub inventory: Inventory,
    /// Job the agent is executing now, if any.
    #[serde(default)]
    pub running_job: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub jobs: Vec<JobSpec>,
    pub poll_seconds: u32,
    /// Jobs the administrator cancelled while they were running.
    #[serde(default)]
    pub cancel: Vec<Uuid>,
    /// A newer agent build the server wants this agent to run.
    #[serde(default)]
    pub update: Option<AgentUpdate>,
    /// Repositories this agent serves to other agents (NAS gateway).
    #[serde(default)]
    pub gateway: Option<gateway::GatewayConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUpdate {
    /// Server path to download, e.g. "/agent/x86_64-pc-windows-msvc/fenrir-backup-agent.exe".
    pub path: String,
    pub sha256: String,
}

/// Grandfather-father-son retention; zero turns a rule off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    #[serde(default)]
    pub keep_last: u32,
    /// One image per hour for this many hours (frequent backups).
    #[serde(default)]
    pub keep_hourly: u32,
    #[serde(default)]
    pub keep_daily: u32,
    #[serde(default)]
    pub keep_weekly: u32,
    #[serde(default)]
    pub keep_monthly: u32,
    #[serde(default)]
    pub keep_yearly: u32,
}

impl Retention {
    pub fn keeps_everything(&self) -> bool {
        self.keep_last == 0
            && self.keep_hourly == 0
            && self.keep_daily == 0
            && self.keep_weekly == 0
            && self.keep_monthly == 0
            && self.keep_yearly == 0
    }
}

/// Where a restore writes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RestoreTarget {
    /// One dynamic VHDX per disk in `directory` on the agent's machine.
    Vhdx { directory: String },
    /// Hyper-V hosts: VHDX files plus a new VM with the original settings.
    HypervVm {
        name: String,
        directory: String,
        #[serde(default)]
        switch: Option<String>,
        #[serde(default)]
        start: bool,
    },
    /// Raw write of one image disk to a device or file. `confirm` must
    /// equal `device`: the administrator typed it.
    Disk {
        device: String,
        disk: u32,
        confirm: String,
        /// Give a larger disk's extra space to the last partition and grow
        /// its file system (phase-5-grow-clone.md).
        #[serde(default)]
        grow: bool,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupSettings {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub rate_limit_mib: u64,
    /// Windows: VSS FULL instead of COPY.
    #[serde(default)]
    pub vss_full: bool,
    /// Verify a sample of the new image's chunks afterwards.
    #[serde(default)]
    pub verify_sample_percent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobKind {
    /// Create the repository at `repository.path`.
    InitRepository,
    /// Whole running system (Windows VSS).
    BackupSystem {
        #[serde(default)]
        settings: BackupSettings,
    },
    /// Listed devices or image files.
    BackupDisks {
        paths: Vec<String>,
        #[serde(default)]
        settings: BackupSettings,
    },
    /// Hyper-V VMs by ID; empty = every VM on the host.
    BackupHyperv {
        #[serde(default)]
        vm_ids: Vec<String>,
        #[serde(default)]
        settings: BackupSettings,
    },
    Verify {
        /// "quick", "sample", "full".
        level: String,
        #[serde(default)]
        sample_percent: Option<f64>,
    },
    /// Report the repository's images to the server.
    ListImages,
    /// Copy images from this job's repository to `target_repository_id`
    /// (off-site copies, docs/design/offsite-copy.md): re-encrypted for the
    /// destination, then verified there. Empty `images` = every image the
    /// destination does not have.
    CopyImages {
        target_repository_id: Uuid,
        #[serde(default)]
        images: Vec<Uuid>,
        #[serde(default)]
        full_verify: bool,
    },
    /// Delete images the policy no longer keeps (manifests only).
    ApplyRetention {
        /// Machine IDs to apply it to; empty = all in the repository.
        #[serde(default)]
        machine_ids: Vec<String>,
        retention: Retention,
        #[serde(default)]
        dry_run: bool,
    },
    /// Delete chunks no image references.
    Prune {
        #[serde(default)]
        dry_run: bool,
    },
    Restore {
        image_id: Uuid,
        /// Image disks to restore; empty = all (ignored for `disk` targets).
        #[serde(default)]
        disks: Vec<u32>,
        target: RestoreTarget,
    },
    /// Boot the image as an isolated VM and check that it starts.
    BootCheck {
        image_id: Uuid,
        /// Keep the VM after the check (network disconnected) until it is
        /// stopped: KVM hosts keep it running for up to 8 hours, Hyper-V
        /// hosts keep it as a VM to log in to and inspect.
        #[serde(default)]
        keep_running: bool,
        #[serde(default)]
        memory_mb: Option<u64>,
        #[serde(default)]
        cpus: Option<u32>,
        /// Hyper-V: folder on the host for the VM's disks (default: the
        /// agent's own folder).
        #[serde(default)]
        directory: Option<String>,
    },
    /// Power off a VM left running by a boot check.
    StopVm { session_id: Uuid },
    /// Without `volume`: the image's volumes. With it: the folder `path`
    /// (`/`-separated from the volume root) in that volume.
    BrowseFiles {
        image_id: Uuid,
        #[serde(default)]
        volume: Option<VolumeRef>,
        #[serde(default)]
        path: String,
    },
    /// Copy chosen files and folders out of an image into `target`, a
    /// folder on this machine.
    RestoreFiles {
        image_id: Uuid,
        volume: VolumeRef,
        paths: Vec<String>,
        target: String,
        /// Recreate the folders above each item under `target`.
        #[serde(default)]
        keep_structure: bool,
        /// "rename" (keep both), "skip" or "overwrite" existing files.
        #[serde(default = "default_conflict")]
        conflict: String,
    },
    /// Can this machine reach and write to `path`? Signs in to a network
    /// share first when credentials are given. Reports free space.
    CheckAccess {
        path: String,
        #[serde(default)]
        sealed_share: Option<seal::Sealed>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        s3: Option<S3Settings>,
    },
}

impl JobKind {
    pub fn label(&self) -> &'static str {
        match self {
            JobKind::InitRepository => "Create repository",
            JobKind::BackupSystem { .. } => "System backup",
            JobKind::BackupDisks { .. } => "Disk backup",
            JobKind::BackupHyperv { .. } => "Hyper-V backup",
            JobKind::Verify { .. } => "Verify",
            JobKind::ListImages => "Refresh images",
            JobKind::CopyImages { .. } => "Copy off-site",
            JobKind::ApplyRetention { .. } => "Apply retention",
            JobKind::Prune { .. } => "Reclaim space",
            JobKind::Restore { .. } => "Restore",
            JobKind::BootCheck { .. } => "Boot check",
            JobKind::StopVm { .. } => "Stop VM",
            JobKind::CheckAccess { .. } => "Test connection",
            JobKind::BrowseFiles { .. } => "Browse files",
            JobKind::RestoreFiles { .. } => "Restore files",
        }
    }
}

/// One partition of one disk of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRef {
    pub disk: u32,
    pub partition: u32,
}

fn default_conflict() -> String {
    "rename".into()
}

/// Where the repository is and the secret to open it, sealed to this agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAccess {
    pub repository_id: Uuid,
    pub path: String,
    pub sealed_secret: seal::Sealed,
    /// Network share sign-in (`ShareCredentials`), sealed to this agent.
    #[serde(default)]
    pub sealed_share: Option<seal::Sealed>,
    /// Reach the repository through a gateway agent instead of `path`.
    #[serde(default)]
    pub gateway: Option<gateway::GatewayRoute>,
    /// S3-compatible storage (`path` = `s3://bucket/prefix`). The access key
    /// and secret are `sealed_share` (username = access key ID, password =
    /// secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Settings>,
}

/// Where an S3 repository is, and its Object Lock (design: phase-4-storage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Settings {
    /// `https://s3.eu-west-2.amazonaws.com`, `http://minio.lan:9000`, ...
    pub endpoint: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// `https://host/bucket/key` instead of `https://bucket.host/key`.
    #[serde(default)]
    pub path_style: bool,
    /// "governance" or "compliance"; none = no Object Lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_mode: Option<String>,
    #[serde(default)]
    pub lock_days: u32,
}

fn default_region() -> String {
    "us-east-1".into()
}

/// Sign-in for a repository on a network share (SMB). Sealed to each agent
/// by the browser; the server never sees it in plain text.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ShareCredentials {
    /// Windows domain, or empty (NAS local account, or user@domain).
    #[serde(default)]
    pub domain: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for ShareCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareCredentials")
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Plaintext inside `RepoAccess::sealed_secret`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RepoSecret {
    pub passphrase: String,
    /// Recovery key file contents; only sent to the agent that creates
    /// the repository.
    #[serde(default)]
    pub recovery_key: Option<String>,
}

impl std::fmt::Debug for RepoSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoSecret(..)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub id: Uuid,
    pub kind: JobKind,
    #[serde(default)]
    pub repository: Option<RepoAccess>,
    /// The destination of a `CopyImages` job, sealed to this machine like
    /// the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_target: Option<RepoAccess>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Dispatched,
    Running,
    Succeeded,
    /// Completed, with warnings worth a look.
    Warning,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Dispatched => "dispatched",
            JobState::Running => "running",
            JobState::Succeeded => "succeeded",
            JobState::Warning => "warning",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => JobState::Queued,
            "dispatched" => JobState::Dispatched,
            "running" => JobState::Running,
            "succeeded" => JobState::Succeeded,
            "warning" => JobState::Warning,
            "failed" => JobState::Failed,
            "cancelled" => JobState::Cancelled,
            _ => return None,
        })
    }
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            JobState::Succeeded | JobState::Warning | JobState::Failed | JobState::Cancelled
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JobProgress {
    /// Short phase name: "snapshot", "reading", "verifying", ...
    pub phase: String,
    pub done: u64,
    pub total: u64,
    #[serde(default)]
    pub message: String,
    /// Bytes per second over this phase so far (0 = not known yet).
    #[serde(default, skip_serializing_if = "is_zero64")]
    pub rate: u64,
    /// Seconds left at that rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,
    /// New data stored in the repository so far (backups).
    #[serde(default, skip_serializing_if = "is_zero64")]
    pub stored: u64,
}

fn is_zero64(v: &u64) -> bool {
    *v == 0
}

impl JobProgress {
    /// Rate and time left for `done` of `total` after `elapsed_secs`.
    pub fn estimate(done: u64, total: u64, elapsed_secs: f64) -> (u64, Option<u64>) {
        if elapsed_secs < 1.0 || done == 0 {
            return (0, None);
        }
        let rate = done as f64 / elapsed_secs;
        let eta = (total > done).then(|| ((total - done) as f64 / rate).ceil() as u64);
        (rate as u64, eta.or(Some(0)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobUpdate {
    pub state: JobState,
    #[serde(default)]
    pub progress: Option<JobProgress>,
    /// Kind-specific result (e.g. backup report).
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Images now in the repository (after backup or ListImages).
    #[serde(default)]
    pub images: Option<Vec<ImageReport>>,
    /// Repository UUID (after InitRepository).
    #[serde(default)]
    pub repo_uuid: Option<Uuid>,
    /// Images deleted by retention.
    #[serde(default)]
    pub removed_images: Vec<Uuid>,
    #[serde(default)]
    pub boot_check: Option<BootCheckResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageReport {
    pub image_id: Uuid,
    pub machine_id: String,
    pub hostname: String,
    pub created: String,
    pub created_unix: i64,
    pub kind: String,
    pub consistency: String,
    pub captured_bytes: u64,
    pub stored_new_bytes: u64,
    pub disks: Vec<u64>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub vm_name: Option<String>,
    /// Change statistics of the backup that created it (anomaly checks).
    #[serde(default)]
    pub chunks_total: u64,
    #[serde(default)]
    pub chunks_new: u64,
    #[serde(default)]
    pub bytes_new_raw: u64,
    /// Application components coordinated with the snapshot (VSS writers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<ImageApplication>,
}

/// An application component in an image (see core-format `ApplicationInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageApplication {
    pub writer: String,
    pub component: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caption: String,
    pub included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

#[cfg(test)]
mod progress_tests {
    use super::JobProgress;

    #[test]
    fn progress_rate_and_time_left() {
        assert_eq!(JobProgress::estimate(0, 100, 10.0), (0, None));
        assert_eq!(JobProgress::estimate(50, 100, 0.5), (0, None), "too early");
        assert_eq!(
            JobProgress::estimate(100 << 20, 400 << 20, 10.0),
            (10 << 20, Some(30))
        );
        assert_eq!(JobProgress::estimate(5, 5, 2.0), (2, Some(0)));
    }
}
