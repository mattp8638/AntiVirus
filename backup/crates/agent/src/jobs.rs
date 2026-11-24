//! Runs one job from the server and reports progress and the outcome.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use core_format::backend::{Backend, LocalBackend};
use core_format::manifest::{Consistency, MachineInfo, ManifestBody};
use core_format::{RecoveryKey, Repository};
use engine::{BackupOptions, BackupReport, ImageMeta, JobControl, VerifyLevel};
use protocol::seal::AgentKey;
use protocol::{
    BackupSettings, ImageReport, JobKind, JobProgress, JobSpec, JobState, JobUpdate, RepoAccess,
    RepoSecret,
};
use serde_json::json;

use crate::client::Client;
use crate::config::AgentConfig;

pub struct Ctx<'a> {
    pub cfg: &'a AgentConfig,
    pub state_dir: &'a Path,
    pub client: &'a Client,
    pub key: &'a AgentKey,
    pub ctl: Arc<JobControl>,
}

/// Sends progress at most every two seconds.
pub struct Reporter<'a> {
    client: &'a Client,
    path: String,
    last: Mutex<Option<Instant>>,
    /// When the current phase started, for the rate and time left.
    phase: Mutex<(String, Instant)>,
}

impl<'a> Reporter<'a> {
    pub fn new(client: &'a Client, job: uuid::Uuid) -> Self {
        Reporter {
            client,
            path: format!("/api/agent/jobs/{job}/update"),
            last: Mutex::new(None),
            phase: Mutex::new((String::new(), Instant::now())),
        }
    }

    pub fn progress(&self, phase: &str, done: u64, total: u64, message: &str) {
        self.progress_stored(phase, done, total, 0, message)
    }

    /// Progress of a phase, with the new data stored so far (backups).
    pub fn progress_stored(&self, phase: &str, done: u64, total: u64, stored: u64, message: &str) {
        let started = {
            let mut p = self.phase.lock().unwrap();
            if p.0 != phase {
                *p = (phase.to_string(), Instant::now());
            }
            p.1
        };
        let mut l = self.last.lock().unwrap();
        if l.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) && done < total {
            return;
        }
        *l = Some(Instant::now());
        let (rate, eta_seconds) =
            JobProgress::estimate(done, total, started.elapsed().as_secs_f64());
        let u = running(Some(JobProgress {
            phase: phase.into(),
            done,
            total,
            message: message.into(),
            rate,
            eta_seconds,
            stored,
        }));
        if let Err(e) = self.client.post::<_, serde_json::Value>(&self.path, &u) {
            crate::log::warn(&format!("progress update failed: {e:#}"));
        }
    }

    pub fn finish(&self, u: &JobUpdate) -> anyhow::Result<()> {
        // Retry: the outcome matters more than progress.
        let mut delay = 2;
        for attempt in 0..6 {
            match self.client.post::<_, serde_json::Value>(&self.path, u) {
                Ok(_) => return Ok(()),
                Err(e) if attempt == 5 => return Err(e),
                Err(e) => {
                    crate::log::warn(&format!("reporting job result failed (will retry): {e:#}"))
                }
            }
            std::thread::sleep(Duration::from_secs(delay));
            delay *= 2;
        }
        Ok(())
    }
}

fn running(progress: Option<JobProgress>) -> JobUpdate {
    JobUpdate {
        state: JobState::Running,
        progress,
        result: None,
        error: None,
        warnings: vec![],
        images: None,
        repo_uuid: None,
        removed_images: vec![],
        boot_check: None,
    }
}

pub fn finished(state: JobState) -> JobUpdate {
    done(state)
}

fn done(state: JobState) -> JobUpdate {
    JobUpdate {
        state,
        progress: None,
        result: None,
        error: None,
        warnings: vec![],
        images: None,
        repo_uuid: None,
        removed_images: vec![],
        boot_check: None,
    }
}

pub fn report_of(m: &ManifestBody) -> ImageReport {
    ImageReport {
        image_id: m.image_id,
        machine_id: m.machine.machine_id.clone(),
        hostname: m.machine.hostname.clone(),
        created: m.created.clone(),
        created_unix: m.created_unix,
        kind: format!("{:?}", m.kind).to_lowercase(),
        consistency: format!("{:?}", m.consistency).to_lowercase(),
        captured_bytes: m
            .disks
            .iter()
            .map(|d| core_format::extent::total_len(&d.used_extents))
            .sum(),
        stored_new_bytes: m.stats.bytes_new_stored,
        disks: m.disks.iter().map(|d| d.size).collect(),
        label: m.label.clone(),
        vm_name: m.vm.as_ref().map(|v| v.name.clone()),
        chunks_total: m.stats.chunks_total,
        chunks_new: m.stats.chunks_new,
        bytes_new_raw: m.stats.bytes_new_raw,
        applications: m
            .applications
            .iter()
            .map(|a| protocol::ImageApplication {
                writer: a.writer.clone(),
                component: a.component.clone(),
                caption: a.caption.clone(),
                included: a.included,
                note: a.note.clone(),
            })
            .collect(),
    }
}

/// A cluster's API client; the token is opened here, never stored.
fn k8s_client(
    ctx: &Ctx,
    cluster: &protocol::sources::K8sCluster,
    sealed: &protocol::seal::Sealed,
) -> anyhow::Result<k8s::Client> {
    cluster.validate().map_err(|e| anyhow!(e))?;
    let token = ctx
        .key
        .open(sealed)
        .map_err(|e| anyhow!("{e}: enter the cluster's token again"))?;
    let token = String::from_utf8(token.to_vec()).map_err(|_| anyhow!("the token is not text"))?;
    k8s::Client::new(&k8s::Connect {
        server: cluster.api_server.clone(),
        token: token.trim().to_string(),
        ca_pem: cluster.ca_pem.clone(),
    })
    .map_err(|e| anyhow!("{e}"))
}

fn saas_conn(
    ctx: &Ctx,
    t: &protocol::sources::SaasTenant,
    sealed: &protocol::seal::Sealed,
) -> anyhow::Result<(saas::run::Settings, saas::run::Conn)> {
    t.validate().map_err(|e| anyhow!(e))?;
    let secret = ctx
        .key
        .open(sealed)
        .map_err(|e| anyhow!("{e}: enter the {} secret again", t.service))?;
    let secret =
        String::from_utf8(secret.to_vec()).map_err(|_| anyhow!("the secret is not text"))?;
    let settings = saas::run::Settings {
        service: t.service.clone(),
        tenant: t.tenant.clone(),
        client_id: t.client_id.clone(),
        domain_url: t.domain_url.clone(),
        admin: t.admin.clone(),
    };
    let conn = saas::run::connect(&settings, &secret).map_err(|e| anyhow!("{e}"))?;
    Ok((settings, conn))
}

fn secret(key: &AgentKey, access: &RepoAccess) -> anyhow::Result<RepoSecret> {
    let pt = key
        .open(&access.sealed_secret)
        .map_err(|e| anyhow!("{e}. Grant this machine access to the repository again."))?;
    Ok(serde_json::from_slice(&pt)?)
}

/// Object storage behind a repository: S3-compatible or Azure Blob.
pub(crate) enum ObjectStore {
    S3(s3store::S3Backend),
    Azure(azstore::AzureBackend),
}

impl ObjectStore {
    pub fn is_empty(&self) -> core_format::Result<bool> {
        match self {
            ObjectStore::S3(b) => b.is_empty(),
            ObjectStore::Azure(b) => b.is_empty(),
        }
    }
    pub fn exists(&self) -> core_format::Result<bool> {
        match self {
            ObjectStore::S3(b) => b.bucket_exists(),
            ObjectStore::Azure(b) => b.container_exists(),
        }
    }
    /// Create the bucket or container if it does not exist yet (new repository).
    pub fn ensure_exists(&self) -> core_format::Result<bool> {
        match self {
            ObjectStore::S3(b) => b.ensure_bucket(),
            ObjectStore::Azure(b) => b.ensure_container(),
        }
    }
    pub fn check(&self) -> core_format::Result<String> {
        match self {
            ObjectStore::S3(b) => b.check(),
            ObjectStore::Azure(b) => b.check(),
        }
    }
    pub fn into_backend(self) -> Arc<dyn Backend> {
        match self {
            ObjectStore::S3(b) => Arc::new(b),
            ObjectStore::Azure(b) => Arc::new(b),
        }
    }
    fn backend(&self) -> &dyn Backend {
        match self {
            ObjectStore::S3(b) => b,
            ObjectStore::Azure(b) => b,
        }
    }
}

/// Object storage for `path` (`s3://bucket/prefix` or
/// `azure://container/prefix`), with the keys sealed to this machine: for
/// S3 the access key and secret, for Azure the account name and its key or
/// a SAS token.
pub(crate) fn object_store(
    key: &AgentKey,
    path: &str,
    s: &protocol::S3Settings,
    sealed: Option<&protocol::seal::Sealed>,
) -> anyhow::Result<ObjectStore> {
    let creds = crate::share::open_credentials(
        key,
        sealed.ok_or_else(|| {
            anyhow!("this machine has no access keys for {path}; give it access again")
        })?,
    )?;
    let mode = match s.lock_mode.as_deref() {
        None | Some("") | Some("none") => None,
        Some(m) => Some(m),
    };
    if path.starts_with("azure://") {
        let (container, prefix) = azstore::parse_url(path)
            .ok_or_else(|| anyhow!("{path} is not an azure://container/prefix location"))?;
        let lock = mode
            .map(|m| {
                Ok::<_, anyhow::Error>(azstore::Lock {
                    mode: azstore::LockMode::parse(m)
                        .ok_or_else(|| anyhow!("unknown immutability mode {m}"))?,
                    days: s.lock_days,
                })
            })
            .transpose()?;
        return Ok(ObjectStore::Azure(azstore::AzureBackend::new(
            azstore::AzureConfig {
                endpoint: s.endpoint.clone(),
                account: creds.username,
                container,
                prefix,
                credential: azstore::credential_from(&creds.password),
                lock,
            },
        )?));
    }
    let (bucket, prefix) = s3store::parse_url(path)
        .ok_or_else(|| anyhow!("{path} is not an s3://bucket/prefix location"))?;
    let lock = mode
        .map(|m| {
            Ok::<_, anyhow::Error>(s3store::Lock {
                mode: s3store::LockMode::parse(m)
                    .ok_or_else(|| anyhow!("unknown Object Lock mode {m}"))?,
                days: s.lock_days,
            })
        })
        .transpose()?;
    Ok(ObjectStore::S3(s3store::S3Backend::new(
        s3store::S3Config {
            endpoint: s.endpoint.clone(),
            region: s.region.clone(),
            bucket,
            prefix,
            path_style: s.path_style,
            access_key: creds.username,
            secret_key: creds.password,
            lock,
        },
    )?))
}

/// The repository's storage: its folder, S3, or a gateway (NAS gateway) when
/// the server routes this machine through one. A dedup group member
/// (`<group>/repos/<id>`) is its folder plus the group's shared store.
fn storage(ctx: &Ctx, access: &RepoAccess, create: bool) -> anyhow::Result<Arc<dyn Backend>> {
    if let Some(route) = &access.gateway {
        let me = uuid::Uuid::parse_str(&ctx.cfg.agent_id).context("agent id")?;
        let transport = crate::gateway::Route::new(route.clone(), ctx.client.clone());
        return Ok(Arc::new(crate::gateway::RemoteBackend::new(
            ctx.key,
            me,
            &route.public_key,
            access.repository_id,
            Box::new(transport),
        )?));
    }
    if let Some((root, _)) = core_format::group::split_member_path(&access.path) {
        let member = location(ctx, access, &access.path, create)?;
        let shared = location(ctx, access, &root, false)?;
        return Ok(Arc::new(core_format::group::GroupBackend {
            member,
            shared,
        }));
    }
    location(ctx, access, &access.path, create)
}

/// A folder, share or object storage location with the repository's
/// credentials. `create`: it must be new or empty (created if missing).
fn location(
    ctx: &Ctx,
    access: &RepoAccess,
    path: &str,
    create: bool,
) -> anyhow::Result<Arc<dyn Backend>> {
    if let Some(s) = &access.s3 {
        let b = object_store(ctx.key, path, s, access.sealed_share.as_ref())?;
        if create {
            b.ensure_exists()
                .with_context(|| format!("creating {path}"))?;
        }
        if create && !b.is_empty()? {
            bail!(
                "{path} already holds data: choose an empty bucket or container, or another folder in it"
            );
        }
        return Ok(b.into_backend());
    }
    let local = crate::share::prepare(ctx.key, path, access.sealed_share.as_ref())?;
    Ok(if create {
        Arc::new(LocalBackend::create(&local).with_context(|| {
            format!("creating the repository at {path} (the folder must be new or empty)")
        })?)
    } else {
        Arc::new(LocalBackend::open(&local).with_context(|| format!("repository path {path}"))?)
    })
}

/// Create a repository; in a dedup group (its path `<group>/repos/<id>`),
/// a new group, or a member of the group `group_source` belongs to.
fn init_repository(
    ctx: &Ctx,
    access: &RepoAccess,
    group_source: Option<&RepoAccess>,
    passphrase: &[u8],
    rk: &RecoveryKey,
) -> anyhow::Result<Repository> {
    let Some((root, id)) = core_format::group::split_member_path(&access.path) else {
        let backend = storage(ctx, access, true)?;
        return Ok(Repository::init_with(
            backend,
            passphrase,
            Default::default(),
            rk,
        )?);
    };
    if id != rk.repo_id {
        bail!(
            "the repository folder {} does not match its recovery key",
            access.path
        );
    }
    let (shared, info, key) = match group_source {
        Some(src) => {
            let other = open_repo(ctx, src).context("opening the group's other repository")?;
            let key = other
                .group_key()
                .cloned()
                .ok_or_else(|| anyhow!("{} is not in a dedup group", src.path))?;
            let shared = location(ctx, access, &root, false)?;
            let info = core_format::group::read_info(&*shared)?;
            if Some(info.group_id) != other.config().group {
                bail!("{} is not in the dedup group at {root}", src.path);
            }
            (shared, info, key)
        }
        None => {
            let shared = location(ctx, access, &root, true)?;
            let info = core_format::group::create(&*shared, core_format::DEFAULT_CHUNK_SIZE)?;
            (shared, info, core_format::crypto::SecretKey::generate()?)
        }
    };
    let member = location(ctx, access, &access.path, true)?;
    let backend: Arc<dyn Backend> = Arc::new(core_format::group::GroupBackend { member, shared });
    Ok(Repository::init_member(
        backend,
        passphrase,
        Default::default(),
        rk,
        &info,
        &key,
    )?)
}

pub(crate) fn open_repo(ctx: &Ctx, access: &RepoAccess) -> anyhow::Result<Repository> {
    let s = secret(ctx.key, access)?;
    let backend = storage(ctx, access, false)?;
    Repository::unlock_with_passphrase(backend, s.passphrase.as_bytes()).map_err(|e| match e {
        core_format::Error::WrongKey => anyhow!("the repository passphrase given to this machine is wrong; grant access again with the right passphrase"),
        e => e.into(),
    })
}

/// Execute a job; never panics outwards. Returns the final update.
pub fn run(ctx: &Ctx, spec: &JobSpec) -> JobUpdate {
    let rep = Reporter::new(ctx.client, spec.id);
    rep.progress("starting", 0, 1, spec.kind.label());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(ctx, spec, &rep)));
    // Network shares stay connected only while a job (or a VM running from
    // a backup) needs them.
    if crate::boot::running_vms().is_empty()
        && !crate::browse::active()
        && !crate::gateway::serving()
    {
        crate::share::release_all();
    }
    match r {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            if ctx.ctl.is_cancelled() {
                let mut u = done(JobState::Cancelled);
                u.error = Some("cancelled".into());
                return u;
            }
            let mut u = done(JobState::Failed);
            u.error = Some(format!("{e:#}"));
            u
        }
        Err(_) => {
            let mut u = done(JobState::Failed);
            u.error = Some("internal error (panic) in the agent; see the agent log".into());
            u
        }
    }
}

fn options(s: &BackupSettings) -> BackupOptions {
    BackupOptions {
        rate_limit: s.rate_limit_mib.saturating_mul(1 << 20),
        ..Default::default()
    }
}

fn progress_cb<'a>(
    rep: &'a Reporter<'a>,
    prefix: String,
) -> impl Fn(&engine::Progress) + Sync + 'a {
    move |p: &engine::Progress| {
        rep.progress_stored(
            "reading",
            p.bytes_done,
            p.bytes_total,
            p.bytes_stored,
            &format!("{prefix}disk {}", p.disk),
        )
    }
}

fn execute(ctx: &Ctx, spec: &JobSpec, rep: &Reporter) -> anyhow::Result<JobUpdate> {
    let access = spec.repository.as_ref();
    match &spec.kind {
        JobKind::InitRepository => {
            let access = access.ok_or_else(|| anyhow!("no repository given"))?;
            let s = secret(ctx.key, access)?;
            let rk = RecoveryKey::from_file_contents(
                s.recovery_key
                    .as_deref()
                    .ok_or_else(|| anyhow!("no recovery key supplied"))?,
            )?;
            rep.progress("creating", 0, 1, "deriving keys");
            let repo = init_repository(
                ctx,
                access,
                spec.group_source.as_ref(),
                s.passphrase.as_bytes(),
                &rk,
            )?;
            let mut u = done(JobState::Succeeded);
            u.repo_uuid = Some(repo.config().repo_id);
            u.result = Some(
                json!({ "path": access.path, "chunk_size": repo.chunk_size(), "dedup_group": repo.config().group }),
            );
            Ok(u)
        }
        JobKind::BackupSystem { settings } => {
            let access = access.ok_or_else(|| anyhow!("no repository"))?;
            let repo = open_repo(ctx, access)?;
            backup_system(ctx, &repo, &access.path, settings, rep)
        }
        JobKind::BackupFiles {
            paths,
            excludes,
            settings,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            crate::folders::run(ctx, &repo, paths, excludes, settings, rep)
        }
        JobKind::BackupDisks { paths, settings } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let mut opened = Vec::new();
            for p in paths {
                opened.push(
                    snapshot_linux::open_disk(Path::new(p), false)
                        .map_err(|e| anyhow!("{p}: {e}"))?,
                );
            }
            let sources: Vec<&dyn engine::DiskSource> = opened
                .iter()
                .map(|o| &o.source as &dyn engine::DiskSource)
                .collect();
            let meta = ImageMeta {
                machine: MachineInfo {
                    machine_id: ctx.cfg.machine_id.clone(),
                    hostname: crate::inventory::hostname(),
                },
                consistency: Consistency::Offline,
                os: Default::default(),
                boot: Default::default(),
                drivers: vec![],
                label: settings.label.clone(),
                warnings: opened.iter().flat_map(|o| o.warnings.clone()).collect(),
                vm: None,
                applications: vec![],
            };
            let cb = progress_cb(rep, String::new());
            let r = engine::backup(&repo, &sources, meta, &options(settings), &ctx.ctl, &cb)?;
            finish_backup(&repo, vec![r], vec![], settings, rep)
        }
        JobKind::BackupHyperv { vm_ids, settings } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            backup_hyperv(ctx, &repo, vm_ids, settings, rep)
        }
        JobKind::Verify {
            level,
            sample_percent,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let lvl = match level.as_str() {
                "full" => VerifyLevel::Full,
                "sample" => VerifyLevel::Sample(sample_percent.unwrap_or(5.0)),
                _ => VerifyLevel::Quick,
            };
            rep.progress("verifying", 0, 1, level);
            let r = engine::verify(&repo, None, lvl, &ctx.ctl, 4)?;
            let mut u = done(if r.ok {
                JobState::Succeeded
            } else {
                JobState::Failed
            });
            if !r.ok {
                u.error = Some(format!(
                    "{} damaged manifest(s), {} missing and {} corrupt chunk(s)",
                    r.bad_manifests.len(),
                    r.missing_chunks.len(),
                    r.corrupt_chunks.len()
                ));
            }
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::ListImages => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let (ok, bad) = repo.load_all_manifests()?;
            let mut u = done(if bad.is_empty() {
                JobState::Succeeded
            } else {
                JobState::Warning
            });
            u.warnings = bad
                .iter()
                .map(|(id, e)| format!("image {id}: {e}"))
                .collect();
            u.images = Some(ok.iter().map(report_of).collect());
            // Adopting an existing repository: the server learns its ID here.
            u.repo_uuid = Some(repo.config().repo_id);
            Ok(u)
        }
        JobKind::CopyImages {
            images,
            full_verify,
            ..
        } => {
            let src = open_repo(ctx, access.ok_or_else(|| anyhow!("no source repository"))?)?;
            let target = spec.copy_target.as_ref().ok_or_else(|| {
                anyhow!("this machine has no access to the destination repository; grant it access there")
            })?;
            let dst = open_repo(ctx, target)?;
            let cb = |done: u64, total: u64| rep.progress("copying", done, total, &target.path);
            let ids = (!images.is_empty()).then_some(images.as_slice());
            let r = engine::copy::copy_images(&src, &dst, ids, *full_verify, &ctx.ctl, &cb)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(json!({
                "copied": r.copied.len(),
                "already_there": r.already_there,
                "chunks_written": r.chunks_written,
                "bytes_stored": r.bytes_stored,
                "verified": r.verified,
                "to": target.path,
            }));
            // The destination's catalogue lists the copies.
            u.images = Some(
                r.copied
                    .iter()
                    .filter_map(|id| dst.load_manifest(id).ok())
                    .map(|m| report_of(&m))
                    .collect(),
            );
            Ok(u)
        }
        JobKind::ApplyRetention {
            machine_ids,
            retention,
            dry_run,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            rep.progress("retention", 0, 1, "reading images");
            let p = engine::retention::RetentionPolicy {
                keep_last: retention.keep_last,
                keep_hourly: retention.keep_hourly,
                keep_daily: retention.keep_daily,
                keep_weekly: retention.keep_weekly,
                keep_monthly: retention.keep_monthly,
                keep_yearly: retention.keep_yearly,
            };
            let r = engine::retention::forget(&repo, machine_ids, &p, *dry_run)?;
            let mut u = done(JobState::Succeeded);
            if !dry_run {
                u.removed_images = r.removed.clone();
            }
            u.result = Some(json!({ "kept": r.kept, "removed": r.removed, "dry_run": r.dry_run }));
            Ok(u)
        }
        JobKind::BackupKubernetes {
            cluster,
            sealed_token,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let c = k8s_client(ctx, cluster, sealed_token)?;
            let progress = |s: &str| rep.progress("kubernetes", 0, 1, s);
            let r = k8s::repo::backup(
                &repo,
                &c,
                &cluster.name,
                &cluster.namespaces,
                None,
                Some(cluster.volume_image.as_str()).filter(|v| !v.is_empty()),
                &ctx.ctl,
                &progress,
            )
            .map_err(|e| anyhow!("{e}"))?;
            let mut u = done(if r.warnings.is_empty() {
                JobState::Succeeded
            } else {
                JobState::Warning
            });
            u.warnings = r.warnings.clone();
            u.images = Some(vec![report_of(&repo.load_manifest(&r.image_id)?)]);
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::RestoreKubernetes {
            image_id,
            cluster,
            sealed_token,
            namespaces,
            rename_to,
            replace,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let c = k8s_client(ctx, cluster, sealed_token)?;
            let m = repo.load_manifest(image_id)?;
            let map: Vec<(String, String)> = match (namespaces.as_slice(), rename_to) {
                ([one], Some(to)) if !to.is_empty() => vec![(one.clone(), to.clone())],
                (_, Some(to)) if !to.is_empty() => {
                    return Err(anyhow!("renaming needs exactly one namespace"))
                }
                _ => vec![],
            };
            rep.progress("restoring", 0, 1, &cluster.name);
            let volume_image = Some(cluster.volume_image.as_str()).filter(|v| !v.is_empty());
            let r = k8s::repo::restore(&repo, &c, &m, namespaces, &map, *replace, volume_image)
                .map_err(|e| anyhow!("{e}"))?;
            let mut u = done(if r.failed.is_empty() {
                JobState::Succeeded
            } else {
                JobState::Warning
            });
            u.warnings = r.failed.clone();
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::BackupSaas {
            tenant,
            sealed_secret,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let (settings, conn) = saas_conn(ctx, tenant, sealed_secret)?;
            let progress = |s: &str| rep.progress("downloading", 0, 1, s);
            let scope = saas::run::Scope {
                users: tenant.users.clone(),
                objects: tenant.objects.clone(),
                mail: tenant.mail,
                files: tenant.files,
            };
            let r = saas::run::backup(&repo, &conn, &settings, &scope, None, &progress)
                .map_err(|e| anyhow!("{e}"))?;
            let mut u = done(if r.warnings.is_empty() {
                JobState::Succeeded
            } else {
                JobState::Warning
            });
            u.warnings = r.warnings.clone();
            u.images = Some(vec![report_of(&repo.load_manifest(&r.image_id)?)]);
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::RestoreSaas {
            image_id,
            tenant,
            sealed_secret,
            account,
            to_account,
            kind,
            path,
            overwrite,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let (_, conn) = saas_conn(ctx, tenant, sealed_secret)?;
            let m = repo.load_manifest(image_id)?;
            rep.progress("restoring", 0, 1, account);
            let sel = saas::run::Selection {
                account: account.clone(),
                to_account: to_account.clone(),
                kind: kind.clone().filter(|k| !k.is_empty()),
                path: path.clone().filter(|p| !p.is_empty()),
                overwrite: *overwrite,
            };
            let r = saas::run::restore(&repo, &conn, &m, &sel).map_err(|e| anyhow!("{e}"))?;
            let mut u = done(if r.failed.is_empty() {
                JobState::Succeeded
            } else if r.restored == 0 {
                JobState::Failed
            } else {
                JobState::Warning
            });
            if r.restored == 0 {
                u.error = Some(format!("nothing was restored ({} failed)", r.failed.len()));
            }
            u.warnings = r.failed.clone();
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::Prune { dry_run } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            rep.progress("pruning", 0, 1, "finding unreferenced data");
            let r = engine::retention::prune(&repo, *dry_run, &ctx.ctl)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(serde_json::to_value(&r)?);
            Ok(u)
        }
        JobKind::Restore {
            image_id,
            disks,
            target,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            crate::restore::run(ctx, &repo, *image_id, disks, target, rep)
        }
        JobKind::BootCheck {
            image_id,
            keep_running,
            memory_mb,
            cpus,
            directory,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let req = crate::boot::BootRequest {
                image_id: *image_id,
                keep_running: *keep_running,
                memory_mb: *memory_mb,
                cpus: *cpus,
                directory: directory.clone(),
            };
            crate::boot::run(ctx, &repo, &req, rep)
        }
        JobKind::StopVm { session_id } => crate::boot::stop_vm(*session_id),
        JobKind::ScanImage {
            image_id,
            indicators,
            rules,
            selection,
            max_file_mib,
        } => {
            let repo = open_repo(ctx, access.ok_or_else(|| anyhow!("no repository"))?)?;
            let req = crate::malware::ScanRequest {
                image_id: *image_id,
                indicators,
                rules,
                selection,
                max_file_mib: *max_file_mib,
            };
            crate::malware::run(ctx, &repo, &req, rep)
        }
        JobKind::BrowseFiles {
            image_id,
            volume,
            path,
        } => crate::browse::browse(
            ctx,
            access.ok_or_else(|| anyhow!("no repository"))?,
            *image_id,
            *volume,
            path,
        ),
        JobKind::DownloadFiles {
            image_id,
            volume,
            paths,
            recipient,
        } => crate::browse::download_files(
            ctx,
            access.ok_or_else(|| anyhow!("no repository"))?,
            *image_id,
            *volume,
            paths,
            recipient,
            spec.id,
            rep,
        ),
        JobKind::RestoreFiles {
            image_id,
            volume,
            paths,
            target,
            keep_structure,
            conflict,
        } => crate::browse::restore_files(
            ctx,
            access.ok_or_else(|| anyhow!("no repository"))?,
            *image_id,
            *volume,
            paths,
            target,
            *keep_structure,
            conflict,
            rep,
        ),
        JobKind::CheckAccess {
            path,
            sealed_share,
            s3: Some(s3),
        } => {
            let b = object_store(ctx.key, path, s3, sealed_share.as_ref())?;
            if !b.exists()? {
                // Signed in fine; nothing to write to yet. Creating the repository creates it.
                let what = if path.starts_with("azure://") {
                    "container"
                } else {
                    "bucket"
                };
                let mut u = done(JobState::Succeeded);
                u.result = Some(json!({ "s3": true, "repository": false, "note": format!(
                    "the keys work; the {what} does not exist yet and is created with the repository{}",
                    if s3.lock_mode.as_deref().is_some_and(|m| !m.is_empty() && m != "none") {
                        " (with immutability on)"
                    } else {
                        ""
                    }
                ) }));
                return Ok(u);
            }
            let note = b.check()?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(
                json!({ "s3": true, "note": note, "repository": b.backend().exists(core_format::repo::CONFIG_KEY)? }),
            );
            Ok(u)
        }
        JobKind::CheckAccess {
            path, sealed_share, ..
        } => check_access(ctx, path, sealed_share.as_ref()),
        JobKind::LocalRecovery {
            action,
            size_mb,
            auto_start,
            confirm,
        } => local_recovery(ctx, spec, *action, *size_mb, *auto_start, confirm, rep),
    }
}

/// Install, rebuild or remove the local recovery partition
/// (docs/design/local-recovery.md).
#[cfg(windows)]
fn local_recovery(
    ctx: &Ctx,
    spec: &JobSpec,
    action: protocol::LocalRecoveryAction,
    size_mb: u32,
    auto_start: bool,
    confirm: &str,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    use protocol::LocalRecoveryAction as A;
    let host = crate::inventory::hostname();
    if matches!(action, A::Install | A::Remove) && !confirm.trim().eq_ignore_ascii_case(&host) {
        bail!("type this machine's name ({host}) to confirm: installing or removing local recovery repartitions its system disk");
    }
    let mut u = done(JobState::Succeeded);
    let notes = if action == A::Remove {
        rep.progress("removing", 0, 1, "recovery partition");
        let n = crate::localrec::remove()?;
        u.result = Some(json!({ "removed": true }));
        n
    } else {
        let mut settings = spec
            .recovery_settings
            .clone()
            .ok_or_else(|| anyhow!("the server sent no recovery settings; update it"))?;
        // The recovery system reaches the server the way this machine does.
        if settings.server.is_empty() {
            settings.server = ctx.cfg.server.clone();
            settings.pin = ctx.cfg.pin.clone();
        }
        let settings = &settings;
        rep.progress(
            "building",
            0,
            1,
            "recovery image from this machine's Windows RE",
        );
        let (st, n) = crate::localrec::install(&crate::localrec::Options {
            volume: "C",
            size_mb,
            auto_start,
            settings,
            base_wim: None,
            machine: &host,
        })?;
        u.result = Some(serde_json::to_value(st.info())?);
        n
    };
    u.warnings = notes
        .into_iter()
        .filter(|n| n.contains("could not"))
        .collect();
    if !u.warnings.is_empty() {
        u.state = JobState::Warning;
    }
    Ok(u)
}

#[cfg(not(windows))]
fn local_recovery(
    _: &Ctx,
    _: &JobSpec,
    _: protocol::LocalRecoveryAction,
    _: u32,
    _: bool,
    _: &str,
    _: &Reporter,
) -> anyhow::Result<JobUpdate> {
    bail!("local recovery partitions are for Windows; on Linux use the recovery media")
}

fn finish_backup(
    repo: &Repository,
    reports: Vec<BackupReport>,
    mut warnings: Vec<String>,
    s: &BackupSettings,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let mut images = Vec::new();
    for r in &reports {
        warnings.extend(r.warnings.iter().cloned());
        images.push(report_of(&repo.load_manifest(&r.image_id)?));
    }
    if let Some(p) = s.verify_sample_percent.filter(|p| *p > 0.0) {
        rep.progress("verifying", 0, 1, "checking the new image");
        let ids: Vec<uuid::Uuid> = reports.iter().map(|r| r.image_id).collect();
        let v = engine::verify(
            repo,
            Some(&ids),
            VerifyLevel::Sample(p),
            &JobControl::new(),
            4,
        )?;
        if !v.ok {
            bail!(
                "the new image failed verification: {} missing, {} corrupt chunks",
                v.missing_chunks.len(),
                v.corrupt_chunks.len()
            );
        }
    }
    let mut u = done(if warnings.is_empty() {
        JobState::Succeeded
    } else {
        JobState::Warning
    });
    u.result = Some(json!({ "images": reports }));
    u.images = Some(images);
    u.warnings = warnings;
    Ok(u)
}

#[cfg(windows)]
fn backup_system(
    ctx: &Ctx,
    repo: &Repository,
    _repo_path: &str,
    s: &BackupSettings,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    rep.progress("snapshot", 0, 1, "creating VSS snapshot set");
    let sb = snapshot_win::prepare_system_backup(&snapshot_win::VssOptions {
        data_disks_only: false,
        full_backup_type: s.vss_full,
        extra_disks: vec![],
    })
    .map_err(|e| anyhow!("{e}"))?;
    let mut meta = sb.meta.clone();
    meta.label = s.label.clone();
    let cb = progress_cb(rep, String::new());
    let result = engine::backup(repo, &sb.sources(), meta, &options(s), &ctx.ctl, &cb);
    let finish = sb.finish(result.is_ok());
    let r = result?;
    let mut warnings = vec![];
    if let Err(e) = finish {
        warnings.push(format!(
            "image stored, but VSS BackupComplete reported: {e}"
        ));
    }
    finish_backup(repo, vec![r], warnings, s, rep)
}

#[cfg(target_os = "linux")]
fn backup_system(
    ctx: &Ctx,
    repo: &Repository,
    repo_path: &str,
    s: &BackupSettings,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    use snapshot_linux::live;
    rep.progress("snapshot", 0, 1, "taking LVM snapshots");
    let temp = if Path::new("/var/tmp").is_dir() {
        std::path::PathBuf::from("/var/tmp")
    } else {
        std::env::temp_dir()
    };
    let lb = live::prepare(&live::LiveOptions {
        disks: vec![],
        allow_inconsistent: false,
        state_dir: crate::config::state_dir(),
        temp_dir: temp,
        // A repository on a local disk: that disk is not imaged.
        exclude_paths: [std::path::PathBuf::from(repo_path)]
            .into_iter()
            .filter(|p| p.is_absolute() && p.is_dir())
            .collect(),
        hooks_dir: Some(std::path::PathBuf::from(snapshot_linux::apps::HOOKS_DIR)),
    })
    .map_err(|e| anyhow!("{e}"))?;
    let meta = ImageMeta {
        machine: MachineInfo {
            machine_id: ctx.cfg.machine_id.clone(),
            hostname: crate::inventory::hostname(),
        },
        consistency: lb.consistency,
        os: lb.os.clone(),
        boot: lb.boot.clone(),
        drivers: vec![],
        label: s.label.clone(),
        warnings: lb.warnings.clone(),
        vm: None,
        applications: lb.applications.clone(),
    };
    let cb = progress_cb(rep, String::new());
    let result = engine::backup(repo, &lb.sources(), meta, &options(s), &ctx.ctl, &cb);
    let finish = lb.finish();
    let r = result?;
    let mut warnings = vec![];
    if let Err(e) = finish {
        warnings.push(format!("image stored, but {e}"));
    }
    finish_backup(repo, vec![r], warnings, s, rep)
}

/// Remove LVM snapshots a crashed backup left behind (only ones we recorded).
#[cfg(target_os = "linux")]
pub fn cleanup_leftover_snapshots(dir: &Path) {
    for l in snapshot_linux::live::remove_leftover_snapshots(dir) {
        crate::log::info(&l);
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn backup_system(
    _ctx: &Ctx,
    _repo: &Repository,
    _repo_path: &str,
    _s: &BackupSettings,
    _rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    bail!("system backups of a running OS are available on Windows and Linux; on this platform back up disks")
}

/// Snapshot IDs created but not yet destroyed, so a crash mid-backup does
/// not leave a recovery checkpoint (and its growing .avhdx) behind.
fn pending_path(dir: &Path) -> std::path::PathBuf {
    dir.join("hyperv-pending.json")
}

fn pending_update(dir: &Path, f: impl FnOnce(&mut Vec<String>)) {
    let p = pending_path(dir);
    let mut v: Vec<String> = std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    f(&mut v);
    let _ = std::fs::write(&p, serde_json::to_vec(&v).unwrap_or_default());
}

/// Remove recovery checkpoints left by a previous crash. Only IDs this
/// agent recorded are touched, never other backup software's checkpoints.
pub fn cleanup_leftover_checkpoints(dir: &Path) {
    let mut ids = vec![];
    pending_update(dir, |v| ids = v.clone());
    for id in ids {
        match crate::hyperv::destroy_script(&id).and_then(|s| crate::hyperv::run_ps(&s)) {
            Ok(_) => {
                crate::log::info(&format!("removed leftover recovery checkpoint {id}"));
                pending_update(dir, |v| v.retain(|x| x != &id));
            }
            Err(e) => {
                crate::log::warn(&format!("could not remove leftover checkpoint {id}: {e:#}"))
            }
        }
    }
}

fn backup_hyperv(
    ctx: &Ctx,
    repo: &Repository,
    vm_ids: &[String],
    s: &BackupSettings,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let all = crate::hyperv::list_vms()?;
    let targets: Vec<protocol::VmSummary> = if vm_ids.is_empty() {
        all
    } else {
        all.into_iter().filter(|v| vm_ids.contains(&v.id)).collect()
    };
    if targets.is_empty() {
        bail!("none of the selected VMs exist on this host");
    }
    let host = crate::inventory::hostname();
    let mut reports = Vec::new();
    let mut warnings = Vec::new();
    let mut failures = Vec::new();
    let n = targets.len();
    for (i, vm) in targets.iter().enumerate() {
        if ctx.ctl.is_cancelled() {
            bail!("cancelled");
        }
        let prefix = format!("VM {}/{n} {}: ", i + 1, vm.name);
        rep.progress(
            "checkpoint",
            i as u64,
            n as u64,
            &format!("{prefix}creating recovery checkpoint"),
        );
        match backup_one_vm(ctx, repo, vm, &host, s, rep, &prefix) {
            Ok((r, w)) => {
                warnings.extend(w);
                reports.push(r);
            }
            Err(e) => failures.push(format!("VM '{}': {e:#}", vm.name)),
        }
    }
    if reports.is_empty() {
        bail!("{}", failures.join("; "));
    }
    warnings.extend(failures);
    finish_backup(repo, reports, warnings, s, rep)
}

fn backup_one_vm(
    ctx: &Ctx,
    repo: &Repository,
    vm: &protocol::VmSummary,
    host: &str,
    s: &BackupSettings,
    rep: &Reporter,
    prefix: &str,
) -> anyhow::Result<(BackupReport, Vec<String>)> {
    let out = crate::hyperv::run_ps(&crate::hyperv::checkpoint_script(&vm.id)?)?;
    let cp = crate::hyperv::parse_checkpoint(&out, host, &vm.id)?;
    pending_update(ctx.state_dir, |v| v.push(cp.snapshot_id.clone()));
    // Change tracking: what the last image of this VM in this repository
    // left behind (rct.rs).
    let key = crate::rct::key(repo.config().repo_id, &vm.id);
    let mut state = crate::rct::load(ctx.state_dir);
    let prev = state.vms.get(&key).cloned();
    let now = core_format::timefmt::now_unix();

    let result = (|| -> anyhow::Result<BackupReport> {
        if cp.disks.is_empty() {
            bail!("the VM has no virtual hard disks to back up");
        }
        let mut sources = Vec::new();
        for d in &cp.disks {
            if d.path.to_ascii_lowercase().ends_with(".vhd") {
                bail!("{} is a VHD (first-generation) disk; convert it to VHDX with Convert-VHD to back it up", d.path);
            }
            sources.push(
                vdisk::VhdxSource::open(&d.path, format!("{} ({})", d.path, d.controller))
                    .with_context(|| format!("opening {}", d.path))?,
            );
        }
        let refs: Vec<&dyn engine::DiskSource> = sources
            .iter()
            .map(|x| x as &dyn engine::DiskSource)
            .collect();
        let meta = ImageMeta {
            machine: MachineInfo {
                machine_id: format!("hyperv-vm:{}", vm.id),
                hostname: vm.name.clone(),
            },
            consistency: cp.consistency,
            os: Default::default(),
            boot: Default::default(),
            drivers: vec![],
            label: s.label.clone(),
            warnings: cp.warning.iter().cloned().collect(),
            vm: Some(cp.vm.clone()),
            applications: vec![],
        };
        let cb = progress_cb(rep, prefix.to_string());
        let mut opts = options(s);
        if !s.full_read {
            rep.progress("changes", 0, 1, &format!("{prefix}finding what changed"));
            opts.changed = tracked_changes(prev.as_ref(), &cp, now, prefix);
        }
        match engine::backup(repo, &refs, meta.clone(), &opts, &ctx.ctl, &cb) {
            Err(engine::EngineError::ChangeTrackingMissed(why)) => {
                // Never trust the tracker for this image: read everything.
                let msg = format!(
                    "VM '{}': change tracking missed a write ({why}); the disks were read in full",
                    vm.name
                );
                crate::log::warn(&msg);
                opts.changed = None;
                let mut r = engine::backup(repo, &refs, meta, &opts, &ctx.ctl, &cb)?;
                r.full_read_reason = Some(msg.clone());
                r.warnings.push(msg);
                Ok(r)
            }
            r => Ok(r?),
        }
    })();

    let mut warnings = vec![];
    // After a good image, keep a reference point for the next backup to
    // read only what changed since this one; otherwise merge the checkpoint
    // back as before.
    let mut kept = false;
    if let (Ok(r), false) = (&result, s.full_read) {
        match crate::rct::to_reference_script(&cp.snapshot_id)
            .and_then(|sc| crate::hyperv::run_ps(&sc))
            .and_then(|o| crate::rct::parse_reference(&o, &cp.disks))
        {
            Ok((rp_id, disks)) => {
                kept = true;
                pending_update(ctx.state_dir, |v| v.retain(|x| x != &cp.snapshot_id));
                if disks.len() < cp.disks.len() {
                    crate::log::info(&format!(
                        "{prefix}{} of {} disks have change tracking; the others are read in full each time",
                        disks.len(),
                        cp.disks.len()
                    ));
                }
                let full_read_unix = match (&prev, r.read_mode) {
                    (Some(p), "changed_blocks") => p.full_read_unix,
                    _ => now,
                };
                state.vms.insert(
                    key.clone(),
                    crate::rct::Entry {
                        image_id: r.image_id,
                        reference_point_id: rp_id.clone(),
                        disks,
                        full_read_unix,
                    },
                );
                if let Err(e) = crate::rct::save(ctx.state_dir, &state) {
                    crate::log::warn(&format!("{prefix}could not save change tracking state: {e:#}"));
                }
                if let Some(p) = prev.as_ref().filter(|p| p.reference_point_id != rp_id) {
                    remove_reference_point(&p.reference_point_id, prefix);
                }
            }
            Err(e) => crate::log::info(&format!(
                "{prefix}change tracking is not available ({e:#}); backups of this VM read its disks in full"
            )),
        }
    }
    if !kept {
        match crate::hyperv::destroy_script(&cp.snapshot_id)
            .and_then(|sc| crate::hyperv::run_ps(&sc))
        {
            Ok(_) => pending_update(ctx.state_dir, |v| v.retain(|x| x != &cp.snapshot_id)),
            Err(e) => warnings.push(format!(
                "VM '{}': the recovery checkpoint could not be removed ({e:#}); the agent will retry, or remove it in Hyper-V Manager",
                vm.name
            )),
        }
        // A good image without a reference point: the old one is no use.
        if result.is_ok() {
            if let Some(p) = state.vms.remove(&key) {
                remove_reference_point(&p.reference_point_id, prefix);
                let _ = crate::rct::save(ctx.state_dir, &state);
            }
        }
    }
    result.map(|r| (r, warnings))
}

/// The changed ranges of each disk since the last image, or `None` to read
/// everything (with the reason in the agent log).
fn tracked_changes(
    prev: Option<&crate::rct::Entry>,
    cp: &crate::hyperv::Checkpoint,
    now: i64,
    prefix: &str,
) -> Option<engine::ChangedSince> {
    let plan = match crate::rct::plan(prev, &cp.disks, now) {
        Ok(p) => p,
        Err(why) => {
            crate::log::info(&format!("{prefix}reading the disks in full: {why}"));
            return None;
        }
    };
    let queries: Vec<&crate::rct::Query> = plan.queries.iter().flatten().collect();
    let answers = match crate::rct::changes_script(&queries)
        .and_then(|sc| crate::hyperv::run_ps(&sc))
        .and_then(|o| crate::rct::parse_changes(&o, &queries))
    {
        Ok(a) => a,
        Err(e) => {
            crate::log::warn(&format!(
                "{prefix}could not read the changed blocks ({e:#}); reading the disks in full"
            ));
            return None;
        }
    };
    let mut answers = answers.into_iter();
    let disks = plan
        .queries
        .iter()
        .map(|q| {
            let q = q.as_ref()?;
            match answers.next()? {
                Ok(ranges) => Some(ranges),
                Err(e) => {
                    crate::log::info(&format!("{prefix}{}: {e}; reading it in full", q.path));
                    None
                }
            }
        })
        .collect();
    Some(engine::ChangedSince {
        base_image: plan.base_image,
        disks,
        spot_check_one_in: crate::rct::SPOT_CHECK_ONE_IN,
    })
}

fn remove_reference_point(id: &str, prefix: &str) {
    if let Err(e) =
        crate::rct::destroy_reference_script(id).and_then(|sc| crate::hyperv::run_ps(&sc))
    {
        crate::log::warn(&format!(
            "{prefix}could not remove the previous reference point {id}: {e:#}"
        ));
    }
}

/// Sign in (if a share), then check the folder: exists, is a repository,
/// writable; report free space. Writes and deletes one small test file.
fn check_access(
    ctx: &Ctx,
    path: &str,
    sealed: Option<&protocol::seal::Sealed>,
) -> anyhow::Result<JobUpdate> {
    let local = crate::share::prepare(ctx.key, path, sealed)?;
    let p = Path::new(&local);
    let exists = p.is_dir();
    let repository = exists && p.join(core_format::repo::CONFIG_KEY).is_file();
    // The folder itself, or the nearest parent that exists (a new repository
    // folder is created when the repository is).
    let mut probe_dir = p.to_path_buf();
    while !probe_dir.is_dir() {
        match probe_dir.parent() {
            Some(q) if q != probe_dir => probe_dir = q.to_path_buf(),
            _ => bail!("{path}: no part of this path exists"),
        }
    }
    let test = probe_dir.join(format!(
        ".fenrir-write-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let writable = std::fs::write(&test, b"fenrir").is_ok();
    let _ = std::fs::remove_file(&test);
    let space = crate::share::space(&probe_dir.display().to_string());
    let mut u = done(if writable {
        JobState::Succeeded
    } else {
        JobState::Failed
    });
    if !writable {
        u.error = Some(format!(
            "{} is readable but this machine cannot write to it (check the share and folder permissions)",
            probe_dir.display()
        ));
    } else if exists
        && !repository
        && std::fs::read_dir(p)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    {
        u.state = JobState::Warning;
        u.warnings.push(format!(
            "{path} exists and is not empty; a new repository needs a new or empty folder"
        ));
    }
    u.result = Some(json!({
        "path": path,
        "exists": exists,
        "repository": repository,
        "writable": writable,
        "free_bytes": space.map(|s| s.0),
        "total_bytes": space.map(|s| s.1),
        "share": crate::share::parse_unc(path).is_some(),
    }));
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_list_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        pending_update(d.path(), |v| v.push("Microsoft:A".into()));
        pending_update(d.path(), |v| v.push("Microsoft:B".into()));
        pending_update(d.path(), |v| v.retain(|x| x != "Microsoft:A"));
        let mut got = vec![];
        pending_update(d.path(), |v| got = v.clone());
        assert_eq!(got, vec!["Microsoft:B"]);
    }
}

#[cfg(test)]
mod dedup_paths {
    #[test]
    fn protocol_and_format_agree_on_member_paths() {
        let id = uuid::Uuid::new_v4();
        for root in ["/nas/b", r"\\nas\b", "s3://bucket/x", "azure://c/p"] {
            let a = protocol::dedup::member_path(root, &id);
            assert_eq!(a, core_format::group::member_path(root, &id));
            assert_eq!(
                protocol::dedup::split_member_path(&a),
                core_format::group::split_member_path(&a)
            );
        }
    }
}
