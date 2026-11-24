//! Kubernetes backups in a repository (docs/design/kubernetes.md): the
//! archive of resources as disk 0 of an image, each volume's tar as a further
//! disk. Shared by the command line and the agent.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use core_format::manifest::{ChunkRef, Consistency, MachineInfo, OsInfo};
use core_format::{ManifestBody, Repository};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::archive::Archive;
use crate::volumes::VolumeRecord;
use crate::{err, Client, Error, RestoreReport, Result};

fn e(x: impl std::fmt::Display) -> Error {
    err(x.to_string())
}

/// A scratch folder that is removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch> {
        let d = std::env::temp_dir().join(format!("fenrir-k8s-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).map_err(e)?;
        Ok(Scratch(d))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupSummary {
    pub image_id: Uuid,
    pub objects: usize,
    pub kinds: serde_json::Value,
    pub volumes: Vec<VolumeRecord>,
    pub warnings: Vec<String>,
}

/// Back up `namespaces` of the cluster (machine `k8s:<cluster>`), with the
/// volumes' data when `volume_image` (the image of fenrir-backup that runs
/// the reader pods) is given.
#[allow(clippy::too_many_arguments)]
pub fn backup(
    repo: &Repository,
    c: &Client,
    cluster: &str,
    namespaces: &[String],
    label: Option<String>,
    volume_image: Option<&str>,
    ctl: &engine::JobControl,
    progress: &dyn Fn(&str),
) -> Result<BackupSummary> {
    let mut a = crate::export(c, namespaces, progress)?;
    let dir = Scratch::new()?;
    let mut files: Vec<PathBuf> = vec![dir.0.join("kubernetes.img")];
    if let Some(image) = volume_image {
        for ns in namespaces {
            for claim in c.claims(ns)? {
                progress(&format!(
                    "{ns}: volume {} ({})",
                    claim.name,
                    if claim.snapshot_class.is_some() {
                        "snapshot"
                    } else {
                        "live"
                    }
                ));
                let path = dir.0.join(format!("volume-{}.tar", files.len()));
                let mut f = File::create(&path).map_err(e)?;
                match c.backup_claim(ns, &claim, image, &mut f) {
                    Ok((method, bytes)) => {
                        // A whole number of 4 KiB blocks (a tar ends with zero blocks anyway).
                        f.set_len(bytes.div_ceil(4096).max(1) * 4096).map_err(e)?;
                        if method == "live" {
                            a.warnings.push(format!(
                                "{ns}/{}: its driver cannot snapshot it, so it was read while in use",
                                claim.name
                            ));
                        }
                        a.volumes.push(VolumeRecord {
                            namespace: ns.clone(),
                            claim: claim.name.clone(),
                            disk: files.len() as u32,
                            method,
                            bytes,
                        });
                        files.push(path);
                    }
                    Err(x) => a.warnings.push(format!(
                        "{ns}/{}: its data was not backed up: {x}",
                        claim.name
                    )),
                }
            }
        }
    }
    std::fs::write(&files[0], a.to_disk().map_err(err)?).map_err(e)?;
    let opened = files
        .iter()
        .map(|f| snapshot_linux::open_disk(f, false).map_err(e))
        .collect::<Result<Vec<_>>>()?;
    let sources: Vec<&dyn engine::DiskSource> = opened
        .iter()
        .map(|o| &o.source as &dyn engine::DiskSource)
        .collect();
    let meta = engine::ImageMeta {
        machine: MachineInfo {
            machine_id: format!("k8s:{cluster}"),
            hostname: cluster.to_string(),
        },
        consistency: if a.volumes.iter().any(|v| v.method == "live") {
            Consistency::Inconsistent
        } else {
            Consistency::Crash
        },
        os: OsInfo {
            family: "kubernetes".into(),
            name: namespaces.join(", "),
            ..Default::default()
        },
        boot: Default::default(),
        drivers: vec![],
        label: label.or_else(|| Some(format!("namespaces: {}", namespaces.join(", ")))),
        warnings: a.warnings.clone(),
        vm: None,
        applications: vec![],
    };
    let r = engine::backup(
        repo,
        &sources,
        meta,
        &engine::BackupOptions {
            workers: 2,
            ..Default::default()
        },
        ctl,
        &|_| {},
    )
    .map_err(e)?;
    Ok(BackupSummary {
        image_id: r.image_id,
        objects: a.objects.len(),
        kinds: json!(a.summary()),
        volumes: a.volumes,
        warnings: a.warnings,
    })
}

/// A Kubernetes backup's archive.
pub fn archive(repo: &Repository, m: &ManifestBody) -> Result<Archive> {
    let d = m
        .disks
        .first()
        .filter(|_| m.os.family == "kubernetes")
        .ok_or_else(|| err(format!("{} is not a Kubernetes backup", m.image_id)))?;
    let cs = m.chunk_size as u64;
    let mut buf = vec![0u8; d.size as usize];
    for ChunkRef(i, cid) in &d.chunks {
        let data = repo.get_chunk(cid).map_err(e)?;
        let at = (*i * cs) as usize;
        let end = (at + data.len()).min(buf.len());
        buf[at..end].copy_from_slice(&data[..end - at]);
    }
    Archive::from_disk(&buf).map_err(err)
}

/// Disk `disk` of an image written to `file` (its first `len` bytes).
pub fn disk_to(
    repo: &Repository,
    m: &ManifestBody,
    disk: u32,
    file: &Path,
    len: u64,
) -> Result<()> {
    let d = m
        .disks
        .get(disk as usize)
        .ok_or_else(|| err(format!("the backup has no disk {disk}")))?;
    let mut f = File::create(file).map_err(e)?;
    f.set_len(len).map_err(e)?;
    let cs = m.chunk_size as u64;
    for ChunkRef(i, cid) in &d.chunks {
        let at = *i * cs;
        if at >= len {
            break;
        }
        let data = repo.get_chunk(cid).map_err(e)?;
        let n = (len - at).min(data.len() as u64) as usize;
        f.seek(SeekFrom::Start(at)).map_err(e)?;
        f.write_all(&data[..n]).map_err(e)?;
    }
    Ok(())
}

/// Restore a backup into the cluster: the namespaces `only` (all if empty),
/// renamed by `map`, and the volumes' data when `volume_image` is given.
pub fn restore(
    repo: &Repository,
    c: &Client,
    m: &ManifestBody,
    only: &[String],
    map: &[(String, String)],
    replace: bool,
    volume_image: Option<&str>,
) -> Result<RestoreReport> {
    let a = archive(repo, m)?;
    let target = |ns: &str| {
        map.iter()
            .find(|(o, _)| o == ns)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| ns.to_string())
    };
    let dir = Scratch::new()?;
    let mut put_back = |rep: &mut RestoreReport| -> Result<()> {
        let Some(img) = volume_image else {
            return Ok(());
        };
        for v in a
            .volumes
            .iter()
            .filter(|v| only.is_empty() || only.contains(&v.namespace))
        {
            let file = dir.0.join(format!("volume-{}.tar", v.disk));
            let r = disk_to(repo, m, v.disk, &file, v.bytes)
                .and_then(|_| File::open(&file).map_err(e))
                .and_then(|f| c.restore_claim(&target(&v.namespace), &v.claim, img, v.bytes, f));
            match r {
                Ok(j) => rep.volumes.push(
                    json!({ "namespace": target(&v.namespace), "claim": v.claim, "result": j }),
                ),
                Err(x) => rep
                    .failed
                    .push(format!("volume {}/{}: {x}", v.namespace, v.claim)),
            }
            let _ = std::fs::remove_file(&file);
        }
        Ok(())
    };
    let mut rep = crate::restore_with(c, &a, only, map, replace, &mut put_back)?;
    if volume_image.is_none() && !a.volumes.is_empty() {
        rep.failed.push(format!(
            "{} volumes' data were not restored (no volume server image given)",
            a.volumes.len()
        ));
    }
    Ok(rep)
}
