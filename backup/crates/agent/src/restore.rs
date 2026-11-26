//! Restore jobs: to VHDX files, to a new Hyper-V VM, to disk files and a VM
//! definition for QEMU, VirtualBox or VMware, or to a disk.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use core_format::{ManifestBody, Repository};
use engine::{DestructiveConfirmation, FileTarget, RestoreOptions};
use protocol::{JobState, JobUpdate, RestoreTarget};
use serde_json::json;

use crate::jobs::{Ctx, Reporter};

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

/// File-name-safe version of a label.
pub fn safe_name(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let t = t.trim_matches('-').to_string();
    if t.is_empty() {
        "image".into()
    } else {
        t.chars().take(60).collect()
    }
}

/// `<machine>-<taken>-disk<n>.<ext>` for each selected disk.
pub fn disk_names(m: &ManifestBody, disks: &[u32], ext: &str) -> Vec<(u32, String)> {
    let base = safe_name(
        m.vm.as_ref()
            .map(|v| v.name.as_str())
            .unwrap_or(&m.machine.hostname),
    );
    let stamp = m
        .created
        .replace([':', '-'], "")
        .trim_end_matches('Z')
        .replace('T', "-");
    m.disks
        .iter()
        .filter(|d| disks.is_empty() || disks.contains(&d.index))
        .map(|d| (d.index, format!("{base}-{stamp}-disk{}.{ext}", d.index)))
        .collect()
}

/// Write the selected disks as VHDX files into `dir`. Returns their paths.
pub fn write_vhdx(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    dir: &Path,
    rep: &Reporter,
) -> anyhow::Result<Vec<(u32, PathBuf)>> {
    write_disk_files(ctx, repo, m, disks, dir, vdisk::Format::Vhdx, rep)
}

/// Write the selected disks as virtual disk files of `format` into `dir`.
/// Returns their paths. A file that fails part-way is removed.
pub fn write_disk_files(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    dir: &Path,
    format: vdisk::Format,
    rep: &Reporter,
) -> anyhow::Result<Vec<(u32, PathBuf)>> {
    Ok(
        write_disk_files_reported(ctx, repo, m, disks, dir, format, rep)?
            .into_iter()
            .map(|(i, p, _)| (i, p))
            .collect(),
    )
}

/// `write_disk_files`, with each disk's restore report.
pub fn write_disk_files_reported(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    dir: &Path,
    format: vdisk::Format,
    rep: &Reporter,
) -> anyhow::Result<Vec<(u32, PathBuf, engine::RestoreReport)>> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let names = disk_names(m, disks, format.extension());
    if names.is_empty() {
        bail!("the image has none of the selected disks");
    }
    let total: u64 = m
        .disks
        .iter()
        .filter(|d| names.iter().any(|(i, _)| *i == d.index))
        .map(|d| d.size)
        .sum();
    let mut base = 0u64;
    let mut out = vec![];
    for (index, name) in names {
        let d = m.disks.iter().find(|d| d.index == index).expect("selected");
        let path = dir.join(&name);
        let t = format
            .create(
                &path,
                d.size,
                d.logical_sector_size,
                d.physical_sector_size,
                m.chunk_size,
            )
            .with_context(|| format!("creating {} (it must not exist already)", path.display()))?;
        let label = format!("disk {index} → {name}");
        let cb = |done: u64, _t: u64| rep.progress("restoring", base + done, total, &label);
        let r = engine::restore_disk(
            repo,
            m,
            index,
            &*t,
            &RestoreOptions {
                workers: 4,
                zero_fill: false,
                fit: false,
                grow: false,
                verify: true,
            },
            &ctx.ctl,
            &cb,
        );
        let report = match r {
            Ok(report) => {
                t.finish()?;
                report
            }
            Err(e) => {
                drop(t);
                let _ = std::fs::remove_file(&path);
                return Err(e.into());
            }
        };
        base += d.size;
        out.push((index, path, report));
    }
    Ok(out)
}

/// Disk files and a VM definition for QEMU, VirtualBox or VMware, in
/// `directory/<name>` (which must be new or empty).
fn restore_vm_files(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    (format, name, directory): (&str, &str, &str),
    folder: &str,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    use crate::vmdef::Hypervisor;
    let (fmt, hv, product) = match format {
        "qcow2" => (vdisk::Format::Qcow2, Hypervisor::Qemu, "QEMU/KVM"),
        "vdi" => (vdisk::Format::Vdi, Hypervisor::VirtualBox, "VirtualBox"),
        "vmdk" => (vdisk::Format::Vmdk, Hypervisor::Vmware, "VMware"),
        other => bail!("unknown virtual disk format {other:?}"),
    };
    crate::vmdef::check_name(name)?;
    let dir = Path::new(directory).join(folder);
    if dir.exists()
        && std::fs::read_dir(&dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        bail!("{} already exists and is not empty", dir.display());
    }
    let files = write_disk_files(ctx, repo, m, disks, &dir, fmt, rep)?;
    rep.progress("writing the VM definition", 1, 1, name);
    let names: Vec<String> = files
        .iter()
        .filter_map(|(_, p)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    let settings = crate::vmdef::settings(m, name, names);
    let (def_name, def) = crate::vmdef::definition(hv, &settings, cfg!(windows));
    let def_path = dir.join(&def_name);
    std::fs::write(&def_path, def).with_context(|| format!("writing {}", def_path.display()))?;
    #[cfg(unix)]
    if def_name.ends_with(".sh") {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&def_path, std::fs::Permissions::from_mode(0o755));
    }
    let mut u = done(JobState::Succeeded);
    u.result = Some(json!({
        "hypervisor": product,
        "path": dir.display().to_string(),
        "files": files.iter().map(|(_, p)| p.display().to_string()).collect::<Vec<_>>(),
        "definition": def_path.display().to_string(),
        "firmware": if settings.uefi { "uefi" } else { "bios" },
    }));
    rep.progress("hashing the restored files", 0, 0, "");
    let mut paths: Vec<&Path> = files.iter().map(|(_, p)| p.as_path()).collect();
    paths.push(def_path.as_path());
    crate::evidence::attach(
        &mut u,
        crate::evidence::outputs(&paths),
        file_level_check(),
        json!([]),
    );
    if m.os.family.eq_ignore_ascii_case("windows") && m.vm.is_none() {
        u.state = JobState::Warning;
        u.warnings.push(format!(
            "This Windows system was backed up from a physical machine. If it stops at INACCESSIBLE_BOOT_DEVICE in {product}, change the VM's disk controller (SATA is set; try IDE or SCSI), or restore it with the recovery media, which prepares Windows for different hardware."
        ));
    }
    if fmt == vdisk::Format::Vmdk {
        u.warnings.push("The VMDK files are for VMware Workstation, Fusion and Player. For ESXi, copy the folder to a datastore and convert each disk there: vmkfstools -i <disk>.vmdk -d thin <new>.vmdk".into());
        if u.state == JobState::Succeeded {
            u.state = JobState::Warning;
        }
    }
    Ok(u)
}

pub fn run(
    ctx: &Ctx,
    repo: &Repository,
    image_id: uuid::Uuid,
    disks: &[u32],
    target: &RestoreTarget,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m = repo.load_manifest(&image_id)?;
    let only: Vec<u32> = match target {
        RestoreTarget::Disk { disk, .. } => vec![*disk],
        _ => disks.to_vec(),
    };
    let mut u = run_target(ctx, repo, &m, disks, target, rep)?;
    let notes = bitlocker_notes(&m, &only);
    if !notes.is_empty() && u.state == JobState::Succeeded {
        u.state = JobState::Warning;
    }
    u.warnings.extend(notes);
    Ok(u)
}

/// What BitLocker means for this restore (design: phase-2 §4.2). Volumes
/// backed up through a snapshot were captured decrypted: they restore
/// unencrypted and start without the recovery key, so BitLocker has to be
/// turned on again. Volumes captured raw (no snapshot, a Hyper-V guest's own
/// BitLocker) are still encrypted, and Windows asks for the recovery key when
/// the TPM differs.
pub fn bitlocker_notes(m: &ManifestBody, disks: &[u32]) -> Vec<String> {
    use core_format::manifest::CaptureMethod;
    let (mut plain, mut sealed) = (Vec::new(), Vec::new());
    for d in m
        .disks
        .iter()
        .filter(|d| disks.is_empty() || disks.contains(&d.index))
    {
        for p in &d.partitions {
            let bitlocker = p.encryption.as_deref() == Some("bitlocker")
                || p.filesystem == core_format::fsdetect::FsType::Bitlocker;
            if !bitlocker {
                continue;
            }
            let name = p
                .mount_points
                .first()
                .cloned()
                .unwrap_or_else(|| format!("disk {} partition {}", d.index, p.entry.number));
            match p.capture {
                CaptureMethod::SnapshotBitmap | CaptureMethod::SnapshotFull
                    if p.filesystem != core_format::fsdetect::FsType::Bitlocker =>
                {
                    plain.push(name)
                }
                _ => sealed.push(name),
            }
        }
    }
    let mut out = Vec::new();
    if !plain.is_empty() {
        out.push(format!(
            "BitLocker was on for {} when it was backed up. The restored copy is not encrypted, so it starts without the recovery key: turn BitLocker on again (Control Panel > BitLocker, or manage-bde -on).",
            plain.join(", ")
        ));
    }
    if !sealed.is_empty() {
        out.push(format!(
            "{} was captured still BitLocker-encrypted. On different hardware (or a different TPM) Windows asks for its 48-digit BitLocker recovery key on first start: have it ready (Microsoft account, Active Directory or Entra ID, or where it was saved).",
            sealed.join(", ")
        ));
    }
    out
}

fn run_target(
    ctx: &Ctx,
    repo: &Repository,
    m: &ManifestBody,
    disks: &[u32],
    target: &RestoreTarget,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m = m.clone();
    match target {
        RestoreTarget::Vhdx { directory } => {
            let files = write_vhdx(ctx, repo, &m, disks, Path::new(directory), rep)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(
                json!({ "files": files.iter().map(|(_, p)| p.display().to_string()).collect::<Vec<_>>() }),
            );
            rep.progress("hashing the restored files", 0, 0, "");
            let paths: Vec<&Path> = files.iter().map(|(_, p)| p.as_path()).collect();
            crate::evidence::attach(
                &mut u,
                crate::evidence::outputs(&paths),
                file_level_check(),
                json!([]),
            );
            Ok(u)
        }
        RestoreTarget::HypervVm {
            name,
            directory,
            switch,
            start,
            replace,
        } => {
            if !cfg!(windows) {
                bail!("restoring as a Hyper-V VM runs on a Hyper-V host");
            }
            crate::hyperv::check_vm_name(name)?;
            let vm = m.vm.clone().unwrap_or_default();
            // A standby gets a new folder each time; the old one goes once
            // the new VM exists.
            let dir = if *replace {
                Path::new(directory).join(format!("{}-{}", safe_name(name), stamp(&m)))
            } else {
                Path::new(directory).join(safe_name(name))
            };
            if dir.exists()
                && std::fs::read_dir(&dir)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(true)
            {
                bail!("{} already exists and is not empty", dir.display());
            }
            let exists = crate::hyperv::vm_exists(name)?;
            if exists && !*replace {
                bail!("a VM named '{name}' already exists on this host; choose another name");
            }
            if exists && crate::hyperv::vm_in_use(name)? {
                bail!("the standby VM '{name}' is running (in use after a failover?): it was left as it is. Turn it off, or turn the standby off in the plan");
            }
            let files = write_vhdx(ctx, repo, &m, disks, &dir, rep)?;
            rep.progress("creating VM", 1, 1, name);
            if exists {
                crate::hyperv::remove_vm(name)?;
            }
            let spec = vm_spec(&m, name, &dir, &files, switch.clone(), *start);
            let out = crate::hyperv::run_ps(&crate::hyperv::new_vm_script(&spec)?)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(
                json!({ "vm": name, "path": dir.display().to_string(), "output": out.trim(), "standby": replace }),
            );
            let paths: Vec<&Path> = files.iter().map(|(_, p)| p.as_path()).collect();
            crate::evidence::attach(
                &mut u,
                crate::evidence::outputs(&paths),
                file_level_check(),
                json!([]),
            );
            if *replace {
                standby_swap(ctx, &format!("hyperv:{name}"), &dir, &mut u.warnings);
            }
            if vm.vm_id.is_empty() {
                u.state = JobState::Warning;
                u.warnings.push("The image has no Hyper-V settings (it was not taken from a Hyper-V host); the VM was created with defaults. Check generation, memory and network before starting it.".into());
            }
            Ok(u)
        }
        RestoreTarget::VmFiles {
            format,
            name,
            directory,
            replace,
        } => {
            let folder = if *replace {
                format!("{name}-{}", stamp(&m))
            } else {
                name.clone()
            };
            let mut u = restore_vm_files(
                ctx,
                repo,
                &m,
                disks,
                (format, name, directory),
                &folder,
                rep,
            )?;
            if *replace {
                let dir = Path::new(directory).join(&folder);
                standby_swap(
                    ctx,
                    &format!("files:{format}:{name}"),
                    &dir,
                    &mut u.warnings,
                );
            }
            Ok(u)
        }
        RestoreTarget::Azure {
            location,
            endpoint,
            name,
            sealed,
        } => crate::cloudrestore::azure(
            ctx,
            repo,
            &m,
            disks,
            (location, endpoint, name),
            sealed,
            rep,
        ),
        RestoreTarget::Aws {
            location,
            endpoint,
            region,
            name,
            staging,
            sealed,
        } => crate::cloudrestore::aws(
            ctx,
            repo,
            &m,
            disks,
            (location, endpoint, region, name, staging),
            sealed,
            rep,
        ),
        RestoreTarget::Disk {
            device,
            disk,
            confirm,
            grow,
        } => {
            if confirm != device {
                bail!("the typed confirmation does not match the target device");
            }
            let d = m
                .disks
                .iter()
                .find(|x| x.index == *disk)
                .ok_or_else(|| anyhow!("the image has no disk {disk}"))?;
            let c = DestructiveConfirmation::confirmed_by_user(device);
            // Bare-metal restore: the new disk may be bigger or smaller.
            let (t, takeover) = open_target(device, engine::fit::min_size(d), &c)?;
            let total = d.size;
            let cb = |done: u64, _t: u64| rep.progress("restoring", done, total, device);
            let r = engine::restore_disk(
                repo,
                &m,
                *disk,
                &t,
                &RestoreOptions {
                    workers: 4,
                    zero_fill: true,
                    fit: true,
                    grow: *grow,
                    verify: true,
                },
                &ctx.ctl,
                &cb,
            )?;
            drop(t);
            let mut u = done(JobState::Succeeded);
            let mut result = serde_json::to_value(&r)?;
            let need = image_firmware(&m, d);
            let uefi = need == Some("uefi");
            if d.partition_table
                .partitions
                .iter()
                .any(|p| p.role == core_format::partition::PartitionRole::Esp)
            {
                rep.progress("making it bootable", 1, 1, device);
                match engine::bootfix::fix_restored_disk(Path::new(device), d) {
                    Ok(Some(fix)) => {
                        if ctx.cfg.role == "recovery" {
                            if let Some(note) = crate::recovery::firmware_entry(device, d, &fix) {
                                u.warnings.push(note);
                            }
                        }
                        result["boot"] = serde_json::to_value(&fix)?;
                    }
                    Ok(None) => {}
                    Err(e) => u
                        .warnings
                        .push(format!("could not add the fallback boot loader: {e}")),
                }
            }
            // Windows: release the disk and let Windows read the restored
            // partition table.
            if let Some(finish) = takeover {
                if let Err(e) = finish() {
                    u.warnings.push(format!(
                        "Windows did not re-read the restored disk ({e}); restart before using it."
                    ));
                }
            }
            // The file system of the grown partition (phase-5-grow-clone).
            if let Some(g) = &r.grown {
                rep.progress("growing the file system", 1, 1, device);
                let gr = engine::grow::grow_filesystem(Path::new(device), g);
                if !gr.filesystem_grown {
                    u.warnings.extend(gr.notes.iter().skip(1).cloned());
                }
                result["grow"] = serde_json::to_value(&gr)?;
            }
            u.warnings.extend(r.notes.iter().cloned());
            // Windows on different hardware: its storage drivers (design:
            // phase-5-hardware).
            if ctx.cfg.role == "recovery" {
                rep.progress(
                    "preparing the restored system for this hardware",
                    1,
                    1,
                    device,
                );
                match crate::hwfix::adapt_restored_disk(device) {
                    Ok(Some(fix)) => {
                        result["windows"] = serde_json::to_value(&fix)?;
                    }
                    // Not Windows: a Linux system gets an initramfs with all storage drivers.
                    Ok(None) => match crate::linuxfix::adapt_restored_linux(device) {
                        Ok(Some(fix)) => {
                            u.warnings.extend(fix.notes.iter().filter(|n| !n.starts_with("Network")).cloned());
                            result["linux"] = serde_json::to_value(&fix)?;
                        }
                        Ok(None) => {}
                        Err(e) => u.warnings.push(format!(
                            "The restored Linux could not be prepared for this machine's storage controller ({e:#}); if it does not find its root file system, rebuild its initramfs without host-only (dracut --no-hostonly)."
                        )),
                    },
                    Err(e) => u.warnings.push(format!(
                        "The restored Windows could not be prepared for this machine's storage controller ({e:#}); if it stops with INACCESSIBLE_BOOT_DEVICE, restore again from Windows PE recovery media."
                    )),
                }
            }
            if ctx.cfg.role == "recovery" {
                if let (Some(need), (Some(fw), _)) = (need, crate::inventory::firmware()) {
                    if fw != need {
                        u.warnings.push(format!(
                            "This machine started in {} mode but the backed-up system boots with {}. Change the boot mode in the firmware settings ({}) before starting it.",
                            fw.to_uppercase(),
                            need.to_uppercase(),
                            if uefi { "turn off CSM / legacy boot" } else { "turn on CSM / legacy boot" }
                        ));
                    }
                }
            }
            if !u.warnings.is_empty() {
                u.state = JobState::Warning;
            }
            u.result = Some(result);
            crate::evidence::attach(
                &mut u,
                json!([{ "target": device, "bytes": r.bytes_written }]),
                crate::evidence::disk_verification(&[&r]),
                json!([]),
            );
            Ok(u)
        }
    }
}

/// Virtual disk containers are written once and not read back chunk by
/// chunk; their files are hashed instead, and the data was authenticated
/// chunk by chunk when it was read from the backup.
fn file_level_check() -> serde_json::Value {
    json!([{ "method": "file-sha256", "supported": true,
             "note": "Each restored file's SHA-256 was read back from disk; the backup data was authenticated chunk by chunk while restoring." }])
}

/// `20261124-120000` from the image's time, for standby folder names.
pub fn stamp(m: &ManifestBody) -> String {
    m.created
        .replace([':', '-'], "")
        .trim_end_matches('Z')
        .replace('T', "-")
}

/// Standby restores: record the new folder for `key` and remove the one the
/// previous standby restore made (best effort; a failure is a warning).
fn standby_swap(ctx: &Ctx, key: &str, new: &Path, warnings: &mut Vec<String>) {
    let file = ctx.state_dir.join("standby.json");
    let mut map: std::collections::BTreeMap<String, String> = std::fs::read(&file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let old = map.insert(key.to_string(), new.display().to_string());
    let _ = std::fs::write(&file, serde_json::to_vec_pretty(&map).unwrap_or_default());
    if let Some(old) = old.filter(|o| Path::new(o) != new) {
        if let Err(e) = std::fs::remove_dir_all(&old) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warnings.push(format!(
                    "the previous standby's files in {old} could not be removed: {e}"
                ));
            }
        }
    }
}

/// Called after writing a taken-over disk.
type Finish = Box<dyn FnOnce() -> std::io::Result<()>>;

/// The restore target. On Windows a physical disk is taken over first (its
/// volumes locked and dismounted; the system disk refused).
fn open_target(
    device: &str,
    min_size: u64,
    c: &DestructiveConfirmation,
) -> anyhow::Result<(FileTarget, Option<Finish>)> {
    #[cfg(windows)]
    if engine::target::is_windows_device_path(device) {
        let (t, lock) = snapshot_win::win::disks::take_over(device, c)?;
        return Ok((t, Some(Box::new(move || lock.finish()))));
    }
    Ok((
        FileTarget::open(Path::new(device), min_size, true, c)?,
        None,
    ))
}

/// How the backed-up system boots: as recorded at backup, else inferred
/// from the disk (an EFI system partition means UEFI; an MBR disk without
/// one means BIOS).
pub fn image_firmware(
    m: &ManifestBody,
    d: &core_format::manifest::DiskImage,
) -> Option<&'static str> {
    use core_format::manifest::Firmware;
    use core_format::partition::{PartitionRole, Scheme};
    match m.boot.firmware {
        Firmware::Uefi => Some("uefi"),
        Firmware::Bios => Some("bios"),
        Firmware::Unknown => {
            let esp = d
                .partition_table
                .partitions
                .iter()
                .any(|p| p.role == PartitionRole::Esp);
            match (esp, d.partition_table.scheme) {
                (true, _) => Some("uefi"),
                (false, Scheme::Mbr) => Some("bios"),
                _ => None,
            }
        }
    }
}

/// Hyper-V settings for a VM made from `m`'s disks written to `files`.
pub fn vm_spec(
    m: &ManifestBody,
    name: &str,
    dir: &Path,
    files: &[(u32, PathBuf)],
    switch: Option<String>,
    start: bool,
) -> crate::hyperv::NewVm {
    let vm = m.vm.clone().unwrap_or_default();
    crate::hyperv::NewVm {
        name: name.to_string(),
        path: dir.display().to_string(),
        generation: if vm.generation == 1 || vm.generation == 2 {
            vm.generation
        } else {
            guess_generation(m)
        },
        cpu_count: vm.cpu_count.max(1),
        memory_mb: if vm.memory_mb >= 512 {
            vm.memory_mb
        } else {
            4096
        },
        secure_boot: vm.secure_boot,
        disks: files
            .iter()
            .map(|(i, p)| crate::hyperv::NewVmDisk {
                path: p.display().to_string(),
                controller: vm
                    .disks
                    .get(*i as usize)
                    .map(|d| d.controller.clone())
                    .unwrap_or_default(),
            })
            .collect(),
        switch: switch
            .or_else(|| vm.network_adapters.first().map(|n| n.switch.clone()))
            .filter(|s| !s.is_empty()),
        adapters: vm.network_adapters.len().max(1) as u32,
        start,
    }
}

/// Without recorded VM settings: UEFI if the image has an EFI system partition.
fn guess_generation(m: &ManifestBody) -> u32 {
    let esp = m.disks.iter().any(|d| {
        d.partitions
            .iter()
            .any(|p| p.entry.role == core_format::partition::PartitionRole::Esp)
    });
    if esp {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitlocker_notes_tell_decrypted_from_still_encrypted() {
        use core_format::manifest::*;
        let part = |n: u32, capture: CaptureMethod, fs: core_format::fsdetect::FsType, mp: &str| {
            serde_json::from_value::<PartitionRecord>(serde_json::json!({
                "number": n, "start": n as u64 * 1048576, "length": 1048576, "role": "data",
                "filesystem": fs, "capture": capture, "captured_bytes": 0,
                "encryption": "bitlocker", "mount_points": if mp.is_empty() { vec![] } else { vec![mp] },
            }))
            .unwrap()
        };
        let disk: DiskImage = serde_json::from_value(serde_json::json!({
            "index": 0, "size": 1 << 30, "logical_sector_size": 512, "physical_sector_size": 512,
            "partition_table": { "scheme": "gpt", "sector_size": 512, "partitions": [], "raw_regions": [] },
            "partitions": [], "used_extents": [], "chunks": [],
        }))
        .unwrap();
        let mut d = disk;
        use core_format::fsdetect::FsType;
        d.partitions = vec![
            part(3, CaptureMethod::SnapshotBitmap, FsType::Ntfs, "C:\\"),
            part(4, CaptureMethod::RawFull, FsType::Bitlocker, ""),
        ];
        let body = serde_json::json!({
            "format": "fenrir-manifest-body", "version": 1, "image_id": uuid::Uuid::nil(), "repo_id": uuid::Uuid::nil(),
            "created": "", "created_unix": 0, "kind": "full", "machine": {"machine_id": "m", "hostname": "h"},
            "consistency": "application", "chunk_size": 4194304, "hash": "blake3-keyed", "compression": "zstd",
            "encryption": "xchacha20poly1305", "disks": [d], "boot": BootConfig::default(), "os": OsInfo::default(),
            "drivers": [], "excluded": [], "warnings": [], "stats": ImageStats::default(),
        });
        let m: ManifestBody = serde_json::from_value(body).unwrap();
        let n = bitlocker_notes(&m, &[]);
        assert_eq!(n.len(), 2, "{n:?}");
        assert!(n[0].contains("C:\\") && n[0].contains("not encrypted"));
        assert!(n[1].contains("disk 0 partition 4") && n[1].contains("recovery key"));
        assert!(bitlocker_notes(&m, &[1]).is_empty(), "other disks only");
    }

    #[test]
    fn names_are_safe() {
        assert_eq!(safe_name("SQL PROD/../x"), "SQL-PROD----x");
        assert_eq!(safe_name("***"), "image");
    }
}
