//! Restore jobs: to VHDX files, to a new Hyper-V VM, or to a disk.

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

pub fn vhdx_names(m: &ManifestBody, disks: &[u32]) -> Vec<(u32, String)> {
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
        .map(|d| (d.index, format!("{base}-{stamp}-disk{}.vhdx", d.index)))
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
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let names = vhdx_names(m, disks);
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
        let t = vdisk::VhdxTarget::create(
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
            &t,
            &RestoreOptions {
                workers: 4,
                zero_fill: false,
                fit: false,
            },
            &ctx.ctl,
            &cb,
        );
        match r {
            Ok(_) => {
                t.finish()?;
            }
            Err(e) => {
                drop(t);
                let _ = std::fs::remove_file(&path);
                return Err(e.into());
            }
        }
        base += d.size;
        out.push((index, path));
    }
    Ok(out)
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
    match target {
        RestoreTarget::Vhdx { directory } => {
            let files = write_vhdx(ctx, repo, &m, disks, Path::new(directory), rep)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(
                json!({ "files": files.iter().map(|(_, p)| p.display().to_string()).collect::<Vec<_>>() }),
            );
            Ok(u)
        }
        RestoreTarget::HypervVm {
            name,
            directory,
            switch,
            start,
        } => {
            if !cfg!(windows) {
                bail!("restoring as a Hyper-V VM runs on a Hyper-V host");
            }
            crate::hyperv::check_vm_name(name)?;
            let vm = m.vm.clone().unwrap_or_default();
            let dir = Path::new(directory).join(safe_name(name));
            if dir.exists()
                && std::fs::read_dir(&dir)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(true)
            {
                bail!("{} already exists and is not empty", dir.display());
            }
            if crate::hyperv::vm_exists(name)? {
                bail!("a VM named '{name}' already exists on this host; choose another name");
            }
            let files = write_vhdx(ctx, repo, &m, disks, &dir, rep)?;
            rep.progress("creating VM", 1, 1, name);
            let spec = vm_spec(&m, name, &dir, &files, switch.clone(), *start);
            let out = crate::hyperv::run_ps(&crate::hyperv::new_vm_script(&spec)?)?;
            let mut u = done(JobState::Succeeded);
            u.result = Some(
                json!({ "vm": name, "path": dir.display().to_string(), "output": out.trim() }),
            );
            if vm.vm_id.is_empty() {
                u.state = JobState::Warning;
                u.warnings.push("The image has no Hyper-V settings (it was not taken from a Hyper-V host); the VM was created with defaults. Check generation, memory and network before starting it.".into());
            }
            Ok(u)
        }
        RestoreTarget::Disk {
            device,
            disk,
            confirm,
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
            let t = FileTarget::open(Path::new(device), engine::fit::min_size(d), true, &c)?;
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
            Ok(u)
        }
    }
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
    fn names_are_safe() {
        assert_eq!(safe_name("SQL PROD/../x"), "SQL-PROD----x");
        assert_eq!(safe_name("***"), "image");
    }
}
