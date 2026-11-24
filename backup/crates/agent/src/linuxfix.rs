//! Restoring Linux onto different hardware (docs/design/phase-5-hardware.md, "Linux").
//!
//! A Linux system starts from its initramfs, which holds the drivers needed
//! to reach the root file system. Built "host-only" (dracut's default on
//! Red Hat, Fedora, SUSE; initramfs-tools with `MODULES=dep`), it has only
//! the storage drivers of the machine it was built on, and another
//! controller leaves it waiting for its root device. After a bare-metal
//! restore from the recovery media this module finds the restored root file
//! system, mounts it with its /boot, and rebuilds every initramfs with all
//! storage drivers, inside the restored system (chroot), with its own tools.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct LinuxFix {
    /// The device holding the root file system.
    pub root: String,
    /// PRETTY_NAME from os-release.
    pub os: String,
    /// What was done to the initramfs.
    pub initramfs: String,
    pub notes: Vec<String>,
}

/// How the restored system builds its initramfs.
#[derive(Debug, PartialEq)]
pub enum Initramfs {
    /// dracut: rebuild every image without host-only.
    Dracut,
    /// initramfs-tools with MODULES=dep: rebuild with MODULES=most.
    ToolsDep,
    /// initramfs-tools already includes most drivers.
    ToolsMost,
    Unknown,
}

pub fn initramfs_kind(root: &Path) -> Initramfs {
    let has = |p: &str| root.join(p).exists();
    if has("usr/bin/dracut") || has("usr/sbin/dracut") {
        return Initramfs::Dracut;
    }
    if has("usr/sbin/update-initramfs") {
        let conf = std::fs::read_to_string(root.join("etc/initramfs-tools/initramfs.conf"))
            .unwrap_or_default();
        let mut modules = "most".to_string();
        for l in conf.lines().chain(conf_d(root).iter().map(String::as_str)) {
            if let Some(v) = l.trim().strip_prefix("MODULES=") {
                modules = v.trim().trim_matches('"').to_string();
            }
        }
        return if modules == "dep" {
            Initramfs::ToolsDep
        } else {
            Initramfs::ToolsMost
        };
    }
    Initramfs::Unknown
}

/// Lines of initramfs-tools' conf.d files, in the order it reads them.
fn conf_d(root: &Path) -> Vec<String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("etc/initramfs-tools/conf.d"))
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `/boot` and `/boot/efi` from fstab: (mount point, device spec).
pub fn boot_mounts(fstab: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = fstab
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 2 && (f[1] == "/boot" || f[1] == "/boot/efi"))
                .then(|| (f[1].to_string(), f[0].to_string()))
        })
        .collect();
    v.sort();
    v
}

pub fn pretty_name(os_release: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into())
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::process::Command;

    fn out(cmd: &str, args: &[&str]) -> Option<String> {
        let o = Command::new(cmd).args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }

    fn ok(cmd: &mut Command) -> bool {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Unmounts (reverse order) and deactivates volume groups on drop.
    struct Mounted {
        points: Vec<PathBuf>,
        vgs: Vec<String>,
    }
    impl Drop for Mounted {
        fn drop(&mut self) {
            let _ = Command::new("sync").status();
            for p in self.points.iter().rev() {
                let _ = Command::new("umount").arg("-l").arg(p).status();
            }
            for vg in &self.vgs {
                let _ = Command::new("vgchange").args(["-an", vg]).output();
            }
        }
    }

    /// Partitions of `device` and logical volumes of volume groups on it.
    fn candidates(device: &str, m: &mut Mounted) -> Vec<String> {
        let mut parts: Vec<String> = crate::hwfix::partitions_of(device)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        if let Some(pvs) = out("pvs", &["--noheadings", "-o", "pv_name,vg_name"]) {
            let mut vgs: Vec<String> = pvs
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() == 2 && parts.iter().any(|p| p == f[0])).then(|| f[1].to_string())
                })
                .collect();
            vgs.sort();
            vgs.dedup();
            for vg in vgs {
                if ok(Command::new("vgchange").args(["-ay", &vg])) {
                    if let Some(lvs) = out("lvs", &["--noheadings", "-o", "lv_path", &vg]) {
                        parts.extend(
                            lvs.lines()
                                .map(|l| l.trim().to_string())
                                .filter(|l| !l.is_empty()),
                        );
                    }
                    m.vgs.push(vg);
                }
            }
        }
        parts
    }

    fn fs_type(dev: &str) -> String {
        out("blkid", &["-o", "value", "-s", "TYPE", dev])
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn resolve(spec: &str) -> Option<String> {
        if let Some(u) = spec.strip_prefix("UUID=") {
            return out("blkid", &["-U", u.trim_matches('"')]).map(|s| s.trim().to_string());
        }
        if let Some(l) = spec.strip_prefix("LABEL=") {
            return out("blkid", &["-L", l.trim_matches('"')]).map(|s| s.trim().to_string());
        }
        if let Some(u) = spec.strip_prefix("PARTUUID=") {
            return out("blkid", &["-t", &format!("PARTUUID={u}"), "-o", "device"])
                .and_then(|s| s.lines().next().map(str::to_string));
        }
        spec.starts_with("/dev/").then(|| spec.to_string())
    }

    pub fn adapt_restored_linux(device: &str) -> anyhow::Result<Option<LinuxFix>> {
        let mut m = Mounted {
            points: vec![],
            vgs: vec![],
        };
        let root = crate::recovery::runtime_dir().join("linux-root");
        std::fs::create_dir_all(&root)?;
        let mut found = None;
        for dev in candidates(device, &mut m) {
            if !matches!(
                fs_type(&dev).as_str(),
                "ext4" | "ext3" | "ext2" | "xfs" | "btrfs"
            ) {
                continue;
            }
            if !ok(Command::new("mount").arg(&dev).arg(&root)) {
                continue;
            }
            if root.join("etc/os-release").is_file()
                && root.join("etc/fstab").is_file()
                && root.join("boot").is_dir()
            {
                found = Some(dev);
                m.points.push(root.clone());
                break;
            }
            let _ = Command::new("umount").arg(&root).status();
        }
        let Some(dev) = found else { return Ok(None) };
        let mut fix = LinuxFix {
            root: dev,
            os: pretty_name(
                &std::fs::read_to_string(root.join("etc/os-release")).unwrap_or_default(),
            ),
            ..Default::default()
        };
        for (point, spec) in boot_mounts(&std::fs::read_to_string(root.join("etc/fstab"))?) {
            let Some(d) = resolve(&spec) else {
                fix.notes.push(format!(
                    "{point} ({spec}) was not found on the restored disk"
                ));
                continue;
            };
            let at = root.join(point.trim_start_matches('/'));
            if ok(Command::new("mount").arg(&d).arg(&at)) {
                m.points.push(at);
            } else {
                fix.notes.push(format!("could not mount {point} ({d})"));
            }
        }
        for fs in ["dev", "proc", "sys", "run"] {
            let at = root.join(fs);
            if ok(Command::new("mount")
                .arg("--bind")
                .arg(format!("/{fs}"))
                .arg(&at))
            {
                m.points.push(at);
            }
        }
        let kind = initramfs_kind(&root);
        let run = |args: &[&str]| -> anyhow::Result<()> {
            let o = Command::new("chroot")
                .arg(&root)
                .args(args)
                .output()
                .context("chroot")?;
            if !o.status.success() {
                let err = String::from_utf8_lossy(&o.stderr);
                bail!(
                    "{}: {}",
                    args.join(" "),
                    err.lines().rev().take(3).collect::<Vec<_>>().join(" / ")
                );
            }
            Ok(())
        };
        fix.initramfs = match kind {
            Initramfs::Dracut => {
                run(&["dracut", "--force", "--no-hostonly", "--regenerate-all"])?;
                "rebuilt with dracut with all drivers (not host-only)".into()
            }
            Initramfs::ToolsDep => {
                // A conf.d file read after the others: the restored system keeps all drivers from now on.
                std::fs::write(
                    root.join("etc/initramfs-tools/conf.d/zz-fenrir-restore"),
                    "# Written by Fenrir-Backup after restoring onto different hardware: include all drivers.\nMODULES=most\n",
                )?;
                run(&["update-initramfs", "-u", "-k", "all"])?;
                "rebuilt with initramfs-tools with MODULES=most".into()
            }
            Initramfs::ToolsMost => {
                "already includes the storage drivers (initramfs-tools, MODULES=most); unchanged"
                    .into()
            }
            Initramfs::Unknown => {
                fix.notes.push("No dracut or initramfs-tools in the restored system: its initramfs was not rebuilt.".into());
                "unchanged".into()
            }
        };
        fix.notes.push("Network interfaces may get other names on new hardware; check network settings that name an interface or a MAC address.".into());
        drop(m);
        Ok(Some(fix))
    }
}

#[cfg(target_os = "linux")]
pub use imp::adapt_restored_linux;

#[cfg(not(target_os = "linux"))]
pub fn adapt_restored_linux(_device: &str) -> anyhow::Result<Option<LinuxFix>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initramfs_tool_is_recognised() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        assert_eq!(initramfs_kind(r), Initramfs::Unknown);
        std::fs::create_dir_all(r.join("usr/sbin")).unwrap();
        std::fs::create_dir_all(r.join("etc/initramfs-tools/conf.d")).unwrap();
        std::fs::write(r.join("usr/sbin/update-initramfs"), "").unwrap();
        std::fs::write(
            r.join("etc/initramfs-tools/initramfs.conf"),
            "MODULES=most\n",
        )
        .unwrap();
        assert_eq!(initramfs_kind(r), Initramfs::ToolsMost);
        std::fs::write(r.join("etc/initramfs-tools/conf.d/host"), "MODULES=dep\n").unwrap();
        assert_eq!(initramfs_kind(r), Initramfs::ToolsDep, "conf.d overrides");
        std::fs::write(
            r.join("etc/initramfs-tools/conf.d/zz-fenrir-restore"),
            "MODULES=most\n",
        )
        .unwrap();
        assert_eq!(initramfs_kind(r), Initramfs::ToolsMost, "ours is read last");
        std::fs::create_dir_all(r.join("usr/bin")).unwrap();
        std::fs::write(r.join("usr/bin/dracut"), "").unwrap();
        assert_eq!(initramfs_kind(r), Initramfs::Dracut);
    }

    #[test]
    fn boot_mounts_come_from_fstab() {
        let fstab = "# comment\nUUID=aaa / ext4 defaults 0 1\nUUID=bbb /boot ext4 defaults 0 2\n\
                     UUID=CCCC-DDDD /boot/efi vfat umask=0077 0 1\n/dev/vg/home /home xfs defaults 0 0\n";
        assert_eq!(
            boot_mounts(fstab),
            vec![
                ("/boot".into(), "UUID=bbb".into()),
                ("/boot/efi".into(), "UUID=CCCC-DDDD".into())
            ]
        );
        assert_eq!(
            pretty_name("NAME=x\nPRETTY_NAME=\"Rocky Linux 9.4\"\n"),
            "Rocky Linux 9.4"
        );
    }
}
