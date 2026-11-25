//! What this machine is and what it can do, reported on every heartbeat.

use protocol::{DiskSummary, Inventory, OsSummary};

pub fn hostname() -> String {
    if let Ok(n) = std::env::var("FENRIR_RECOVERY_NAME") {
        return n;
    }
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .or_else(|| cmd("hostname", &[]))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn cmd(prog: &str, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(prog).args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn machine_id() -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let id = snapshot_win::win::system::machine_id();
        if id.is_empty() {
            anyhow::bail!("cannot read MachineGuid");
        }
        Ok(id)
    }
    #[cfg(target_os = "macos")]
    {
        // IOPlatformUUID: stable hardware UUID.
        let out = cmd("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])
            .ok_or_else(|| anyhow::anyhow!("ioreg failed"))?;
        out.lines()
            .find(|l| l.contains("IOPlatformUUID"))
            .and_then(|l| l.split('"').nth(3))
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("IOPlatformUUID not found"))
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        Ok(snapshot_linux::machine_id()?)
    }
}

pub fn os() -> OsSummary {
    let arch = std::env::consts::ARCH.to_string();
    #[cfg(windows)]
    {
        let i = snapshot_win::win::system::os_info();
        OsSummary {
            family: "windows".into(),
            name: i.name,
            version: format!("{} ({})", i.version, i.build),
            arch,
        }
    }
    #[cfg(target_os = "macos")]
    {
        OsSummary {
            family: "macos".into(),
            name: cmd("sw_vers", &["-productName"]).unwrap_or_else(|| "macOS".into()),
            version: cmd("sw_vers", &["-productVersion"]).unwrap_or_default(),
            arch,
        }
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        let rel = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let field = |k: &str| {
            rel.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default()
        };
        OsSummary {
            family: "linux".into(),
            name: field("NAME"),
            version: field("VERSION_ID"),
            arch,
        }
    }
}

pub fn capabilities(role: &str) -> Vec<String> {
    if role == "recovery" {
        return ["restore_disk", "restore_files", "verify"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    let mut c: Vec<String> = [
        "verify",
        "maintenance",
        // Retention keeps images on legal hold (sent with ApplyRetention).
        "legal_hold",
        "restore_vhdx",
        // qcow2, VDI and VMDK files with a VM definition (vmdef.rs).
        "restore_vm_files",
        "restore_files",
        // Malware scans of images (malware.rs).
        "scan_images",
        // Chosen files and folders (folders.rs).
        "backup_files",
        // File catalogues and search across backups (search.rs).
        "search_files",
        // Restores to Azure and AWS (cloudrestore.rs).
        "restore_cloud",
        "gateway",
        "kubernetes",
        "saas",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if cfg!(windows) {
        c.push("backup_system".into());
        // Onto a disk that is not the system disk (its volumes are locked).
        c.push("restore_disk".into());
        c.push("local_recovery".into());
        // One SQL Server or Exchange database from an application-aware image (apprestore.rs).
        c.push("restore_apps".into());
        if crate::hyperv::is_host(role) {
            c.push("backup_hyperv".into());
            c.push("restore_hyperv".into());
        }
    } else {
        if cfg!(target_os = "linux") {
            // Live images through LVM snapshots (the job explains what a
            // system without LVM needs).
            c.push("backup_system".into());
        }
        c.push("backup_disks".into());
        c.push("restore_disk".into());
    }
    if let Some(b) = crate::boot::capability(role) {
        c.push(b.into());
    }
    c
}

/// Block devices on Linux (whole disks only).
pub fn disks() -> Vec<DiskSummary> {
    #[cfg(target_os = "linux")]
    {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let root_dev = mountinfo
            .lines()
            .find(|l| l.split_whitespace().nth(4) == Some("/"))
            .and_then(|l| l.split_whitespace().nth(2).map(String::from));
        // Every mounted device number, and swap devices by name.
        let mounted: std::collections::HashSet<String> = mountinfo
            .lines()
            .filter_map(|l| l.split_whitespace().nth(2).map(String::from))
            .collect();
        let swaps: Vec<String> = std::fs::read_to_string("/proc/swaps")
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next())
            .filter_map(|d| d.strip_prefix("/dev/").map(String::from))
            .collect();
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir("/sys/block") else {
            return out;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if ["loop", "ram", "zram", "dm-", "md", "sr", "fd"]
                .iter()
                .any(|p| name.starts_with(p))
            {
                continue;
            }
            let base = e.path();
            let rd = |f: &str| {
                std::fs::read_to_string(base.join(f))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            };
            let size = rd("size").parse::<u64>().unwrap_or(0) * 512;
            if size == 0 {
                continue;
            }
            // The disk and its partitions: device numbers, names, holders.
            let mut devs = vec![rd("dev")];
            let mut names = vec![name.clone()];
            let mut held = std::fs::read_dir(base.join("holders"))
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            if let Ok(parts) = std::fs::read_dir(&base) {
                for p in parts.flatten() {
                    if p.path().join("partition").exists() {
                        devs.push(
                            std::fs::read_to_string(p.path().join("dev"))
                                .map(|s| s.trim().to_string())
                                .unwrap_or_default(),
                        );
                        names.push(p.file_name().to_string_lossy().to_string());
                        held |= std::fs::read_dir(p.path().join("holders"))
                            .map(|mut d| d.next().is_some())
                            .unwrap_or(false);
                    }
                }
            }
            let serial = [rd("device/serial"), rd("serial")]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            out.push(DiskSummary {
                path: format!("/dev/{name}"),
                size,
                model: rd("device/model"),
                system: root_dev.as_ref().is_some_and(|r| devs.contains(r)),
                serial,
                sector_size: rd("queue/logical_block_size").parse().unwrap_or(0),
                in_use: held
                    || devs.iter().any(|d| mounted.contains(d))
                    || names.iter().any(|n| swaps.contains(n)),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }
    #[cfg(windows)]
    {
        snapshot_win::win::disks::list()
            .into_iter()
            .map(|d| DiskSummary {
                path: d.path,
                size: d.size,
                model: d.model,
                system: d.system,
                serial: d.serial,
                sector_size: d.sector_size,
                in_use: d.in_use,
            })
            .collect()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Vec::new()
    }
}

/// How this machine booted, and whether Secure Boot is on.
pub fn firmware() -> (Option<String>, Option<bool>) {
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/sys/firmware/efi").exists() {
            return (Some("bios".into()), Some(false));
        }
        let sb = std::fs::read_dir("/sys/firmware/efi/efivars")
            .ok()
            .and_then(|d| {
                d.flatten()
                    .find(|e| e.file_name().to_string_lossy().starts_with("SecureBoot-"))
            })
            .and_then(|e| std::fs::read(e.path()).ok())
            // 4 bytes of attributes, then the value.
            .and_then(|v| v.get(4).map(|b| *b == 1));
        (Some("uefi".into()), sb)
    }
    #[cfg(windows)]
    {
        snapshot_win::win::disks::firmware_mode()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        (None, None)
    }
}

pub fn collect(role: &str, vms: Vec<protocol::VmSummary>, notes: Vec<String>) -> Inventory {
    let mut notes = notes;
    if cfg!(target_os = "macos") {
        notes.push("macOS: back up the whole Data volume with a files-and-folders backup of / (read from an APFS snapshot; the agent needs Full Disk Access). The system volume comes back by installing macOS. Disk images of non-system disks also work.".into());
    }
    let fw = firmware();
    Inventory {
        hostname: hostname(),
        hardware_serial: hardware_serial(),
        os: os(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        capabilities: capabilities(role),
        disks: disks(),
        vms,
        notes,
        agent_target: crate::update::TARGET.into(),
        agent_sha256: crate::update::self_sha256(),
        running_vms: crate::boot::running_vms(),
        gateway_addresses: vec![],
        firmware: fw.0,
        secure_boot: fw.1,
        local_recovery: crate::localrec::load_state(&crate::config::state_dir()).map(|s| s.info()),
        other_backup: if role == "recovery" {
            vec![]
        } else {
            crate::discover::other_backup()
        },
    }
}

/// SMBIOS system serial number, unless it is a firmware placeholder.
pub fn hardware_serial() -> Option<String> {
    #[cfg(windows)]
    let s = snapshot_win::win::disks::hardware_identity().map(|(_, serial)| serial);
    #[cfg(target_os = "linux")]
    let s = std::fs::read_to_string("/sys/class/dmi/id/product_serial").ok();
    #[cfg(not(any(windows, target_os = "linux")))]
    let s: Option<String> = None;
    s.map(|s| s.trim().to_string()).filter(|s| real_serial(s))
}

/// Not empty and not a placeholder ("To Be Filled By O.E.M.", "Default
/// string", "System Serial Number", zeros...).
pub fn real_serial(s: &str) -> bool {
    let l = s.trim().to_ascii_lowercase();
    !(l.len() < 3
        || l.contains("o.e.m")
        || l.contains("default")
        || l.contains("not specified")
        || l.contains("serial number")
        || l.contains("none")
        || l.chars()
            .all(|c| c == '0' || c == '-' || c == ' ' || c == '.'))
}

/// The role for `--role auto` (the all-in-one Fenrir installer): a Hyper-V host
/// backs up its VMs, Windows Server and Linux are servers, the rest workstations.
pub fn detect_role() -> String {
    if cfg!(windows) {
        let ok = |prog: &str, args: &[&str]| {
            std::process::Command::new(prog)
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        };
        if ok("sc.exe", &["query", "vmms"]).is_some() {
            return "hyperv".into();
        }
        let product = ok(
            "reg.exe",
            &[
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions",
                "/v",
                "ProductType",
            ],
        )
        .unwrap_or_default();
        // "WinNT" is a workstation edition; "ServerNT" / "LanmanNT" are servers.
        let server = product.contains("ServerNT") || product.contains("LanmanNT");
        return if server { "server" } else { "workstation" }.into();
    }
    if cfg!(target_os = "macos") {
        "workstation".into()
    } else {
        "server".into()
    }
}

#[cfg(test)]
mod serial_tests {
    #[test]
    fn placeholder_serials_are_not_identities() {
        for bad in [
            "",
            "0",
            "To Be Filled By O.E.M.",
            "Default string",
            "System Serial Number",
            "0000000000",
            "None",
            "Not Specified",
        ] {
            assert!(!super::real_serial(bad), "{bad:?}");
        }
        for good in ["CN-0X35B", "VMware-56 4d 8a", "PF2ABCDE", "1234-5678-9012"] {
            assert!(super::real_serial(good), "{good:?}");
        }
    }
}
