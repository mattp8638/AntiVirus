//! What this machine is and what it can do, reported on every heartbeat.

use protocol::{DiskSummary, Inventory, OsSummary};

pub fn hostname() -> String {
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
    let mut c: Vec<String> = ["verify", "maintenance", "restore_vhdx", "restore_files"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if cfg!(windows) {
        c.push("backup_system".into());
        if role == "hyperv" {
            c.push("backup_hyperv".into());
            c.push("restore_hyperv".into());
        }
    } else {
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
        let root_dev = std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|m| {
                m.lines()
                    .find(|l| l.split_whitespace().nth(4) == Some("/"))
                    .and_then(|l| l.split_whitespace().nth(2).map(String::from))
            });
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
            // System disk: the root filesystem is on it or one of its partitions.
            let mut devs = vec![rd("dev")];
            if let Ok(parts) = std::fs::read_dir(&base) {
                for p in parts.flatten() {
                    if p.path().join("partition").exists() {
                        devs.push(
                            std::fs::read_to_string(p.path().join("dev"))
                                .map(|s| s.trim().to_string())
                                .unwrap_or_default(),
                        );
                    }
                }
            }
            out.push(DiskSummary {
                path: format!("/dev/{name}"),
                size,
                model: rd("device/model"),
                system: root_dev.as_ref().is_some_and(|r| devs.contains(r)),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

pub fn collect(role: &str, vms: Vec<protocol::VmSummary>, notes: Vec<String>) -> Inventory {
    let mut notes = notes;
    if cfg!(target_os = "macos") {
        notes.push("macOS system protection needs file-level backup, which is not available yet. Disk images of non-system disks and verification work.".into());
    }
    Inventory {
        hostname: hostname(),
        os: os(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        capabilities: capabilities(role),
        disks: disks(),
        vms,
        notes,
        agent_target: crate::update::TARGET.into(),
        agent_sha256: crate::update::self_sha256(),
        running_vms: crate::boot::running_vms(),
    }
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
