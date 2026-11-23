//! Recovery media mode (design: phase-2 §3): the agent on a machine booted
//! from the recovery ISO (or WinPE). State lives in RAM, the identity comes
//! from the hardware, and only restores are offered.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use protocol::recovery::{self, RecoveryConfig};

/// Where the recovery session keeps its state and status.
pub fn runtime_dir() -> PathBuf {
    if cfg!(windows) {
        // Windows PE runs from X:; elsewhere (tests, a running Windows) the
        // temporary folder.
        if Path::new(r"X:\Windows\System32").is_dir() {
            PathBuf::from(r"X:\fenrir")
        } else {
            std::env::temp_dir().join("fenrir-recovery")
        }
    } else {
        PathBuf::from("/run/fenrir-recovery")
    }
}

/// Places the settings can be, in order. The console writes what the user
/// typed, or found on another stick, to the first.
pub fn candidates() -> Vec<PathBuf> {
    let rt = runtime_dir();
    let mut v = vec![rt.join("recovery.json")];
    if cfg!(windows) {
        for d in b'C'..=b'Z' {
            let root = PathBuf::from(format!("{}:\\", d as char));
            v.push(root.join("fenrir").join("recovery.json"));
            v.push(root.join("fenrir-recovery.json"));
        }
    } else {
        // Debian live-boot mounts the boot medium here.
        v.push(PathBuf::from("/run/live/medium/fenrir/recovery.json"));
    }
    v
}

/// The first configured settings file.
pub fn find_config(paths: &[PathBuf]) -> Option<(RecoveryConfig, PathBuf)> {
    for p in paths {
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        match recovery::parse(&bytes) {
            Ok(Some(c)) => return Some((c, p.clone())),
            Ok(None) => {}
            Err(e) => status(&format!("ignoring {}: {e}", p.display())),
        }
    }
    None
}

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// (hostname, machine id) from the hardware, stable across boots of the
/// same machine. Firmware placeholders ("To Be Filled By O.E.M.", all-zero
/// UUIDs) are ignored.
pub fn identity(dmi: &Path, net: &Path) -> (String, String) {
    let rd = |f: &str| {
        std::fs::read_to_string(dmi.join(f))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let junk = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.is_empty()
            || l.contains("o.e.m")
            || l.contains("default")
            || l.contains("not specified")
            || l.chars().all(|c| c == '0' || c == '-' || c == 'f')
    };
    let mac = std::fs::read_dir(net)
        .ok()
        .and_then(|d| {
            let mut names: Vec<_> = d
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n != "lo")
                .collect();
            names.sort();
            names.into_iter().find_map(|n| {
                std::fs::read_to_string(net.join(&n).join("address"))
                    .ok()
                    .map(|a| a.trim().replace(':', ""))
                    .filter(|a| !junk(a))
            })
        })
        .unwrap_or_default();
    let uuid = rd("product_uuid");
    let serial = rd("product_serial");
    let id = if !junk(&uuid) {
        uuid.to_ascii_lowercase()
    } else if !mac.is_empty() {
        format!("mac-{mac}")
    } else {
        uuid::Uuid::new_v4().to_string()
    };
    let name = if !junk(&serial) {
        clean(&serial)
    } else if !mac.is_empty() {
        mac.clone()
    } else {
        id[..8].to_string()
    };
    (format!("recovery-{name}"), format!("recovery:{id}"))
}

/// (hostname, machine id) from SMBIOS on Windows PE: the same identity the
/// Linux recovery media gives this machine.
fn windows_identity() -> Option<(String, String)> {
    #[cfg(windows)]
    {
        let (uuid, serial) = snapshot_win::win::disks::hardware_identity()?;
        let junk = |s: &str| {
            let l = s.to_ascii_lowercase();
            l.is_empty()
                || l.contains("o.e.m")
                || l.contains("default")
                || l.contains("not specified")
        };
        let id = uuid.clone()?;
        let name = if junk(&serial) {
            id[..8].to_string()
        } else {
            clean(&serial)
        };
        Some((format!("recovery-{name}"), format!("recovery:{id}")))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// One line for the console's status screen.
pub fn status(line: &str) {
    let dir = runtime_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("status"), format!("{line}\n"));
    eprintln!("{line}");
}

/// `fenrir-backup-agent recovery`: find the settings, enrol, serve jobs.
/// Runs until stopped; retries when the network or server is not there yet.
pub fn run(config: Option<PathBuf>) -> anyhow::Result<()> {
    let state = runtime_dir().join("agent");
    if std::env::var_os("FENRIR_AGENT_STATE").is_none() {
        std::env::set_var("FENRIR_AGENT_STATE", &state);
    }
    let paths = match &config {
        Some(p) => vec![p.clone()],
        None => candidates(),
    };
    let (host, machine) = if cfg!(target_os = "linux") {
        identity(Path::new("/sys/class/dmi/id"), Path::new("/sys/class/net"))
    } else if let Some(hw) = windows_identity() {
        hw
    } else {
        let id =
            crate::inventory::machine_id().unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
        (
            format!("recovery-{}", clean(&crate::inventory::hostname())),
            format!("recovery:{id}"),
        )
    };
    // The name the server shows, also in the inventory.
    std::env::set_var("FENRIR_RECOVERY_NAME", &host);
    let stop = Arc::new(AtomicBool::new(false));
    let mut enrolled_with: Option<String> = None;
    loop {
        let Some((cfg, from)) = find_config(&paths) else {
            status("waiting for server settings (choose \"Connect to a server\" on the menu)");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        };
        if enrolled_with.as_deref() != Some(cfg.server.as_str()) {
            status(&format!("connecting to {} ...", cfg.server));
            match crate::enroll_as(
                &cfg.server,
                &cfg.token,
                &cfg.pin,
                "recovery",
                Some((&host, &machine)),
            ) {
                Ok(()) => enrolled_with = Some(cfg.server.clone()),
                Err(e) => {
                    status(&format!(
                        "cannot reach {} ({e:#}); retrying. Settings from {}",
                        cfg.server,
                        from.display()
                    ));
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            }
        }
        status(&format!(
            "connected to {} as {host}: continue the restore in the web UI",
            cfg.server
        ));
        match crate::run_loop(stop.clone()) {
            Ok(_) => return Ok(()),
            Err(e) => {
                status(&format!("disconnected ({e:#}); retrying"));
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }
}

/// Add a firmware boot entry for the restored system (UEFI, Linux recovery
/// media with `efibootmgr`). Returns a note for the job when it could not.
pub fn firmware_entry(
    device: &str,
    disk: &core_format::manifest::DiskImage,
    fix: &engine::bootfix::BootFix,
) -> Option<String> {
    if !cfg!(target_os = "linux") || !Path::new("/sys/firmware/efi").exists() {
        return None;
    }
    let loader = fix.loader.as_ref()?;
    let esp = disk
        .partition_table
        .partitions
        .iter()
        .find(|p| p.role == core_format::partition::PartitionRole::Esp)?;
    let out = std::process::Command::new("efibootmgr")
        .args(["--create", "--disk", device, "--part"])
        .arg(esp.number.to_string())
        .args(["--label", &loader.label, "--loader", &loader.path])
        .output();
    match out {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "Could not add a firmware boot entry ({}); the machine will still try the fallback loader.",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_prefers_dmi_then_mac() {
        let t = tempfile::tempdir().unwrap();
        let dmi = t.path().join("dmi");
        let net = t.path().join("net");
        std::fs::create_dir_all(net.join("lo")).unwrap();
        std::fs::create_dir_all(net.join("enp3s0")).unwrap();
        std::fs::create_dir_all(&dmi).unwrap();
        std::fs::write(net.join("lo/address"), "00:00:00:00:00:00\n").unwrap();
        std::fs::write(net.join("enp3s0/address"), "52:54:00:12:34:56\n").unwrap();

        std::fs::write(
            dmi.join("product_uuid"),
            "4C4C4544-0042-3510-8051-B4C04F4B4E32\n",
        )
        .unwrap();
        std::fs::write(dmi.join("product_serial"), "CN-0X3 5/B\n").unwrap();
        assert_eq!(
            identity(&dmi, &net),
            (
                "recovery-cn-0x35b".to_string(),
                "recovery:4c4c4544-0042-3510-8051-b4c04f4b4e32".to_string()
            )
        );
        // Firmware placeholders fall back to the network card.
        std::fs::write(
            dmi.join("product_uuid"),
            "00000000-0000-0000-0000-000000000000",
        )
        .unwrap();
        std::fs::write(dmi.join("product_serial"), "To Be Filled By O.E.M.").unwrap();
        assert_eq!(
            identity(&dmi, &net),
            (
                "recovery-525400123456".to_string(),
                "recovery:mac-525400123456".to_string()
            )
        );
    }

    #[test]
    fn config_search_skips_the_stock_placeholder() {
        let t = tempfile::tempdir().unwrap();
        let stock = t.path().join("stock.json");
        let stick = t.path().join("fenrir-recovery.json");
        std::fs::write(&stock, recovery::placeholder()).unwrap();
        std::fs::write(
            &stick,
            r#"{"server":"https://b.example:8443","token":"fet_1"}"#,
        )
        .unwrap();
        let paths = vec![t.path().join("missing.json"), stock, stick.clone()];
        let (c, from) = find_config(&paths).unwrap();
        assert_eq!(c.server, "https://b.example:8443");
        assert_eq!(from, stick);
        assert!(find_config(&paths[..2]).is_none());
    }
}
