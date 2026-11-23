//! Restoring Windows onto different hardware (design: docs/design/phase-5-hardware.md).
//!
//! A Windows installation starts only the storage drivers it needed on the
//! hardware it was installed on; on a machine with another controller (AHCI
//! instead of RAID, NVMe instead of SATA, a different hypervisor) it stops
//! with INACCESSIBLE_BOOT_DEVICE. After a bare-metal restore this module
//! edits the restored installation offline:
//!
//! * Windows' own storage drivers that are present on the disk are set to
//!   start at boot (`Start` = 0), and their per-boot-configuration
//!   `StartOverride` is removed, in the current control set of the SYSTEM
//!   hive.
//! * On Windows PE media, drivers supplied with the media or on a USB stick
//!   (`fenrir-drivers` folder) are added with DISM.
//!
//! The registry is changed through [`Hive`]: on the Linux recovery media
//! with the hivex tools (`hivexget`, `hivexregedit`, run as programs), on
//! Windows PE with `reg.exe`. A copy of the hive is kept next to it.

// Only Linux and Windows recovery media prepare a restored Windows.
#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};
use serde::Serialize;

/// Boot-critical storage drivers that ship with Windows (and common
/// virtualisation drivers). Only those present on the restored disk are
/// touched; a boot-start driver for absent hardware loads and does nothing.
pub const STORAGE_DRIVERS: &[&str] = &[
    // Standard controllers
    "storahci",
    "stornvme",
    "msahci",
    "atapi",
    "intelide",
    "pciide",
    "amdsata",
    "amdxata",
    // Intel RST / VMD
    "iaStorV",
    "iaStorAVC",
    "iaStorAC",
    "iaStorVD",
    // RAID / SAS HBAs
    "LSI_SAS",
    "LSI_SAS2i",
    "LSI_SAS3i",
    "LSI_SSS",
    "megasas",
    "megasas2i",
    "megasas35i",
    "percsas2i",
    "percsas3i",
    "SmartSAMD",
    "HpSAMD",
    "arcsas",
    "ADP80XX",
    "3ware",
    "mvumis",
    "nvraid",
    "nvstor",
    "amdsbs",
    "vsmraid",
    "stexstor",
    // Virtual machines
    "storvsc",
    "vmbus",
    "pvscsi",
    "viostor",
    "vioscsi",
];

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct WindowsFix {
    /// The Windows volume that was prepared (device or drive).
    pub volume: String,
    /// e.g. "ControlSet001".
    pub control_set: String,
    /// Drivers set to start at boot.
    pub boot_start: Vec<String>,
    /// Drivers whose StartOverride was removed.
    pub overrides_removed: Vec<String>,
    /// Driver packages added (Windows PE).
    pub drivers_added: Vec<String>,
    pub notes: Vec<String>,
}

/// Offline access to a SYSTEM hive. Key paths are relative to the hive root,
/// with backslashes (`ControlSet001\Services\storahci`).
pub trait Hive {
    fn dword(&self, key: &str, name: &str) -> Option<u32>;
    fn string(&self, key: &str, name: &str) -> Option<String>;
    fn key_exists(&self, key: &str) -> bool;
    /// Set DWORD values and delete keys, all at once.
    fn apply(&self, set: &[(String, String, u32)], delete: &[String]) -> anyhow::Result<()>;
}

/// What to change in the hive.
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub control_set: String,
    pub boot_start: Vec<String>,
    pub overrides: Vec<String>,
}

/// Work out the changes. `driver_present(file)` says whether a driver file
/// (e.g. `storahci.sys`) is in the installation's System32\drivers.
pub fn plan(h: &dyn Hive, driver_present: &dyn Fn(&str) -> bool) -> Option<Plan> {
    let current = h.dword("Select", "Current")?;
    let cs = format!("ControlSet{current:03}");
    if !h.key_exists(&cs) {
        return None;
    }
    let mut p = Plan {
        control_set: cs.clone(),
        ..Default::default()
    };
    for svc in STORAGE_DRIVERS {
        let key = format!(r"{cs}\Services\{svc}");
        if !h.key_exists(&key) {
            continue;
        }
        let file = h
            .string(&key, "ImagePath")
            .and_then(|p| p.rsplit(['\\', '/']).next().map(str::to_string))
            .unwrap_or_else(|| format!("{svc}.sys"));
        if !driver_present(&file) {
            continue;
        }
        if h.dword(&key, "Start") != Some(0) {
            p.boot_start.push(svc.to_string());
        }
        if h.key_exists(&format!(r"{key}\StartOverride")) {
            p.overrides.push(svc.to_string());
        }
    }
    Some(p)
}

/// Case-insensitive path under `root`.
fn find_ci(root: &Path, parts: &[&str]) -> Option<PathBuf> {
    let mut cur = root.to_path_buf();
    for part in parts {
        let next = std::fs::read_dir(&cur).ok()?.flatten().find(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(part))
        })?;
        cur = next.path();
    }
    Some(cur)
}

/// The SYSTEM hive and drivers folder of a Windows installation mounted at
/// `root`, if there is one.
pub fn find_windows(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let hive = find_ci(root, &["Windows", "System32", "config", "SYSTEM"])?;
    let drivers = find_ci(root, &["Windows", "System32", "drivers"])?;
    hive.is_file().then_some((hive, drivers))
}

/// A hive whose last changes are still only in its transaction logs
/// (sequence numbers differ): Windows would replay the logs over offline
/// edits, so it is left alone.
pub fn hive_is_dirty(path: &Path) -> anyhow::Result<bool> {
    use std::io::Read;
    let mut b = [0u8; 12];
    while_locked(|| std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut b)))
        .with_context(|| format!("reading {}", path.display()))?;
    if &b[..4] != b"regf" {
        bail!("{} is not a registry hive", path.display());
    }
    Ok(b[4..8] != b[8..12])
}

/// Run `f` again while the file it opens is held by another program (on a
/// volume Windows has just mounted, the indexer or a virus scanner often
/// opens files for a moment): sharing or lock violations, for up to a minute.
pub fn while_locked<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let start = std::time::Instant::now();
    loop {
        match f() {
            // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
            Err(e)
                if matches!(e.raw_os_error(), Some(32) | Some(33))
                    && cfg!(windows)
                    && start.elapsed() < std::time::Duration::from_secs(60) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(500))
            }
            r => return r,
        }
    }
}

/// The original SYSTEM hive, kept next to it before it is changed.
pub const BACKUP_NAME: &str = "SYSTEM.fenrir-before-hardware";

/// Prepare the Windows installation mounted at `root` for this hardware.
/// `dirty` is [`hive_is_dirty`], checked by the caller before it opened the
/// hive (reg.exe holds a loaded hive exclusively, so it cannot be read then).
pub fn adapt(
    root: &Path,
    volume: &str,
    hive: &dyn Hive,
    hive_path: &Path,
    drivers_dir: &Path,
    dirty: bool,
) -> anyhow::Result<WindowsFix> {
    let mut fix = WindowsFix {
        volume: volume.to_string(),
        ..Default::default()
    };
    if dirty {
        fix.notes.push("The registry of the restored Windows has unsaved changes in its logs; its storage drivers were not changed.".into());
        return Ok(fix);
    }
    let present = |file: &str| find_ci(drivers_dir, &[file]).is_some_and(|p| p.is_file());
    let Some(p) = plan(hive, &present) else {
        fix.notes.push(
            "No current control set in the restored Windows registry; nothing changed.".into(),
        );
        return Ok(fix);
    };
    fix.control_set = p.control_set.clone();
    if !p.boot_start.is_empty() || !p.overrides.is_empty() {
        let backup = hive_path.with_file_name(BACKUP_NAME);
        if !backup.exists() {
            while_locked(|| std::fs::copy(hive_path, &backup))
                .context("keeping a copy of the registry")?;
        }
        let set: Vec<(String, String, u32)> = p
            .boot_start
            .iter()
            .map(|s| {
                (
                    format!(r"{}\Services\{s}", p.control_set),
                    "Start".to_string(),
                    0,
                )
            })
            .collect();
        let delete: Vec<String> = p
            .overrides
            .iter()
            .map(|s| format!(r"{}\Services\{s}\StartOverride", p.control_set))
            .collect();
        hive.apply(&set, &delete)?;
    }
    fix.boot_start = p.boot_start;
    fix.overrides_removed = p.overrides;
    let _ = root;
    Ok(fix)
}

// ---------------------------------------------------------------------------
// hivex (Linux recovery media)
// ---------------------------------------------------------------------------

#[cfg_attr(windows, allow(dead_code))]
pub struct HivexHive {
    pub path: PathBuf,
}

#[cfg_attr(windows, allow(dead_code))]
impl HivexHive {
    fn get(&self, key: &str, name: Option<&str>) -> Option<String> {
        let mut c = Command::new("hivexget");
        c.arg(&self.path).arg(format!(r"\{key}"));
        if let Some(n) = name {
            c.arg(n);
        }
        let o = c.output().ok()?;
        o.status.success().then(|| {
            String::from_utf8_lossy(&o.stdout)
                .trim_end_matches('\n')
                .to_string()
        })
    }
}

impl Hive for HivexHive {
    fn dword(&self, key: &str, name: &str) -> Option<u32> {
        self.get(key, Some(name))?.trim().parse().ok()
    }
    fn string(&self, key: &str, name: &str) -> Option<String> {
        self.get(key, Some(name))
    }
    fn key_exists(&self, key: &str) -> bool {
        self.get(key, None).is_some()
    }
    fn apply(&self, set: &[(String, String, u32)], delete: &[String]) -> anyhow::Result<()> {
        let mut reg = String::from("Windows Registry Editor Version 5.00\n\n");
        for (key, name, v) in set {
            reg += &format!("[HKEY_LOCAL_MACHINE\\SYSTEM\\{key}]\n\"{name}\"=dword:{v:08x}\n\n");
        }
        for key in delete {
            reg += &format!("[-HKEY_LOCAL_MACHINE\\SYSTEM\\{key}]\n\n");
        }
        let file = self.path.with_file_name("fenrir-hardware.reg");
        std::fs::write(&file, reg)?;
        let o = Command::new("hivexregedit")
            .args(["--merge", "--prefix", r"HKEY_LOCAL_MACHINE\SYSTEM"])
            .arg(&self.path)
            .arg(&file)
            .output()
            .context("running hivexregedit")?;
        let _ = std::fs::remove_file(&file);
        if !o.status.success() {
            bail!(
                "hivexregedit: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Ok(())
    }
}

/// Linux recovery media: after a Windows disk was restored to `device`,
/// find the Windows volume on it (the NTFS partitions, largest first),
/// mount it, and prepare it. `None` when the disk holds no Windows.
#[cfg(target_os = "linux")]
pub fn adapt_restored_disk(device: &str) -> anyhow::Result<Option<WindowsFix>> {
    // The kernel reads the restored partition table.
    let _ = Command::new("blockdev")
        .args(["--rereadpt", device])
        .status();
    let _ = Command::new("udevadm").arg("settle").status();
    let mut parts = partitions(device);
    parts.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    let ntfs: Vec<String> = parts
        .into_iter()
        .map(|(node, _)| node)
        .filter(|node| {
            Command::new("blkid")
                .args(["-o", "value", "-s", "TYPE", node])
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "ntfs")
        })
        .collect();
    if ntfs.is_empty() {
        return Ok(None);
    }
    if Command::new("hivexget").arg("--help").output().is_err() {
        bail!("the hivex tools are not on this recovery medium");
    }
    let mnt = crate::recovery::runtime_dir().join("windows");
    std::fs::create_dir_all(&mnt)?;
    for node in ntfs {
        let mounted = ["ntfs3", "ntfs-3g"].iter().any(|fs| {
            Command::new("mount")
                .args(["-t", fs, "-o", "rw"])
                .arg(&node)
                .arg(&mnt)
                .status()
                .is_ok_and(|s| s.success())
        });
        if !mounted {
            continue;
        }
        let r = match find_windows(&mnt) {
            Some((hive, drivers)) => hive_is_dirty(&hive)
                .and_then(|dirty| {
                    adapt(
                        &mnt,
                        &node,
                        &HivexHive { path: hive.clone() },
                        &hive,
                        &drivers,
                        dirty,
                    )
                })
                .map(Some),
            None => Ok(None),
        };
        let _ = Command::new("sync").status();
        let _ = Command::new("umount").arg(&mnt).status();
        match r {
            Ok(Some(mut fix)) => {
                fix.notes.push("Drivers that do not come with Windows (some RAID controllers) can only be added from Windows PE recovery media.".into());
                return Ok(Some(fix));
            }
            Ok(None) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Partitions of a whole disk as the kernel lists them: (device node, bytes).
#[cfg(target_os = "linux")]
fn partitions(device: &str) -> Vec<(String, u64)> {
    let Some(name) = Path::new(device).file_name().and_then(|n| n.to_str()) else {
        return vec![];
    };
    let dir = Path::new("/sys/class/block").join(name);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    rd.flatten()
        .filter(|e| e.path().join("partition").exists())
        .map(|e| {
            let size = std::fs::read_to_string(e.path().join("size"))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
                * 512;
            (format!("/dev/{}", e.file_name().to_string_lossy()), size)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// reg.exe and DISM (Windows PE)
// ---------------------------------------------------------------------------

/// `    Start    REG_DWORD    0x3` → ("REG_DWORD", "0x3").
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_reg_query(out: &str, name: &str) -> Option<(String, String)> {
    out.lines().find_map(|l| {
        let rest = l.trim().strip_prefix(name)?;
        let mut it = rest.split_whitespace();
        let typ = it.next()?.to_string();
        if !typ.starts_with("REG_") {
            return None;
        }
        Some((typ, it.collect::<Vec<_>>().join(" ")))
    })
}

/// A hive loaded under `HKLM\FenrirOffline` with reg.exe; unloaded on drop.
#[cfg(windows)]
pub struct RegHive;

#[cfg(windows)]
const OFFLINE: &str = r"HKLM\FenrirOffline";

#[cfg(windows)]
fn reg(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("reg.exe").args(args).output()
}

#[cfg(windows)]
impl RegHive {
    pub fn load(path: &Path) -> anyhow::Result<RegHive> {
        let p = path.to_string_lossy().to_string();
        // A program that had the file open for a moment (see while_locked).
        for _ in 0..60 {
            let o = reg(&["load", OFFLINE, &p]).context("running reg.exe")?;
            if o.status.success() {
                return Ok(RegHive);
            }
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !err.contains("used by another process") {
                bail!("reg load: {err}");
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        bail!("reg load: {p} stayed in use by another program")
    }

    fn query(&self, key: &str, name: &str) -> Option<(String, String)> {
        let full = format!(r"{OFFLINE}\{key}");
        let o = reg(&["query", &full, "/v", name]).ok()?;
        if !o.status.success() {
            return None;
        }
        parse_reg_query(&String::from_utf8_lossy(&o.stdout), name)
    }
}

#[cfg(windows)]
impl Drop for RegHive {
    fn drop(&mut self) {
        let _ = reg(&["unload", OFFLINE]);
    }
}

#[cfg(windows)]
impl Hive for RegHive {
    fn dword(&self, key: &str, name: &str) -> Option<u32> {
        let (_, v) = self.query(key, name)?;
        u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()
    }
    fn string(&self, key: &str, name: &str) -> Option<String> {
        self.query(key, name).map(|(_, v)| v)
    }
    fn key_exists(&self, key: &str) -> bool {
        reg(&["query", &format!(r"{OFFLINE}\{key}")]).is_ok_and(|o| o.status.success())
    }
    fn apply(&self, set: &[(String, String, u32)], delete: &[String]) -> anyhow::Result<()> {
        for (key, name, v) in set {
            let k = format!(r"{OFFLINE}\{key}");
            let o = reg(&[
                "add",
                &k,
                "/v",
                name,
                "/t",
                "REG_DWORD",
                "/d",
                &v.to_string(),
                "/f",
            ])?;
            if !o.status.success() {
                bail!(
                    "reg add {key}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
        }
        for key in delete {
            let o = reg(&["delete", &format!(r"{OFFLINE}\{key}"), "/f"])?;
            if !o.status.success() {
                bail!(
                    "reg delete {key}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
        }
        Ok(())
    }
}

/// For a dirty hive: `adapt` returns before reading it.
#[cfg(windows)]
struct NoHive;

#[cfg(windows)]
impl Hive for NoHive {
    fn dword(&self, _: &str, _: &str) -> Option<u32> {
        None
    }
    fn string(&self, _: &str, _: &str) -> Option<String> {
        None
    }
    fn key_exists(&self, _: &str) -> bool {
        false
    }
    fn apply(&self, _: &[(String, String, u32)], _: &[String]) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Driver folders to add on Windows PE: the media's own, and a
/// `fenrir-drivers` folder in the root of any drive.
#[cfg(windows)]
fn driver_folders() -> Vec<PathBuf> {
    let mut v = vec![crate::recovery::runtime_dir().join("drivers")];
    for d in b'C'..=b'Z' {
        v.push(PathBuf::from(format!(r"{}:\fenrir-drivers", d as char)));
    }
    v.into_iter()
        .filter(|p| std::fs::read_dir(p).is_ok_and(|mut r| r.next().is_some()))
        .collect()
}

/// Windows (PE): after a Windows disk was restored to `device`
/// (`\\.\PhysicalDriveN`) and Windows read its new partition table, find
/// the Windows volume, set its storage drivers to start at boot, and add
/// driver packages with DISM.
#[cfg(windows)]
pub fn adapt_restored_disk(device: &str) -> anyhow::Result<Option<WindowsFix>> {
    use snapshot_win::win::disks;
    let n = disks::disk_number(device).context("not a physical disk")?;
    // The restored volumes appear shortly after the partition table is re-read.
    let mut vols = Vec::new();
    for _ in 0..30 {
        vols = disks::volumes_on_disk(n);
        if !vols.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    vols.sort_by_key(|v| std::cmp::Reverse(v.2));
    let folder = crate::recovery::runtime_dir().join("windows");
    for (vol, _, _) in vols {
        let root = match disks::volume_root(&vol, &folder) {
            Ok(r) => r,
            Err(e) => {
                crate::log::warn(&format!("{vol}: {e}"));
                continue;
            }
        };
        let Some((hive_path, drivers)) = find_windows(&root.root) else {
            continue;
        };
        let mut fix = if hive_is_dirty(&hive_path)? {
            adapt(&root.root, &vol, &NoHive, &hive_path, &drivers, true)?
        } else {
            // reg.exe holds a loaded hive open exclusively: keep the copy of
            // the original first (adapt finds it there), and drop it again if
            // nothing changed.
            let backup = hive_path.with_file_name(BACKUP_NAME);
            let made = !backup.exists();
            if made {
                while_locked(|| std::fs::copy(&hive_path, &backup)).with_context(|| {
                    format!("keeping a copy of the registry as {}", backup.display())
                })?;
            }
            let fix = {
                let h = RegHive::load(&hive_path)
                    .with_context(|| format!("loading {}", hive_path.display()))?;
                adapt(&root.root, &vol, &h, &hive_path, &drivers, false)?
            };
            if made && fix.boot_start.is_empty() && fix.overrides_removed.is_empty() {
                let _ = std::fs::remove_file(&backup);
            }
            fix
        };
        let image = root.root.to_string_lossy().to_string();
        for d in driver_folders() {
            let o = Command::new("dism.exe")
                .arg(format!("/Image:{image}"))
                .arg("/Add-Driver")
                .arg(format!("/Driver:{}", d.display()))
                .arg("/Recurse")
                .output();
            match o {
                Ok(o) if o.status.success() => fix.drivers_added.push(d.display().to_string()),
                Ok(o) => fix.notes.push(format!(
                    "DISM could not add the drivers in {}: {}",
                    d.display(),
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("")
                        .trim()
                )),
                Err(e) => fix.notes.push(format!("DISM is not available: {e}")),
            }
        }
        return Ok(Some(fix));
    }
    Ok(None)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn adapt_restored_disk(_device: &str) -> anyhow::Result<Option<WindowsFix>> {
    Ok(None)
}

#[cfg(test)]
pub(crate) mod testhive {
    //! A minimal registry hive (regf) for tests: base block, one hbin, nk/vk/lh/sk cells.

    pub enum V {
        Dword(u32),
        Str(&'static str),
    }
    pub struct K {
        pub name: &'static str,
        pub values: Vec<(&'static str, V)>,
        pub keys: Vec<K>,
    }

    pub fn build(root: &K) -> Vec<u8> {
        let mut cells: Vec<u8> = Vec::new();
        fn alloc(cells: &mut Vec<u8>, data: &[u8]) -> u32 {
            let size = (data.len() + 4).div_ceil(8) * 8;
            let off = cells.len() as u32 + 32;
            cells.extend((-(size as i32)).to_le_bytes());
            cells.extend(data);
            cells.resize(cells.len() + size - 4 - data.len(), 0);
            off
        }
        fn patch(cells: &mut [u8], off: u32, at: usize, v: u32) {
            let p = off as usize - 32 + 4 + at;
            cells[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        let desc = [
            1u8, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut sk = b"sk".to_vec();
        sk.extend([0u8; 2]);
        sk.extend([0u8; 12]);
        sk.extend((desc.len() as u32).to_le_bytes());
        sk.extend(desc);
        let sk = alloc(&mut cells, &sk);
        patch(&mut cells, sk, 4, sk);
        patch(&mut cells, sk, 8, sk);
        fn hash(n: &str) -> u32 {
            n.to_uppercase()
                .chars()
                .fold(0u32, |h, c| h.wrapping_mul(37).wrapping_add(c as u32))
        }
        fn node(
            cells: &mut Vec<u8>,
            k: &K,
            parent: u32,
            sk: u32,
            root: bool,
            count: &mut u32,
        ) -> u32 {
            *count += 1;
            let mut nk = b"nk".to_vec();
            nk.extend((if root { 0x2Cu16 } else { 0x20 }).to_le_bytes());
            nk.extend([0u8; 8]);
            let words = [
                0,
                parent,
                k.keys.len() as u32,
                0,
                u32::MAX,
                u32::MAX,
                k.values.len() as u32,
                u32::MAX,
                sk,
                u32::MAX,
                0,
                0,
                0,
                0,
                0,
            ];
            for w in words {
                nk.extend(w.to_le_bytes());
            }
            nk.extend((k.name.len() as u16).to_le_bytes());
            nk.extend(0u16.to_le_bytes());
            nk.extend(k.name.as_bytes());
            let me = alloc(cells, &nk);
            if !k.values.is_empty() {
                let mut vks = Vec::new();
                for (name, v) in &k.values {
                    let (typ, data): (u32, Vec<u8>) = match v {
                        V::Dword(d) => (4, d.to_le_bytes().to_vec()),
                        V::Str(s) => (
                            2,
                            s.encode_utf16()
                                .chain([0])
                                .flat_map(|c| c.to_le_bytes())
                                .collect(),
                        ),
                    };
                    let (len, off) = if data.len() <= 4 {
                        let mut d = [0u8; 4];
                        d[..data.len()].copy_from_slice(&data);
                        (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(d))
                    } else {
                        (data.len() as u32, alloc(cells, &data))
                    };
                    let mut vk = b"vk".to_vec();
                    vk.extend((name.len() as u16).to_le_bytes());
                    vk.extend(len.to_le_bytes());
                    vk.extend(off.to_le_bytes());
                    vk.extend(typ.to_le_bytes());
                    vk.extend(1u16.to_le_bytes());
                    vk.extend(0u16.to_le_bytes());
                    vk.extend(name.as_bytes());
                    vks.push(alloc(cells, &vk));
                }
                let list: Vec<u8> = vks.iter().flat_map(|v| v.to_le_bytes()).collect();
                let vl = alloc(cells, &list);
                patch(cells, me, 40, vl);
            }
            if !k.keys.is_empty() {
                let mut kids: Vec<&K> = k.keys.iter().collect();
                kids.sort_by_key(|c| c.name.to_uppercase());
                let mut lh = b"lh".to_vec();
                lh.extend((kids.len() as u16).to_le_bytes());
                for c in kids {
                    let off = node(cells, c, me, sk, false, count);
                    lh.extend(off.to_le_bytes());
                    lh.extend(hash(c.name).to_le_bytes());
                }
                let l = alloc(cells, &lh);
                patch(cells, me, 28, l);
            }
            me
        }
        let mut count = 0;
        let root_off = node(&mut cells, root, 0, sk, true, &mut count);
        patch(&mut cells, sk, 12, count);
        let size = (cells.len() + 32).div_ceil(4096) * 4096;
        let free = size - 32 - cells.len();
        if free > 0 {
            cells.extend((free as i32).to_le_bytes());
            cells.resize(cells.len() + free - 4, 0);
        }
        let mut base = vec![0u8; 4096];
        base[..4].copy_from_slice(b"regf");
        for (i, w) in [1u32, 1, 0, 0, 1, 3, 0, 1, root_off, size as u32, 1]
            .iter()
            .enumerate()
        {
            // seq1, seq2, timestamp (2 words), major, minor, type, format, root, size, clustering
            base[4 + i * 4..8 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        let sum = (0..127).fold(0u32, |s, i| {
            s ^ u32::from_le_bytes(base[i * 4..i * 4 + 4].try_into().unwrap())
        });
        base[508..512].copy_from_slice(&sum.to_le_bytes());
        let mut out = base;
        out.extend(b"hbin");
        out.extend(0u32.to_le_bytes());
        out.extend((size as u32).to_le_bytes());
        out.extend([0u8; 20]);
        out.extend(cells);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testhive::{build, K, V};
    use super::*;

    fn svc(name: &'static str, start: u32, overrides: bool) -> K {
        K {
            name,
            values: vec![
                ("Start", V::Dword(start)),
                (
                    "ImagePath",
                    V::Str(match name {
                        "storahci" => r"System32\drivers\storahci.sys",
                        "stornvme" => r"\SystemRoot\System32\drivers\stornvme.sys",
                        "iaStorV" => r"System32\drivers\iaStorV.sys",
                        _ => r"System32\drivers\other.sys",
                    }),
                ),
            ],
            keys: if overrides {
                vec![K {
                    name: "StartOverride",
                    values: vec![("0", V::Dword(3))],
                    keys: vec![],
                }]
            } else {
                vec![]
            },
        }
    }

    fn windows(root: &Path, seq_dirty: bool) -> PathBuf {
        let hive = build(&K {
            name: "ROOT",
            values: vec![],
            keys: vec![
                K {
                    name: "Select",
                    values: vec![("Current", V::Dword(1))],
                    keys: vec![],
                },
                K {
                    name: "ControlSet001",
                    values: vec![],
                    keys: vec![K {
                        name: "Services",
                        values: vec![],
                        keys: vec![
                            svc("storahci", 3, true),
                            svc("stornvme", 3, false),
                            svc("iaStorV", 4, false),
                            svc("Tcpip", 1, false),
                            svc("storvsc", 0, false),
                        ],
                    }],
                },
            ],
        });
        let cfg = root.join("Windows/System32/config");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(root.join("Windows/System32/drivers")).unwrap();
        // File names differ in case on purpose: lookups are case-insensitive.
        for f in ["storahci.sys", "STORNVME.SYS", "storvsc.sys"] {
            std::fs::write(root.join("Windows/System32/drivers").join(f), b"MZ").unwrap();
        }
        let mut h = hive;
        if seq_dirty {
            h[4] = 7;
        }
        let p = cfg.join("SYSTEM");
        std::fs::write(&p, h).unwrap();
        p
    }

    fn hivex() -> bool {
        let ok = Command::new("hivexregedit").arg("--help").output().is_ok()
            && Command::new("hivexget").arg("--help").output().is_ok();
        if !ok {
            eprintln!("hivex tools not installed (libhivex-bin, libwin-hivex-perl): skipped");
        }
        ok
    }

    #[test]
    fn storage_drivers_start_at_boot_and_overrides_go() {
        if !hivex() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let hive = windows(t.path(), false);
        let (found, drivers) = find_windows(t.path()).unwrap();
        assert_eq!(found, hive);
        let h = HivexHive { path: hive.clone() };
        let fix = adapt(
            t.path(),
            "/dev/sda3",
            &h,
            &hive,
            &drivers,
            hive_is_dirty(&hive).unwrap(),
        )
        .unwrap();
        assert_eq!(fix.control_set, "ControlSet001");
        // iaStorV has no driver file; storvsc already starts at boot.
        assert_eq!(fix.boot_start, vec!["storahci", "stornvme"]);
        assert_eq!(fix.overrides_removed, vec!["storahci"]);
        assert_eq!(
            h.dword(r"ControlSet001\Services\storahci", "Start"),
            Some(0)
        );
        assert_eq!(
            h.dword(r"ControlSet001\Services\stornvme", "Start"),
            Some(0)
        );
        assert_eq!(h.dword(r"ControlSet001\Services\iaStorV", "Start"), Some(4));
        assert_eq!(h.dword(r"ControlSet001\Services\Tcpip", "Start"), Some(1));
        assert!(!h.key_exists(r"ControlSet001\Services\storahci\StartOverride"));
        assert_eq!(
            h.string(r"ControlSet001\Services\storahci", "ImagePath")
                .as_deref(),
            Some(r"System32\drivers\storahci.sys"),
            "other values are kept"
        );
        assert!(hive
            .with_file_name("SYSTEM.fenrir-before-hardware")
            .is_file());
        // Running again changes nothing.
        let again = adapt(
            t.path(),
            "/dev/sda3",
            &h,
            &hive,
            &drivers,
            hive_is_dirty(&hive).unwrap(),
        )
        .unwrap();
        assert!(again.boot_start.is_empty() && again.overrides_removed.is_empty());
    }

    #[test]
    fn a_dirty_hive_is_left_alone() {
        let t = tempfile::tempdir().unwrap();
        let hive = windows(t.path(), true);
        let (_, drivers) = find_windows(t.path()).unwrap();
        let before = std::fs::read(&hive).unwrap();
        let h = HivexHive { path: hive.clone() };
        let fix = adapt(
            t.path(),
            "x",
            &h,
            &hive,
            &drivers,
            hive_is_dirty(&hive).unwrap(),
        )
        .unwrap();
        assert!(fix.boot_start.is_empty() && fix.notes[0].contains("unsaved"));
        assert_eq!(std::fs::read(&hive).unwrap(), before);
    }

    #[test]
    fn reg_query_output_is_parsed() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\FenrirOffline\\Select\r\n    Current    REG_DWORD    0x1\r\n\r\n";
        assert_eq!(
            parse_reg_query(out, "Current"),
            Some(("REG_DWORD".into(), "0x1".into()))
        );
        let out =
            "    ImagePath    REG_EXPAND_SZ    \\SystemRoot\\System32\\drivers\\stornvme.sys\r\n";
        assert_eq!(
            parse_reg_query(out, "ImagePath").unwrap().1,
            r"\SystemRoot\System32\drivers\stornvme.sys"
        );
        assert_eq!(
            parse_reg_query("    Start2    REG_DWORD    0x0", "Start"),
            None
        );
    }

    #[test]
    fn no_windows_no_change() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        assert!(find_windows(t.path()).is_none());
    }
}
