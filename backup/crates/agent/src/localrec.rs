//! Local recovery partition (docs/design/local-recovery.md).
//!
//! A "Fenrir Recovery" partition on the system disk holds a recovery system
//! built from this machine's own Windows Recovery Environment (winre.wim,
//! part of every Windows 10/11): the agent, its recovery settings (this
//! server and an enrolment code for recovery sessions) and the machine's
//! network and storage drivers are added to a copy of it. A boot menu entry
//! starts it from a RAM disk. When Windows no longer starts, it connects to
//! the server as a recovery session and restores the machine (onto the same
//! disk or another one) like the recovery media do.
//!
//! Installing shrinks the system volume, so the job needs the machine's name
//! typed as confirmation; removing deletes the partition and gives the space
//! back to the system volume.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Where the agent remembers what it installed.
pub const STATE_FILE: &str = "local-recovery.json";
/// Files in the partition.
pub const DIR: &str = "Fenrir";
pub const LABEL: &str = "Fenrir Recovery";
pub const GPT_RECOVERY: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";
/// Hidden, no drive letter, required by the platform (like Windows RE).
pub const GPT_ATTRIBUTES: &str = "0x8000000000000001";
/// Driver classes the recovery system and a restored Windows need.
pub const DRIVER_CLASSES: &[&str] = &["Net", "SCSIAdapter", "HDC"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub disk: u32,
    pub partition: u32,
    /// Byte offset of the partition on the disk (its identity).
    pub offset: u64,
    pub size: u64,
    /// The volume it was carved from (e.g. "C").
    pub volume: String,
    pub bcd_entry: String,
    pub ramdisk_entry: String,
    /// `recoverysequence` of the Windows entry before we set ours.
    #[serde(default)]
    pub previous_recovery: Option<String>,
    pub auto_start: bool,
    pub built_unix: i64,
    pub agent_version: String,
    #[serde(default)]
    pub expires: u64,
}

impl State {
    pub fn info(&self) -> protocol::LocalRecoveryInfo {
        protocol::LocalRecoveryInfo {
            disk: self.disk,
            partition: self.partition,
            size: self.size,
            built_unix: self.built_unix,
            agent_version: self.agent_version.clone(),
            expires: self.expires,
            auto_start: self.auto_start,
        }
    }
}

pub fn load_state(dir: &Path) -> Option<State> {
    serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).ok()?).ok()
}

/// `Windows RE location:  \\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE`
/// from `reagentc /info` (None when Windows RE is disabled or not set up).
pub fn parse_reagentc(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        let v = v.trim();
        (k.trim().eq_ignore_ascii_case("Windows RE location") && v.starts_with(r"\\?\"))
            .then(|| v.to_string())
    })
}

/// The `{guid}` in bcdedit's "The entry {...} was successfully created."
pub fn parse_bcd_guid(out: &str) -> Option<String> {
    let start = out.find('{')?;
    let end = start + out[start..].find('}')?;
    let g = &out[start..=end];
    (g.len() == 38 && g[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        .then(|| g.to_string())
}

/// `recoverysequence {guid}` of `bcdedit /enum {current}`.
pub fn parse_recovery_sequence(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next()? == "recoverysequence")
            .then(|| f.next().map(str::to_string))
            .flatten()
    })
}

/// Partition size for a recovery image of `wim` bytes: room for it, the
/// RAM disk file and a rebuild that grows a little, in whole 64 MiB.
pub fn size_for(wim: u64, sdi: u64, asked_mb: u32) -> u64 {
    let need = wim + wim / 4 + sdi + (128 << 20);
    let want = (asked_mb as u64) << 20;
    let s = need.max(want).max(768 << 20);
    s.div_ceil(64 << 20) * (64 << 20)
}

/// What starts in the recovery system: network, the agent, a status window.
pub const STARTNET: &str = "@echo off\r\nwpeinit\r\ntitle Fenrir Recovery\r\nstart \"Fenrir-Backup agent\" /min X:\\Windows\\System32\\fenrir-backup-agent.exe recovery\r\nX:\\Windows\\System32\\cmd.exe /k X:\\fenrir\\status.cmd\r\n";

pub fn status_cmd(machine: &str) -> String {
    format!(
        "@echo off\r\n:loop\r\ncls\r\necho  Fenrir Recovery for {machine}\r\necho  ==============================\r\necho.\r\n\
         if exist X:\\fenrir\\status (type X:\\fenrir\\status) else (echo  starting ...)\r\necho.\r\n\
         ipconfig | findstr /i \"IPv4\"\r\necho.\r\n\
         echo  Continue in the web UI: Machines ^> Recovery sessions: restore this machine from its backups.\r\n\
         echo  Drivers for the restored Windows: a fenrir-drivers folder on a USB stick.\r\necho.\r\n\
         echo  [Enter] refresh   [c] command prompt   [w] start Windows   [s] shut down\r\n\
         set /p k=\" > \"\r\n\
         if /i \"%k%\"==\"c\" (start cmd.exe & goto loop)\r\n\
         if /i \"%k%\"==\"w\" (wpeutil reboot)\r\n\
         if /i \"%k%\"==\"s\" (wpeutil shutdown)\r\ngoto loop\r\n"
    )
}

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{anyhow, bail, Context};
    use std::path::PathBuf;
    use std::process::Command;

    pub struct Options<'a> {
        /// The volume to shrink (normally "C").
        pub volume: &'a str,
        pub size_mb: u32,
        pub auto_start: bool,
        pub settings: &'a protocol::recovery::RecoveryConfig,
        /// Instead of this machine's Windows RE (tests: Windows PE from the ADK).
        pub base_wim: Option<&'a Path>,
        pub machine: &'a str,
    }

    fn run(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
        let o = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("running {cmd}"))?;
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        if !o.status.success() {
            let last = out
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim()
                .to_string();
            bail!(
                "{cmd} {}: {last} {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Ok(out)
    }

    fn diskpart(script: &str) -> anyhow::Result<String> {
        let f = std::env::temp_dir().join(format!("fenrir-dp-{}.txt", std::process::id()));
        std::fs::write(&f, script)?;
        let r = run("diskpart.exe", &["/s", &f.to_string_lossy()]);
        let _ = std::fs::remove_file(&f);
        r
    }

    fn ps(script: &str) -> anyhow::Result<String> {
        crate::hyperv::run_ps(&format!("$ErrorActionPreference = 'Stop'\n{script}"))
    }

    fn work_dir() -> PathBuf {
        crate::config::state_dir().join("local-recovery-work")
    }

    /// This machine's winre.wim and boot.sdi (copied into `dir`).
    fn base_files(dir: &Path, base_wim: Option<&Path>) -> anyhow::Result<(PathBuf, PathBuf)> {
        let wim = dir.join("boot.wim");
        let sdi = dir.join("boot.sdi");
        let windir =
            PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
        let re = run("reagentc.exe", &["/info"])
            .ok()
            .and_then(|o| parse_reagentc(&o))
            .map(PathBuf::from);
        let candidates: Vec<PathBuf> = match base_wim {
            Some(b) => vec![b.to_path_buf()],
            None => re
                .iter()
                .map(|d| d.join("Winre.wim"))
                .chain([windir.join(r"System32\Recovery\Winre.wim")])
                .collect(),
        };
        let src = candidates.iter().find(|p| std::fs::copy(p, &wim).is_ok()).ok_or_else(|| {
            anyhow!("this Windows has no recovery environment (winre.wim) to build from; repair it with reagentc /enable, or use recovery media instead")
        })?;
        let sdis: Vec<PathBuf> = re
            .iter()
            .map(|d| d.join("boot.sdi"))
            .chain(src.parent().map(|p| p.join("boot.sdi")))
            .chain([
                windir.join(r"Boot\DVD\EFI\boot.sdi"),
                windir.join(r"Boot\DVD\PCAT\boot.sdi"),
            ])
            .collect();
        sdis.iter()
            .find(|p| std::fs::copy(p, &sdi).is_ok())
            .ok_or_else(|| anyhow!("boot.sdi (the RAM disk file) is missing from this Windows"))?;
        Ok((wim, sdi))
    }

    /// Export this machine's network and storage drivers.
    fn export_drivers(dir: &Path) -> Vec<String> {
        let _ = std::fs::create_dir_all(dir);
        let list = ps(&format!(
            "Get-WindowsDriver -Online | Where-Object {{ @('{}') -contains $_.ClassName }} | ForEach-Object {{ $_.Driver }}",
            DRIVER_CLASSES.join("','")
        ))
        .unwrap_or_default();
        let mut done = Vec::new();
        for inf in list
            .lines()
            .map(str::trim)
            .filter(|l| l.to_ascii_lowercase().ends_with(".inf"))
        {
            let to = dir.join(inf.trim_end_matches(".inf"));
            let _ = std::fs::create_dir_all(&to);
            if run(
                "pnputil.exe",
                &["/export-driver", inf, &to.to_string_lossy()],
            )
            .is_ok()
            {
                done.push(inf.to_string());
            }
        }
        done
    }

    /// Build the recovery image in the work folder. Returns (wim, sdi, notes).
    fn build(o: &Options) -> anyhow::Result<(PathBuf, PathBuf, Vec<String>)> {
        let dir = work_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let (wim, sdi) = base_files(&dir, o.base_wim)?;
        let drivers = dir.join("drivers");
        let exported = export_drivers(&drivers);
        let mount = dir.join("mount");
        std::fs::create_dir_all(&mount)?;
        let _ = run("dism.exe", &["/Cleanup-Mountpoints"]);
        run(
            "dism.exe",
            &[
                "/Mount-Image",
                &format!("/ImageFile:{}", wim.display()),
                "/Index:1",
                &format!("/MountDir:{}", mount.display()),
            ],
        )
        .context("mounting the recovery image")?;
        let mut notes = Vec::new();
        let r = (|| -> anyhow::Result<()> {
            let sys32 = mount.join(r"Windows\System32");
            std::fs::copy(
                std::env::current_exe()?,
                sys32.join("fenrir-backup-agent.exe"),
            )?;
            let fenrir = mount.join("fenrir");
            std::fs::create_dir_all(&fenrir)?;
            std::fs::write(
                fenrir.join("recovery.json"),
                serde_json::to_vec_pretty(o.settings)?,
            )?;
            std::fs::write(fenrir.join("status.cmd"), status_cmd(o.machine))?;
            std::fs::write(sys32.join("startnet.cmd"), STARTNET)?;
            // Without winpeshl.ini Windows PE runs startnet.cmd (Windows RE's
            // own ini starts its menus instead).
            let _ = std::fs::remove_file(sys32.join("winpeshl.ini"));
            if !exported.is_empty() {
                if let Err(e) = run(
                    "dism.exe",
                    &[
                        &format!("/Image:{}", mount.display()),
                        "/Add-Driver",
                        &format!("/Driver:{}", drivers.display()),
                        "/Recurse",
                    ],
                ) {
                    notes.push(format!(
                        "some of this machine's drivers could not be added: {e}"
                    ));
                }
                // Also for the restored Windows (hwfix adds X:\fenrir\drivers).
                copy_tree(&drivers, &fenrir.join("drivers"))?;
            }
            Ok(())
        })();
        let commit = if r.is_ok() { "/Commit" } else { "/Discard" };
        let u = run(
            "dism.exe",
            &[
                "/Unmount-Image",
                &format!("/MountDir:{}", mount.display()),
                commit,
            ],
        );
        r?;
        u.context("saving the recovery image")?;
        notes.push(format!(
            "{} network and storage driver packages of this machine included",
            exported.len()
        ));
        Ok((wim, sdi, notes))
    }

    fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(to)?;
        for e in std::fs::read_dir(from)? {
            let e = e?;
            let dst = to.join(e.file_name());
            if e.file_type()?.is_dir() {
                copy_tree(&e.path(), &dst)?;
            } else {
                std::fs::copy(e.path(), dst)?;
            }
        }
        Ok(())
    }

    #[derive(Deserialize)]
    struct Created {
        disk: u32,
        partition: u32,
        offset: u64,
        size: u64,
        letter: String,
        style: String,
    }

    const PS_CREATE: &str = r#"
$v = '__VOL__'; $size = [int64]__SIZE__
$c = Get-Partition -DriveLetter $v
$s = Get-PartitionSupportedSize -DriveLetter $v
$room = $c.Size - $s.SizeMin - 2GB - 16MB
if ($room -lt $size) { throw ("${v}: can give up at most {0} MB (the recovery partition needs {1} MB); free some space first" -f [math]::Max(0, [math]::Floor($room / 1MB)), [math]::Ceiling($size / 1MB)) }
# A little more than the partition: alignment takes some of the freed space.
Resize-Partition -DriveLetter $v -Size ($c.Size - $size - 16MB)
$p = New-Partition -DiskNumber $c.DiskNumber -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel '__LABEL__' -Confirm:$false | Out-Null
$p = Get-Partition -DiskNumber $c.DiskNumber -PartitionNumber $p.PartitionNumber
[pscustomobject]@{ disk = $c.DiskNumber; partition = $p.PartitionNumber; offset = $p.Offset; size = $p.Size;
  letter = [string]$p.DriveLetter; style = [string](Get-Disk -Number $c.DiskNumber).PartitionStyle } | ConvertTo-Json -Compress
"#;

    /// Our partition now (found by disk and offset), with a drive letter.
    fn open_partition(st: &State) -> anyhow::Result<String> {
        let out = ps(&format!(
            "$p = Get-Partition -DiskNumber {} | Where-Object {{ $_.Offset -eq {} }}\n\
             if (-not $p) {{ throw 'the recovery partition is gone' }}\n\
             if (-not $p.DriveLetter -or $p.DriveLetter -eq [char]0) {{ $p | Add-PartitionAccessPath -AssignDriveLetter; $p = Get-Partition -DiskNumber {} | Where-Object {{ $_.Offset -eq {} }} }}\n\
             [pscustomobject]@{{ partition = $p.PartitionNumber; letter = [string]$p.DriveLetter }} | ConvertTo-Json -Compress",
            st.disk, st.offset, st.disk, st.offset
        ))?;
        let v: serde_json::Value = serde_json::from_str(out.trim())?;
        let letter = v["letter"].as_str().unwrap_or("").to_string();
        if letter.is_empty() {
            bail!("could not give the recovery partition a drive letter");
        }
        Ok(letter)
    }

    /// Back to a hidden recovery partition without a letter.
    fn hide(disk: u32, partition: u32, letter: &str, gpt: bool) -> anyhow::Result<()> {
        let mut s = format!(
            "select disk {disk}\nselect partition {partition}\nremove letter={letter} noerr\n"
        );
        if gpt {
            s += &format!("set id={GPT_RECOVERY} override\ngpt attributes={GPT_ATTRIBUTES}\n");
        } else {
            s += "set id=27 override\n";
        }
        diskpart(&s).map(|_| ())
    }

    fn copy_in(letter: &str, wim: &Path, sdi: &Path) -> anyhow::Result<()> {
        let d = PathBuf::from(format!(r"{letter}:\{DIR}"));
        std::fs::create_dir_all(&d)?;
        let tmp = d.join("boot.wim.new");
        std::fs::copy(wim, &tmp).context("copying the recovery image to its partition")?;
        std::fs::rename(&tmp, d.join("boot.wim"))?;
        std::fs::copy(sdi, d.join("boot.sdi"))?;
        Ok(())
    }

    fn bcd(args: &[&str]) -> anyhow::Result<String> {
        run("bcdedit.exe", args)
    }

    /// Boot menu entry that starts the image from a RAM disk.
    fn add_boot_entry(letter: &str, uefi: bool) -> anyhow::Result<(String, String)> {
        let r = parse_bcd_guid(&bcd(&["/create", "/d", LABEL, "/device"])?)
            .ok_or_else(|| anyhow!("bcdedit did not create the RAM disk entry"))?;
        bcd(&[
            "/set",
            &r,
            "ramdisksdidevice",
            &format!("partition={letter}:"),
        ])?;
        bcd(&["/set", &r, "ramdisksdipath", &format!(r"\{DIR}\boot.sdi")])?;
        let o = parse_bcd_guid(&bcd(&["/create", "/d", LABEL, "/application", "osloader"])?)
            .ok_or_else(|| anyhow!("bcdedit did not create the boot entry"))?;
        let dev = format!(r"ramdisk=[{letter}:]\{DIR}\boot.wim,{r}");
        let winload = if uefi {
            r"\windows\system32\winload.efi"
        } else {
            r"\windows\system32\winload.exe"
        };
        for (k, v) in [
            ("device", dev.as_str()),
            ("osdevice", dev.as_str()),
            ("path", winload),
            ("systemroot", r"\windows"),
            ("winpe", "yes"),
            ("detecthal", "yes"),
        ] {
            bcd(&["/set", &o, k, v])?;
        }
        bcd(&["/displayorder", &o, "/addlast"])?;
        // The menu must be visible long enough to choose it.
        let t: u32 = bcd(&["/enum", "{bootmgr}"])
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.trim()
                        .strip_prefix("timeout")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
            })
            .unwrap_or(0);
        if t < 5 {
            bcd(&["/timeout", "5"])?;
        }
        Ok((o, r))
    }

    fn set_auto_start(st: &mut State, on: bool) -> anyhow::Result<()> {
        if on {
            if st.previous_recovery.is_none() {
                st.previous_recovery = parse_recovery_sequence(&bcd(&["/enum", "{current}"])?)
                    .filter(|g| *g != st.bcd_entry);
            }
            bcd(&["/set", "{current}", "recoverysequence", &st.bcd_entry])?;
            bcd(&["/set", "{current}", "recoveryenabled", "yes"])?;
        } else if parse_recovery_sequence(&bcd(&["/enum", "{current}"])?).as_deref()
            == Some(st.bcd_entry.as_str())
        {
            match &st.previous_recovery {
                Some(p) => bcd(&["/set", "{current}", "recoverysequence", p])?,
                None => bcd(&["/deletevalue", "{current}", "recoverysequence"])?,
            };
        }
        st.auto_start = on;
        Ok(())
    }

    fn save(st: &State) -> anyhow::Result<()> {
        let dir = crate::config::state_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(STATE_FILE), serde_json::to_vec_pretty(st)?)?;
        Ok(())
    }

    pub fn install(o: &Options) -> anyhow::Result<(State, Vec<String>)> {
        if crate::recovery::runtime_dir().starts_with(r"X:\") {
            bail!("local recovery is installed from Windows, not from recovery media");
        }
        if let Some(st) = load_state(&crate::config::state_dir()) {
            return refresh(&st, o);
        }
        let uefi = crate::inventory::firmware().0.as_deref() != Some("bios");
        let (wim, sdi, mut notes) = build(o)?;
        let size = size_for(
            std::fs::metadata(&wim)?.len(),
            std::fs::metadata(&sdi)?.len(),
            o.size_mb,
        );
        let out = ps(&PS_CREATE
            .replace("__VOL__", o.volume)
            .replace("__SIZE__", &size.to_string())
            .replace("__LABEL__", LABEL))
        .context("making room for the recovery partition")?;
        let c: Created = serde_json::from_str(out.trim()).context("reading the new partition")?;
        let gpt = c.style.eq_ignore_ascii_case("GPT");
        let mut st = State {
            disk: c.disk,
            partition: c.partition,
            offset: c.offset,
            size: c.size,
            volume: o.volume.to_string(),
            built_unix: core_format::timefmt::now_unix(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            expires: o.settings.expires,
            ..Default::default()
        };
        // From here on the partition exists: remember it so remove can undo.
        save(&st)?;
        copy_in(&c.letter, &wim, &sdi)?;
        let (e, r) = add_boot_entry(&c.letter, uefi)?;
        st.bcd_entry = e;
        st.ramdisk_entry = r;
        save(&st)?;
        set_auto_start(&mut st, o.auto_start)?;
        hide(c.disk, c.partition, &c.letter, gpt)?;
        save(&st)?;
        let _ = std::fs::remove_dir_all(work_dir());
        notes.push(format!(
            "{}: {} MB taken from {}: for the recovery partition",
            LABEL,
            c.size >> 20,
            o.volume
        ));
        Ok((st, notes))
    }

    pub fn refresh(old: &State, o: &Options) -> anyhow::Result<(State, Vec<String>)> {
        let (wim, sdi, mut notes) = build(o)?;
        let need = size_for(
            std::fs::metadata(&wim)?.len(),
            std::fs::metadata(&sdi)?.len(),
            0,
        );
        if need > old.size {
            bail!("the new recovery image needs {} MB and the partition has {} MB: remove local recovery and install it again", need >> 20, old.size >> 20);
        }
        let letter = open_partition(old)?;
        let gpt = ps(&format!(
            "[string](Get-Disk -Number {}).PartitionStyle",
            old.disk
        ))?
        .trim()
        .eq_ignore_ascii_case("GPT");
        let r = copy_in(&letter, &wim, &sdi);
        let part: u32 = ps(&format!(
            "(Get-Partition -DiskNumber {} | Where-Object {{ $_.Offset -eq {} }}).PartitionNumber",
            old.disk, old.offset
        ))?
        .trim()
        .parse()
        .unwrap_or(old.partition);
        hide(old.disk, part, &letter, gpt)?;
        r?;
        let mut st = old.clone();
        st.partition = part;
        st.built_unix = core_format::timefmt::now_unix();
        st.agent_version = env!("CARGO_PKG_VERSION").to_string();
        st.expires = o.settings.expires;
        if st.auto_start != o.auto_start {
            set_auto_start(&mut st, o.auto_start)?;
        }
        save(&st)?;
        let _ = std::fs::remove_dir_all(work_dir());
        notes.insert(0, "recovery image rebuilt".into());
        Ok((st, notes))
    }

    pub fn remove() -> anyhow::Result<Vec<String>> {
        let dir = crate::config::state_dir();
        let mut st = load_state(&dir)
            .ok_or_else(|| anyhow!("local recovery is not installed on this machine"))?;
        let mut notes = Vec::new();
        if !st.bcd_entry.is_empty() {
            set_auto_start(&mut st, false)?;
            for id in [st.bcd_entry.clone(), st.ramdisk_entry.clone()] {
                if id.is_empty() {
                    continue;
                }
                if let Err(e) =
                    bcd(&["/delete", &id, "/cleanup"]).or_else(|_| bcd(&["/delete", &id, "/f"]))
                {
                    notes.push(format!("boot entry {id} was not removed ({e}); remove it with bcdedit /delete {id}"));
                }
            }
        }
        let part = ps(&format!(
            "$p = Get-Partition -DiskNumber {} | Where-Object {{ $_.Offset -eq {} -and $_.Size -eq {} }}\nif ($p) {{ $p.PartitionNumber }}",
            st.disk, st.offset, st.size
        ))?;
        match part.trim().parse::<u32>() {
            Ok(n) => {
                diskpart(&format!(
                    "select disk {}\nselect partition {n}\ndelete partition override\n",
                    st.disk
                ))?;
                // The space goes back to the volume it came from, when it follows it.
                match ps(&format!("$s = Get-PartitionSupportedSize -DriveLetter {v}\nResize-Partition -DriveLetter {v} -Size $s.SizeMax", v = st.volume)) {
                    Ok(_) => notes.push(format!("the space went back to {}:", st.volume)),
                    Err(e) => notes.push(format!("the partition was deleted, but {}: could not take its space ({e}); extend it in Disk Management", st.volume)),
                }
            }
            Err(_) => notes.push("the recovery partition was already gone".into()),
        }
        let _ = std::fs::remove_file(dir.join(STATE_FILE));
        Ok(notes)
    }
}

#[cfg(windows)]
pub use imp::{install, remove, Options};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reagentc_location_is_parsed() {
        let out = "Windows Recovery Environment (Windows RE) and system reset configuration\nInformation:\n\n    Windows RE status:         Enabled\n    Windows RE location:       \\\\?\\GLOBALROOT\\device\\harddisk0\\partition4\\Recovery\\WindowsRE\n    Boot Configuration Data (BCD) identifier: 6a1b2c3d-0000-0000-0000-000000000000\n";
        assert_eq!(
            parse_reagentc(out).as_deref(),
            Some(r"\\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE")
        );
        assert_eq!(
            parse_reagentc("    Windows RE status:         Disabled\n    Windows RE location:\n"),
            None
        );
    }

    #[test]
    fn bcdedit_output_is_parsed() {
        assert_eq!(
            parse_bcd_guid(
                "The entry {1a2b3c4d-1111-2222-3333-444455556666} was successfully created."
            )
            .as_deref(),
            Some("{1a2b3c4d-1111-2222-3333-444455556666}")
        );
        assert_eq!(
            parse_bcd_guid("The operation completed successfully."),
            None
        );
        let e = "Windows Boot Loader\n-------------------\nidentifier              {current}\nrecoverysequence        {9d1f5e2a-1111-2222-3333-444455556666}\nrecoveryenabled         Yes\n";
        assert_eq!(
            parse_recovery_sequence(e).as_deref(),
            Some("{9d1f5e2a-1111-2222-3333-444455556666}")
        );
    }

    #[test]
    fn partition_size_has_room_to_grow() {
        let mb = 1u64 << 20;
        assert_eq!(size_for(400 * mb, 3 * mb, 0), 768 * mb, "at least 768 MiB");
        let s = size_for(700 * mb, 3 * mb, 0);
        assert!(s >= 700 * mb + 175 * mb + 131 * mb && s % (64 * mb) == 0);
        assert_eq!(
            size_for(400 * mb, 3 * mb, 2048),
            2048 * mb,
            "a larger size asked for"
        );
        assert!(STARTNET.contains("fenrir-backup-agent.exe recovery"));
        assert!(status_cmd("PC-01").contains("Fenrir Recovery for PC-01"));
    }
}
