//! macOS: folder backups (up to the whole Data volume) read from an APFS
//! local snapshot, so files are copied as they were at one moment. The
//! snapshot is made with `tmutil localsnapshot`, mounted read-only with
//! `mount_apfs -s`, and deleted afterwards. The sealed system volume is not
//! backed up: it is restored by reinstalling macOS, then the Data volume.
//!
//! Needs the agent to run as root with Full Disk Access (System Settings ›
//! Privacy & Security), like any backup of other users' files on macOS.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const DATA: &str = "/System/Volumes/Data";

pub struct Snapshot {
    /// `2026-11-24-123456` (tmutil's date), and the full snapshot name.
    date: String,
    mount: PathBuf,
    pub notes: Vec<String>,
}

/// `Created local snapshot with date: 2026-11-24-123456` → the date.
pub fn parse_created(out: &str) -> Option<String> {
    let d = out.rsplit(':').next()?.trim();
    (d.len() >= 17 && d.chars().all(|c| c.is_ascii_digit() || c == '-')).then(|| d.to_string())
}

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
    let o = Command::new(cmd).args(args).output()?;
    if !o.status.success() {
        anyhow::bail!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

impl Snapshot {
    pub fn create() -> anyhow::Result<Snapshot> {
        let out = run("tmutil", &["localsnapshot"])?;
        let date =
            parse_created(&out).ok_or_else(|| anyhow::anyhow!("tmutil said: {}", out.trim()))?;
        let name = format!("com.apple.TimeMachine.{date}.local");
        // Made after the snapshot, so the mount point is not inside it.
        let mount = std::env::temp_dir().join(format!("fenrir-apfs-{date}"));
        std::fs::create_dir_all(&mount)?;
        let mounted = run(
            "mount_apfs",
            &[
                "-o",
                "nobrowse,rdonly",
                "-s",
                &name,
                DATA,
                &mount.to_string_lossy(),
            ],
        );
        if let Err(e) = mounted {
            let _ = run("tmutil", &["deletelocalsnapshots", &date]);
            let _ = std::fs::remove_dir(&mount);
            anyhow::bail!("mounting the APFS snapshot: {e} (the agent needs Full Disk Access)");
        }
        Ok(Snapshot {
            notes: vec![],
            date,
            mount,
        })
    }

    /// Where a live path is in the snapshot: paths on the Data volume
    /// (users' folders, applications, /private, /usr/local, ...), through
    /// its firmlinks; anything else is read live.
    pub fn translate(&self, live: &Path) -> PathBuf {
        let rel = live.strip_prefix(DATA).unwrap_or(live);
        let rel = rel.strip_prefix("/").unwrap_or(rel);
        if rel.as_os_str().is_empty() {
            return self.mount.clone();
        }
        let on_data = Path::new(DATA).join(rel);
        if on_data.symlink_metadata().is_ok() {
            self.mount.join(rel)
        } else {
            live.to_path_buf()
        }
    }

    pub fn name(&self) -> String {
        format!("com.apple.TimeMachine.{}.local", self.date)
    }

    pub fn finish(self) -> anyhow::Result<()> {
        let u = run("umount", &[&self.mount.to_string_lossy()]);
        let d = run("tmutil", &["deletelocalsnapshots", &self.date]);
        let _ = std::fs::remove_dir(&self.mount);
        u?;
        d.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_created;

    #[test]
    fn tmutil_output() {
        assert_eq!(
            parse_created("Created local snapshot with date: 2026-11-24-123456\n").as_deref(),
            Some("2026-11-24-123456")
        );
        assert_eq!(parse_created("Failed to create local snapshot"), None);
    }
}
