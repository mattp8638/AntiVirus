//! Grow the file system of a partition that [`crate::fit::Fit::grow`] made
//! larger (phase-5-grow-clone.md §1), with the operating system's tools.
//! Failing leaves a valid, smaller file system and a note saying what to run.

use std::path::Path;
use std::process::{Command, Stdio};

use core_format::fsdetect::FsType;
use serde::Serialize;

use crate::fit::Grown;

#[derive(Debug, Clone, Serialize)]
pub struct GrowReport {
    pub partition: u32,
    pub old_length: u64,
    pub new_length: u64,
    pub filesystem: FsType,
    /// The file system now fills the partition.
    pub filesystem_grown: bool,
    pub notes: Vec<String>,
}

/// What to tell someone to run for a file system grown only once mounted.
fn later(fs: FsType) -> Option<&'static str> {
    match fs {
        FsType::Xfs => Some("xfs_growfs <mount point> once it is mounted"),
        FsType::Btrfs => Some("btrfs filesystem resize max <mount point> once it is mounted"),
        FsType::Luks => {
            Some("cryptsetup resize <name> once it is opened, then grow the file system inside")
        }
        _ => None,
    }
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

/// Run a tool; Err carries the last lines of its output.
#[allow(dead_code)]
fn run(cmd: &str, args: &[&str], stdin: Option<&str>, ok_codes: &[i32]) -> Result<(), String> {
    let mut c = Command::new(cmd);
    c.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    if let (Some(input), Some(mut i)) = (stdin, child.stdin.take()) {
        use std::io::Write;
        let _ = i.write_all(input.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let code = out.status.code().unwrap_or(-1);
    if ok_codes.contains(&code) {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let tail: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    Err(format!(
        "{cmd} {} (exit {code}): {}",
        args.join(" "),
        tail[tail.len().saturating_sub(3)..].join(" / ")
    ))
}

/// Grow the file system of `g` on `target` (the restored device or image
/// file).
pub fn grow_filesystem(target: &Path, g: &Grown) -> GrowReport {
    let mut r = GrowReport {
        partition: g.number,
        old_length: g.old_length,
        new_length: g.new_length,
        filesystem: g.filesystem,
        filesystem_grown: false,
        notes: vec![format!(
            "partition {} grown from {} to {}",
            g.number,
            gib(g.old_length),
            gib(g.new_length)
        )],
    };
    if let Some(what) = later(g.filesystem) {
        r.notes
            .push(format!("its file system grows while in use: run {what}"));
        return r;
    }
    match platform::grow(target, g) {
        Ok(()) => r.filesystem_grown = true,
        Err(e) => r.notes.push(format!(
            "the {:?} file system keeps its old size ({e}); it is valid, and can be grown later",
            g.filesystem
        )),
    }
    r
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::unix::fs::FileTypeExt;

    /// The block device of the partition starting at `start` on `disk`.
    fn partition_device(disk: &Path, start: u64) -> Result<String, String> {
        let name = std::fs::canonicalize(disk)
            .map_err(|e| e.to_string())?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dir = Path::new("/sys/class/block").join(&name);
        // The kernel must see the new table first.
        let _ = run(
            "blockdev",
            &["--rereadpt", &disk.to_string_lossy()],
            None,
            &[0],
        );
        let _ = run("udevadm", &["settle"], None, &[0]);
        for _ in 0..20 {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    let s = std::fs::read_to_string(p.join("start")).ok();
                    if s.and_then(|s| s.trim().parse::<u64>().ok()) == Some(start / 512) {
                        return Ok(format!("/dev/{}", e.file_name().to_string_lossy()));
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(format!(
            "no partition device at offset {start} of {}",
            disk.display()
        ))
    }

    pub fn grow(target: &Path, g: &Grown) -> Result<(), String> {
        let meta = std::fs::metadata(target).map_err(|e| e.to_string())?;
        let mut loopdev = None;
        let dev = if meta.file_type().is_block_device() {
            partition_device(target, g.start)?
        } else {
            // An image file: the partition as a loop device.
            let out = Command::new("losetup")
                .args([
                    "--find",
                    "--show",
                    "--offset",
                    &g.start.to_string(),
                    "--sizelimit",
                    &g.new_length.to_string(),
                ])
                .arg(target)
                .output()
                .map_err(|e| format!("losetup: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "losetup: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let d = String::from_utf8_lossy(&out.stdout).trim().to_string();
            loopdev = Some(d.clone());
            d
        };
        let r = (|| match g.filesystem {
            FsType::Ext => {
                // e2fsck: 0 clean, 1 corrected.
                run("e2fsck", &["-f", "-y", &dev], None, &[0, 1])?;
                run("resize2fs", &[&dev], None, &[0])
            }
            FsType::Ntfs => run(
                "ntfsresize",
                &["--force", "--no-progress-bar", &dev],
                Some("y\n"),
                &[0],
            ),
            FsType::LvmPv => run("pvresize", &[&dev], None, &[0]),
            other => Err(format!("{other:?} is not grown here")),
        })();
        if let Some(d) = loopdev {
            let _ = run("losetup", &["-d", &d], None, &[0]);
        }
        r
    }
}

#[cfg(windows)]
mod platform {
    use super::*;

    pub fn grow(target: &Path, g: &Grown) -> Result<(), String> {
        if g.filesystem != FsType::Ntfs {
            return Err(format!("Windows cannot grow {:?}", g.filesystem));
        }
        let t = target.to_string_lossy();
        let disk = t
            .to_ascii_lowercase()
            .strip_prefix(r"\\.\physicaldrive")
            .and_then(|n| n.parse::<u32>().ok())
            .ok_or("only a physical disk can be grown on Windows")?;
        // Windows numbers partitions in table order (the extended container
        // and empty GPT entries are not counted); the grown one is the last.
        let script = format!(
            "rescan\nselect disk {disk}\nlist partition\nselect partition {}\nextend filesystem\n",
            g.windows_number
        );
        let dir = std::env::temp_dir().join(format!("fenrir-grow-{}.txt", std::process::id()));
        std::fs::write(&dir, script).map_err(|e| e.to_string())?;
        let r = run("diskpart", &["/s", &dir.to_string_lossy()], None, &[0]);
        let _ = std::fs::remove_file(&dir);
        r
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;
    pub fn grow(_target: &Path, g: &Grown) -> Result<(), String> {
        Err(format!(
            "{:?} cannot be grown on this platform",
            g.filesystem
        ))
    }
}
