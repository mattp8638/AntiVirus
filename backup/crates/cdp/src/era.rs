//! Changed-block tracking for physical Linux volumes (docs/design/cbt-physical.md)
//! with the kernel's device-mapper `era` target: it sits under the file
//! system (like CDP's log-writes device) and records, per block, the "era"
//! in which it was last written. Each backup checkpoints the era while the
//! file system is frozen, snapshots the volume, and reads only the blocks
//! written since the era of the previous backup's checkpoint.
//!
//! The written blocks are listed by `era_invalidate` (thin-provisioning-tools,
//! run as a separate program, never linked) from a metadata snapshot.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub name: String,
    pub vg: String,
    pub lv: String,
    /// The era target's metadata volume (an LV in the same volume group).
    pub metadata: String,
    /// Tracking granularity, 512-byte sectors.
    pub block_sectors: u64,
    /// The image the next backup reads changes against, and the era from
    /// which blocks count as changed since it.
    #[serde(default)]
    pub last_image: Option<String>,
    #[serde(default)]
    pub since_era: Option<u64>,
}

pub fn dm_name(name: &str) -> String {
    format!("fenrir-era-{name}")
}

pub fn device(name: &str) -> PathBuf {
    PathBuf::from(format!("/dev/mapper/{}", dm_name(name)))
}

fn state_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("era-{name}.json"))
}

pub fn load(dir: &Path, name: &str) -> Result<State> {
    let p = state_path(dir, name);
    serde_json::from_slice(
        &std::fs::read(&p)
            .map_err(|e| format!("{}: {e} (is tracking enabled for {name}?)", p.display()))?,
    )
    .map_err(|e| e.to_string())
}

pub fn save(dir: &Path, st: &State) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let p = state_path(dir, &st.name);
    let tmp = p.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(st).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd)
        .args(args)
        .env("LVM_SUPPRESS_FD_WARNINGS", "1")
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn sectors(dev: &str) -> Result<u64> {
    run("blockdev", &["--getsz", dev])?
        .trim()
        .parse()
        .map_err(|_| format!("size of {dev}"))
}

fn origin(st: &State) -> String {
    format!("/dev/{}/{}", st.vg, st.lv)
}

/// Track changes on an unmounted logical volume: a metadata LV next to it
/// and the era device to mount from now on.
pub fn enable(dir: &Path, name: &str, volume: &str, block_kib: u64) -> Result<State> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("the name may only have letters, digits, - and _".into());
    }
    if state_path(dir, name).exists() {
        return Err(format!("change tracking is already enabled as {name}"));
    }
    if !(4..=1024).contains(&block_kib) || !block_kib.is_power_of_two() {
        return Err("the block size is a power of two from 4 to 1024 KiB".into());
    }
    if Command::new("era_invalidate")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err("era_invalidate is not installed (package thin-provisioning-tools)".into());
    }
    let _ = run("modprobe", &["dm-era"]);
    let info = run(
        "lvs",
        &[
            "--noheadings",
            "--separator",
            "|",
            "-o",
            "vg_name,lv_name",
            volume,
        ],
    )?;
    let (vg, lv) = info
        .trim()
        .split_once('|')
        .ok_or_else(|| format!("{volume} is not an LVM logical volume"))?;
    let (vg, lv) = (vg.trim().to_string(), lv.trim().to_string());
    let real = std::fs::canonicalize(volume).map_err(|e| format!("{volume}: {e}"))?;
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    if mounts
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|d| std::fs::canonicalize(d).ok().as_ref() == Some(&real))
    {
        return Err(format!(
            "{volume} is mounted: unmount it, enable tracking, then mount {} instead",
            device(name).display()
        ));
    }
    let meta = format!("{lv}-fenrir-era");
    run("lvcreate", &["-q", "-y", "-L", "32m", "-n", &meta, &vg])?;
    let metadata = format!("/dev/{vg}/{meta}");
    // A fresh metadata device: the target formats it when its first block is zero.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&metadata)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &[0u8; 4096]))
        .map_err(|e| format!("{metadata}: {e}"))?;
    let st = State {
        name: name.into(),
        vg,
        lv,
        metadata,
        block_sectors: block_kib * 2,
        last_image: None,
        since_era: None,
    };
    let table = format!(
        "0 {} era {} {} {}",
        sectors(&origin(&st))?,
        st.metadata,
        origin(&st),
        st.block_sectors
    );
    if let Err(e) = run("dmsetup", &["create", &dm_name(name), "--table", &table]) {
        let _ = run("lvremove", &["-q", "-y", &st.metadata]);
        return Err(e);
    }
    save(dir, &st)?;
    Ok(st)
}

/// The current era (dmsetup status: `<start> <len> era <md block size>
/// <used>/<total> <current era> <held root>`).
pub fn current_era(name: &str) -> Result<u64> {
    let s = run("dmsetup", &["status", &dm_name(name)])?;
    s.split_whitespace()
        .nth(5)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("unexpected era status: {}", s.trim()))
}

fn message(name: &str, m: &str) -> Result<()> {
    run("dmsetup", &["message", &dm_name(name), "0", m]).map(|_| ())
}

/// Where the era device is mounted, if it is.
fn mountpoint(name: &str) -> Option<String> {
    let dev = std::fs::canonicalize(device(name)).ok()?;
    std::fs::read_to_string("/proc/self/mounts")
        .ok()?
        .lines()
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let d = f.next()?;
            let m = f.next()?;
            (std::fs::canonicalize(d).ok()? == dev).then(|| m.replace("\\040", " "))
        })
}

/// A consistent point to back up: with the file system frozen, a checkpoint
/// (blocks written from now on get the new era) and an LVM snapshot of the
/// volume. Returns the snapshot's path and the new era.
pub fn snapshot(st: &State, snap: &str) -> Result<(String, u64)> {
    let mp = mountpoint(&st.name);
    if let Some(m) = &mp {
        run("fsfreeze", &["-f", m])?;
    }
    let r = (|| -> Result<u64> {
        message(&st.name, "checkpoint")?;
        let era = current_era(&st.name)?;
        let size = sectors(&origin(st))? / 10 * 512;
        run(
            "lvcreate",
            &[
                "-q",
                "-y",
                "-s",
                "-L",
                &format!("{}b", size.max(64 << 20)),
                "-n",
                snap,
                &format!("{}/{}", st.vg, st.lv),
            ],
        )?;
        Ok(era)
    })();
    if let Some(m) = &mp {
        let _ = run("fsfreeze", &["-u", m]);
    }
    Ok((format!("/dev/{}/{snap}", st.vg), r?))
}

/// Byte ranges written since `era` (from a metadata snapshot), merged.
pub fn written_since(st: &State, era: u64) -> Result<Vec<(u64, u64)>> {
    message(&st.name, "take_metadata_snap")?;
    let out = (|| -> Result<String> {
        // The held snapshot's root block is the status's last field.
        let status = run("dmsetup", &["status", &dm_name(&st.name)])?;
        let root = status
            .split_whitespace()
            .nth(6)
            .filter(|r| *r != "-")
            .map(str::to_string);
        let since = era.to_string();
        let with_root = root.as_ref().map(|r| {
            run(
                "era_invalidate",
                &[
                    "--metadata-snapshot",
                    r,
                    "--written-since",
                    &since,
                    &st.metadata,
                ],
            )
        });
        match with_root {
            Some(Ok(o)) => Ok(o),
            // Older versions take the flag without a value.
            _ => run(
                "era_invalidate",
                &[
                    "--metadata-snapshot",
                    "--written-since",
                    &since,
                    &st.metadata,
                ],
            ),
        }
    })();
    let _ = message(&st.name, "drop_metadata_snap");
    let blocks = parse_invalidate(&out?)?;
    let bs = st.block_sectors * 512;
    Ok(blocks.into_iter().map(|(b, n)| (b * bs, n * bs)).collect())
}

/// `era_invalidate` XML: `<block block="n"/>` and `<range begin="a" end="b"/>`
/// (end exclusive; counted inclusive here, which can only read more). Returns
/// merged (first block, count) runs.
pub fn parse_invalidate(xml: &str) -> Result<Vec<(u64, u64)>> {
    let attr = |tag: &str, name: &str| -> Option<u64> {
        let k = format!("{name}=\"");
        let i = tag.find(&k)? + k.len();
        tag[i..].split('"').next()?.parse().ok()
    };
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for tag in xml.split('<').skip(1) {
        let tag = tag.split('>').next().unwrap_or("");
        let r = if tag.starts_with("block ") {
            attr(tag, "block").map(|b| (b, 1))
        } else if tag.starts_with("range ") {
            match (attr(tag, "begin"), attr(tag, "end")) {
                (Some(a), Some(b)) if b >= a => Some((a, b - a + 1)),
                _ => return Err(format!("unexpected era_invalidate range: <{tag}>")),
            }
        } else {
            None
        };
        if let Some(r) = r {
            runs.push(r);
        }
    }
    runs.sort();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (b, n) in runs {
        match out.last_mut() {
            Some((pb, pn)) if b <= *pb + *pn => *pn = (*pn).max(b + n - *pb),
            _ => out.push((b, n)),
        }
    }
    Ok(out)
}

/// Stop tracking: the era device is removed (unmount it first) and its
/// metadata volume deleted; the volume itself is untouched.
pub fn disable(dir: &Path, name: &str) -> Result<()> {
    let st = load(dir, name)?;
    run("dmsetup", &["remove", &dm_name(name)])?;
    let _ = run("lvremove", &["-q", "-y", &st.metadata]);
    std::fs::remove_file(state_path(dir, name)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_invalidate;

    #[test]
    fn invalidate_output_is_merged() {
        let xml = r#"<blocks>
  <block block="7"/>
  <range begin="10" end="12"/>
  <block block="13"/>
  <block block="8"/>
  <range begin="40" end="41"/>
</blocks>"#;
        assert_eq!(
            parse_invalidate(xml).unwrap(),
            vec![(7, 2), (10, 4), (40, 2)]
        );
        assert_eq!(parse_invalidate("<blocks>\n</blocks>").unwrap(), vec![]);
        assert!(parse_invalidate(r#"<range begin="9" end="3"/>"#).is_err());
    }
}
