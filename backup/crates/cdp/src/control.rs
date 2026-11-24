//! Running CDP on a logical volume (docs/design/cdp.md): the file system is
//! mounted through a device-mapper `log-writes` device that journals every
//! write into one of two journal volumes. Every few seconds a timestamp mark
//! goes into the journal; every minute or so the journals are swapped (a
//! table reload while the device is suspended) and the full one is shipped
//! to the repository. A base image is taken, from an LVM snapshot made
//! while the device is suspended at a swap, so that base + journals replay
//! to any marked second.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub name: String,
    pub vg: String,
    pub lv: String,
    /// The two journal volumes (LV paths) and which is in use.
    pub journals: [String; 2],
    pub active: usize,
    /// Sequence number of the journal in use.
    pub seq: u64,
    /// Base image the journals since `base_seq` replay onto.
    #[serde(default)]
    pub base_image: Option<String>,
    #[serde(default)]
    pub base_seq: u64,
    #[serde(default)]
    pub base_unix: i64,
}

pub fn dm_name(name: &str) -> String {
    format!("fenrir-cdp-{name}")
}

pub fn device(name: &str) -> PathBuf {
    PathBuf::from(format!("/dev/mapper/{}", dm_name(name)))
}

pub fn state_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("cdp-{name}.json"))
}

pub fn load(dir: &Path, name: &str) -> Result<State> {
    let p = state_path(dir, name);
    serde_json::from_slice(
        &std::fs::read(&p)
            .map_err(|e| format!("{}: {e} (is CDP enabled for {name}?)", p.display()))?,
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

/// 512-byte sectors of a block device.
fn sectors(dev: &str) -> Result<u64> {
    run("blockdev", &["--getsz", dev])?
        .trim()
        .parse()
        .map_err(|_| format!("size of {dev}"))
}

fn table(st: &State, journal: usize) -> Result<String> {
    let origin = format!("/dev/{}/{}", st.vg, st.lv);
    Ok(format!(
        "0 {} log-writes {origin} {}",
        sectors(&origin)?,
        st.journals[journal]
    ))
}

/// Set up CDP for an unmounted logical volume: two journal volumes in its
/// volume group, and the device to mount from now on.
pub fn enable(dir: &Path, name: &str, volume: &str, journal_mb: u64) -> Result<State> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("the name may only have letters, digits, - and _".into());
    }
    if state_path(dir, name).exists() {
        return Err(format!("CDP is already enabled as {name}"));
    }
    let _ = run("modprobe", &["dm-log-writes"]);
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
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let real = std::fs::canonicalize(volume).map_err(|e| format!("{volume}: {e}"))?;
    if mounts
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|d| std::fs::canonicalize(d).ok().as_ref() == Some(&real))
    {
        return Err(format!(
            "{volume} is mounted: unmount it, enable CDP, then mount {} instead",
            device(name).display()
        ));
    }
    let mut journals = [String::new(), String::new()];
    for (i, j) in journals.iter_mut().enumerate() {
        let jl = format!("{lv}-fenrir-cdp-{}", ["a", "b"][i]);
        run(
            "lvcreate",
            &["-q", "-y", "-L", &format!("{journal_mb}m"), "-n", &jl, &vg],
        )?;
        *j = format!("/dev/{vg}/{jl}");
    }
    let st = State {
        name: name.into(),
        vg,
        lv,
        journals,
        active: 0,
        seq: 1,
        base_image: None,
        base_seq: 0,
        base_unix: 0,
    };
    run(
        "dmsetup",
        &["create", &dm_name(name), "--table", &table(&st, 0)?],
    )?;
    save(dir, &st)?;
    Ok(st)
}

pub fn mark(name: &str, label: &str) -> Result<()> {
    run("dmsetup", &["message", &dm_name(name), "0", "mark", label]).map(|_| ())
}

/// The journal in use: (entries logged, highest 512-byte sector used, logging stopped).
pub fn usage(name: &str) -> Result<(u64, u64, bool)> {
    let s = run("dmsetup", &["status", &dm_name(name)])?;
    let f: Vec<&str> = s.split_whitespace().collect();
    // "<start> <len> log-writes <entries> <highest sector> [logging_disabled]"
    let n = f.get(3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let hi = f.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
    Ok((n, hi, s.contains("logging_disabled")))
}

/// Swap journals: the device is suspended (writes flushed and held), its
/// table reloaded with the other journal, and resumed. With `snapshot`, an
/// LVM snapshot of the volume is made while suspended: the state the new
/// journal starts from. Returns the finished journal and its sequence number.
pub fn rotate(dir: &Path, st: &mut State, snapshot: Option<&str>) -> Result<(String, u64)> {
    let dm = dm_name(&st.name);
    mark(&st.name, &crate::journal::time_mark(now()))?;
    let next = 1 - st.active;
    let t = table(st, next)?;
    run("dmsetup", &["suspend", &dm])?;
    let r = (|| -> Result<()> {
        if let Some(snap) = snapshot {
            let size = sectors(&format!("/dev/{}/{}", st.vg, st.lv))? / 10 * 512;
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
        }
        run("dmsetup", &["reload", &dm, "--table", &t])?;
        Ok(())
    })();
    let resumed = run("dmsetup", &["resume", &dm]);
    r?;
    resumed?;
    let done = (st.journals[st.active].clone(), st.seq);
    st.active = next;
    st.seq += 1;
    save(dir, st)?;
    Ok(done)
}

/// Stop CDP: the device is removed (unmount it first); the journal volumes
/// stay unless `remove_journals`.
pub fn disable(dir: &Path, name: &str, remove_journals: bool) -> Result<()> {
    let st = load(dir, name)?;
    run("dmsetup", &["remove", &dm_name(name)])?;
    if remove_journals {
        for j in &st.journals {
            let _ = run("lvremove", &["-q", "-y", j]);
        }
    }
    std::fs::remove_file(state_path(dir, name)).map_err(|e| e.to_string())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Bytes of a journal device in use (super, entries and their data).
pub fn used_bytes(journal: &mut (impl std::io::Read + std::io::Seek)) -> std::io::Result<u64> {
    let (sup, list) = crate::journal::entries(journal)?;
    let ss = sup.sectorsize as u64;
    let mut end = ss * (1 + list.len() as u64);
    for e in &list {
        if let crate::journal::Entry::Write { len, .. } = e {
            end += len;
        }
    }
    Ok(end)
}
