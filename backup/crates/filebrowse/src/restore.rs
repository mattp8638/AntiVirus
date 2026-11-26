//! Restore chosen files and folders from an opened volume to a folder.
//!
//! * Files are written to a temporary name in the target folder and renamed
//!   into place when complete, so a cancelled or failed restore never
//!   leaves a half-written file under the real name.
//! * Names from the image are made safe for this machine; nothing is ever
//!   written outside the target folder, and existing links in the target
//!   are never followed.
//! * Existing files are skipped, overwritten or kept with the restored copy
//!   written alongside, as chosen.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{components, EntryKind, Error, Result, Volumefs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conflict {
    /// Keep the existing file; write the restored one as "name (restored).ext".
    #[default]
    Rename,
    /// Leave the existing file and do not restore this one.
    Skip,
    /// Replace the existing file.
    Overwrite,
}

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Folder on this machine to restore into (created if missing).
    pub target: PathBuf,
    /// Recreate the folders above each chosen item (`target/Users/anna/...`);
    /// otherwise each chosen item lands directly in `target`.
    pub keep_structure: bool,
    pub conflict: Conflict,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub target: String,
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    /// Existing files left alone (conflict = skip).
    pub skipped: u64,
    /// Restored next to an existing file under another name.
    pub renamed: u64,
    /// At most 200 listed; `failed_total` counts all.
    pub failed: Vec<Failure>,
    pub failed_total: u64,
    /// Files written, in order (at most `WRITTEN_LIST`), for restore evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<String>,
}

/// How many written files a report lists by name.
pub const WRITTEN_LIST: usize = 10_000;

impl RestoreReport {
    fn fail(&mut self, path: &str, e: impl std::fmt::Display) {
        self.failed_total += 1;
        if self.failed.len() < 200 {
            self.failed.push(Failure {
                path: path.to_string(),
                error: e.to_string(),
            });
        }
    }
}

/// A name from the image, usable as one path component on this machine.
pub fn safe_component(name: &str) -> String {
    let bad = |c: char| {
        c.is_control()
            || matches!(c, '/' | '\\')
            || (cfg!(windows) && matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    };
    let mut s: String = name.chars().map(|c| if bad(c) { '_' } else { c }).collect();
    if cfg!(windows) {
        while s.ends_with('.') || s.ends_with(' ') {
            s.pop();
        }
        let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit());
        if reserved {
            s.insert(0, '_');
        }
    }
    if s.is_empty() || s == "." || s == ".." {
        s = "_".into();
    }
    s
}

/// `dir/name` for a new file: as is, or "name (restored).ext", "(restored 2)", ... if taken.
fn alternative(dir: &Path, name: &str) -> PathBuf {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1..10_000 {
        let tag = if n == 1 {
            " (restored)".to_string()
        } else {
            format!(" (restored {n})")
        };
        let p = dir.join(format!("{stem}{tag}{ext}"));
        if fs::symlink_metadata(&p).is_err() {
            return p;
        }
    }
    dir.join(format!("{stem} (restored {}){ext}", std::process::id()))
}

/// Create `dir` and its parents, refusing to pass through links.
fn make_dir(dir: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(std::io::Error::other(format!(
            "{} is a link; not following it",
            dir.display()
        ))),
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!(
            "{} exists and is not a folder",
            dir.display()
        ))),
        Err(_) => {
            if let Some(p) = dir.parent() {
                make_dir(p)?;
            }
            fs::create_dir(dir).or_else(|e| if dir.is_dir() { Ok(()) } else { Err(e) })
        }
    }
}

struct Ctx<'a> {
    fs: &'a mut dyn Volumefs,
    opts: &'a RestoreOptions,
    cancel: &'a dyn Fn() -> bool,
    progress: &'a dyn Fn(&RestoreReport, &str),
    report: RestoreReport,
}

impl Ctx<'_> {
    fn file(&mut self, src: &str, dir: &Path, name: &str, modified: Option<i64>) -> Result<()> {
        if let Err(e) = make_dir(dir) {
            self.report.fail(src, e);
            return Ok(());
        }
        let mut dest = dir.join(safe_component(name));
        if let Ok(m) = fs::symlink_metadata(&dest) {
            match self.opts.conflict {
                Conflict::Skip => {
                    self.report.skipped += 1;
                    return Ok(());
                }
                Conflict::Overwrite if m.is_file() => {}
                // A folder or link with that name is never replaced.
                Conflict::Overwrite | Conflict::Rename => {
                    dest = alternative(dir, &safe_component(name));
                    self.report.renamed += 1;
                }
            }
        }
        let tmp = dir.join(format!(".{}.fenrir-restore", uuid_like()));
        let res = (|| -> Result<u64> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let n = self.fs.copy(src, &mut f, self.cancel)?;
            f.sync_all()?;
            if let Some(t) = modified.filter(|t| *t > 0) {
                let _ = f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(t as u64));
            }
            drop(f);
            fs::rename(&tmp, &dest)?;
            Ok(n)
        })();
        match res {
            Ok(n) => {
                self.report.files += 1;
                self.report.bytes += n;
                if self.report.written.len() < WRITTEN_LIST {
                    self.report.written.push(dest.display().to_string());
                }
            }
            Err(Error::Cancelled) => {
                let _ = fs::remove_file(&tmp);
                return Err(Error::Cancelled);
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.report.fail(src, e);
            }
        }
        (self.progress)(&self.report, src);
        Ok(())
    }

    fn walk(&mut self, src: &str, dir: &Path, depth: usize) -> Result<()> {
        if (self.cancel)() {
            return Err(Error::Cancelled);
        }
        if depth > 256 {
            self.report.fail(src, "folders nested too deeply");
            return Ok(());
        }
        let entries = match self.fs.list(src) {
            Ok(e) => e,
            Err(e) => {
                self.report.fail(src, e);
                return Ok(());
            }
        };
        if let Err(e) = make_dir(dir) {
            self.report.fail(src, e);
            return Ok(());
        }
        self.report.folders += 1;
        for e in entries {
            let child = format!("{}/{}", src.trim_end_matches('/'), e.name);
            match e.kind {
                EntryKind::Dir => {
                    self.walk(&child, &dir.join(safe_component(&e.name)), depth + 1)?
                }
                EntryKind::File => self.file(&child, dir, &e.name, e.modified)?,
                EntryKind::Link | EntryKind::Other => self
                    .report
                    .fail(&child, "links and special files are not restored"),
            }
        }
        Ok(())
    }
}

fn uuid_like() -> String {
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", t.as_nanos(), std::process::id())
}

/// Restore `paths` (files or folders) from `fs` into `opts.target`.
pub fn restore(
    fs: &mut dyn Volumefs,
    paths: &[String],
    opts: &RestoreOptions,
    cancel: &dyn Fn() -> bool,
    progress: &dyn Fn(&RestoreReport, &str),
) -> Result<RestoreReport> {
    if paths.is_empty() {
        return Err(Error::Invalid("choose at least one file or folder".into()));
    }
    make_dir(&opts.target)
        .map_err(|e| Error::Invalid(format!("cannot use {}: {e}", opts.target.display())))?;
    let mut ctx = Ctx {
        fs,
        opts,
        cancel,
        progress,
        report: RestoreReport {
            target: opts.target.display().to_string(),
            ..Default::default()
        },
    };
    for p in paths {
        let parts = components(p)?;
        let Some(name) = parts.last().cloned() else {
            return Err(Error::Invalid("choose files or folders, not the whole volume (restore the volume as a VHDX for that)".into()));
        };
        let src = crate::join(&parts);
        let parent: PathBuf = if opts.keep_structure {
            parts[..parts.len() - 1]
                .iter()
                .fold(opts.target.clone(), |d, c| d.join(safe_component(c)))
        } else {
            opts.target.clone()
        };
        let e = match ctx.fs.stat(&src) {
            Ok(e) => e,
            Err(e) => {
                ctx.report.fail(&src, e);
                continue;
            }
        };
        match e.kind {
            EntryKind::Dir => ctx.walk(&src, &parent.join(safe_component(&name)), 0)?,
            EntryKind::File => ctx.file(&src, &parent, &name, e.modified)?,
            _ => ctx
                .report
                .fail(&src, "links and special files are not restored"),
        }
    }
    Ok(ctx.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_names_are_made_safe() {
        assert_eq!(safe_component(".."), "_");
        assert_eq!(safe_component("a/b"), "a_b");
        assert_eq!(safe_component("ok.txt"), "ok.txt");
        if cfg!(windows) {
            assert_eq!(safe_component("CON.txt"), "_CON.txt");
            assert_eq!(safe_component("a:b"), "a_b");
        }
    }

    #[test]
    fn alternative_names() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("r.docx"), b"x").unwrap();
        assert_eq!(
            alternative(d.path(), "r.docx").file_name().unwrap(),
            "r (restored).docx"
        );
        fs::write(d.path().join("r (restored).docx"), b"x").unwrap();
        assert_eq!(
            alternative(d.path(), "r.docx").file_name().unwrap(),
            "r (restored 2).docx"
        );
    }
}
