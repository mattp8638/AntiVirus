//! Browse the files inside a backup image and restore chosen files, without
//! restoring the disk.
//!
//! The image is read straight from the encrypted chunk store (only the
//! chunks a listing or a file needs are fetched and decrypted). Volumes are
//! opened read-only with permissively licensed parsers: NTFS (`ntfs`) and
//! ext2/3/4 (`ext4-view`). Nothing is mounted and nothing in the repository
//! is modified.
//!
//! Paths inside a volume are `/`-separated from the volume root
//! (`/Users/anna/Documents/report.docx`). NTFS lookups ignore case, as
//! Windows does.

mod ext;
mod ntfsfs;
pub mod restore;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use core_format::fsdetect::FsType;
use core_format::ManifestBody;
use serde::{Deserialize, Serialize};

pub use restore::{restore, Conflict, RestoreOptions, RestoreReport};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Invalid(String),
    #[error("reading the image: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Fs(String),
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Random-access reader over one disk of an image.
pub trait Disk: Send + Sync {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl Disk for nbd_server::ImageExport {
    fn size(&self) -> u64 {
        nbd_server::Export::size(self)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        nbd_server::Export::read_at(self, offset, buf)
    }
}

/// A volume in an image, as shown before browsing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Volume {
    pub disk: u32,
    pub partition: u32,
    pub filesystem: FsType,
    pub size: u64,
    /// Drive letters / mount points at backup time ("C:\\", "/home").
    #[serde(default)]
    pub mount_points: Vec<String>,
    /// Partition name from the table (GPT), if any.
    #[serde(default)]
    pub name: String,
    pub browsable: bool,
    /// Why it cannot be browsed, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Every partition of every disk, browsable ones first by disk order.
pub fn volumes(m: &ManifestBody) -> Vec<Volume> {
    let mut out = Vec::new();
    for d in &m.disks {
        for p in &d.partitions {
            let fs = p.filesystem;
            let (browsable, note) = match fs {
                FsType::Ntfs | FsType::Ext => (true, None),
                FsType::Bitlocker => (false, Some("BitLocker-encrypted at backup time: restore the disk or VHDX and unlock it there".to_string())),
                FsType::Luks => (false, Some("LUKS-encrypted: restore the disk and unlock it there".to_string())),
                FsType::Swap => (false, Some("swap space".to_string())),
                FsType::Unknown => (false, Some("no recognised file system".to_string())),
                other => (false, Some(format!("{other:?} volumes cannot be browsed yet: restore the disk or VHDX"))),
            };
            out.push(Volume {
                disk: d.index,
                partition: p.entry.number,
                filesystem: fs,
                size: p.entry.length,
                mount_points: p.mount_points.clone(),
                name: p.entry.name.clone(),
                browsable,
                note,
            });
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Link,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Unix seconds, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    /// Hidden or system file (NTFS), or a dot file (ext).
    #[serde(default)]
    pub hidden: bool,
}

/// A directory listing. `truncated` is set when more than `limit` entries
/// exist; the first `limit` (sorted: folders, then by name) are returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
    pub truncated: bool,
    pub total: usize,
}

/// One opened volume.
pub trait Volumefs {
    /// Entries of the directory at `path`.
    fn list(&mut self, path: &str) -> Result<Vec<Entry>>;
    /// What `path` is.
    fn stat(&mut self, path: &str) -> Result<Entry>;
    /// Write the contents of the file at `path` to `out`; returns bytes written.
    fn copy(&mut self, path: &str, out: &mut dyn Write, cancel: &dyn Fn() -> bool) -> Result<u64>;
}

/// Normalise a browse path: `/`-separated, no `.`/`..`, no empty parts.
pub fn components(path: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for c in path.split(['/', '\\']) {
        match c {
            "" | "." => continue,
            ".." => return Err(Error::Invalid("paths may not contain ..".into())),
            c if c.contains('\0') => {
                return Err(Error::Invalid("invalid character in path".into()))
            }
            c => out.push(c.to_string()),
        }
    }
    Ok(out)
}

pub fn join(parts: &[String]) -> String {
    format!("/{}", parts.join("/"))
}

/// Open partition `partition` of `disk` (indexes as in the manifest).
pub fn open(
    m: &ManifestBody,
    reader: Arc<dyn Disk>,
    disk: u32,
    partition: u32,
) -> Result<Box<dyn Volumefs>> {
    let d = m
        .disks
        .iter()
        .find(|d| d.index == disk)
        .ok_or_else(|| Error::NotFound(format!("the image has no disk {disk}")))?;
    let p = d
        .partitions
        .iter()
        .find(|p| p.entry.number == partition)
        .ok_or_else(|| Error::NotFound(format!("disk {disk} has no partition {partition}")))?;
    let part = PartReader {
        disk: reader,
        base: p.entry.start,
        len: p.entry.length,
        pos: 0,
    };
    match p.filesystem {
        FsType::Ntfs => Ok(Box::new(ntfsfs::NtfsVolume::open(part)?)),
        FsType::Ext => Ok(Box::new(ext::ExtVolume::open(part)?)),
        other => Err(Error::Unsupported(
            volumes(m)
                .into_iter()
                .find(|v| v.disk == disk && v.partition == partition)
                .and_then(|v| v.note)
                .unwrap_or_else(|| format!("{other:?} cannot be browsed")),
        )),
    }
}

/// List a directory, sorted (folders first, then case-insensitive name), at most `limit` entries.
pub fn list(fs: &mut dyn Volumefs, path: &str, limit: usize) -> Result<Listing> {
    let parts = components(path)?;
    let mut entries = fs.list(&join(&parts))?;
    entries.sort_by(|a, b| {
        (a.kind != EntryKind::Dir, a.name.to_lowercase())
            .cmp(&(b.kind != EntryKind::Dir, b.name.to_lowercase()))
    });
    let total = entries.len();
    entries.truncate(limit);
    Ok(Listing {
        path: join(&parts),
        truncated: total > entries.len(),
        total,
        entries,
    })
}

/// `Read + Seek` over one partition of a disk.
#[derive(Clone)]
pub(crate) struct PartReader {
    disk: Arc<dyn Disk>,
    base: u64,
    len: u64,
    pos: u64,
}

impl PartReader {
    pub(crate) fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past the end of the volume",
            ));
        }
        self.disk.read_at(self.base + offset, buf)
    }
}

impl Read for PartReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.len.saturating_sub(self.pos)) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.disk.read_at(self.base + self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PartReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalised_and_dotdot_refused() {
        assert_eq!(
            components("/Users//anna/./Docs/").unwrap(),
            vec!["Users", "anna", "Docs"]
        );
        assert_eq!(
            components("\\Windows\\System32").unwrap(),
            vec!["Windows", "System32"]
        );
        assert!(components("/a/../b").is_err());
        assert_eq!(join(&[]), "/");
    }
}
