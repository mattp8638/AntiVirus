//! ext2/3/4 through `ext4-view` (read-only; the journal is not replayed).

use std::io::{Read, Write};

use ext4_view::{Ext4, Ext4Error, Ext4Read, Metadata};

use crate::{Entry, EntryKind, Error, PartReader, Result, Volumefs};

struct Src(PartReader);

impl Ext4Read for Src {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(self.0.read_exact_at(start_byte, dst)?)
    }
}

pub struct ExtVolume {
    fs: Ext4,
}

fn err(e: Ext4Error) -> Error {
    match e {
        Ext4Error::NotFound => Error::NotFound("no such file or folder in this backup".into()),
        Ext4Error::NotADirectory => Error::Invalid("not a folder".into()),
        e => Error::Fs(format!("ext file system: {e}")),
    }
}

fn kind(m: &Metadata) -> EntryKind {
    let t = m.file_type();
    if t.is_dir() {
        EntryKind::Dir
    } else if t.is_symlink() {
        EntryKind::Link
    } else if t.is_regular_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

fn entry(name: String, m: &Metadata) -> Entry {
    Entry {
        hidden: name.starts_with('.'),
        kind: kind(m),
        size: if m.is_dir() { 0 } else { m.len() },
        modified: Some(m.modified().seconds()),
        name,
    }
}

impl ExtVolume {
    pub(crate) fn open(part: PartReader) -> Result<Self> {
        Ok(ExtVolume {
            fs: Ext4::load(Box::new(Src(part))).map_err(err)?,
        })
    }
}

impl Volumefs for ExtVolume {
    fn list(&mut self, path: &str) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for e in self.fs.read_dir(path).map_err(err)? {
            let e = e.map_err(err)?;
            let name = e.file_name().display().to_string();
            if name == "." || name == ".." {
                continue;
            }
            // Symlinks are listed as links and never followed.
            let m = self.fs.symlink_metadata(e.path().as_path()).map_err(err)?;
            out.push(entry(name, &m));
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<Entry> {
        let m = self.fs.symlink_metadata(path).map_err(err)?;
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        Ok(entry(name, &m))
    }

    fn copy(&mut self, path: &str, out: &mut dyn Write, cancel: &dyn Fn() -> bool) -> Result<u64> {
        let m = self.fs.symlink_metadata(path).map_err(err)?;
        if !m.file_type().is_regular_file() {
            return Err(Error::Invalid(format!("{path} is not a regular file")));
        }
        let mut f = self.fs.open(path).map_err(err)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut n = 0u64;
        loop {
            if cancel() {
                return Err(Error::Cancelled);
            }
            let r = f.read(&mut buf)?;
            if r == 0 {
                return Ok(n);
            }
            out.write_all(&buf[..r])?;
            n += r as u64;
        }
    }
}
