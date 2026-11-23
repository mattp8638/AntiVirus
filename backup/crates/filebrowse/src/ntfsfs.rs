//! NTFS through the `ntfs` crate (read-only).

use std::io::{BufReader, Write};

use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsAttributeFlags, NtfsFile, NtfsReadSeek};

use crate::{components, Entry, EntryKind, Error, PartReader, Result, Volumefs};

type Fs = BufReader<PartReader>;

pub struct NtfsVolume {
    ntfs: Ntfs,
    fs: Fs,
}

fn err(e: ntfs::NtfsError) -> Error {
    Error::Fs(format!("NTFS: {e}"))
}

/// 100 ns intervals since 1601-01-01 to Unix seconds.
fn unix(nt: u64) -> Option<i64> {
    (nt > 0).then(|| (nt / 10_000_000) as i64 - 11_644_473_600)
}

impl NtfsVolume {
    pub(crate) fn open(part: PartReader) -> Result<Self> {
        let mut fs = BufReader::with_capacity(64 << 10, part);
        let mut ntfs = Ntfs::new(&mut fs).map_err(err)?;
        ntfs.read_upcase_table(&mut fs).map_err(err)?;
        Ok(NtfsVolume { ntfs, fs })
    }

    fn resolve<'n>(ntfs: &'n Ntfs, fs: &mut Fs, path: &str) -> Result<NtfsFile<'n>> {
        let mut cur = ntfs.root_directory(fs).map_err(err)?;
        for part in components(path)? {
            if !cur.is_directory() {
                return Err(Error::NotFound(format!("{path}: not a folder")));
            }
            let index = cur.directory_index(fs).map_err(err)?;
            let mut finder = index.finder();
            let entry = NtfsFileNameIndex::find(&mut finder, ntfs, fs, &part)
                .ok_or_else(|| Error::NotFound(format!("{part} is not in this backup")))?
                .map_err(err)?;
            cur = entry.to_file(ntfs, fs).map_err(err)?;
        }
        Ok(cur)
    }
}

impl Volumefs for NtfsVolume {
    fn list(&mut self, path: &str) -> Result<Vec<Entry>> {
        let root = components(path)?.is_empty();
        let dir = Self::resolve(&self.ntfs, &mut self.fs, path)?;
        if !dir.is_directory() {
            return Err(Error::Invalid(format!("{path} is not a folder")));
        }
        let index = dir.directory_index(&mut self.fs).map_err(err)?;
        let mut it = index.entries();
        let mut out = Vec::new();
        while let Some(e) = it.next(&mut self.fs) {
            let e = e.map_err(err)?;
            let Some(key) = e.key() else { continue };
            let name = key.map_err(err)?;
            // Short 8.3 aliases duplicate the long names.
            if name.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let n = name.name().to_string_lossy();
            // NTFS metadata files ($MFT, $LogFile, ...) live in the root.
            if root && n.starts_with('$') && e.file_reference().file_record_number() < 64 {
                continue;
            }
            let attrs = name.file_attributes();
            let kind = if name.is_directory() {
                EntryKind::Dir
            } else if attrs.contains(NtfsFileAttributeFlags::REPARSE_POINT) {
                EntryKind::Link
            } else {
                EntryKind::File
            };
            out.push(Entry {
                hidden: attrs
                    .intersects(NtfsFileAttributeFlags::HIDDEN | NtfsFileAttributeFlags::SYSTEM),
                size: if kind == EntryKind::Dir {
                    0
                } else {
                    name.data_size()
                },
                modified: unix(name.modification_time().nt_timestamp()),
                kind,
                name: n,
            });
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<Entry> {
        let f = Self::resolve(&self.ntfs, &mut self.fs, path)?;
        let info = f.info().map_err(err)?;
        let attrs = info.file_attributes();
        let kind = if f.is_directory() {
            EntryKind::Dir
        } else if attrs.contains(NtfsFileAttributeFlags::REPARSE_POINT) {
            EntryKind::Link
        } else {
            EntryKind::File
        };
        let size = if kind == EntryKind::File {
            match f.data(&mut self.fs, "") {
                Some(item) => item
                    .map_err(err)?
                    .to_attribute()
                    .map_err(err)?
                    .value_length(),
                None => 0,
            }
        } else {
            0
        };
        Ok(Entry {
            name: components(path)?.pop().unwrap_or_default(),
            hidden: attrs
                .intersects(NtfsFileAttributeFlags::HIDDEN | NtfsFileAttributeFlags::SYSTEM),
            size,
            modified: unix(info.modification_time().nt_timestamp()),
            kind,
        })
    }

    fn copy(&mut self, path: &str, out: &mut dyn Write, cancel: &dyn Fn() -> bool) -> Result<u64> {
        let f = Self::resolve(&self.ntfs, &mut self.fs, path)?;
        if f.is_directory() {
            return Err(Error::Invalid(format!("{path} is a folder")));
        }
        let attrs = f.info().map_err(err)?.file_attributes();
        if attrs.contains(NtfsFileAttributeFlags::REPARSE_POINT) {
            return Err(Error::Unsupported(format!(
                "{path} is a link or a cloud placeholder (reparse point), not file contents"
            )));
        }
        let item = match f.data(&mut self.fs, "") {
            Some(i) => i.map_err(err)?,
            None => return Ok(0),
        };
        let attr = item.to_attribute().map_err(err)?;
        let flags = attr.flags();
        if flags.contains(NtfsAttributeFlags::COMPRESSED) {
            return Err(Error::Unsupported(format!("{path} is NTFS-compressed, which file restore does not read yet: restore the volume as a VHDX instead")));
        }
        if flags.contains(NtfsAttributeFlags::ENCRYPTED)
            || attrs.contains(NtfsFileAttributeFlags::ENCRYPTED)
        {
            return Err(Error::Unsupported(format!(
                "{path} is EFS-encrypted by Windows and cannot be read outside that user account"
            )));
        }
        let mut value = attr.value(&mut self.fs).map_err(err)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut n = 0u64;
        loop {
            if cancel() {
                return Err(Error::Cancelled);
            }
            let r = value.read(&mut self.fs, &mut buf).map_err(err)?;
            if r == 0 {
                return Ok(n);
            }
            out.write_all(&buf[..r])?;
            n += r as u64;
        }
    }
}
