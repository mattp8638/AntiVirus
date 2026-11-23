//! Make a restored disk boot on hardware that has never seen it (design:
//! phase-2 §4.2).
//!
//! The firmware of the new machine has no boot entry for the restored
//! system, so it falls back to `\EFI\BOOT\BOOTX64.EFI` on the ESP. Windows
//! installs normally have that file; some Linux installs do not. Copy the
//! system's own loader there when it is missing. Existing files are never
//! changed.

use std::io::{self, Read, Seek, SeekFrom, Write};

use serde::Serialize;

/// The loader found on an ESP, for a firmware boot entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Loader {
    /// e.g. "Windows Boot Manager".
    pub label: String,
    /// Path on the ESP with backslashes, e.g. `\EFI\Microsoft\Boot\bootmgfw.efi`.
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BootFix {
    pub loader: Option<Loader>,
    /// Files created on the ESP.
    pub added: Vec<String>,
}

/// (label, directory under EFI, files to copy: (source name, name in EFI/BOOT)).
type Found = (String, String, Vec<(String, String)>);

const FALLBACK_DIR: &str = "EFI/BOOT";
const FALLBACK: &str = "BOOTX64.EFI";

fn exists(dir: &fatfs::Dir<'_, impl Read + Write + Seek>, name: &str) -> bool {
    dir.iter()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().eq_ignore_ascii_case(name))
}

fn subdirs(dir: &fatfs::Dir<'_, impl Read + Write + Seek>) -> Vec<String> {
    dir.iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.is_dir() && e.file_name() != "." && e.file_name() != "..")
        .map(|e| e.file_name())
        .collect()
}

/// Find the system's loader and copy it to the fallback path if missing.
pub fn ensure_fallback<T: Read + Write + Seek>(esp: T) -> io::Result<BootFix> {
    let fs = fatfs::FileSystem::new(esp, fatfs::FsOptions::new())?;
    let root = fs.root_dir();
    let Ok(efi) = root.open_dir("EFI") else {
        return Ok(BootFix::default());
    };

    // (label, dir, files to copy: (source name, name in EFI/BOOT))
    let mut found: Option<Found> = None;
    if let Ok(ms) = efi.open_dir("Microsoft/Boot") {
        if exists(&ms, "bootmgfw.efi") {
            found = Some((
                "Windows Boot Manager".into(),
                "Microsoft/Boot".into(),
                vec![("bootmgfw.efi".into(), FALLBACK.into())],
            ));
        }
    }
    if found.is_none() {
        let mut dirs = subdirs(&efi);
        dirs.sort();
        for name in dirs {
            if name.eq_ignore_ascii_case("BOOT") || name.eq_ignore_ascii_case("Microsoft") {
                continue;
            }
            let Ok(d) = efi.open_dir(&name) else { continue };
            let label = if name.eq_ignore_ascii_case("systemd") {
                "Linux Boot Manager".to_string()
            } else {
                name.clone()
            };
            if exists(&d, "shimx64.efi") {
                let mut files = vec![("shimx64.efi".to_string(), FALLBACK.to_string())];
                for extra in ["grubx64.efi", "mmx64.efi"] {
                    if exists(&d, extra) {
                        files.push((extra.into(), extra.into()));
                    }
                }
                found = Some((label, name, files));
                break;
            }
            for single in ["grubx64.efi", "systemd-bootx64.efi"] {
                if exists(&d, single) {
                    found = Some((
                        label.clone(),
                        name.clone(),
                        vec![(single.into(), FALLBACK.into())],
                    ));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
    }
    let Some((label, dir, files)) = found else {
        return Ok(BootFix::default());
    };
    let mut fix = BootFix {
        loader: Some(Loader {
            label,
            path: format!("\\EFI\\{}\\{}", dir.replace('/', "\\"), files[0].0),
        }),
        added: vec![],
    };

    let boot = match efi.open_dir("BOOT") {
        Ok(d) => d,
        Err(_) => efi.create_dir("BOOT")?,
    };
    if exists(&boot, FALLBACK) {
        return Ok(fix);
    }
    let src = efi.open_dir(&dir)?;
    for (from, to) in files {
        if exists(&boot, &to) {
            continue;
        }
        let mut data = Vec::new();
        src.open_file(&from)?.read_to_end(&mut data)?;
        let mut f = boot.create_file(&to)?;
        f.truncate()?;
        f.write_all(&data)?;
        f.flush()?;
        fix.added
            .push(format!("\\{}\\{}", FALLBACK_DIR.replace('/', "\\"), to));
    }
    Ok(fix)
}

/// After restoring `disk` of an image to `device`: add the fallback loader
/// on the restored ESP if it is missing. `None` when the disk has no ESP.
pub fn fix_restored_disk(
    device: &std::path::Path,
    disk: &core_format::manifest::DiskImage,
) -> io::Result<Option<BootFix>> {
    use core_format::partition::PartitionRole;
    let Some(esp) = disk
        .partition_table
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Esp)
    else {
        return Ok(None);
    };
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)?;
    let fix = ensure_fallback(Window::new(f, esp.start, esp.length))?;
    Ok(Some(fix))
}

/// `[start, start + len)` of a seekable stream (a partition of a disk).
pub struct Window<S> {
    inner: S,
    start: u64,
    len: u64,
    pos: u64,
}

impl<S: Seek> Window<S> {
    pub fn new(inner: S, start: u64, len: u64) -> Self {
        Window {
            inner,
            start,
            len,
            pos: 0,
        }
    }
}

impl<S: Read + Seek> Read for Window<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        if n == 0 {
            return Ok(0);
        }
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let r = self.inner.read(&mut buf[..n])?;
        self.pos += r as u64;
        Ok(r)
    }
}

impl<S: Write + Seek> Write for Window<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        if n == 0 && !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write past the end of the partition",
            ));
        }
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let w = self.inner.write(&buf[..n])?;
        self.pos += w as u64;
        Ok(w)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S> Seek for Window<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn esp(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut img = Cursor::new(vec![0u8; 34 << 20]);
        fatfs::format_volume(
            &mut img,
            fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32),
        )
        .unwrap();
        {
            let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
            let root = fs.root_dir();
            for (path, data) in files {
                let (dir, name) = path.rsplit_once('/').unwrap();
                let mut d = root.clone();
                for part in dir.split('/') {
                    d = match d.open_dir(part) {
                        Ok(x) => x,
                        Err(_) => d.create_dir(part).unwrap(),
                    };
                }
                d.create_file(name).unwrap().write_all(data).unwrap();
            }
        }
        img.into_inner()
    }

    fn read(img: &mut Vec<u8>, path: &str) -> Option<Vec<u8>> {
        let fs = fatfs::FileSystem::new(Cursor::new(img), fatfs::FsOptions::new()).unwrap();
        let mut f = fs.root_dir().open_file(path).ok()?;
        let mut v = Vec::new();
        f.read_to_end(&mut v).unwrap();
        Some(v)
    }

    #[test]
    fn windows_gets_a_fallback_from_bootmgfw() {
        let mut img = esp(&[("EFI/Microsoft/Boot/bootmgfw.efi", b"WINDOWS")]);
        let fix = ensure_fallback(Cursor::new(&mut img)).unwrap();
        assert_eq!(
            fix.loader.unwrap().path,
            r"\EFI\Microsoft\Boot\bootmgfw.efi"
        );
        assert_eq!(fix.added, vec![r"\EFI\BOOT\BOOTX64.EFI"]);
        assert_eq!(read(&mut img, "EFI/BOOT/BOOTX64.EFI").unwrap(), b"WINDOWS");
    }

    #[test]
    fn existing_fallback_is_never_replaced() {
        let mut img = esp(&[
            ("EFI/Microsoft/Boot/bootmgfw.efi", b"WINDOWS"),
            ("EFI/Boot/bootx64.efi", b"ORIGINAL"),
        ]);
        let fix = ensure_fallback(Cursor::new(&mut img)).unwrap();
        assert!(fix.added.is_empty());
        assert_eq!(fix.loader.unwrap().label, "Windows Boot Manager");
        assert_eq!(read(&mut img, "EFI/BOOT/BOOTX64.EFI").unwrap(), b"ORIGINAL");
    }

    #[test]
    fn linux_shim_brings_grub_and_mok_manager() {
        let mut img = esp(&[
            ("EFI/debian/shimx64.efi", b"SHIM"),
            ("EFI/debian/grubx64.efi", b"GRUB"),
            ("EFI/debian/mmx64.efi", b"MM"),
        ]);
        let fix = ensure_fallback(Cursor::new(&mut img)).unwrap();
        let l = fix.loader.unwrap();
        assert_eq!(
            (l.label.as_str(), l.path.as_str()),
            ("debian", r"\EFI\debian\shimx64.efi")
        );
        assert_eq!(fix.added.len(), 3);
        assert_eq!(read(&mut img, "EFI/BOOT/BOOTX64.EFI").unwrap(), b"SHIM");
        assert_eq!(read(&mut img, "EFI/BOOT/grubx64.efi").unwrap(), b"GRUB");
        assert_eq!(read(&mut img, "EFI/BOOT/mmx64.efi").unwrap(), b"MM");
    }

    #[test]
    fn lone_grub_or_systemd_boot() {
        let mut img = esp(&[("EFI/ubuntu/grubx64.efi", b"GRUB")]);
        ensure_fallback(Cursor::new(&mut img)).unwrap();
        assert_eq!(read(&mut img, "EFI/BOOT/BOOTX64.EFI").unwrap(), b"GRUB");
        let mut img = esp(&[("EFI/systemd/systemd-bootx64.efi", b"SDBOOT")]);
        let fix = ensure_fallback(Cursor::new(&mut img)).unwrap();
        assert_eq!(fix.loader.unwrap().label, "Linux Boot Manager");
        assert_eq!(read(&mut img, "EFI/BOOT/BOOTX64.EFI").unwrap(), b"SDBOOT");
    }

    #[test]
    fn nothing_to_do_without_a_loader() {
        let mut img = esp(&[("notes/readme.txt", b"x")]);
        let fix = ensure_fallback(Cursor::new(&mut img)).unwrap();
        assert!(fix.loader.is_none() && fix.added.is_empty());
    }

    #[test]
    fn works_inside_a_partition_window() {
        let part = esp(&[("EFI/Microsoft/Boot/bootmgfw.efi", b"WINDOWS")]);
        let mut disk = vec![0xEEu8; (1 << 20) + part.len() + 4096];
        disk[1 << 20..(1 << 20) + part.len()].copy_from_slice(&part);
        let w = Window::new(Cursor::new(&mut disk), 1 << 20, part.len() as u64);
        assert_eq!(ensure_fallback(w).unwrap().added.len(), 1);
        // Bytes around the partition untouched.
        assert!(disk[..1 << 20].iter().all(|&b| b == 0xEE));
        assert!(disk[(1 << 20) + part.len()..].iter().all(|&b| b == 0xEE));
    }
}
