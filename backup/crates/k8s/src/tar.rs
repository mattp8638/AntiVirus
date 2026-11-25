//! A volume's files as a tar stream (POSIX ustar with PAX long names), and
//! extracting one safely: nothing outside the target folder, no device files,
//! links only within it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

fn octal(dst: &mut [u8], v: u64) {
    let s = format!("{:0width$o}\0", v, width = dst.len() - 1);
    dst.copy_from_slice(s.as_bytes());
}

fn header(name: &str, size: u64, mode: u32, mtime: u64, typeflag: u8, link: &str) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.as_bytes();
    h[..n.len().min(100)].copy_from_slice(&n[..n.len().min(100)]);
    octal(&mut h[100..108], mode as u64 & 0o7777);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[148..156].fill(b' ');
    h[156] = typeflag;
    let l = link.as_bytes();
    h[157..157 + l.len().min(100)].copy_from_slice(&l[..l.len().min(100)]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn pad(out: &mut impl Write, n: u64) -> io::Result<()> {
    out.write_all(&vec![0u8; ((512 - n % 512) % 512) as usize])
}

fn pax(out: &mut impl Write, records: &[(&str, &str)]) -> io::Result<()> {
    let mut body = Vec::new();
    for (k, v) in records {
        let rec = format!(" {k}={v}\n");
        let mut len = rec.len() + 1;
        while format!("{len}{rec}").len() != len {
            len += 1;
        }
        body.extend(format!("{len}{rec}").into_bytes());
    }
    out.write_all(&header(
        "././@PaxHeader",
        body.len() as u64,
        0o644,
        0,
        b'x',
        "",
    ))?;
    out.write_all(&body)?;
    pad(out, body.len() as u64)
}

fn entry(
    out: &mut impl Write,
    name: &str,
    size: u64,
    mode: u32,
    mtime: u64,
    typeflag: u8,
    link: &str,
) -> io::Result<()> {
    let mut recs = Vec::new();
    if name.len() > 100 || !name.is_ascii() {
        recs.push(("path", name));
    }
    if link.len() > 100 || !link.is_ascii() {
        recs.push(("linkpath", link));
    }
    if !recs.is_empty() {
        pax(out, &recs)?;
    }
    let short: String = name.chars().filter(char::is_ascii).take(100).collect();
    let short_link: String = link.chars().filter(char::is_ascii).take(100).collect();
    out.write_all(&header(&short, size, mode, mtime, typeflag, &short_link))
}

/// Write `root`'s contents (files, folders, symbolic links) as a tar stream.
/// Returns bytes written.
pub fn write_dir(root: &Path, out: &mut impl Write) -> io::Result<u64> {
    struct Count<'a, W: Write>(&'a mut W, u64);
    impl<W: Write> Write for Count<'_, W> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let n = self.0.write(b)?;
            self.1 += n as u64;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    let mut c = Count(out, 0);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut items: Vec<_> = std::fs::read_dir(&dir)?.flatten().collect();
        items.sort_by_key(|e| e.file_name());
        for e in items {
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let md = std::fs::symlink_metadata(&p)?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            #[cfg(unix)]
            let mode = std::os::unix::fs::PermissionsExt::mode(&md.permissions());
            #[cfg(not(unix))]
            let mode = if md.is_dir() { 0o755 } else { 0o644 };
            if md.file_type().is_symlink() {
                let target = std::fs::read_link(&p)?.to_string_lossy().into_owned();
                entry(&mut c, &rel, 0, mode, mtime, b'2', &target)?;
            } else if md.is_dir() {
                entry(&mut c, &format!("{rel}/"), 0, mode, mtime, b'5', "")?;
                stack.push(p);
            } else if md.is_file() {
                entry(&mut c, &rel, md.len(), mode, mtime, b'0', "")?;
                let n = io::copy(&mut File::open(&p)?.take(md.len()), &mut c)?;
                if n < md.len() {
                    // Shrank while read (only on a live volume): keep the stream well-formed.
                    io::copy(&mut io::repeat(0).take(md.len() - n), &mut c)?;
                }
                pad(&mut c, md.len())?;
            }
            // Sockets, FIFOs and devices are not data.
        }
    }
    c.write_all(&[0u8; 1024])?;
    Ok(c.1)
}

/// What an extraction did.
#[derive(Debug, Default, PartialEq, serde::Serialize)]
pub struct Extracted {
    pub files: u64,
    pub bytes: u64,
    pub skipped: Vec<String>,
}

fn safe(root: &Path, name: &str) -> Option<PathBuf> {
    let mut p = root.to_path_buf();
    for c in Path::new(name.trim_start_matches("./")).components() {
        match c {
            Component::Normal(s) => p.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (p != root).then_some(p)
}

fn parse_octal(b: &[u8]) -> u64 {
    let s: String = b
        .iter()
        .take_while(|&&c| c != 0 && c != b' ')
        .map(|&c| c as char)
        .collect();
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

/// Extract a tar stream into `root` (which must exist). Entries that would
/// land outside it, links pointing outside it, and special files are skipped.
pub fn extract(input: &mut impl Read, root: &Path) -> io::Result<Extracted> {
    let mut rep = Extracted::default();
    let mut pending_path: Option<String> = None;
    let mut pending_link: Option<String> = None;
    let mut h = [0u8; 512];
    loop {
        if input.read_exact(&mut h).is_err() || h.iter().all(|&b| b == 0) {
            break;
        }
        let size = parse_octal(&h[124..136]);
        let typeflag = h[156];
        let mode = parse_octal(&h[100..108]) as u32;
        let name = pending_path.take().unwrap_or_else(|| {
            let prefix = cstr(&h[345..500]);
            let n = cstr(&h[..100]);
            if prefix.is_empty() {
                n
            } else {
                format!("{prefix}/{n}")
            }
        });
        let link = pending_link.take().unwrap_or_else(|| cstr(&h[157..257]));
        let padded = size.div_ceil(512) * 512;
        let mut body = input.take(padded);
        if typeflag == b'x' {
            let mut b = Vec::new();
            body.read_to_end(&mut b)?;
            b.truncate(size as usize);
            for rec in String::from_utf8_lossy(&b).split('\n') {
                if let Some((_, kv)) = rec.split_once(' ') {
                    if let Some(v) = kv.strip_prefix("path=") {
                        pending_path = Some(v.to_string());
                    } else if let Some(v) = kv.strip_prefix("linkpath=") {
                        pending_link = Some(v.to_string());
                    }
                }
            }
            continue;
        }
        let Some(dst) = safe(root, &name) else {
            io::copy(&mut body, &mut io::sink())?;
            if !name.trim_matches(['/', '.']).is_empty() {
                rep.skipped.push(name);
            }
            continue;
        };
        match typeflag {
            b'5' => {
                std::fs::create_dir_all(&dst)?;
                set_mode(&dst, mode);
            }
            b'0' | 0 | b'7' => {
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::remove_file(&dst);
                let mut f = File::create(&dst)?;
                let n = io::copy(&mut (&mut body).take(size), &mut f)?;
                rep.files += 1;
                rep.bytes += n;
                set_mode(&dst, mode);
            }
            b'2' => {
                // Only links that stay inside the volume.
                let resolved = dst.parent().map(|d| d.join(&link));
                let inside = !Path::new(&link).is_absolute()
                    && resolved
                        .as_ref()
                        .is_some_and(|r| normalize(r).starts_with(root));
                if inside {
                    #[cfg(unix)]
                    {
                        if let Some(parent) = dst.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let _ = std::fs::remove_file(&dst);
                        std::os::unix::fs::symlink(&link, &dst)?;
                    }
                } else {
                    rep.skipped.push(format!("{name} -> {link}"));
                }
            }
            _ => rep.skipped.push(name),
        }
        io::copy(&mut body, &mut io::sink())?;
    }
    Ok(rep)
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

fn set_mode(_p: &Path, _mode: u32) {
    #[cfg(unix)]
    {
        if _mode != 0 {
            let _ = std::fs::set_permissions(
                _p,
                std::os::unix::fs::PermissionsExt::from_mode(_mode & 0o7777),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_long_names_and_links() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        let long = "folder-with-a-rather-long-name-indeed/".repeat(4) + "file.bin";
        std::fs::create_dir_all(src.join(&long).parent().unwrap()).unwrap();
        std::fs::write(src.join(&long), vec![7u8; 5000]).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::create_dir_all(src.join("empty")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
        let mut stream = Vec::new();
        let n = write_dir(&src, &mut stream).unwrap();
        assert_eq!(n as usize, stream.len());
        let dst = d.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let r = extract(&mut &stream[..], &dst).unwrap();
        assert_eq!(std::fs::read(dst.join(&long)).unwrap(), vec![7u8; 5000]);
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"hello");
        assert!(dst.join("empty").is_dir());
        #[cfg(unix)]
        assert_eq!(
            std::fs::read_link(dst.join("link")).unwrap(),
            Path::new("a.txt")
        );
        assert_eq!(r.files, 2);
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    }

    #[test]
    fn nothing_escapes_the_target() {
        let mut s = Vec::new();
        entry(&mut s, "../evil", 4, 0o644, 0, b'0', "").unwrap();
        s.extend(b"evil");
        pad(&mut s, 4).unwrap();
        entry(&mut s, "ok/../../evil2", 0, 0o644, 0, b'0', "").unwrap();
        entry(&mut s, "out", 0, 0o777, 0, b'2', "/etc/passwd").unwrap();
        entry(&mut s, "up", 0, 0o777, 0, b'2', "../../x").unwrap();
        entry(&mut s, "dev", 0, 0o644, 0, b'3', "").unwrap();
        s.extend([0u8; 1024]);
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("vol");
        std::fs::create_dir_all(&root).unwrap();
        let r = extract(&mut &s[..], &root).unwrap();
        assert!(!d.path().join("evil").exists() && !d.path().join("evil2").exists());
        assert!(
            std::fs::read_dir(&root).unwrap().next().is_none(),
            "nothing written"
        );
        assert_eq!(r.skipped.len(), 5, "{:?}", r.skipped);
    }
}
