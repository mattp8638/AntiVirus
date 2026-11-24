//! Restored files downloaded to the browser, end to end encrypted
//! (docs/design/file-download.md): restore to a private temporary folder,
//! pack it as a tar archive (POSIX ustar with PAX long names), encrypt the
//! archive for the browser's one-time key and upload it to the server.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use protocol::download::{DownloadHeader, Encryptor, FRAME};

/// Largest archive a download carries; bigger restores go to a folder.
pub const MAX_BYTES: u64 = 4 << 30;

fn octal(dst: &mut [u8], v: u64) {
    let s = format!("{:0width$o}\0", v, width = dst.len() - 1);
    dst.copy_from_slice(s.as_bytes());
}

fn header(name: &str, size: u64, mtime: u64, dir: bool, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.as_bytes();
    h[..n.len().min(100)].copy_from_slice(&n[..n.len().min(100)]);
    octal(&mut h[100..108], if dir { 0o755 } else { 0o644 });
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[148..156].fill(b' ');
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

fn pad(out: &mut impl Write, n: u64) -> io::Result<()> {
    let r = (512 - n % 512) % 512;
    out.write_all(&vec![0u8; r as usize])
}

/// A PAX record "len path=...\n" (len counts itself).
fn pax_path(path: &str) -> Vec<u8> {
    let body = format!(" path={path}\n");
    let mut len = body.len() + 1;
    while format!("{len}{body}").len() != len {
        len += 1;
    }
    format!("{len}{body}").into_bytes()
}

fn entry(out: &mut impl Write, name: &str, size: u64, mtime: u64, dir: bool) -> io::Result<()> {
    if name.len() > 100 || !name.is_ascii() {
        let rec = pax_path(name);
        out.write_all(&header(
            "././@PaxHeader",
            rec.len() as u64,
            mtime,
            false,
            b'x',
        ))?;
        out.write_all(&rec)?;
        pad(out, rec.len() as u64)?;
    }
    let short: String = name.chars().filter(char::is_ascii).take(100).collect();
    out.write_all(&header(
        &short,
        size,
        mtime,
        dir,
        if dir { b'5' } else { b'0' },
    ))
}

/// Write `root`'s contents as a tar archive; returns the bytes written.
pub fn tar_dir(root: &Path, out: &mut impl Write) -> io::Result<u64> {
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
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
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
            let md = e.metadata()?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            if md.is_dir() {
                entry(&mut c, &format!("{rel}/"), 0, mtime, true)?;
                stack.push(p);
            } else if md.is_file() {
                entry(&mut c, &rel, md.len(), mtime, false)?;
                let mut f = File::open(&p)?;
                let n = io::copy(&mut f, &mut c)?;
                pad(&mut c, n)?;
            }
        }
    }
    c.write_all(&[0u8; 1024])?;
    Ok(c.1)
}

/// Encrypt `archive` for `recipient` and hand the stream to `upload` in
/// batches (offset, bytes). Returns the header for the browser.
pub fn encrypt_and_send(
    archive: &Path,
    recipient: &str,
    file_name: &str,
    mut upload: impl FnMut(u64, &[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<DownloadHeader> {
    let mut f = File::open(archive)?;
    let total = f.metadata()?.len();
    if total > MAX_BYTES {
        bail!(
            "the files come to {} MiB, more than a download carries ({} MiB): restore them to a folder instead",
            total >> 20,
            MAX_BYTES >> 20
        );
    }
    let mut enc = Encryptor::new();
    let sealed_key = enc
        .sealed_key(recipient)
        .map_err(|e| anyhow::anyhow!("the browser's key: {e}"))?;
    let mut buf = vec![0u8; FRAME];
    let mut batch = Vec::new();
    let (mut done, mut sent) = (0u64, 0u64);
    loop {
        let mut n = 0;
        while n < FRAME {
            let r = f.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        done += n as u64;
        let last = done >= total;
        batch.extend(enc.frame(&buf[..n], last));
        if last || batch.len() >= 8 * FRAME {
            upload(sent, &batch).context("uploading the encrypted files")?;
            sent += batch.len() as u64;
            batch.clear();
        }
        if last {
            break;
        }
    }
    Ok(DownloadHeader {
        v: 1,
        sealed_key,
        frame: FRAME as u32,
        stream_bytes: sent,
        archive_bytes: total,
        file_name: file_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_is_readable_and_round_trips_through_encryption() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("files");
        std::fs::create_dir_all(root.join("Users/Ann/Documents")).unwrap();
        std::fs::write(
            root.join("Users/Ann/Documents/report.txt"),
            b"quarterly report\n",
        )
        .unwrap();
        let long =
            "a-very-long-folder-name-that-goes-on-and-on-for-quite-a-while/".repeat(3) + "file.bin";
        std::fs::create_dir_all(root.join(&long).parent().unwrap()).unwrap();
        std::fs::write(root.join(&long), vec![9u8; 3000]).unwrap();
        let tar = d.path().join("out.tar");
        let n = tar_dir(&root, &mut File::create(&tar).unwrap()).unwrap();
        assert_eq!(n, std::fs::metadata(&tar).unwrap().len());
        assert_eq!(n % 512, 0);
        // The system's tar reads it back, long name included.
        if std::process::Command::new("tar")
            .arg("--version")
            .output()
            .is_ok()
        {
            let x = d.path().join("x");
            std::fs::create_dir_all(&x).unwrap();
            let st = std::process::Command::new("tar")
                .arg("-xf")
                .arg(&tar)
                .arg("-C")
                .arg(&x)
                .status()
                .unwrap();
            assert!(st.success());
            assert_eq!(
                std::fs::read(x.join("Users/Ann/Documents/report.txt")).unwrap(),
                b"quarterly report\n"
            );
            assert_eq!(std::fs::read(x.join(&long)).unwrap(), vec![9u8; 3000]);
        }
        // Encrypted for a browser key, uploaded in batches, decrypted back.
        let browser = protocol::seal::AgentKey::generate();
        let mut stream = Vec::new();
        let h = encrypt_and_send(&tar, &browser.public_b64(), "restore.tar", |off, b| {
            assert_eq!(off as usize, stream.len());
            stream.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(h.stream_bytes as usize, stream.len());
        let key: [u8; 32] = browser.open(&h.sealed_key).unwrap()[..].try_into().unwrap();
        assert_eq!(
            protocol::download::decrypt(&key, &stream).unwrap(),
            std::fs::read(&tar).unwrap()
        );
    }
}
