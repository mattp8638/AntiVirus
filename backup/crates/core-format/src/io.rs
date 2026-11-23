//! Minimal positional-read abstraction shared by sources and readers.

use std::io;

/// Positional, exact read. Implementations must fill all of `buf` or fail.
pub trait ReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl ReadAt for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let end = start
            .checked_add(buf.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let src = self.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.as_slice().read_at(offset, buf)
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            let mut done = 0usize;
            while done < buf.len() {
                let n = std::os::windows::fs::FileExt::seek_read(
                    self,
                    &mut buf[done..],
                    offset + done as u64,
                )?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                done += n;
            }
            Ok(())
        }
    }
}
