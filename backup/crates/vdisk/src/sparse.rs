//! Shared core of the sparse virtual disk writers (qcow2, VDI, VMDK).
//!
//! Each format maps fixed-size virtual blocks to places in the file. A block
//! is allocated on its first non-zero write, appended after the last one
//! (extending the file zero-fills it), and all-zero writes to an unallocated
//! block are dropped, so the file holds only data. The format writes its map
//! from [`Sparse::blocks`] when it finishes.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) fn write_at(f: &File, off: u64, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_all_at(f, data, off)
    }
    #[cfg(windows)]
    {
        let mut done = 0;
        while done < data.len() {
            done += std::os::windows::fs::FileExt::seek_write(f, &data[done..], off + done as u64)?;
        }
        Ok(())
    }
}

struct State {
    /// File offset of each virtual block, 0 = not allocated.
    blocks: Vec<u64>,
    next: u64,
}

pub(crate) struct Sparse {
    pub file: File,
    pub path: PathBuf,
    pub size: u64,
    pub block: u64,
    state: Mutex<State>,
}

impl Sparse {
    /// A new file (never overwrites) whose data blocks start at `data_start`.
    pub fn create(path: &Path, size: u64, block: u64, data_start: u64) -> io::Result<Sparse> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.set_len(data_start)?;
        Ok(Sparse {
            file,
            path: path.to_path_buf(),
            size,
            block,
            state: Mutex::new(State {
                blocks: vec![0; size.div_ceil(block) as usize],
                next: data_start,
            }),
        })
    }

    /// Write `data` at virtual offset `off`.
    pub fn write_at(&self, off: u64, data: &[u8]) -> io::Result<()> {
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if end > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write beyond the virtual disk",
            ));
        }
        let mut pos = 0usize;
        while pos < data.len() {
            let v = off + pos as u64;
            let index = (v / self.block) as usize;
            let within = v % self.block;
            let n = ((self.block - within) as usize).min(data.len() - pos);
            let piece = &data[pos..pos + n];
            let file_off = {
                let mut st = self.state.lock().unwrap();
                if st.blocks[index] == 0 {
                    if piece.iter().all(|&x| x == 0) {
                        pos += n;
                        continue;
                    }
                    let at = st.next;
                    st.next += self.block;
                    st.blocks[index] = at;
                    self.file.set_len(st.next)?;
                    at
                } else {
                    st.blocks[index]
                }
            };
            write_at(&self.file, file_off + within, piece)?;
            pos += n;
        }
        Ok(())
    }

    /// File offset of each virtual block (0 = not allocated) and the end of
    /// the data.
    pub fn blocks(&self) -> (Vec<u64>, u64) {
        let st = self.state.lock().unwrap();
        (st.blocks.clone(), st.next)
    }
}

/// A restore target that becomes a valid virtual disk once finished.
pub trait VirtualDiskTarget: engine::WriteTarget {
    /// Write the format's maps and flush. Returns the allocated blocks.
    fn finish(self: Box<Self>) -> io::Result<u64>;
}

macro_rules! write_target_via_sparse {
    ($t:ty) => {
        impl engine::WriteTarget for $t {
            fn size(&self) -> u64 {
                self.s.size
            }
            fn write_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
                self.s.write_at(offset, data)
            }
            fn sync(&self) -> std::io::Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                self.s.path.display().to_string()
            }
        }
    };
}
pub(crate) use write_target_via_sparse;
