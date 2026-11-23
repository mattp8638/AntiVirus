//! One disk of a backup image as an NBD export.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};

use core_format::chunk::ChunkId;
use core_format::lock::{LockKind, RepoLock};
use core_format::{ManifestBody, Repository};

use crate::Export;

struct Lru {
    map: HashMap<u64, Arc<Vec<u8>>>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl Lru {
    fn get(&mut self, k: u64) -> Option<Arc<Vec<u8>>> {
        let v = self.map.get(&k)?.clone();
        self.order.retain(|x| *x != k);
        self.order.push_back(k);
        Some(v)
    }
    fn put(&mut self, k: u64, v: Arc<Vec<u8>>) {
        if self.map.insert(k, v).is_none() {
            self.order.push_back(k);
        }
        while self.map.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

pub struct ImageExport {
    repo: Repository,
    size: u64,
    chunk_size: u64,
    chunks: HashMap<u64, ChunkId>,
    cache: Mutex<Lru>,
    /// Keeps prune away from the chunks this export reads.
    _lock: Option<RepoLock>,
}

impl ImageExport {
    /// Export disk `disk_index` of `image`. `cache_bytes` bounds memory
    /// used for decrypted chunks.
    pub fn new(
        repo: &Repository,
        image: &ManifestBody,
        disk_index: u32,
        cache_bytes: u64,
    ) -> core_format::Result<ImageExport> {
        let d = image
            .disks
            .iter()
            .find(|d| d.index == disk_index)
            .ok_or_else(|| {
                core_format::Error::InvalidArgument(format!("image has no disk {disk_index}"))
            })?;
        let lock = match repo.lock(LockKind::Shared) {
            Ok(l) => Some(l),
            Err(e @ core_format::Error::Busy(_)) => return Err(e),
            Err(_) => None, // read-only medium
        };
        let chunk_size = image.chunk_size as u64;
        Ok(ImageExport {
            repo: repo.clone(),
            size: d.size,
            chunk_size,
            chunks: d.chunks.iter().map(|c| (c.0, c.1)).collect(),
            cache: Mutex::new(Lru {
                map: HashMap::new(),
                order: VecDeque::new(),
                capacity: (cache_bytes / chunk_size).max(2) as usize,
            }),
            _lock: lock,
        })
    }

    fn chunk(&self, index: u64) -> io::Result<Option<Arc<Vec<u8>>>> {
        let Some(id) = self.chunks.get(&index) else {
            return Ok(None);
        };
        if let Some(c) = self.cache.lock().unwrap().get(index) {
            return Ok(Some(c));
        }
        let data = Arc::new(
            self.repo
                .get_chunk(id)
                .map_err(|e| io::Error::other(e.to_string()))?,
        );
        self.cache.lock().unwrap().put(index, data.clone());
        Ok(Some(data))
    }
}

impl Export for ImageExport {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut pos = 0usize;
        while pos < buf.len() {
            let abs = offset + pos as u64;
            let index = abs / self.chunk_size;
            let within = (abs % self.chunk_size) as usize;
            let n = (self.chunk_size as usize - within).min(buf.len() - pos);
            match self.chunk(index)? {
                Some(c) => {
                    let avail = c.len().saturating_sub(within).min(n);
                    buf[pos..pos + avail].copy_from_slice(&c[within..within + avail]);
                    buf[pos + avail..pos + n].fill(0);
                }
                None => buf[pos..pos + n].fill(0),
            }
            pos += n;
        }
        Ok(())
    }
}
