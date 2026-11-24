//! SaaS data in a repository (docs/design/saas.md).
//!
//! A SaaS backup is an image of two disks:
//!
//! * disk 0: the index (JSON): every item of the account(s) at that time,
//!   where its bytes are, and the change cursors for the next backup;
//! * disk 1: a virtual disk whose chunks are the items' bytes, each item
//!   starting on its own chunk, so an item that did not change is the same
//!   chunk in every backup and is stored once.
//!
//! Every backup lists every item (it restores on its own); items the
//! service reports unchanged are not downloaded again: their chunks are taken
//! from the previous backup's index. Prune keeps exactly the chunks images
//! list, as for disk images.

use std::collections::BTreeMap;

use core_format::chunk::ChunkId;
use core_format::manifest::{
    BootConfig, ChunkRef, Consistency, DiskImage, ImageKind, ImageStats, MachineInfo, ManifestBody,
    OsInfo,
};
use core_format::partition::{PartitionTable, Scheme};
use core_format::{Extent, Repository};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// One item of a service: a mail message, a file, a record...
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// User, mailbox, site or org it belongs to.
    pub account: String,
    /// "mail", "file", "record"...
    pub kind: String,
    /// The service's ID for it.
    pub id: String,
    /// Where it was (folder path, drive path, object name).
    pub path: String,
    #[serde(default)]
    pub modified: String,
    pub size: u64,
    /// BLAKE3 of its bytes (hex).
    pub hash: String,
    /// Service-specific details (subject, MIME type, folder ID...).
    #[serde(default)]
    pub meta: Value,
    /// Its chunks on disk 1 (filled in when stored).
    #[serde(default)]
    pub chunks: Vec<ChunkId>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    /// "m365" | "google" | "salesforce".
    pub service: String,
    /// The tenant, domain or org.
    pub tenant: String,
    pub items: Vec<Item>,
    /// Change tokens per account and kind ("user|mail" → delta link...).
    #[serde(default)]
    pub cursors: BTreeMap<String, String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub fn machine_id(service: &str, tenant: &str) -> String {
    format!("saas:{service}:{tenant}")
}

/// Collects items for one backup and stores them.
pub struct Writer<'a> {
    repo: &'a Repository,
    pub index: Index,
    pub stats: ImageStats,
    /// Image OS family ("saas", or "files" for folder backups) and machine.
    family: String,
    machine: MachineInfo,
}

impl<'a> Writer<'a> {
    pub fn new(repo: &'a Repository, service: &str, tenant: &str) -> Self {
        let machine = MachineInfo {
            machine_id: machine_id(service, tenant),
            hostname: tenant.into(),
        };
        Self::with_identity(repo, "saas", machine, service, tenant)
    }

    /// A writer for another kind of item backup with the same layout (folder
    /// backups: family "files", the backed-up machine's own ID).
    pub fn with_identity(
        repo: &'a Repository,
        family: &str,
        machine: MachineInfo,
        service: &str,
        tenant: &str,
    ) -> Self {
        Writer {
            repo,
            index: Index {
                version: 1,
                service: service.into(),
                tenant: tenant.into(),
                ..Default::default()
            },
            stats: ImageStats::default(),
            family: family.into(),
            machine,
        }
    }

    /// Add an item whose bytes are read from `r` one chunk at a time (large
    /// files are never held in memory).
    pub fn add_stream(&mut self, mut item: Item, r: &mut dyn std::io::Read) -> std::io::Result<()> {
        let cs = self.repo.chunk_size() as usize;
        let mut h = blake3::Hasher::new();
        let mut chunks = Vec::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; cs];
        loop {
            let mut n = 0;
            while n < cs {
                let k = r.read(&mut buf[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
            }
            if n == 0 && !chunks.is_empty() {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
            chunks.extend(self.put(&buf[..n]).map_err(std::io::Error::other)?);
            if n < cs {
                break;
            }
        }
        item.size = size;
        item.hash = h.finalize().to_hex().to_string();
        item.chunks = chunks;
        self.index.items.push(item);
        Ok(())
    }

    fn put(&mut self, data: &[u8]) -> core_format::Result<Vec<ChunkId>> {
        let cs = self.repo.chunk_size() as usize;
        let mut ids = Vec::new();
        // An empty item still has one (empty) chunk, so it has a place.
        let pieces: Vec<&[u8]> = if data.is_empty() {
            vec![&[][..]]
        } else {
            data.chunks(cs).collect()
        };
        for p in pieces {
            let id = self.repo.chunk_id(p);
            self.stats.chunks_total += 1;
            self.stats.bytes_read += p.len() as u64;
            if !self.repo.has_chunk(&id)? {
                let (outcome, stored) = self.repo.put_chunk(&id, p)?;
                if outcome == core_format::PutOutcome::Created {
                    self.stats.chunks_new += 1;
                    self.stats.bytes_new_stored += stored;
                    self.stats.bytes_new_raw += p.len() as u64;
                }
            }
            ids.push(id);
        }
        Ok(ids)
    }

    /// Add an item with its bytes.
    pub fn add(&mut self, mut item: Item, data: &[u8]) -> core_format::Result<()> {
        item.size = data.len() as u64;
        item.hash = blake3::hash(data).to_hex().to_string();
        item.chunks = self.put(data)?;
        self.index.items.push(item);
        Ok(())
    }

    /// Whether a chunk is still stored (a kept item's chunks may have been pruned).
    pub fn has_chunk(&self, c: &ChunkId) -> bool {
        self.repo.has_chunk(c).unwrap_or(false)
    }

    /// Keep an item from the previous backup as it was (not downloaded again).
    pub fn keep(&mut self, item: Item) {
        self.stats.chunks_total += item.chunks.len() as u64;
        self.index.items.push(item);
    }

    /// Store the image. Returns its ID.
    pub fn finish(
        mut self,
        label: Option<String>,
        started: std::time::Instant,
    ) -> core_format::Result<Uuid> {
        let _lock = self.repo.lock(core_format::lock::LockKind::Shared)?;
        let cs = self.repo.chunk_size() as u64;
        self.index.items.sort_by(|a, b| {
            (&a.account, &a.kind, &a.path, &a.id).cmp(&(&b.account, &b.kind, &b.path, &b.id))
        });
        // Every chunk an item uses must exist (a kept item whose chunks a prune removed is downloaded again next time).
        let json = serde_json::to_vec(&self.index)?;
        let index_chunks = self.put(&json)?;
        let disk = |index: u32, refs: Vec<ChunkRef>, size: u64| DiskImage {
            index,
            size,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            model: String::new(),
            serial: String::new(),
            device: String::new(),
            partition_table: PartitionTable {
                scheme: Scheme::None,
                sector_size: 512,
                disk_guid: None,
                mbr_signature: None,
                first_usable_lba: None,
                last_usable_lba: None,
                backup_table_valid: true,
                partitions: vec![],
                raw_regions: vec![],
            },
            partitions: vec![],
            used_extents: vec![Extent(0, size)],
            chunks: refs,
        };
        let d0: Vec<ChunkRef> = index_chunks
            .iter()
            .enumerate()
            .map(|(i, c)| ChunkRef(i as u64, *c))
            .collect();
        let mut d1 = Vec::new();
        for it in &self.index.items {
            for c in &it.chunks {
                d1.push(ChunkRef(d1.len() as u64, *c));
            }
        }
        let size1 = (d1.len() as u64 * cs).max(cs);
        let machine = self.machine.clone();
        let (all, _) = self.repo.load_all_manifests()?;
        let parent = all
            .iter()
            .filter(|m| m.machine.machine_id == machine.machine_id)
            .max_by_key(|m| m.created_unix)
            .map(|m| m.image_id);
        let now = core_format::timefmt::now_unix();
        self.stats.duration_ms = started.elapsed().as_millis() as u64;
        let body = ManifestBody {
            format: core_format::manifest::BODY_FORMAT.into(),
            version: core_format::manifest::BODY_VERSION,
            image_id: Uuid::new_v4(),
            repo_id: self.repo.config().repo_id,
            created: core_format::timefmt::rfc3339_utc(now),
            created_unix: now,
            kind: if parent.is_some() {
                ImageKind::Incremental
            } else {
                ImageKind::Full
            },
            parent,
            label,
            machine: machine.clone(),
            consistency: Consistency::Crash,
            chunk_size: self.repo.chunk_size(),
            hash: self.repo.config().hash.clone(),
            compression: "zstd".into(),
            encryption: self.repo.config().encryption.clone(),
            disks: vec![
                disk(0, d0, (index_chunks.len() as u64 * cs).max(cs)),
                disk(1, d1, size1),
            ],
            boot: BootConfig::default(),
            os: OsInfo {
                family: self.family.clone(),
                name: self.index.service.clone(),
                version: json.len().to_string(),
                ..Default::default()
            },
            drivers: vec![],
            excluded: vec![],
            warnings: self.index.warnings.clone(),
            stats: self.stats.clone(),
            vm: None,
            applications: vec![],
        };
        let signer = self.repo.signer_for_machine(&machine.machine_id)?;
        self.repo.store_manifest(&body, &signer)?;
        Ok(body.image_id)
    }
}

/// The index of a SaaS image.
pub fn read_index(repo: &Repository, m: &ManifestBody) -> core_format::Result<Index> {
    if !matches!(m.os.family.as_str(), "saas" | "files") || m.disks.len() < 2 {
        return Err(core_format::Error::InvalidArgument(format!(
            "{} is not a SaaS or folder backup",
            m.image_id
        )));
    }
    let len: usize =
        m.os.version
            .parse()
            .map_err(|_| core_format::Error::malformed("SaaS index length"))?;
    let mut buf = Vec::with_capacity(len);
    for c in &m.disks[0].chunks {
        buf.extend(repo.get_chunk(&c.1)?);
    }
    buf.truncate(len);
    Ok(serde_json::from_slice(&buf)?)
}

/// An item's bytes.
pub fn read_item(repo: &Repository, item: &Item) -> core_format::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(item.size as usize);
    for c in &item.chunks {
        out.extend(repo.get_chunk(c)?);
    }
    if blake3::hash(&out).to_hex().as_str() != item.hash {
        return Err(core_format::Error::integrity(format!(
            "{} does not match its hash",
            item.path
        )));
    }
    Ok(out)
}

/// The newest SaaS image of this service and tenant, with its index (the
/// base of the next backup).
pub fn previous(
    repo: &Repository,
    service: &str,
    tenant: &str,
) -> core_format::Result<Option<(ManifestBody, Index)>> {
    let id = machine_id(service, tenant);
    let (all, _) = repo.load_all_manifests()?;
    let Some(m) = all
        .into_iter()
        .filter(|m| m.machine.machine_id == id)
        .max_by_key(|m| m.created_unix)
    else {
        return Ok(None);
    };
    let idx = read_index(repo, &m)?;
    // Items whose chunks are gone (pruned) cannot be kept: they are fetched again.
    Ok(Some((m, idx)))
}
