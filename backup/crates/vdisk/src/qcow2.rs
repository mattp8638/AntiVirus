//! qcow2 (version 3) writer, the native disk format of QEMU/KVM (Proxmox,
//! libvirt, OpenStack). Follows the published qcow2 specification
//! (QEMU `docs/interop/qcow2.txt`).
//!
//! Layout written:
//!
//! ```text
//! cluster 0          header (version 3, no extensions, 16-bit refcounts)
//! clusters 1..       data clusters, appended as first written
//! then, at finish:   L2 tables, L1 table, refcount blocks, refcount table
//! ```
//!
//! Every cluster in the file is used exactly once, so every refcount is 1
//! and every L1/L2 entry carries the COPIED flag. Unallocated clusters read
//! as zero.

use std::io;
use std::path::Path;

use crate::sparse::{write_at, write_target_via_sparse, Sparse, VirtualDiskTarget};

pub const CLUSTER_BITS: u32 = 16;
const CLUSTER: u64 = 1 << CLUSTER_BITS;
/// Entries in an L2 table (one cluster of 8-byte entries).
const L2_ENTRIES: u64 = CLUSTER / 8;
/// Entries in a refcount block (16-bit refcounts).
const RC_ENTRIES: u64 = CLUSTER / 2;
const COPIED: u64 = 1 << 63;
const HEADER_LEN: u32 = 104;

pub struct Qcow2Target {
    s: Sparse,
}

impl Qcow2Target {
    /// A new file (never overwrites) of `size` virtual bytes.
    pub fn create(path: &Path, size: u64) -> io::Result<Self> {
        if size == 0 || size % 512 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtual size must be a non-zero multiple of 512",
            ));
        }
        Ok(Qcow2Target {
            s: Sparse::create(path, size, CLUSTER, CLUSTER)?,
        })
    }
}

write_target_via_sparse!(Qcow2Target);

fn clusters(bytes: u64) -> u64 {
    bytes.div_ceil(CLUSTER)
}

impl VirtualDiskTarget for Qcow2Target {
    fn finish(self: Box<Self>) -> io::Result<u64> {
        let (blocks, mut next) = self.s.blocks();
        let l1_size = (blocks.len() as u64).div_ceil(L2_ENTRIES);
        // L2 tables, only where a cluster is allocated.
        let mut l1 = vec![0u64; l1_size as usize];
        let mut allocated = 0;
        for (t, entry) in l1.iter_mut().enumerate() {
            let first = t * L2_ENTRIES as usize;
            let part = &blocks[first..blocks.len().min(first + L2_ENTRIES as usize)];
            if part.iter().all(|&b| b == 0) {
                continue;
            }
            let mut l2 = vec![0u8; CLUSTER as usize];
            for (i, &b) in part.iter().enumerate() {
                if b != 0 {
                    l2[i * 8..i * 8 + 8].copy_from_slice(&(b | COPIED).to_be_bytes());
                    allocated += 1;
                }
            }
            write_at(&self.s.file, next, &l2)?;
            *entry = next | COPIED;
            next += CLUSTER;
        }
        let l1_offset = next;
        let l1_bytes: Vec<u8> = l1.iter().flat_map(|e| e.to_be_bytes()).collect();
        if !l1_bytes.is_empty() {
            write_at(&self.s.file, l1_offset, &l1_bytes)?;
        }
        next += clusters(l1_bytes.len() as u64).max(1) * CLUSTER;

        // Refcounts for every cluster up to the end, including the
        // refcount blocks and table themselves.
        let used = next / CLUSTER;
        let (mut rc_blocks, mut rc_table) = (0u64, 0u64);
        loop {
            let total = used + rc_blocks + rc_table;
            let b = total.div_ceil(RC_ENTRIES);
            let t = clusters(b * 8);
            if b == rc_blocks && t == rc_table {
                break;
            }
            (rc_blocks, rc_table) = (b, t);
        }
        let total = used + rc_blocks + rc_table;
        let rc_blocks_offset = next;
        let rc_table_offset = next + rc_blocks * CLUSTER;
        let mut table = vec![0u8; (rc_table * CLUSTER) as usize];
        for i in 0..rc_blocks {
            let mut blk = vec![0u8; CLUSTER as usize];
            let first = i * RC_ENTRIES;
            for c in first..total.min(first + RC_ENTRIES) {
                let o = ((c - first) * 2) as usize;
                blk[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
            }
            let at = rc_blocks_offset + i * CLUSTER;
            write_at(&self.s.file, at, &blk)?;
            table[(i * 8) as usize..(i * 8 + 8) as usize].copy_from_slice(&at.to_be_bytes());
        }
        write_at(&self.s.file, rc_table_offset, &table)?;
        self.s.file.set_len(total * CLUSTER)?;

        // Header last: until now the file is not a valid qcow2.
        let mut h = vec![0u8; HEADER_LEN as usize + 8];
        h[0..4].copy_from_slice(b"QFI\xfb");
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        // backing file offset/size: 0
        h[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        h[24..32].copy_from_slice(&self.s.size.to_be_bytes());
        // crypt method: 0
        h[36..40].copy_from_slice(&(l1_size as u32).to_be_bytes());
        h[40..48].copy_from_slice(&l1_offset.to_be_bytes());
        h[48..56].copy_from_slice(&rc_table_offset.to_be_bytes());
        h[56..60].copy_from_slice(&(rc_table as u32).to_be_bytes());
        // snapshots: none; feature bits: none
        h[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount order: 16 bits
        h[100..104].copy_from_slice(&HEADER_LEN.to_be_bytes());
        // header extension end marker (type 0, length 0): already zero
        write_at(&self.s.file, 0, &h)?;
        self.s.file.sync_all()?;
        Ok(allocated)
    }
}
