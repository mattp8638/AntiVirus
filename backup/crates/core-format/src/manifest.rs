//! Image manifests: what an image contains and how to rebuild it.
//!
//! Stored form (see docs/FORMAT.md §5):
//!
//! ```text
//! manifests/<image_id>  =  sealed object "FNRM" (binding = image_id bytes)
//!     plaintext = envelope JSON:
//!     { "format": "fenrir-manifest-envelope", "version": 1,
//!       "signer": "<key id hex>", "signature": "<base64 Ed25519>",
//!       "body": "<manifest body JSON as a string>" }
//! ```
//!
//! The signature covers the UTF-8 bytes of `body` exactly as stored, so a
//! reader verifies before parsing and never has to re-serialise JSON.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chunk::ChunkId;
use crate::crypto::{self, b64, SecretKey};
use crate::error::{Error, Result};
use crate::extent::Extent;
use crate::fsdetect::FsType;
use crate::object::{self, SealOptions, MAGIC_MANIFEST};
use crate::partition::{PartitionEntry, PartitionTable};

pub const ENVELOPE_FORMAT: &str = "fenrir-manifest-envelope";
pub const BODY_FORMAT: &str = "fenrir-image-manifest";
pub const BODY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    /// VSS with writers (or an equivalent application quiesce).
    Application,
    /// Point-in-time snapshot without application quiesce.
    Crash,
    /// Source was offline / not mounted while read.
    Offline,
    /// Read from a live, unsnapshotted device. Restorable but may be torn.
    Inconsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    Full,
    /// Shares chunks with `parent`; still self-contained to restore.
    Incremental,
}

/// How a partition's contents were captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    /// Used blocks only, from a snapshot, according to the filesystem bitmap.
    SnapshotBitmap,
    /// Every block, from a snapshot.
    SnapshotFull,
    /// Every block, read directly from the disk.
    RawFull,
    /// Used blocks only, read directly (offline source).
    RawBitmap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineInfo {
    pub machine_id: String,
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    /// "windows", "linux", or "unknown".
    pub family: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverInfo {
    pub name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub inf: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Firmware {
    Uefi,
    Bios,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UefiBootEntry {
    /// e.g. "Boot0001".
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Device path as text if decoded, otherwise hex of the raw variable.
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfig {
    pub firmware: Firmware,
    #[serde(default)]
    pub secure_boot: Option<bool>,
    #[serde(default)]
    pub uefi_entries: Vec<UefiBootEntry>,
    #[serde(default)]
    pub boot_order: Vec<String>,
    /// Windows Boot Manager BCD store found (path relative to its partition).
    #[serde(default)]
    pub bcd: Option<String>,
    /// GRUB configuration found.
    #[serde(default)]
    pub grub: Option<String>,
    #[serde(default)]
    pub systemd_boot: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Default for BootConfig {
    fn default() -> Self {
        BootConfig {
            firmware: Firmware::Unknown,
            secure_boot: None,
            uefi_entries: vec![],
            boot_order: vec![],
            bcd: None,
            grub: None,
            systemd_boot: None,
            notes: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionRecord {
    #[serde(flatten)]
    pub entry: PartitionEntry,
    pub filesystem: FsType,
    pub capture: CaptureMethod,
    /// Bytes of this partition included in the image.
    pub captured_bytes: u64,
    /// OS volume name, e.g. `\\?\Volume{...}\` or `/dev/sda2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// Drive letters / mount points at backup time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mount_points: Vec<String>,
    /// BitLocker or LUKS status if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedFile {
    pub path: String,
    pub bytes: u64,
}

/// One chunk of a disk: `[index, chunk_id]` with offset `index * chunk_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef(pub u64, pub ChunkId);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskImage {
    /// Position in this image (0-based).
    pub index: u32,
    pub size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub serial: String,
    /// OS device path at backup time, informational.
    #[serde(default)]
    pub device: String,
    pub partition_table: PartitionTable,
    pub partitions: Vec<PartitionRecord>,
    /// Byte ranges of the disk captured in this image (normalised). Bytes
    /// outside these ranges were not read and restore as zero.
    pub used_extents: Vec<Extent>,
    /// Ordered by index. Indices not listed are all-zero chunks.
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageStats {
    pub bytes_read: u64,
    pub chunks_total: u64,
    pub chunks_new: u64,
    pub bytes_new_stored: u64,
    /// Plaintext size of the newly stored chunks. With `bytes_new_stored`
    /// this gives the new data's compressibility (anomaly detection).
    #[serde(default)]
    pub bytes_new_raw: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    pub format: String,
    pub version: u32,
    pub image_id: Uuid,
    pub repo_id: Uuid,
    /// RFC 3339 UTC.
    pub created: String,
    pub created_unix: i64,
    pub kind: ImageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub machine: MachineInfo,
    pub consistency: Consistency,
    pub chunk_size: u32,
    pub hash: String,
    pub compression: String,
    pub encryption: String,
    pub disks: Vec<DiskImage>,
    pub boot: BootConfig,
    pub os: OsInfo,
    #[serde(default)]
    pub drivers: Vec<DriverInfo>,
    #[serde(default)]
    pub excluded: Vec<ExcludedFile>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub stats: ImageStats,
    /// Present when the image is of a virtual machine backed up from its
    /// host. Optional in format version 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<VmInfo>,
}

/// Hypervisor-level description of a backed-up VM, enough to recreate it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInfo {
    /// "hyper-v".
    pub hypervisor: String,
    pub host: String,
    pub vm_id: String,
    pub name: String,
    /// Hyper-V generation (1 = BIOS, 2 = UEFI).
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub cpu_count: u32,
    #[serde(default)]
    pub memory_mb: u64,
    #[serde(default)]
    pub secure_boot: Option<bool>,
    /// One entry per image disk, same order as `disks`.
    #[serde(default)]
    pub disks: Vec<VmDisk>,
    #[serde(default)]
    pub network_adapters: Vec<VmNetworkAdapter>,
    #[serde(default)]
    pub config_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDisk {
    /// e.g. "SCSI 0:1" or "IDE 0:0".
    pub controller: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmNetworkAdapter {
    pub name: String,
    #[serde(default)]
    pub switch: String,
    #[serde(default)]
    pub mac: String,
}

impl ManifestBody {
    /// Structural checks a reader performs after verifying the signature.
    pub fn validate(&self) -> Result<()> {
        if self.format != BODY_FORMAT {
            return Err(Error::malformed("not an image manifest"));
        }
        if self.version != BODY_VERSION {
            return Err(Error::UnsupportedVersion {
                what: "manifest",
                version: self.version,
            });
        }
        crate::chunk::check_chunk_size(self.chunk_size)?;
        let cs = self.chunk_size as u64;
        for d in &self.disks {
            let n_chunks = d.size.div_ceil(cs);
            let mut prev: Option<u64> = None;
            for c in &d.chunks {
                if c.0 >= n_chunks {
                    return Err(Error::malformed(format!(
                        "disk {}: chunk index {} beyond disk",
                        d.index, c.0
                    )));
                }
                if prev.is_some_and(|p| c.0 <= p) {
                    return Err(Error::malformed(format!(
                        "disk {}: chunk list not strictly ordered",
                        d.index
                    )));
                }
                prev = Some(c.0);
            }
            for e in &d.used_extents {
                if e.end() > d.size {
                    return Err(Error::malformed(format!(
                        "disk {}: used extent beyond disk",
                        d.index
                    )));
                }
            }
        }
        Ok(())
    }

    /// Every distinct chunk this image references.
    pub fn chunk_ids(&self) -> std::collections::BTreeSet<ChunkId> {
        self.disks
            .iter()
            .flat_map(|d| d.chunks.iter().map(|c| c.1))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub format: String,
    pub version: u32,
    pub signer: String,
    pub signature: String,
    pub body: String,
}

/// An Ed25519 manifest signing identity.
pub struct ManifestSigner {
    pub key_id: String,
    key: SigningKey,
}

impl ManifestSigner {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        crypto::fill_random(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        ManifestSigner {
            key_id: key_id_for(&key.verifying_key()),
            key,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

/// Key ID: first 16 bytes of BLAKE3(public key), hex.
pub fn key_id_for(vk: &VerifyingKey) -> String {
    hex::encode(&blake3::hash(vk.as_bytes()).as_bytes()[..16])
}

pub fn seal_manifest(
    body: &ManifestBody,
    signer: &ManifestSigner,
    enc_key: &SecretKey,
    zstd_level: i32,
) -> Result<Vec<u8>> {
    body.validate()?;
    let body_json = serde_json::to_string(body)?;
    let sig = signer.key.sign(body_json.as_bytes());
    let env = Envelope {
        format: ENVELOPE_FORMAT.into(),
        version: 1,
        signer: signer.key_id.clone(),
        signature: b64::encode(&sig.to_bytes()),
        body: body_json,
    };
    let pt = serde_json::to_vec(&env)?;
    object::seal_object(
        MAGIC_MANIFEST,
        enc_key,
        body.image_id.as_bytes(),
        &pt,
        &SealOptions {
            zstd_level: Some(zstd_level),
        },
    )
}

/// Decrypt a manifest object and return its envelope (signature not yet checked).
pub fn open_envelope(image_id: &Uuid, enc_key: &SecretKey, data: &[u8]) -> Result<Envelope> {
    let pt = object::open_object(MAGIC_MANIFEST, enc_key, image_id.as_bytes(), data)
        .map_err(|e| Error::integrity(format!("manifest {image_id}: {e}")))?;
    let env: Envelope = serde_json::from_slice(&pt)?;
    if env.format != ENVELOPE_FORMAT {
        return Err(Error::malformed("not a manifest envelope"));
    }
    if env.version != 1 {
        return Err(Error::UnsupportedVersion {
            what: "manifest envelope",
            version: env.version,
        });
    }
    Ok(env)
}

/// Verify the envelope's signature with `vk`, then parse and validate the body.
pub fn verify_envelope(env: &Envelope, vk: &VerifyingKey, image_id: &Uuid) -> Result<ManifestBody> {
    if key_id_for(vk) != env.signer {
        return Err(Error::integrity("manifest signer key id mismatch"));
    }
    let sig_bytes: [u8; 64] = b64::decode(&env.signature)?
        .try_into()
        .map_err(|_| Error::malformed("signature length"))?;
    vk.verify(env.body.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Error::integrity(format!("manifest {image_id}: bad signature")))?;
    let body: ManifestBody = serde_json::from_str(&env.body)?;
    if body.image_id != *image_id {
        return Err(Error::integrity(
            "manifest image id does not match its name",
        ));
    }
    body.validate()?;
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::partition::Scheme;

    pub fn sample_body() -> ManifestBody {
        ManifestBody {
            format: BODY_FORMAT.into(),
            version: BODY_VERSION,
            image_id: Uuid::new_v4(),
            repo_id: Uuid::new_v4(),
            created: "2026-11-20T10:00:00Z".into(),
            created_unix: 1_795_000_000,
            kind: ImageKind::Full,
            parent: None,
            label: None,
            machine: MachineInfo {
                machine_id: "m1".into(),
                hostname: "host".into(),
            },
            consistency: Consistency::Application,
            chunk_size: crate::chunk::DEFAULT_CHUNK_SIZE,
            hash: "blake3-keyed".into(),
            compression: "zstd".into(),
            encryption: "xchacha20poly1305".into(),
            disks: vec![DiskImage {
                index: 0,
                size: 10 << 20,
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
                used_extents: vec![Extent(0, 10 << 20)],
                chunks: vec![ChunkRef(0, ChunkId([1; 32])), ChunkRef(2, ChunkId([2; 32]))],
            }],
            boot: BootConfig::default(),
            os: OsInfo::default(),
            drivers: vec![],
            excluded: vec![],
            warnings: vec![],
            stats: ImageStats::default(),
            vm: None,
        }
    }

    #[test]
    fn sign_seal_open_verify() {
        let body = sample_body();
        let signer = ManifestSigner::generate().unwrap();
        let k = SecretKey::generate().unwrap();
        let sealed = seal_manifest(&body, &signer, &k, 3).unwrap();
        let env = open_envelope(&body.image_id, &k, &sealed).unwrap();
        let back = verify_envelope(&env, &signer.verifying_key(), &body.image_id).unwrap();
        assert_eq!(back, body);

        // Other signer rejected.
        let other = ManifestSigner::generate().unwrap();
        assert!(verify_envelope(&env, &other.verifying_key(), &body.image_id).is_err());

        // Body altered after signing rejected.
        let mut env2 = env.clone();
        env2.body = env2.body.replace("\"host\"", "\"evil\"");
        assert!(verify_envelope(&env2, &signer.verifying_key(), &body.image_id).is_err());

        // Stored under another name rejected.
        assert!(open_envelope(&Uuid::new_v4(), &k, &sealed).is_err());
    }

    #[test]
    fn validate_rejects_bad_chunk_lists() {
        let mut b = sample_body();
        b.disks[0].chunks = vec![ChunkRef(2, ChunkId([2; 32])), ChunkRef(0, ChunkId([1; 32]))];
        assert!(b.validate().is_err());
        let mut b = sample_body();
        b.disks[0].chunks = vec![ChunkRef(99, ChunkId([2; 32]))];
        assert!(b.validate().is_err());
        let mut b = sample_body();
        b.disks[0].used_extents = vec![Extent(0, 11 << 20)];
        assert!(b.validate().is_err());
        let mut b = sample_body();
        b.version = 99;
        assert!(b.validate().is_err());
    }

    #[test]
    fn chunk_refs_serialise_compactly() {
        let s = serde_json::to_string(&ChunkRef(5, ChunkId([0; 32]))).unwrap();
        assert_eq!(s, format!("[5,\"{}\"]", "0".repeat(64)));
    }
}
