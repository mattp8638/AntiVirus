//! A repository: configuration, key slots, signers, chunks and manifests on
//! top of a `Backend`.
//!
//! ```text
//! config.json                 plaintext repository parameters
//! keys/<slot uuid>.json       master key wrapped by passphrase or recovery key
//! signers/<key id>.json       manifest signing keys (secret half sealed)
//! chunks/<aa>/<64 hex>        sealed chunk objects
//! manifests/<image uuid>      sealed, signed image manifests
//! ```

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::{Backend, PutOutcome};
use crate::chunk::{self, ChunkId, DEFAULT_CHUNK_SIZE};
use crate::crypto::{self, b64, KdfParams, SecretKey};
use crate::error::{Error, Result};
use crate::keys::{KeySlot, RecoveryKey, RepoKeys, SlotKind};
use crate::manifest::{self, ManifestBody, ManifestSigner};

pub const CONFIG_KEY: &str = "config.json";
pub const REPO_FORMAT: &str = "fenrir-repository";
pub const SIGNER_FORMAT: &str = "fenrir-signer";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    pub format: String,
    pub version: u32,
    pub repo_id: Uuid,
    pub created: String,
    pub chunk_size: u32,
    pub zstd_level: i32,
    pub hash: String,
    pub encryption: String,
    /// Member of this dedup group (format version 2; group.rs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Uuid>,
}

impl RepoConfig {
    fn check(&self) -> Result<()> {
        if self.format != REPO_FORMAT {
            return Err(Error::NotARepository(
                "config.json is not a Fenrir-Backup repository config".into(),
            ));
        }
        // Version 2: a dedup group member (older versions cannot read its
        // chunks, so they must refuse it).
        if !matches!((self.version, self.group.is_some()), (1, false) | (2, true)) {
            return Err(Error::UnsupportedVersion {
                what: "repository",
                version: self.version,
            });
        }
        chunk::check_chunk_size(self.chunk_size)?;
        if !(-7..=22).contains(&self.zstd_level) {
            return Err(Error::malformed("zstd level out of range"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub chunk_size: u32,
    pub zstd_level: i32,
    pub kdf: KdfParams,
}

impl Default for InitOptions {
    fn default() -> Self {
        InitOptions {
            chunk_size: DEFAULT_CHUNK_SIZE,
            zstd_level: 3,
            kdf: KdfParams::DEFAULT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignerRecord {
    format: String,
    version: u32,
    key_id: String,
    #[serde(with = "b64::serde_bytes")]
    public_key: Vec<u8>,
    #[serde(with = "b64::serde_bytes")]
    nonce: Vec<u8>,
    /// Sealed `SignerSecret` JSON.
    #[serde(with = "b64::serde_bytes")]
    sealed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SignerSecret {
    machine_id: String,
    #[serde(with = "b64::serde_bytes")]
    seed: Vec<u8>,
}

fn signer_aad(repo_id: &Uuid, public_key: &[u8]) -> Vec<u8> {
    let mut a = b"fenrir-signer-v1".to_vec();
    a.extend_from_slice(repo_id.as_bytes());
    a.extend_from_slice(public_key);
    a
}

/// An unlocked repository. Cheap to clone; safe to share across threads.
#[derive(Clone)]
pub struct Repository {
    backend: Arc<dyn Backend>,
    config: RepoConfig,
    keys: Arc<RepoKeys>,
    /// The dedup group's key (members only).
    group_key: Option<Arc<SecretKey>>,
}

impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("backend", &self.backend.describe())
            .field("config", &self.config)
            .finish()
    }
}

impl Repository {
    /// Create a new repository. Returns it unlocked, plus a recovery key the
    /// caller must hand to the user (it is not stored anywhere else).
    pub fn init(
        backend: Arc<dyn Backend>,
        passphrase: &[u8],
        opts: InitOptions,
    ) -> Result<(Repository, RecoveryKey)> {
        let repo_id = Uuid::new_v4();
        let recovery = RecoveryKey::generate(repo_id)?;
        let repo = Self::init_with(backend, passphrase, opts, &recovery)?;
        Ok((repo, recovery))
    }

    /// Create a repository whose ID and recovery key were chosen by the
    /// caller (`recovery.repo_id` becomes the repository ID). Used by the
    /// management server flow, where the administrator's browser generates
    /// the recovery key so that it never passes through the server.
    pub fn init_with(
        backend: Arc<dyn Backend>,
        passphrase: &[u8],
        opts: InitOptions,
        recovery: &RecoveryKey,
    ) -> Result<Repository> {
        if backend.exists(CONFIG_KEY)? {
            return Err(Error::InvalidArgument(
                "a repository already exists here".into(),
            ));
        }
        chunk::check_chunk_size(opts.chunk_size)?;
        let now = crate::timefmt::now_unix();
        let config = RepoConfig {
            format: REPO_FORMAT.into(),
            version: 1,
            repo_id: recovery.repo_id,
            created: crate::timefmt::rfc3339_utc(now),
            chunk_size: opts.chunk_size,
            zstd_level: opts.zstd_level,
            hash: "blake3-keyed".into(),
            encryption: "xchacha20poly1305".into(),
            group: None,
        };
        config.check()?;
        let master = SecretKey::generate()?;
        let pslot = KeySlot::wrap_with_passphrase(&config.repo_id, &master, passphrase, opts.kdf)?;
        let rslot = KeySlot::wrap_with_recovery_key(&config.repo_id, &master, recovery)?;
        // Key slots first, config last: a directory with config.json is
        // always a complete, openable repository.
        put_new(
            &*backend,
            &format!("keys/{}.json", pslot.slot_id),
            &serde_json::to_vec_pretty(&pslot)?,
        )?;
        put_new(
            &*backend,
            &format!("keys/{}.json", rslot.slot_id),
            &serde_json::to_vec_pretty(&rslot)?,
        )?;
        put_new(&*backend, CONFIG_KEY, &serde_json::to_vec_pretty(&config)?)?;
        Ok(Repository {
            backend,
            config,
            keys: Arc::new(RepoKeys::from_master(master)),
            group_key: None,
        })
    }

    /// Create a member of a dedup group. `backend` routes to the group
    /// (`group::GroupBackend`); `group_key` is a new group's key or the one
    /// another member holds (`Repository::group_key`).
    pub fn init_member(
        backend: Arc<dyn Backend>,
        passphrase: &[u8],
        opts: InitOptions,
        recovery: &RecoveryKey,
        group: &crate::group::GroupInfo,
        group_key: &SecretKey,
    ) -> Result<Repository> {
        if backend.exists(CONFIG_KEY)? {
            return Err(Error::InvalidArgument(
                "a repository already exists here".into(),
            ));
        }
        let config = RepoConfig {
            format: REPO_FORMAT.into(),
            version: 2,
            repo_id: recovery.repo_id,
            created: crate::timefmt::rfc3339_utc(crate::timefmt::now_unix()),
            // Chunks are shared, so every member cuts them the same way.
            chunk_size: group.chunk_size,
            zstd_level: opts.zstd_level,
            hash: "blake3-keyed".into(),
            encryption: "xchacha20poly1305".into(),
            group: Some(group.group_id),
        };
        config.check()?;
        let master = SecretKey::generate()?;
        let pslot = KeySlot::wrap_with_passphrase(&config.repo_id, &master, passphrase, opts.kdf)?;
        let rslot = KeySlot::wrap_with_recovery_key(&config.repo_id, &master, recovery)?;
        for slot in [&pslot, &rslot] {
            put_new(
                &*backend,
                &format!("keys/{}.json", slot.slot_id),
                &serde_json::to_vec_pretty(slot)?,
            )?;
        }
        put_new(
            &*backend,
            crate::group::MEMBER_KEY_FILE,
            &crate::group::seal_member_key(&master, &group.group_id, &config.repo_id, group_key)?,
        )?;
        put_new(&*backend, CONFIG_KEY, &serde_json::to_vec_pretty(&config)?)?;
        Self::unlocked(backend, config, master)
    }

    /// An unlocked repository from its master key (a member also opens the
    /// group key it holds).
    fn unlocked(
        backend: Arc<dyn Backend>,
        config: RepoConfig,
        master: SecretKey,
    ) -> Result<Repository> {
        let mut keys = RepoKeys::from_master(master);
        let group_key = match config.group {
            None => None,
            Some(g) => {
                let raw = backend.get(crate::group::MEMBER_KEY_FILE)?;
                let gk = crate::group::open_member_key(&keys.master, &g, &config.repo_id, &raw)?;
                keys.chunk_id = gk.derive(crate::keys::context::CHUNK_ID);
                keys.chunk_enc = gk.derive(crate::keys::context::CHUNK_ENC);
                Some(Arc::new(gk))
            }
        };
        Ok(Repository {
            backend,
            config,
            keys: Arc::new(keys),
            group_key,
        })
    }

    /// The dedup group's key, for creating another member of the group.
    pub fn group_key(&self) -> Option<&SecretKey> {
        self.group_key.as_deref()
    }

    pub fn read_config(backend: &dyn Backend) -> Result<RepoConfig> {
        let raw = backend.get(CONFIG_KEY).map_err(|e| match e {
            Error::NotFound(_) => {
                Error::NotARepository(format!("no {CONFIG_KEY} at {}", backend.describe()))
            }
            e => e,
        })?;
        let c: RepoConfig = serde_json::from_slice(&raw)
            .map_err(|e| Error::NotARepository(format!("config.json: {e}")))?;
        c.check()?;
        Ok(c)
    }

    fn slots(backend: &dyn Backend) -> Result<Vec<KeySlot>> {
        let mut out = Vec::new();
        for k in backend.list("keys")? {
            if let Ok(s) = serde_json::from_slice::<KeySlot>(&backend.get(&k)?) {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub fn unlock_with_passphrase(
        backend: Arc<dyn Backend>,
        passphrase: &[u8],
    ) -> Result<Repository> {
        let config = Self::read_config(&*backend)?;
        for slot in Self::slots(&*backend)?
            .iter()
            .filter(|s| s.kind == SlotKind::Passphrase)
        {
            match slot.unwrap_with_passphrase(&config.repo_id, passphrase) {
                Ok(master) => return Self::unlocked(backend, config, master),
                Err(Error::WrongKey) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::WrongKey)
    }

    pub fn unlock_with_recovery_key(
        backend: Arc<dyn Backend>,
        rk: &RecoveryKey,
    ) -> Result<Repository> {
        let config = Self::read_config(&*backend)?;
        if rk.repo_id != config.repo_id {
            return Err(Error::WrongKey);
        }
        let raw = backend
            .get(&format!("keys/{}.json", rk.slot_id))
            .map_err(|e| match e {
                Error::NotFound(_) => Error::WrongKey,
                e => e,
            })?;
        let slot: KeySlot = serde_json::from_slice(&raw)?;
        let master = slot.unwrap_with_recovery_key(&config.repo_id, rk)?;
        Self::unlocked(backend, config, master)
    }

    pub fn add_passphrase(&self, passphrase: &[u8], kdf: KdfParams) -> Result<Uuid> {
        let slot = KeySlot::wrap_with_passphrase(
            &self.config.repo_id,
            &self.keys.master,
            passphrase,
            kdf,
        )?;
        put_new(
            &*self.backend,
            &format!("keys/{}.json", slot.slot_id),
            &serde_json::to_vec_pretty(&slot)?,
        )?;
        Ok(slot.slot_id)
    }

    pub fn add_recovery_key(&self) -> Result<RecoveryKey> {
        let rk = RecoveryKey::generate(self.config.repo_id)?;
        let slot = KeySlot::wrap_with_recovery_key(&self.config.repo_id, &self.keys.master, &rk)?;
        put_new(
            &*self.backend,
            &format!("keys/{}.json", slot.slot_id),
            &serde_json::to_vec_pretty(&slot)?,
        )?;
        Ok(rk)
    }

    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// Take a repository lock (see `lock`).
    pub fn lock(&self, kind: crate::lock::LockKind) -> Result<crate::lock::RepoLock> {
        crate::lock::acquire(self.backend.clone(), kind)
    }

    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    pub fn chunk_size(&self) -> u32 {
        self.config.chunk_size
    }

    // ---- chunks ----

    pub fn chunk_id(&self, plaintext: &[u8]) -> ChunkId {
        ChunkId::compute(&self.keys.chunk_id, plaintext)
    }

    pub fn has_chunk(&self, id: &ChunkId) -> Result<bool> {
        self.backend.exists(&id.object_key())
    }

    /// Encrypt and store. Returns whether it was new and its stored size.
    pub fn put_chunk(&self, id: &ChunkId, plaintext: &[u8]) -> Result<(PutOutcome, u64)> {
        debug_assert_eq!(*id, self.chunk_id(plaintext));
        let obj = chunk::encode_chunk(
            &self.keys.chunk_enc,
            id,
            plaintext,
            Some(self.config.zstd_level),
        )?;
        let outcome = self.backend.put(&id.object_key(), &obj)?;
        Ok((outcome, obj.len() as u64))
    }

    /// Fetch, decrypt and hash-check a chunk.
    pub fn get_chunk(&self, id: &ChunkId) -> Result<Vec<u8>> {
        let obj = self.backend.get(&id.object_key())?;
        chunk::decode_chunk(&self.keys.chunk_enc, &self.keys.chunk_id, id, &obj)
    }

    // ---- signers ----

    fn load_signers(&self) -> Result<Vec<(ManifestSigner, String)>> {
        let mut out = Vec::new();
        for k in self.backend.list("signers")? {
            let rec: SignerRecord = serde_json::from_slice(&self.backend.get(&k)?)?;
            if let Ok(s) = self.open_signer(&rec) {
                out.push(s);
            }
        }
        Ok(out)
    }

    fn open_signer(&self, rec: &SignerRecord) -> Result<(ManifestSigner, String)> {
        if rec.format != SIGNER_FORMAT || rec.version != 1 {
            return Err(Error::malformed("bad signer record"));
        }
        let pt = crypto::open(
            &self.keys.signer_wrap,
            &rec.nonce,
            &signer_aad(&self.config.repo_id, &rec.public_key),
            &rec.sealed,
        )?;
        let sec: SignerSecret = serde_json::from_slice(&pt)?;
        let seed: [u8; 32] = sec
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::malformed("signer seed length"))?;
        let s = ManifestSigner::from_seed(seed);
        if s.verifying_key().as_bytes()[..] != rec.public_key[..] || s.key_id != rec.key_id {
            return Err(Error::integrity("signer record does not match its key"));
        }
        Ok((s, sec.machine_id))
    }

    /// The signing key for `machine_id`, created on first use.
    pub fn signer_for_machine(&self, machine_id: &str) -> Result<ManifestSigner> {
        if let Some((s, _)) = self
            .load_signers()?
            .into_iter()
            .find(|(_, m)| m == machine_id)
        {
            return Ok(s);
        }
        let s = ManifestSigner::generate()?;
        let pk = s.verifying_key().as_bytes().to_vec();
        let secret = SignerSecret {
            machine_id: machine_id.to_string(),
            seed: s.seed().to_vec(),
        };
        let nonce = crypto::random_nonce()?;
        let sealed = crypto::seal(
            &self.keys.signer_wrap,
            &nonce,
            &signer_aad(&self.config.repo_id, &pk),
            &serde_json::to_vec(&secret)?,
        )?;
        let rec = SignerRecord {
            format: SIGNER_FORMAT.into(),
            version: 1,
            key_id: s.key_id.clone(),
            public_key: pk,
            nonce: nonce.to_vec(),
            sealed,
        };
        put_new(
            &*self.backend,
            &format!("signers/{}.json", s.key_id),
            &serde_json::to_vec_pretty(&rec)?,
        )?;
        Ok(s)
    }

    fn verifying_key(&self, key_id: &str) -> Result<VerifyingKey> {
        if key_id.len() != 32 || !key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::malformed("bad signer key id"));
        }
        let raw = self
            .backend
            .get(&format!("signers/{key_id}.json"))
            .map_err(|e| match e {
                Error::NotFound(_) => {
                    Error::integrity(format!("manifest signed by unknown key {key_id}"))
                }
                e => e,
            })?;
        let rec: SignerRecord = serde_json::from_slice(&raw)?;
        // Opening the sealed half authenticates the public key with the
        // master key: an attacker with storage access cannot plant a signer.
        let (s, _) = self
            .open_signer(&rec)
            .map_err(|_| Error::integrity(format!("signer {key_id} failed authentication")))?;
        Ok(s.verifying_key())
    }

    // ---- manifests ----

    pub fn store_manifest(&self, body: &ManifestBody, signer: &ManifestSigner) -> Result<()> {
        if body.repo_id != self.config.repo_id {
            return Err(Error::InvalidArgument(
                "manifest is for another repository".into(),
            ));
        }
        let sealed = manifest::seal_manifest(
            body,
            signer,
            &self.keys.manifest_enc,
            self.config.zstd_level.max(1),
        )?;
        // A group member first tells the group which chunks the image uses,
        // so that no other member's prune deletes them (a reference left by a
        // crash before the manifest only keeps chunks longer).
        if let Some(gk) = &self.group_key {
            let ids: Vec<ChunkId> = body.chunk_ids().into_iter().collect();
            let refs = crate::group::seal_refs(gk, &self.config.repo_id, &body.image_id, &ids)?;
            self.backend.put(
                &crate::group::refs_key(&self.config.repo_id, &body.image_id),
                &refs,
            )?;
        }
        match self
            .backend
            .put(&format!("manifests/{}", body.image_id), &sealed)?
        {
            PutOutcome::Created => Ok(()),
            PutOutcome::AlreadyExists => Err(Error::InvalidArgument(format!(
                "image {} already exists",
                body.image_id
            ))),
        }
    }

    pub fn list_image_ids(&self) -> Result<Vec<Uuid>> {
        let mut ids: Vec<Uuid> = self
            .backend
            .list("manifests")?
            .iter()
            .filter_map(|k| {
                k.strip_prefix("manifests/")
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Load, decrypt and verify a manifest.
    pub fn load_manifest(&self, image_id: &Uuid) -> Result<ManifestBody> {
        let raw = self.backend.get(&format!("manifests/{image_id}"))?;
        let env = manifest::open_envelope(image_id, &self.keys.manifest_enc, &raw)?;
        let vk = self.verifying_key(&env.signer)?;
        let body = manifest::verify_envelope(&env, &vk, image_id)?;
        if body.repo_id != self.config.repo_id {
            return Err(Error::integrity("manifest belongs to another repository"));
        }
        Ok(body)
    }

    /// All manifests, sorted oldest first, plus the ones that failed to load.
    pub fn load_all_manifests(&self) -> Result<LoadedManifests> {
        let mut ok = Vec::new();
        let mut bad = Vec::new();
        for id in self.list_image_ids()? {
            match self.load_manifest(&id) {
                Ok(m) => ok.push(m),
                Err(e) => bad.push((id, e)),
            }
        }
        ok.sort_by(|a, b| {
            a.created_unix
                .cmp(&b.created_unix)
                .then(a.image_id.cmp(&b.image_id))
        });
        Ok((ok, bad))
    }

    /// Delete an image's manifest (and, in a dedup group, its chunk list
    /// afterwards). Its chunks stay until a prune.
    pub fn delete_image(&self, image_id: &Uuid) -> Result<()> {
        self.backend.delete(&format!("manifests/{image_id}"))?;
        if self.group_key.is_some() {
            match self
                .backend
                .delete(&crate::group::refs_key(&self.config.repo_id, image_id))
            {
                Ok(()) | Err(Error::NotFound(_)) | Err(Error::Retained(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Chunks referenced by any member of this repository's dedup group
    /// (object keys), and this member's references whose manifest is gone.
    /// `None` for a repository in no group. Fails if a reference list
    /// cannot be read: nothing may then be pruned.
    pub fn group_references(
        &self,
    ) -> Result<Option<(std::collections::HashSet<String>, Vec<String>)>> {
        let Some(gk) = &self.group_key else {
            return Ok(None);
        };
        let mine: std::collections::HashSet<Uuid> = self.list_image_ids()?.into_iter().collect();
        let mut live = std::collections::HashSet::new();
        let mut orphans = Vec::new();
        for k in self.backend.list("refs")? {
            let Some((repo, image)) = crate::group::parse_refs_key(&k) else {
                continue;
            };
            if repo == self.config.repo_id && !mine.contains(&image) {
                orphans.push(k);
                continue;
            }
            let raw = self.backend.get(&k)?;
            let ids = crate::group::open_refs(gk, &repo, &image, &raw)
                .map_err(|e| Error::integrity(format!("chunk list {k}: {e}")))?;
            live.extend(ids.iter().map(ChunkId::object_key));
        }
        Ok(Some((live, orphans)))
    }

    /// Resolve a full UUID or a unique prefix of one.
    pub fn resolve_image_id(&self, s: &str) -> Result<Uuid> {
        if let Ok(u) = Uuid::parse_str(s) {
            return Ok(u);
        }
        let s = s.to_ascii_lowercase();
        let matches: Vec<Uuid> = self
            .list_image_ids()?
            .into_iter()
            .filter(|u| u.to_string().starts_with(&s))
            .collect();
        match matches.len() {
            1 => Ok(matches[0]),
            0 => Err(Error::NotFound(format!("image {s}"))),
            _ => Err(Error::InvalidArgument(format!(
                "image prefix {s} is ambiguous"
            ))),
        }
    }
}

/// Manifests that loaded and verified (oldest first), and those that failed.
pub type LoadedManifests = (Vec<ManifestBody>, Vec<(Uuid, Error)>);

fn put_new(b: &dyn Backend, key: &str, data: &[u8]) -> Result<()> {
    match b.put(key, data)? {
        PutOutcome::Created => Ok(()),
        PutOutcome::AlreadyExists => Err(Error::InvalidArgument(format!("{key} already exists"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;
    use crate::manifest::tests::sample_body;

    fn fast() -> InitOptions {
        InitOptions {
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        }
    }

    fn new_repo() -> (tempfile::TempDir, Repository, RecoveryKey) {
        let dir = tempfile::tempdir().unwrap();
        let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("r")).unwrap());
        let (r, rk) = Repository::init(b, b"pass", fast()).unwrap();
        (dir, r, rk)
    }

    #[test]
    fn init_unlock_and_reject_wrong_passphrase() {
        let (dir, r, rk) = new_repo();
        let b: Arc<dyn Backend> = Arc::new(LocalBackend::open(dir.path().join("r")).unwrap());
        assert!(matches!(
            Repository::unlock_with_passphrase(b.clone(), b"nope"),
            Err(Error::WrongKey)
        ));
        let r2 = Repository::unlock_with_passphrase(b.clone(), b"pass").unwrap();
        let r3 = Repository::unlock_with_recovery_key(b.clone(), &rk).unwrap();
        assert_eq!(r.chunk_id(b"x"), r2.chunk_id(b"x"));
        assert_eq!(r.chunk_id(b"x"), r3.chunk_id(b"x"));
        // Second init in the same place refused.
        assert!(Repository::init(b, b"pass", fast()).is_err());
    }

    #[test]
    fn init_with_caller_recovery_key() {
        let dir = tempfile::tempdir().unwrap();
        let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("r")).unwrap());
        let rk = RecoveryKey::generate(Uuid::new_v4()).unwrap();
        let r = Repository::init_with(b.clone(), b"pass", fast(), &rk).unwrap();
        assert_eq!(r.config().repo_id, rk.repo_id);
        let r2 = Repository::unlock_with_recovery_key(b, &rk).unwrap();
        assert_eq!(r.chunk_id(b"x"), r2.chunk_id(b"x"));
    }

    #[test]
    fn added_passphrase_works() {
        let (_dir, r, _) = new_repo();
        r.add_passphrase(b"second", KdfParams::INSECURE_FAST)
            .unwrap();
        let r2 = Repository::unlock_with_passphrase(r.backend().clone(), b"second").unwrap();
        assert_eq!(r.chunk_id(b"x"), r2.chunk_id(b"x"));
    }

    #[test]
    fn chunks_dedupe_and_detect_corruption() {
        let (dir, r, _) = new_repo();
        let data = vec![9u8; 100_000];
        let id = r.chunk_id(&data);
        assert!(!r.has_chunk(&id).unwrap());
        assert_eq!(r.put_chunk(&id, &data).unwrap().0, PutOutcome::Created);
        assert_eq!(
            r.put_chunk(&id, &data).unwrap().0,
            PutOutcome::AlreadyExists
        );
        assert_eq!(r.get_chunk(&id).unwrap(), data);
        // Corrupt on disk.
        let h = id.to_hex();
        let p = dir.path().join("r").join("chunks").join(&h[..2]).join(&h);
        let mut raw = std::fs::read(&p).unwrap();
        let n = raw.len();
        raw[n - 20] ^= 1;
        std::fs::write(&p, raw).unwrap();
        assert!(matches!(r.get_chunk(&id), Err(Error::Integrity(_))));
    }

    #[test]
    fn manifests_roundtrip_and_signers_are_per_machine() {
        let (_dir, r, _) = new_repo();
        let s1 = r.signer_for_machine("m1").unwrap();
        let s1b = r.signer_for_machine("m1").unwrap();
        let s2 = r.signer_for_machine("m2").unwrap();
        assert_eq!(s1.key_id, s1b.key_id);
        assert_ne!(s1.key_id, s2.key_id);

        let mut body = sample_body();
        body.repo_id = r.config().repo_id;
        r.store_manifest(&body, &s1).unwrap();
        assert!(r.store_manifest(&body, &s1).is_err());
        assert_eq!(r.load_manifest(&body.image_id).unwrap(), body);
        assert_eq!(r.list_image_ids().unwrap(), vec![body.image_id]);
        let prefix = &body.image_id.to_string()[..8];
        assert_eq!(r.resolve_image_id(prefix).unwrap(), body.image_id);
    }

    #[test]
    fn planted_signer_is_rejected() {
        let (_dir, r, _) = new_repo();
        // Attacker with storage write access but no master key creates a
        // signer record and a manifest... they cannot even seal the manifest
        // without the manifest key, but check the signer path directly.
        let fake = ManifestSigner::generate().unwrap();
        let rec = SignerRecord {
            format: SIGNER_FORMAT.into(),
            version: 1,
            key_id: fake.key_id.clone(),
            public_key: fake.verifying_key().as_bytes().to_vec(),
            nonce: vec![0; 24],
            sealed: vec![0; 48],
        };
        r.backend()
            .put(
                &format!("signers/{}.json", fake.key_id),
                &serde_json::to_vec(&rec).unwrap(),
            )
            .unwrap();
        assert!(r.verifying_key(&fake.key_id).is_err());
    }
}
