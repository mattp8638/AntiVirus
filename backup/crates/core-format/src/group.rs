//! Dedup groups: several repositories sharing one chunk store
//! (docs/design/dedup-groups.md).
//!
//! ```text
//! <group>/group.json                    plaintext: group id, chunk size
//! <group>/chunks/<aa>/<64 hex>          shared chunks (group key)
//! <group>/locks/...                     shared repository locks
//! <group>/refs/<repo id>/<image id>     chunk list of each image (group key)
//! <group>/repos/<repo id>/config.json   a member: its own key slots, signers,
//!                   keys/, signers/,    manifests (its own master key) and
//!                   manifests/, group-key.json   the group key it holds
//! ```
//!
//! A member's path is `<group>/repos/<repo id>`. Its chunk ID and chunk
//! encryption keys come from the group key instead of its master key, so the
//! same data in two members is one chunk. Anyone holding one member's key
//! can therefore read every chunk in the group (not the other members'
//! manifests): groups are for repositories of one owner.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::{Backend, PutOutcome};
use crate::chunk::ChunkId;
use crate::crypto::{self, b64, SecretKey};
use crate::error::{Error, Result};

pub const GROUP_FILE: &str = "group.json";
pub const GROUP_FORMAT: &str = "fenrir-dedup-group";
pub const MEMBER_KEY_FILE: &str = "group-key.json";
pub const MEMBERS: &str = "repos";
const GROUP_WRAP: &str = "Fenrir-Backup 2026 v1 dedup group key wrap";
pub const REFS_ENC: &str = "Fenrir-Backup 2026 v1 dedup group chunk references";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub format: String,
    pub version: u32,
    pub group_id: Uuid,
    pub created: String,
    pub chunk_size: u32,
}

/// The group key, sealed with a member's master key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberKey {
    format: String,
    version: u32,
    group_id: Uuid,
    #[serde(with = "b64::serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "b64::serde_bytes")]
    sealed: Vec<u8>,
}

fn member_aad(group: &Uuid, repo: &Uuid) -> Vec<u8> {
    let mut a = b"fenrir-group-key-v1".to_vec();
    a.extend_from_slice(group.as_bytes());
    a.extend_from_slice(repo.as_bytes());
    a
}

/// `<group>/repos/<uuid>` → (`<group>`, uuid). Works for folders, shares and
/// object storage locations alike (`/` or `\` separators).
pub fn split_member_path(path: &str) -> Option<(String, Uuid)> {
    let p = path.trim_end_matches(['/', '\\']);
    let (rest, id) = p.rsplit_once(['/', '\\'])?;
    let id = Uuid::parse_str(id).ok()?;
    let (root, members) = rest.rsplit_once(['/', '\\'])?;
    (members == MEMBERS && !root.is_empty()).then(|| (root.to_string(), id))
}

/// The path of member `id` in the group at `root`.
pub fn member_path(root: &str, id: &Uuid) -> String {
    let sep = if root.contains('\\') && !root.contains('/') {
        '\\'
    } else {
        '/'
    };
    format!(
        "{}{sep}{MEMBERS}{sep}{id}",
        root.trim_end_matches(['/', '\\'])
    )
}

/// Routes a member's objects: chunks, locks and chunk references to the
/// group, everything else to the member's own folder.
pub struct GroupBackend {
    pub member: Arc<dyn Backend>,
    pub shared: Arc<dyn Backend>,
}

impl GroupBackend {
    fn shared(key: &str) -> bool {
        ["chunks", "locks", "refs"]
            .iter()
            .any(|p| key == *p || key.starts_with(&format!("{p}/")))
    }
    fn of(&self, key: &str) -> &dyn Backend {
        if Self::shared(key) {
            &*self.shared
        } else {
            &*self.member
        }
    }
}

impl Backend for GroupBackend {
    fn put(&self, key: &str, data: &[u8]) -> Result<PutOutcome> {
        self.of(key).put(key, data)
    }
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.of(key).get(key)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.of(key).exists(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.of(prefix).list(prefix)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.of(key).delete(key)
    }
    fn size(&self, key: &str) -> Result<u64> {
        self.of(key).size(key)
    }
    fn describe(&self) -> String {
        format!(
            "{} (dedup group {})",
            self.member.describe(),
            self.shared.describe()
        )
    }
    fn lock_days(&self) -> Option<u32> {
        self.member.lock_days()
    }
    fn extend_lock(&self, key: &str) -> Result<bool> {
        self.of(key).extend_lock(key)
    }
}

pub fn read_info(shared: &dyn Backend) -> Result<GroupInfo> {
    let g: GroupInfo = serde_json::from_slice(&shared.get(GROUP_FILE)?)?;
    if g.format != GROUP_FORMAT || g.version != 1 {
        return Err(Error::NotARepository(format!(
            "{GROUP_FILE} is not a Fenrir-Backup dedup group"
        )));
    }
    Ok(g)
}

/// Create a group in `shared` (empty, or holding only other groups' files is refused).
pub fn create(shared: &dyn Backend, chunk_size: u32) -> Result<GroupInfo> {
    if shared.exists(GROUP_FILE)? {
        return Err(Error::InvalidArgument(
            "a dedup group already exists here".into(),
        ));
    }
    if shared.exists(crate::repo::CONFIG_KEY)? {
        return Err(Error::InvalidArgument(
            "a repository already exists here".into(),
        ));
    }
    let g = GroupInfo {
        format: GROUP_FORMAT.into(),
        version: 1,
        group_id: Uuid::new_v4(),
        created: crate::timefmt::rfc3339_utc(crate::timefmt::now_unix()),
        chunk_size,
    };
    match shared.put(GROUP_FILE, &serde_json::to_vec_pretty(&g)?)? {
        PutOutcome::Created => Ok(g),
        PutOutcome::AlreadyExists => Err(Error::InvalidArgument(
            "a dedup group already exists here".into(),
        )),
    }
}

pub fn seal_member_key(
    master: &SecretKey,
    group: &Uuid,
    repo: &Uuid,
    key: &SecretKey,
) -> Result<Vec<u8>> {
    let nonce = crypto::random_nonce()?;
    let sealed = crypto::seal(
        &master.derive(GROUP_WRAP),
        &nonce,
        &member_aad(group, repo),
        key.as_bytes(),
    )?;
    Ok(serde_json::to_vec_pretty(&MemberKey {
        format: "fenrir-group-key".into(),
        version: 1,
        group_id: *group,
        nonce: nonce.to_vec(),
        sealed,
    })?)
}

pub fn open_member_key(
    master: &SecretKey,
    group: &Uuid,
    repo: &Uuid,
    raw: &[u8],
) -> Result<SecretKey> {
    let m: MemberKey = serde_json::from_slice(raw)?;
    if m.group_id != *group {
        return Err(Error::integrity("the group key belongs to another group"));
    }
    let pt = crypto::open(
        &master.derive(GROUP_WRAP),
        &m.nonce,
        &member_aad(group, repo),
        &m.sealed,
    )?;
    let bytes: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| Error::malformed("group key length"))?;
    Ok(SecretKey::from_bytes(bytes))
}

fn refs_aad(repo: &Uuid, image: &Uuid) -> Vec<u8> {
    let mut a = b"fenrir-refs-v1".to_vec();
    a.extend_from_slice(repo.as_bytes());
    a.extend_from_slice(image.as_bytes());
    a
}

pub fn refs_key(repo: &Uuid, image: &Uuid) -> String {
    format!("refs/{repo}/{image}")
}

/// An image's chunk list, encrypted for the group.
pub fn seal_refs(
    group_key: &SecretKey,
    repo: &Uuid,
    image: &Uuid,
    ids: &[ChunkId],
) -> Result<Vec<u8>> {
    let mut pt = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        pt.extend_from_slice(&id.0);
    }
    let nonce = crypto::random_nonce()?;
    let mut out = nonce.to_vec();
    out.extend(crypto::seal(
        &group_key.derive(REFS_ENC),
        &nonce,
        &refs_aad(repo, image),
        &pt,
    )?);
    Ok(out)
}

pub fn open_refs(
    group_key: &SecretKey,
    repo: &Uuid,
    image: &Uuid,
    raw: &[u8],
) -> Result<Vec<ChunkId>> {
    if raw.len() < crypto::NONCE_LEN {
        return Err(Error::malformed("chunk references too short"));
    }
    let (nonce, ct) = raw.split_at(crypto::NONCE_LEN);
    let pt = crypto::open(
        &group_key.derive(REFS_ENC),
        nonce,
        &refs_aad(repo, image),
        ct,
    )?;
    if pt.len() % 32 != 0 {
        return Err(Error::malformed("chunk references length"));
    }
    Ok(pt
        .chunks_exact(32)
        .map(|c| ChunkId(c.try_into().expect("32 bytes")))
        .collect())
}

/// `refs/<repo>/<image>` → (repo, image).
pub fn parse_refs_key(k: &str) -> Option<(Uuid, Uuid)> {
    let mut p = k.strip_prefix("refs/")?.split('/');
    let repo = Uuid::parse_str(p.next()?).ok()?;
    let image = Uuid::parse_str(p.next()?).ok()?;
    p.next().is_none().then_some((repo, image))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_paths() {
        let id = Uuid::new_v4();
        let p = member_path("/nas/backups", &id);
        assert_eq!(p, format!("/nas/backups/repos/{id}"));
        assert_eq!(split_member_path(&p), Some(("/nas/backups".into(), id)));
        let w = member_path(r"\\nas\backups", &id);
        assert_eq!(w, format!(r"\\nas\backups\repos\{id}"));
        assert_eq!(split_member_path(&w), Some((r"\\nas\backups".into(), id)));
        let s3 = format!("s3://bucket/site/repos/{id}/");
        assert_eq!(
            split_member_path(&s3),
            Some(("s3://bucket/site".into(), id))
        );
        assert_eq!(split_member_path("/nas/backups"), None);
        assert_eq!(split_member_path(&format!("/nas/other/{id}")), None);
    }

    #[test]
    fn refs_round_trip_and_bind_to_their_image() {
        let k = SecretKey::generate().unwrap();
        let (r, i) = (Uuid::new_v4(), Uuid::new_v4());
        let ids = vec![ChunkId([1; 32]), ChunkId([2; 32])];
        let raw = seal_refs(&k, &r, &i, &ids).unwrap();
        assert_eq!(open_refs(&k, &r, &i, &raw).unwrap(), ids);
        assert!(
            open_refs(&k, &r, &Uuid::new_v4(), &raw).is_err(),
            "moved to another image"
        );
        assert_eq!(parse_refs_key(&refs_key(&r, &i)), Some((r, i)));
    }
}
