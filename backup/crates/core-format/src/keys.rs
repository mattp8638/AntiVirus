//! Master key, its wrapped copies, and the subkeys derived from it.
//!
//! The master key is random and never stored unwrapped. Each way of
//! unlocking a repository is a *key slot*: a JSON object under `keys/` that
//! holds the master key encrypted under either an Argon2id-derived
//! passphrase key or a random recovery key that the user keeps offline.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{self, b64, KdfParams, SecretKey, KEY_LEN};
use crate::error::{Error, Result};

pub const KEY_SLOT_FORMAT: &str = "fenrir-key-slot";
pub const RECOVERY_KEY_FORMAT: &str = "fenrir-recovery-key";

/// Context strings for BLAKE3 `derive_key`. Changing any of these breaks
/// every existing repository; they are part of the format (docs/FORMAT.md).
pub mod context {
    pub const CHUNK_ID: &str = "Fenrir-Backup 2026 v1 chunk id";
    pub const CHUNK_ENC: &str = "Fenrir-Backup 2026 v1 chunk encryption";
    pub const MANIFEST_ENC: &str = "Fenrir-Backup 2026 v1 manifest encryption";
    pub const SIGNER_WRAP: &str = "Fenrir-Backup 2026 v1 signer key wrap";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    Passphrase,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfRecord {
    pub alg: String,
    #[serde(flatten)]
    pub params: KdfParams,
    #[serde(with = "b64::serde_bytes")]
    pub salt: Vec<u8>,
}

/// One key slot, stored as `keys/<slot_id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    pub format: String,
    pub version: u32,
    pub slot_id: Uuid,
    pub kind: SlotKind,
    /// Present for passphrase slots only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfRecord>,
    #[serde(with = "b64::serde_bytes")]
    pub nonce: Vec<u8>,
    /// Master key sealed with XChaCha20-Poly1305.
    #[serde(with = "b64::serde_bytes")]
    pub wrapped: Vec<u8>,
}

fn slot_aad(repo_id: &Uuid, slot_id: &Uuid, kind: SlotKind) -> Vec<u8> {
    let mut aad = b"fenrir-key-slot-v1".to_vec();
    aad.extend_from_slice(repo_id.as_bytes());
    aad.extend_from_slice(slot_id.as_bytes());
    aad.push(match kind {
        SlotKind::Passphrase => 1,
        SlotKind::Recovery => 2,
    });
    aad
}

impl KeySlot {
    pub fn wrap_with_passphrase(
        repo_id: &Uuid,
        master: &SecretKey,
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(Error::InvalidArgument(
                "passphrase must not be empty".into(),
            ));
        }
        let mut salt = vec![0u8; 16];
        crypto::fill_random(&mut salt)?;
        let kek = crypto::derive_from_passphrase(passphrase, &salt, params)?;
        let slot_id = Uuid::new_v4();
        let nonce = crypto::random_nonce()?;
        let wrapped = crypto::seal(
            &kek,
            &nonce,
            &slot_aad(repo_id, &slot_id, SlotKind::Passphrase),
            master.as_bytes(),
        )?;
        Ok(KeySlot {
            format: KEY_SLOT_FORMAT.into(),
            version: 1,
            slot_id,
            kind: SlotKind::Passphrase,
            kdf: Some(KdfRecord {
                alg: "argon2id".into(),
                params,
                salt,
            }),
            nonce: nonce.to_vec(),
            wrapped,
        })
    }

    pub fn wrap_with_recovery_key(
        repo_id: &Uuid,
        master: &SecretKey,
        recovery: &RecoveryKey,
    ) -> Result<Self> {
        let slot_id = recovery.slot_id;
        let nonce = crypto::random_nonce()?;
        let wrapped = crypto::seal(
            &recovery.key,
            &nonce,
            &slot_aad(repo_id, &slot_id, SlotKind::Recovery),
            master.as_bytes(),
        )?;
        Ok(KeySlot {
            format: KEY_SLOT_FORMAT.into(),
            version: 1,
            slot_id,
            kind: SlotKind::Recovery,
            kdf: None,
            nonce: nonce.to_vec(),
            wrapped,
        })
    }

    fn check_header(&self) -> Result<()> {
        if self.format != KEY_SLOT_FORMAT {
            return Err(Error::malformed("not a key slot"));
        }
        if self.version != 1 {
            return Err(Error::UnsupportedVersion {
                what: "key slot",
                version: self.version,
            });
        }
        Ok(())
    }

    pub fn unwrap_with_passphrase(&self, repo_id: &Uuid, passphrase: &[u8]) -> Result<SecretKey> {
        self.check_header()?;
        if self.kind != SlotKind::Passphrase {
            return Err(Error::WrongKey);
        }
        let kdf = self
            .kdf
            .as_ref()
            .ok_or_else(|| Error::malformed("passphrase slot without kdf"))?;
        if kdf.alg != "argon2id" {
            return Err(Error::malformed(format!("unknown kdf {}", kdf.alg)));
        }
        let kek = crypto::derive_from_passphrase(passphrase, &kdf.salt, kdf.params)?;
        self.unwrap_with(&kek, repo_id)
    }

    pub fn unwrap_with_recovery_key(
        &self,
        repo_id: &Uuid,
        recovery: &RecoveryKey,
    ) -> Result<SecretKey> {
        self.check_header()?;
        if self.kind != SlotKind::Recovery || self.slot_id != recovery.slot_id {
            return Err(Error::WrongKey);
        }
        self.unwrap_with(&recovery.key, repo_id)
    }

    fn unwrap_with(&self, kek: &SecretKey, repo_id: &Uuid) -> Result<SecretKey> {
        let pt = crypto::open(
            kek,
            &self.nonce,
            &slot_aad(repo_id, &self.slot_id, self.kind),
            &self.wrapped,
        )
        .map_err(|_| Error::WrongKey)?;
        let bytes: [u8; KEY_LEN] = pt
            .as_slice()
            .try_into()
            .map_err(|_| Error::malformed("master key length"))?;
        Ok(SecretKey::from_bytes(bytes))
    }
}

/// A recovery key. Serialised to a small JSON file the user stores offline
/// (USB stick, password manager, printed). Anyone holding it can decrypt
/// the repository, so it is as sensitive as the passphrase.
#[derive(Debug, Clone)]
pub struct RecoveryKey {
    pub repo_id: Uuid,
    pub slot_id: Uuid,
    pub key: SecretKey,
}

#[derive(Serialize, Deserialize)]
struct RecoveryKeyFile {
    format: String,
    version: u32,
    repo_id: Uuid,
    slot_id: Uuid,
    key: String,
}

impl RecoveryKey {
    pub fn generate(repo_id: Uuid) -> Result<Self> {
        Ok(RecoveryKey {
            repo_id,
            slot_id: Uuid::new_v4(),
            key: SecretKey::generate()?,
        })
    }

    pub fn to_file_contents(&self) -> String {
        let f = RecoveryKeyFile {
            format: RECOVERY_KEY_FORMAT.into(),
            version: 1,
            repo_id: self.repo_id,
            slot_id: self.slot_id,
            key: b64::encode(self.key.as_bytes()),
        };
        let mut s = serde_json::to_string_pretty(&f).expect("serialisable");
        s.push('\n');
        s
    }

    pub fn from_file_contents(s: &str) -> Result<Self> {
        let f: RecoveryKeyFile = serde_json::from_str(s)?;
        if f.format != RECOVERY_KEY_FORMAT {
            return Err(Error::malformed("not a recovery key file"));
        }
        if f.version != 1 {
            return Err(Error::UnsupportedVersion {
                what: "recovery key",
                version: f.version,
            });
        }
        let raw = b64::decode(&f.key)?;
        let bytes: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::malformed("recovery key length"))?;
        Ok(RecoveryKey {
            repo_id: f.repo_id,
            slot_id: f.slot_id,
            key: SecretKey::from_bytes(bytes),
        })
    }
}

/// Subkeys derived from an unlocked master key.
#[derive(Clone)]
pub struct RepoKeys {
    pub master: SecretKey,
    pub chunk_id: SecretKey,
    pub chunk_enc: SecretKey,
    pub manifest_enc: SecretKey,
    pub signer_wrap: SecretKey,
}

impl RepoKeys {
    pub fn from_master(master: SecretKey) -> Self {
        RepoKeys {
            chunk_id: master.derive(context::CHUNK_ID),
            chunk_enc: master.derive(context::CHUNK_ENC),
            manifest_enc: master.derive(context::MANIFEST_ENC),
            signer_wrap: master.derive(context::SIGNER_WRAP),
            master,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_slot_roundtrip() {
        let repo = Uuid::new_v4();
        let m = SecretKey::generate().unwrap();
        let slot =
            KeySlot::wrap_with_passphrase(&repo, &m, b"correct horse", KdfParams::INSECURE_FAST)
                .unwrap();
        let json = serde_json::to_string(&slot).unwrap();
        let slot: KeySlot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            slot.unwrap_with_passphrase(&repo, b"correct horse")
                .unwrap()
                .as_bytes(),
            m.as_bytes()
        );
        assert!(matches!(
            slot.unwrap_with_passphrase(&repo, b"wrong"),
            Err(Error::WrongKey)
        ));
        // Slot bound to its repository.
        assert!(matches!(
            slot.unwrap_with_passphrase(&Uuid::new_v4(), b"correct horse"),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn recovery_slot_roundtrip_via_file() {
        let repo = Uuid::new_v4();
        let m = SecretKey::generate().unwrap();
        let rk = RecoveryKey::generate(repo).unwrap();
        let slot = KeySlot::wrap_with_recovery_key(&repo, &m, &rk).unwrap();
        let rk2 = RecoveryKey::from_file_contents(&rk.to_file_contents()).unwrap();
        assert_eq!(
            slot.unwrap_with_recovery_key(&repo, &rk2)
                .unwrap()
                .as_bytes(),
            m.as_bytes()
        );
        let other = RecoveryKey::generate(repo).unwrap();
        assert!(slot.unwrap_with_recovery_key(&repo, &other).is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        let m = SecretKey::generate().unwrap();
        assert!(
            KeySlot::wrap_with_passphrase(&Uuid::new_v4(), &m, b"", KdfParams::INSECURE_FAST)
                .is_err()
        );
    }
}
