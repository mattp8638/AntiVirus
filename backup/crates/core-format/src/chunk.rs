//! Chunk identifiers and chunk encoding.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::SecretKey;
use crate::error::{Error, Result};
use crate::object::{self, SealOptions, MAGIC_CHUNK};

/// Default chunk size for disk images: 4 MiB.
pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
pub const MIN_CHUNK_SIZE: u32 = 64 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

/// Keyed BLAKE3 hash of a chunk's plaintext (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub [u8; 32]);

impl ChunkId {
    pub fn compute(id_key: &SecretKey, plaintext: &[u8]) -> ChunkId {
        ChunkId(*blake3::keyed_hash(id_key.as_bytes(), plaintext).as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Object key in the repository: `chunks/<first two hex>/<hex>`.
    pub fn object_key(&self) -> String {
        let h = self.to_hex();
        format!("chunks/{}/{}", &h[..2], h)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({})", &self.to_hex()[..16])
    }
}

impl FromStr for ChunkId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v = hex::decode(s).map_err(|_| Error::malformed("chunk id is not hex"))?;
        Ok(ChunkId(
            v.try_into()
                .map_err(|_| Error::malformed("chunk id length"))?,
        ))
    }
}

impl Serialize for ChunkId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChunkId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Encrypt a chunk for storage.
pub fn encode_chunk(
    enc_key: &SecretKey,
    id: &ChunkId,
    plaintext: &[u8],
    zstd_level: Option<i32>,
) -> Result<Vec<u8>> {
    object::seal_object(
        MAGIC_CHUNK,
        enc_key,
        &id.0,
        plaintext,
        &SealOptions { zstd_level },
    )
}

/// Decrypt a stored chunk and check that its content hashes to `id`.
pub fn decode_chunk(
    enc_key: &SecretKey,
    id_key: &SecretKey,
    id: &ChunkId,
    data: &[u8],
) -> Result<Vec<u8>> {
    let plain = object::open_object(MAGIC_CHUNK, enc_key, &id.0, data)
        .map_err(|e| Error::integrity(format!("chunk {id}: {e}")))?;
    if ChunkId::compute(id_key, &plain) != *id {
        return Err(Error::integrity(format!(
            "chunk {id}: content hash mismatch"
        )));
    }
    Ok(plain)
}

pub fn check_chunk_size(size: u32) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) || !size.is_power_of_two() {
        return Err(Error::InvalidArgument(format!(
            "chunk size {size} must be a power of two between 64 KiB and 64 MiB"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_and_id_binding() {
        let id_key = SecretKey::generate().unwrap();
        let enc = SecretKey::generate().unwrap();
        let a = b"chunk A".repeat(1000);
        let b = b"chunk B".repeat(1000);
        let ia = ChunkId::compute(&id_key, &a);
        let ib = ChunkId::compute(&id_key, &b);
        let oa = encode_chunk(&enc, &ia, &a, Some(3)).unwrap();
        assert_eq!(decode_chunk(&enc, &id_key, &ia, &oa).unwrap(), a);
        // Stored under the wrong name: rejected.
        assert!(decode_chunk(&enc, &id_key, &ib, &oa).is_err());
    }

    #[test]
    fn ids_are_keyed() {
        let k1 = SecretKey::generate().unwrap();
        let k2 = SecretKey::generate().unwrap();
        assert_ne!(ChunkId::compute(&k1, b"x"), ChunkId::compute(&k2, b"x"));
    }

    #[test]
    fn hex_roundtrip_and_object_key() {
        let id = ChunkId([0xab; 32]);
        assert_eq!(id.to_hex().parse::<ChunkId>().unwrap(), id);
        assert!(id.object_key().starts_with("chunks/ab/abab"));
        assert!("zz".parse::<ChunkId>().is_err());
    }

    #[test]
    fn chunk_size_bounds() {
        assert!(check_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
        assert!(check_chunk_size(1000).is_err());
        assert!(check_chunk_size(128 * 1024 * 1024).is_err());
    }
}
