//! Sealed object container shared by chunks and manifests.
//!
//! ```text
//! offset size  field
//! 0      4     magic: "FNRC" (chunk) or "FNRM" (manifest)
//! 4      1     container version = 1
//! 5      1     flags: bit 0 = payload is zstd-compressed; other bits must be 0
//! 6      2     reserved, must be 0
//! 8      4     plaintext length (u32, little endian)
//! 12     24    XChaCha20-Poly1305 nonce
//! 36     ..    ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Associated data = the 36 header bytes followed by the object's binding
//! (chunk ID for chunks, image ID for manifests). The header is therefore
//! authenticated, and an object cannot be moved to another name.

use crate::crypto::{self, SecretKey, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 36;
pub const MAGIC_CHUNK: [u8; 4] = *b"FNRC";
pub const MAGIC_MANIFEST: [u8; 4] = *b"FNRM";
pub const FLAG_ZSTD: u8 = 0x01;

/// Largest plaintext accepted by readers. Chunks are 4 MiB by default and
/// at most 64 MiB; manifests of very large disks stay well below this.
pub const MAX_PLAINTEXT: usize = 256 * 1024 * 1024;

pub struct SealOptions {
    /// zstd level; `None` stores uncompressed.
    pub zstd_level: Option<i32>,
}

pub fn seal_object(
    magic: [u8; 4],
    key: &SecretKey,
    binding: &[u8],
    plaintext: &[u8],
    opts: &SealOptions,
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::InvalidArgument("object too large".into()));
    }
    let mut flags = 0u8;
    let compressed;
    let payload: &[u8] = match opts.zstd_level {
        Some(level) => {
            compressed = zstd::bulk::compress(plaintext, level)?;
            // Only keep compression if it helps.
            if compressed.len() < plaintext.len() {
                flags |= FLAG_ZSTD;
                &compressed
            } else {
                plaintext
            }
        }
        None => plaintext,
    };
    let nonce = crypto::random_nonce()?;
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&magic);
    header[4] = 1;
    header[5] = flags;
    header[8..12].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    header[12..36].copy_from_slice(&nonce);
    let mut aad = header.to_vec();
    aad.extend_from_slice(binding);
    let ct = crypto::seal(key, &nonce, &aad, payload)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_object(
    magic: [u8; 4],
    key: &SecretKey,
    binding: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::integrity("object truncated"));
    }
    let header = &data[..HEADER_LEN];
    if header[0..4] != magic {
        return Err(Error::integrity("bad object magic"));
    }
    if header[4] != 1 {
        return Err(Error::UnsupportedVersion {
            what: "object container",
            version: header[4] as u32,
        });
    }
    let flags = header[5];
    if flags & !FLAG_ZSTD != 0 || header[6] != 0 || header[7] != 0 {
        return Err(Error::integrity("unknown object flags"));
    }
    let plain_len = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    if plain_len > MAX_PLAINTEXT {
        return Err(Error::integrity("object length out of range"));
    }
    let nonce = &header[12..12 + NONCE_LEN];
    let mut aad = header.to_vec();
    aad.extend_from_slice(binding);
    let payload = crypto::open(key, nonce, &aad, &data[HEADER_LEN..])?;
    let plain = if flags & FLAG_ZSTD != 0 {
        // Capacity bounds decompression: a payload expanding beyond the
        // declared length is an error, not an allocation.
        zstd::bulk::decompress(&payload, plain_len)
            .map_err(|e| Error::integrity(format!("decompression: {e}")))?
    } else {
        payload
    };
    if plain.len() != plain_len {
        return Err(Error::integrity("object length mismatch"));
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SealOptions {
        SealOptions {
            zstd_level: Some(3),
        }
    }

    #[test]
    fn roundtrip_compressible_and_incompressible() {
        let k = SecretKey::generate().unwrap();
        let zeros = vec![7u8; 100_000];
        let o = seal_object(MAGIC_CHUNK, &k, b"id", &zeros, &opts()).unwrap();
        assert!(o.len() < 10_000);
        assert_eq!(o[5] & FLAG_ZSTD, FLAG_ZSTD);
        assert_eq!(open_object(MAGIC_CHUNK, &k, b"id", &o).unwrap(), zeros);

        let mut rnd = vec![0u8; 4096];
        crypto::fill_random(&mut rnd).unwrap();
        let o = seal_object(MAGIC_CHUNK, &k, b"id", &rnd, &opts()).unwrap();
        assert_eq!(o[5], 0);
        assert_eq!(open_object(MAGIC_CHUNK, &k, b"id", &o).unwrap(), rnd);
    }

    #[test]
    fn tampering_is_detected() {
        let k = SecretKey::generate().unwrap();
        let o = seal_object(MAGIC_CHUNK, &k, b"id", b"payload payload payload", &opts()).unwrap();
        // Any single-byte flip anywhere must fail.
        for i in 0..o.len() {
            let mut t = o.clone();
            t[i] ^= 0x40;
            assert!(
                open_object(MAGIC_CHUNK, &k, b"id", &t).is_err(),
                "flip at {i} not detected"
            );
        }
        assert!(open_object(MAGIC_CHUNK, &k, b"other-id", &o).is_err());
        assert!(open_object(MAGIC_MANIFEST, &k, b"id", &o).is_err());
        assert!(open_object(MAGIC_CHUNK, &k, b"id", &o[..o.len() - 1]).is_err());
        assert!(open_object(MAGIC_CHUNK, &k, b"id", &o[..10]).is_err());
    }
}
