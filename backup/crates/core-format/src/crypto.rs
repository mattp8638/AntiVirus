//! Thin wrappers over the primitives used by the format.
//!
//! * AEAD: XChaCha20-Poly1305, 256-bit key, 192-bit random nonce.
//! * KDF (passphrase → key): Argon2id.
//! * Subkey derivation: BLAKE3 `derive_key` with fixed context strings.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// A 256-bit secret key, wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        SecretKey(bytes)
    }

    pub fn generate() -> Result<Self> {
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k)?;
        Ok(SecretKey(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive an independent subkey for one purpose.
    pub fn derive(&self, context: &str) -> SecretKey {
        SecretKey(blake3::derive_key(context, &self.0))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "OS random source failed: {e}"
        )))
    })
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    fill_random(&mut n)?;
    Ok(n)
}

pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::integrity("encryption failed"))
}

/// Decrypt and authenticate. Any failure is reported as an integrity error;
/// callers that know the failure means "wrong key" map it themselves.
pub fn open(key: &SecretKey, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::malformed("bad nonce length"));
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::integrity("authentication failed"))
}

/// Argon2id parameters, stored alongside each passphrase-wrapped key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// Default for new repositories: 64 MiB, 3 passes, 1 lane (the OWASP
    /// and RFC 9106 "second recommended option" ballpark). Runs well inside
    /// the recovery environment's memory budget.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Cheap parameters for tests only.
    pub const INSECURE_FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    /// Bounds a reader enforces before running the KDF so a hostile key
    /// file cannot exhaust memory or time.
    pub fn check_bounds(&self) -> Result<()> {
        if self.m_cost_kib < 8 || self.m_cost_kib > 4 * 1024 * 1024 {
            return Err(Error::malformed("argon2 memory cost out of range"));
        }
        if self.t_cost == 0 || self.t_cost > 100 || self.p_cost == 0 || self.p_cost > 64 {
            return Err(Error::malformed("argon2 time/parallelism out of range"));
        }
        Ok(())
    }
}

pub fn derive_from_passphrase(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretKey> {
    params.check_bounds()?;
    let p = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::InvalidArgument(format!("argon2 params: {e}")))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = [0u8; KEY_LEN];
    a.hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| Error::InvalidArgument(format!("argon2: {e}")))?;
    let k = SecretKey(out);
    out.zeroize();
    Ok(k)
}

pub mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    pub fn decode(s: &str) -> crate::Result<Vec<u8>> {
        STANDARD
            .decode(s)
            .map_err(|e| crate::Error::malformed(format!("base64: {e}")))
    }

    /// serde helper for `Vec<u8>` fields stored as base64 strings.
    pub mod serde_bytes {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&super::encode(v))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let s = String::deserialize(d)?;
            super::decode(&s).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let k = SecretKey::generate().unwrap();
        let n = random_nonce().unwrap();
        let ct = seal(&k, &n, b"aad", b"hello").unwrap();
        assert_eq!(open(&k, &n, b"aad", &ct).unwrap(), b"hello");
        assert!(open(&k, &n, b"other", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, &n, b"aad", &bad).is_err());
        let k2 = SecretKey::generate().unwrap();
        assert!(open(&k2, &n, b"aad", &ct).is_err());
    }

    #[test]
    fn kdf_is_deterministic_and_salted() {
        let a =
            derive_from_passphrase(b"pw", b"saltsaltsaltsalt", KdfParams::INSECURE_FAST).unwrap();
        let b =
            derive_from_passphrase(b"pw", b"saltsaltsaltsalt", KdfParams::INSECURE_FAST).unwrap();
        let c =
            derive_from_passphrase(b"pw", b"SALTSALTSALTSALT", KdfParams::INSECURE_FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn kdf_bounds_rejected() {
        let p = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(derive_from_passphrase(b"pw", b"saltsaltsaltsalt", p).is_err());
    }

    #[test]
    fn subkeys_differ() {
        let k = SecretKey::generate().unwrap();
        assert_ne!(k.derive("a").as_bytes(), k.derive("b").as_bytes());
    }
}
