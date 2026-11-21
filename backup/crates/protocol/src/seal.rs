//! Seal small secrets to an agent's X25519 public key.
//!
//! ```text
//! eph            = random X25519 key pair
//! shared         = X25519(eph.secret, agent.public)
//! key            = HKDF-SHA256(ikm = shared, salt = eph.public || agent.public,
//!                              info = "fenrir-agent-seal-v1", L = 32)
//! ct             = AES-256-GCM(key, nonce = random 12 bytes, aad = "", plaintext)
//! sealed (JSON)  = { "v": 1, "epk": b64(eph.public), "nonce": b64, "ct": b64 }
//! ```
//!
//! The web UI implements the sealing half with WebCrypto (ui/src/seal.ts);
//! the test vector below was produced by that same WebCrypto API in Node.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const INFO: &[u8] = b"fenrir-agent-seal-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub v: u32,
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

#[derive(Debug)]
pub struct SealError(pub &'static str);

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sealed secret: {}", self.0)
    }
}
impl std::error::Error for SealError {}

/// An agent's long-term key pair.
pub struct AgentKey {
    secret: StaticSecret,
}

impl AgentKey {
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *b).expect("OS random source");
        AgentKey {
            secret: StaticSecret::from(*b),
        }
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        AgentKey {
            secret: StaticSecret::from(b),
        }
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_b64(&self) -> String {
        B64.encode(PublicKey::from(&self.secret).as_bytes())
    }

    /// X25519 with another agent's public key (gateway channels).
    pub(crate) fn diffie_hellman(&self, peer: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            *self
                .secret
                .diffie_hellman(&PublicKey::from(*peer))
                .as_bytes(),
        )
    }

    pub(crate) fn public_bytes(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    pub fn open(&self, s: &Sealed) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if s.v != 1 {
            return Err(SealError("unsupported version"));
        }
        let epk: [u8; 32] = B64
            .decode(&s.epk)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(SealError("bad epk"))?;
        let nonce: [u8; 12] = B64
            .decode(&s.nonce)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(SealError("bad nonce"))?;
        let ct = B64.decode(&s.ct).map_err(|_| SealError("bad ciphertext"))?;
        let epk = PublicKey::from(epk);
        let shared = self.secret.diffie_hellman(&epk);
        let me = PublicKey::from(&self.secret);
        let key = derive(shared.as_bytes(), epk.as_bytes(), me.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&*key).expect("32-byte key");
        cipher
            .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| SealError("authentication failed (sealed for another agent, or tampered)"))
    }
}

fn derive(shared: &[u8; 32], epk: &[u8; 32], agent_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(agent_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, &mut *okm)
        .expect("32 bytes is a valid HKDF length");
    okm
}

/// Seal `plaintext` to `agent_public_b64`. The browser does this in
/// production; Rust uses it for tests and the CLI.
pub fn seal(agent_public_b64: &str, plaintext: &[u8]) -> Result<Sealed, SealError> {
    let apk: [u8; 32] = B64
        .decode(agent_public_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(SealError("bad agent public key"))?;
    let apk = PublicKey::from(apk);
    let eph = AgentKey::generate();
    let epk = PublicKey::from(&eph.secret);
    let shared = eph.secret.diffie_hellman(&apk);
    let key = derive(shared.as_bytes(), epk.as_bytes(), apk.as_bytes());
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| SealError("random source"))?;
    let ct = Aes256Gcm::new_from_slice(&*key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| SealError("encryption failed"))?;
    Ok(Sealed {
        v: 1,
        epk: B64.encode(epk.as_bytes()),
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_agent() {
        let a = AgentKey::generate();
        let b = AgentKey::generate();
        let s = seal(&a.public_b64(), b"secret passphrase").unwrap();
        assert_eq!(&*a.open(&s).unwrap(), b"secret passphrase");
        assert!(b.open(&s).is_err());
        let mut t = s.clone();
        t.ct = B64.encode(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert!(a.open(&t).is_err());
    }

    #[test]
    fn key_persists() {
        let a = AgentKey::generate();
        let a2 = AgentKey::from_bytes(*a.to_bytes());
        assert_eq!(a.public_b64(), a2.public_b64());
    }
}

#[cfg(test)]
mod webcrypto_vector {
    /// Produced by ui/src/seal.ts running on Node 22's WebCrypto (the same
    /// API browsers expose), sealed to the public key of the fixed secret
    /// [7; 32]. If this fails, browser-sealed secrets cannot be opened.
    #[test]
    fn opens_blob_sealed_by_webcrypto() {
        let agent = super::AgentKey::from_bytes([7u8; 32]);
        assert_eq!(
            agent.public_b64(),
            "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20="
        );
        let s: super::Sealed = serde_json::from_str(
            r#"{"v":1,"epk":"frLlgCaPGtmjJ8rrLPw+eXFVK9YUppmVJMBNayD4pHo=","nonce":"wc1puHAFfsLhzwOM","ct":"q0vWbshBs6ORzDRQU80KjNLiYIgH5ASANriTluZ8LFMYS5Lfw5BoGzx/wJIOb3ClYIXu"}"#,
        )
        .unwrap();
        let pt = agent.open(&s).unwrap();
        assert_eq!(
            std::str::from_utf8(&pt).unwrap(),
            r#"{"passphrase":"from WebCrypto ✓"}"#
        );
    }
}
