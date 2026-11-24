//! Files downloaded through the server, end to end encrypted
//! (docs/design/file-download.md).
//!
//! The browser makes a one-time X25519 key pair and sends only its public
//! key. The agent picks a random content key, seals it to that public key
//! (the `seal` scheme: X25519, HKDF-SHA256, AES-256-GCM) and encrypts the
//! tar archive of the files in frames:
//!
//! ```text
//! frame i = AES-256-GCM(content key, nonce = 4 zero bytes || i as u64 BE,
//!                       aad = [1 if last frame else 0], plaintext <= 1 MiB)
//! stream  = (u32 BE length || frame)*
//! ```
//!
//! The server stores and serves the stream without being able to read it.
//! Numbered nonces stop frames being reordered or repeated; the last-frame
//! flag stops a truncated stream passing as complete.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};

use crate::seal::{seal, SealError, Sealed};

/// Plaintext bytes per frame.
pub const FRAME: usize = 1 << 20;

/// Sent with the job's result: what the browser needs to decrypt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadHeader {
    pub v: u32,
    /// The content key, sealed to the browser's one-time public key.
    pub sealed_key: Sealed,
    pub frame: u32,
    /// Bytes of the (encrypted) stream and of the tar archive.
    pub stream_bytes: u64,
    pub archive_bytes: u64,
    pub file_name: String,
}

/// Encrypts a stream for one recipient.
pub struct Encryptor {
    cipher: Aes256Gcm,
    key: [u8; 32],
    next: u64,
}

impl Encryptor {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS random source");
        Encryptor {
            cipher: Aes256Gcm::new_from_slice(&key).expect("32-byte key"),
            key,
            next: 0,
        }
    }

    /// The content key sealed to the browser's public key.
    pub fn sealed_key(&self, recipient_b64: &str) -> Result<Sealed, SealError> {
        seal(recipient_b64, &self.key)
    }

    /// The next frame, length-prefixed; `last` for the final one.
    pub fn frame(&mut self, plain: &[u8], last: bool) -> Vec<u8> {
        assert!(plain.len() <= FRAME);
        let ct = self
            .cipher
            .encrypt(
                &nonce(self.next),
                Payload {
                    msg: plain,
                    aad: &[last as u8],
                },
            )
            .expect("AES-GCM encrypt");
        self.next += 1;
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }
}

impl Default for Encryptor {
    fn default() -> Self {
        Self::new()
    }
}

fn nonce(i: u64) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&i.to_be_bytes());
    Nonce::from(n)
}

/// Decrypt a whole stream with the content key (tests, and any client
/// written in Rust). Fails if a frame was altered, moved, or the stream is
/// cut short.
pub fn decrypt(key: &[u8; 32], stream: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "key")?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut i = 0u64;
    while pos < stream.len() {
        let len = u32::from_be_bytes(
            stream
                .get(pos..pos + 4)
                .ok_or("cut short")?
                .try_into()
                .unwrap(),
        ) as usize;
        let ct = stream.get(pos + 4..pos + 4 + len).ok_or("cut short")?;
        pos += 4 + len;
        let last = pos == stream.len();
        let p = cipher
            .decrypt(
                &nonce(i),
                Payload {
                    msg: ct,
                    aad: &[last as u8],
                },
            )
            .map_err(|_| {
                format!("frame {i} does not decrypt (altered, reordered or incomplete)")
            })?;
        out.extend_from_slice(&p);
        i += 1;
    }
    if i == 0 {
        return Err("empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::AgentKey;

    #[test]
    fn round_trip_and_tampering() {
        let browser = AgentKey::generate();
        let mut e = Encryptor::new();
        let sealed = e.sealed_key(&browser.public_b64()).unwrap();
        let data: Vec<u8> = (0..(FRAME * 2 + 77)).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<&[u8]> = data.chunks(FRAME).collect();
        let mut stream = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            stream.extend(e.frame(c, i + 1 == chunks.len()));
        }
        let key: [u8; 32] = browser.open(&sealed).unwrap()[..].try_into().unwrap();
        assert_eq!(decrypt(&key, &stream).unwrap(), data);
        // Cut after the first frame: refused (that frame was not the last).
        let first = 4 + u32::from_be_bytes(stream[..4].try_into().unwrap()) as usize;
        assert!(decrypt(&key, &stream[..first]).is_err());
        // A flipped byte: refused.
        let mut bad = stream.clone();
        bad[100] ^= 1;
        assert!(decrypt(&key, &bad).is_err());
        // Another key: refused.
        assert!(decrypt(&[7u8; 32], &stream).is_err());
        assert!(decrypt(&key, &[]).is_err());
    }
}

/// Writes a sample download for the browser-side interop check
/// (ci/download-interop.mjs) when FENRIR_INTEROP_DIR is set.
#[cfg(test)]
#[test]
fn interop_sample() {
    let Ok(dir) = std::env::var("FENRIR_INTEROP_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    let browser = crate::seal::AgentKey::generate();
    let mut e = Encryptor::new();
    let sealed = e.sealed_key(&browser.public_b64()).unwrap();
    let data: Vec<u8> = (0..(FRAME + 12345)).map(|i| (i * 7 % 256) as u8).collect();
    let mut stream = e.frame(&data[..FRAME], false);
    stream.extend(e.frame(&data[FRAME..], true));
    std::fs::write(dir.join("private.bin"), *browser.to_bytes()).unwrap();
    std::fs::write(dir.join("public.b64"), browser.public_b64()).unwrap();
    std::fs::write(
        dir.join("header.json"),
        serde_json::to_vec(&serde_json::json!({ "sealed_key": sealed })).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("stream.bin"), &stream).unwrap();
    std::fs::write(dir.join("plain.bin"), &data).unwrap();
}
