//! NAS gateway: one agent inside a network serves a repository (on a NAS or
//! file server) to agents elsewhere, directly when they can reach it and
//! through the Fenrir server otherwise.
//!
//! Every message is encrypted and authenticated end to end between the two
//! agents with a key only they can derive:
//!
//! ```text
//! key  = HKDF-SHA256(ikm  = X25519(own secret, peer public),
//!                    salt = client public || gateway public,
//!                    info = "fenrir-gateway-v1", L = 32)
//! wire = 0x01 || request id (16) || client agent id (16) || nonce (12)
//!        || AES-256-GCM(key, nonce, aad = 0x01 || direction || request id || client id, plaintext)
//! ```
//!
//! The relay sees only these bytes: it can neither read nor forge them.
//! Plaintext is a JSON header line, `\n`, then the object bytes (puts and
//! get replies). Requests older than `MAX_AGE_SECS` are refused.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::seal::{AgentKey, Sealed};

pub const INFO: &[u8] = b"fenrir-gateway-v1";
pub const VERSION: u8 = 1;
pub const MAX_AGE_SECS: i64 = 600;
/// Largest message either way (a chunk is at most a few MiB).
pub const MAX_MESSAGE: usize = 64 << 20;
const HEAD: usize = 1 + 16 + 16 + 12;
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;

/// Sent to a gateway agent in its heartbeat: what it serves, and to whom.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// TCP port for direct connections; 0 = relay only.
    #[serde(default)]
    pub listen_port: u16,
    pub repositories: Vec<GatewayRepo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayRepo {
    pub repository_id: Uuid,
    pub path: String,
    #[serde(default)]
    pub sealed_share: Option<Sealed>,
    pub clients: Vec<GatewayClient>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayClient {
    pub agent_id: Uuid,
    pub public_key: String,
}

/// In a client's `RepoAccess`: how to reach the repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayRoute {
    pub agent_id: Uuid,
    pub public_key: String,
    /// "host:port" addresses to try directly, in order.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Fall back to the server relay.
    #[serde(default = "yes")]
    pub relay: bool,
}

fn yes() -> bool {
    true
}

/// A storage operation (`core_format::Backend`) on one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Put { key: String },
    Get { key: String },
    Exists { key: String },
    Size { key: String },
    List { prefix: String },
    Delete { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub repository_id: Uuid,
    /// Unix seconds when sent.
    pub ts: i64,
    #[serde(flatten)]
    pub op: Op,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// None on success; else "not_found", "denied", "invalid" or "io".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub exists: bool,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GatewayError(pub String);

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gateway message: {}", self.0)
    }
}

impl std::error::Error for GatewayError {}

fn err(s: &str) -> GatewayError {
    GatewayError(s.into())
}

pub fn decode_key(b64: &str) -> Result<[u8; 32], GatewayError> {
    B64.decode(b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err("bad public key"))
}

/// The key one client and one gateway share.
pub struct Channel {
    key: Zeroizing<[u8; 32]>,
    client: Uuid,
}

impl Channel {
    /// On the client: `me` is the client's key, `gateway_pk` the gateway's.
    pub fn client(
        me: &AgentKey,
        client_id: Uuid,
        gateway_pk: &str,
    ) -> Result<Channel, GatewayError> {
        let g = decode_key(gateway_pk)?;
        Ok(Channel {
            key: derive(&me.diffie_hellman(&g), &me.public_bytes(), &g),
            client: client_id,
        })
    }

    /// On the gateway: `me` is the gateway's key, `client_pk` the client's.
    pub fn gateway(
        me: &AgentKey,
        client_id: Uuid,
        client_pk: &str,
    ) -> Result<Channel, GatewayError> {
        let c = decode_key(client_pk)?;
        Ok(Channel {
            key: derive(&me.diffie_hellman(&c), &c, &me.public_bytes()),
            client: client_id,
        })
    }

    fn seal(&self, direction: u8, rid: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("OS random source");
        let mut out = Vec::with_capacity(HEAD + plaintext.len() + 16);
        out.push(VERSION);
        out.extend_from_slice(rid);
        out.extend_from_slice(self.client.as_bytes());
        out.extend_from_slice(&nonce);
        let aad = aad(direction, rid, self.client.as_bytes());
        let ct = Aes256Gcm::new_from_slice(&*self.key)
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption");
        out.extend_from_slice(&ct);
        out
    }

    fn open(&self, direction: u8, wire: &[u8]) -> Result<([u8; 16], Vec<u8>), GatewayError> {
        let (rid, client) = peek(wire)?;
        if client != self.client {
            return Err(err("message is for another client"));
        }
        let nonce = &wire[33..45];
        let aad = aad(direction, &rid, client.as_bytes());
        let pt = Aes256Gcm::new_from_slice(&*self.key)
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &wire[HEAD..],
                    aad: &aad,
                },
            )
            .map_err(|_| err("authentication failed (wrong key, or tampered with)"))?;
        Ok((rid, pt))
    }

    /// Client: encrypt a request. Returns the wire bytes and the request id.
    pub fn request(&self, req: &Request, body: &[u8]) -> ([u8; 16], Vec<u8>) {
        let rid = *Uuid::new_v4().as_bytes();
        (rid, self.seal(REQUEST, &rid, &frame(req, body)))
    }

    /// Gateway: decrypt a request, checking its age against `now`.
    pub fn open_request(
        &self,
        wire: &[u8],
        now: i64,
    ) -> Result<([u8; 16], Request, Vec<u8>), GatewayError> {
        let (rid, pt) = self.open(REQUEST, wire)?;
        let (req, body): (Request, Vec<u8>) = unframe(&pt)?;
        if (now - req.ts).abs() > MAX_AGE_SECS {
            return Err(err("request too old (check the clocks of both machines)"));
        }
        Ok((rid, req, body))
    }

    /// Gateway: encrypt the response to request `rid`.
    pub fn response(&self, rid: &[u8; 16], resp: &Response, body: &[u8]) -> Vec<u8> {
        self.seal(RESPONSE, rid, &frame(resp, body))
    }

    /// Client: decrypt the response, checking it answers `rid`.
    pub fn open_response(
        &self,
        rid: &[u8; 16],
        wire: &[u8],
    ) -> Result<(Response, Vec<u8>), GatewayError> {
        let (got, pt) = self.open(RESPONSE, wire)?;
        if &got != rid {
            return Err(err("response to another request"));
        }
        unframe(&pt)
    }
}

/// Request id and client id of a message, before decrypting it.
pub fn peek(wire: &[u8]) -> Result<([u8; 16], Uuid), GatewayError> {
    if wire.len() < HEAD + 16 || wire.len() > MAX_MESSAGE + HEAD + 16 + 4096 {
        return Err(err("bad length"));
    }
    if wire[0] != VERSION {
        return Err(err("unsupported version"));
    }
    let rid: [u8; 16] = wire[1..17].try_into().expect("16 bytes");
    let client = Uuid::from_bytes(wire[17..33].try_into().expect("16 bytes"));
    Ok((rid, client))
}

fn aad(direction: u8, rid: &[u8; 16], client: &[u8; 16]) -> [u8; 34] {
    let mut a = [0u8; 34];
    a[0] = VERSION;
    a[1] = direction;
    a[2..18].copy_from_slice(rid);
    a[18..].copy_from_slice(client);
    a
}

fn derive(shared: &[u8; 32], client_pk: &[u8; 32], gateway_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_pk);
    salt[32..].copy_from_slice(gateway_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, &mut *okm)
        .expect("32 bytes is a valid HKDF length");
    okm
}

fn frame<T: Serialize>(head: &T, body: &[u8]) -> Vec<u8> {
    let mut v = serde_json::to_vec(head).expect("serialisable");
    v.push(b'\n');
    v.extend_from_slice(body);
    v
}

fn unframe<T: for<'de> Deserialize<'de>>(pt: &[u8]) -> Result<(T, Vec<u8>), GatewayError> {
    let nl = pt
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| err("no header"))?;
    let head = serde_json::from_slice(&pt[..nl]).map_err(|_| err("bad header"))?;
    Ok((head, pt[nl + 1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (AgentKey, AgentKey, Uuid) {
        (AgentKey::generate(), AgentKey::generate(), Uuid::new_v4())
    }

    #[test]
    fn round_trip_and_tamper_detection() {
        let (client, gateway, id) = pair();
        let c = Channel::client(&client, id, &gateway.public_b64()).unwrap();
        let g = Channel::gateway(&gateway, id, &client.public_b64()).unwrap();
        let req = Request {
            repository_id: Uuid::new_v4(),
            ts: 1000,
            op: Op::Put {
                key: "chunks/ab/abcd".into(),
            },
        };
        let (rid, wire) = c.request(&req, b"chunk bytes");
        assert_eq!(peek(&wire).unwrap(), (rid, id));
        let (rid2, got, body) = g.open_request(&wire, 1010).unwrap();
        assert_eq!(
            (rid2, &got, body.as_slice()),
            (rid, &req, &b"chunk bytes"[..])
        );
        let resp = g.response(
            &rid,
            &Response {
                created: true,
                ..Default::default()
            },
            b"",
        );
        assert!(c.open_response(&rid, &resp).unwrap().0.created);

        // Tampering, another key, old messages, or a reply to another request all fail.
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(g.open_request(&bad, 1010).is_err());
        let other = AgentKey::generate();
        let g2 = Channel::gateway(&other, id, &client.public_b64()).unwrap();
        assert!(g2.open_request(&wire, 1010).is_err());
        assert!(g.open_request(&wire, 1000 + MAX_AGE_SECS + 1).is_err());
        assert!(c.open_response(&[9; 16], &resp).is_err());
        // A response cannot be passed off as a request (direction is authenticated).
        assert!(g.open_request(&resp, 1010).is_err());
        // Changing the client id in the header breaks authentication.
        let mut swapped = wire.clone();
        swapped[17] ^= 1;
        assert!(g.open_request(&swapped, 1010).is_err());
    }
}
