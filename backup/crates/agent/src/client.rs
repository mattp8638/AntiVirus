//! HTTPS client for the server API. With a pin, only the server
//! certificate whose SHA-256 matches is accepted (self-signed servers);
//! without one, normal WebPKI validation applies.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned fingerprint".into(),
            ))
        }
    }

    // The handshake signature must still be valid for the pinned key.
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
}

impl Client {
    pub fn new(base: &str, pin_hex: &str, token: Option<String>) -> anyhow::Result<Client> {
        let mut b = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .user_agent(&format!(
                "fenrir-backup-agent/{}",
                env!("CARGO_PKG_VERSION")
            ));
        if !pin_hex.is_empty() {
            let pin: [u8; 32] = hex::decode(pin_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| anyhow!("pin must be 64 hex characters"))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
                .with_no_client_auth();
            b = b.tls_config(Arc::new(cfg));
        }
        Ok(Client {
            agent: b.build(),
            base: base.to_string(),
            token,
        })
    }

    pub fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<R> {
        let mut req = self.agent.post(&format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        match req.send_json(body) {
            Ok(r) => Ok(r.into_json()?),
            Err(ureq::Error::Status(code, r)) => {
                let msg = r
                    .into_json::<protocol::ErrorBody>()
                    .map(|e| e.error)
                    .unwrap_or_default();
                bail!(ServerRefused { code, message: msg })
            }
            Err(e) => Err(anyhow!("cannot reach {}: {e}", self.base)),
        }
    }
}

impl Client {
    /// GET a binary body, refusing more than `limit` bytes.
    pub fn get_bytes(&self, path: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
        let mut req = self.agent.get(&format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let r = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let msg = r.into_string().unwrap_or_default();
                bail!(ServerRefused { code, message: msg })
            }
            Err(e) => return Err(anyhow!("cannot reach {}: {e}", self.base)),
        };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(r.into_reader(), limit + 1),
            &mut buf,
        )?;
        if buf.len() as u64 > limit {
            bail!("download larger than {limit} bytes");
        }
        Ok(buf)
    }
}

/// The server answered with an error status (as opposed to being unreachable).
#[derive(Debug)]
pub struct ServerRefused {
    pub code: u16,
    pub message: String,
}

impl std::fmt::Display for ServerRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server refused ({}): {}", self.code, self.message)
    }
}
impl std::error::Error for ServerRefused {}
