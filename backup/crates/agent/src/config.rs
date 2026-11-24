//! Agent identity and secrets on disk.
//!
//! * `agent.json`: server URL, certificate pin, agent ID, role. Not secret.
//! * `secrets.bin`: agent bearer token and X25519 private key. On Windows
//!   protected with DPAPI (machine scope) inside a directory only SYSTEM and
//!   Administrators can read; elsewhere a 0600 file in a 0700 root directory.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use protocol::seal::AgentKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: String,
    /// SHA-256 of the server certificate (hex). Empty = normal CA validation.
    #[serde(default)]
    pub pin: String,
    pub agent_id: String,
    pub role: String,
    pub machine_id: String,
}

#[derive(Serialize, Deserialize)]
struct SecretsFile {
    agent_token: String,
    x25519: String,
}

pub struct Secrets {
    pub agent_token: String,
    pub key: AgentKey,
}

pub fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FENRIR_AGENT_STATE") {
        return PathBuf::from(d);
    }
    // Installs from before the rename keep their state where it was.
    let legacy = crate::names::legacy_install();
    if cfg!(windows) {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join(if legacy {
                r"Fenrir\agent"
            } else {
                r"Fenrir-Backup\agent"
            })
    } else if cfg!(target_os = "macos") {
        PathBuf::from(if legacy {
            "/Library/Application Support/Fenrir/agent"
        } else {
            "/Library/Application Support/Fenrir-Backup/agent"
        })
    } else {
        PathBuf::from(if legacy {
            "/var/lib/fenrir-agent"
        } else {
            "/var/lib/fenrir-backup-agent"
        })
    }
}

pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        // Remove inherited ACEs (ProgramData lets Users read) and allow only
        // SYSTEM and Administrators. Well-known SIDs avoid localised names.
        let st = std::process::Command::new("icacls")
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .stdout(std::process::Stdio::null())
            .status()?;
        if !st.success() {
            bail!("could not restrict permissions on {}", dir.display());
        }
    }
    Ok(())
}

impl AgentConfig {
    pub fn load(dir: &Path) -> anyhow::Result<AgentConfig> {
        let p = dir.join("agent.json");
        let s = std::fs::read_to_string(&p).with_context(|| {
            format!(
                "{} not found: run `fenrir-backup-agent enroll` first",
                p.display()
            )
        })?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(
            &dir.join("agent.json"),
            serde_json::to_string_pretty(self)?.as_bytes(),
        )
    }
}

/// Load the existing key pair, if any (kept across re-enrollment so that
/// repository access survives a reinstall).
pub fn load_secrets(dir: &Path) -> anyhow::Result<Option<Secrets>> {
    let p = dir.join("secrets.bin");
    let raw = match std::fs::read(&p) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let plain = unprotect(&raw)?;
    let f: SecretsFile = serde_json::from_slice(&plain)?;
    let kb: [u8; 32] = B64
        .decode(&f.x25519)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad key length"))?;
    Ok(Some(Secrets {
        agent_token: f.agent_token,
        key: AgentKey::from_bytes(kb),
    }))
}

pub fn save_secrets(dir: &Path, s: &Secrets) -> anyhow::Result<()> {
    let f = SecretsFile {
        agent_token: s.agent_token.clone(),
        x25519: B64.encode(*s.key.to_bytes()),
    };
    let plain = serde_json::to_vec(&f)?;
    write_atomic(&dir.join("secrets.bin"), &protect(&plain)?)
}

fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    dpapi::protect(data)
}
#[cfg(windows)]
fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    dpapi::unprotect(data)
}

#[cfg(not(windows))]
fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(windows)]
mod dpapi {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(d: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: d.len() as u32,
            pbData: d.as_ptr() as *mut u8,
        }
    }

    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
        v
    }

    /// Machine-scope DPAPI: the enrolling administrator and the SYSTEM
    /// service can both read it; the directory ACL keeps other users out.
    pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(
                &blob(data),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )?;
            Ok(take(out))
        }
    }

    pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptUnprotectData(
                &blob(data),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )?;
            Ok(take(out))
        }
    }
}

pub fn validate_server_url(s: &str) -> anyhow::Result<String> {
    let s = s.trim().trim_end_matches('/');
    if !(s.starts_with("https://") || s.starts_with("http://")) {
        bail!("server URL must start with https:// or http://");
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        assert!(load_secrets(d.path()).unwrap().is_none());
        let k = AgentKey::generate();
        let pk = k.public_b64();
        save_secrets(
            d.path(),
            &Secrets {
                agent_token: "tok".into(),
                key: k,
            },
        )
        .unwrap();
        let s = load_secrets(d.path()).unwrap().unwrap();
        assert_eq!(s.agent_token, "tok");
        assert_eq!(s.key.public_b64(), pk);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(d.path().join("secrets.bin"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
