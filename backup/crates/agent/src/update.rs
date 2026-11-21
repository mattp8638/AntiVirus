//! Agent self-update: download the build the server offers, check its
//! SHA-256, swap the executable, and let the service manager restart us.
//! Any failure leaves the running executable untouched.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context};
use protocol::AgentUpdate;
use sha2::{Digest, Sha256};

use crate::client::Client;

pub const TARGET: &str = env!("FENRIR_TARGET");

pub fn self_sha256() -> String {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| hex::encode(Sha256::digest(&b)))
            .unwrap_or_default()
    })
    .clone()
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Remove the previous executable left by an update on Windows.
pub fn cleanup_old() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(sibling(&exe, ".old"));
        let _ = std::fs::remove_file(sibling(&exe, ".new"));
    }
}

pub fn valid_offer(u: &AgentUpdate) -> bool {
    u.path.starts_with("/agent/")
        && !u.path.contains("..")
        && u.path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        && u.sha256.len() == 64
        && u.sha256.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Download, verify and install `u`. On success the new build is in place
/// and the caller should exit so the service manager restarts it.
pub fn apply(client: &Client, u: &AgentUpdate) -> anyhow::Result<()> {
    if !valid_offer(u) {
        bail!("ignoring malformed update offer");
    }
    let data = client.get_bytes(&u.path, 512 << 20)?;
    let got = hex::encode(Sha256::digest(&data));
    if !got.eq_ignore_ascii_case(&u.sha256) {
        bail!(
            "downloaded agent hash {got} does not match the offer {}",
            u.sha256
        );
    }
    let exe = std::env::current_exe().context("locating the running executable")?;
    install(&exe, &data)
}

pub fn install(exe: &Path, data: &[u8]) -> anyhow::Result<()> {
    let new = sibling(exe, ".new");
    std::fs::write(&new, data).with_context(|| format!("writing {}", new.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        // rename(2) over a running executable is atomic and safe.
        std::fs::rename(&new, exe)?;
    }
    #[cfg(windows)]
    {
        // A running .exe cannot be replaced but can be renamed aside.
        let old = sibling(exe, ".old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).context("moving the running agent aside")?;
        if let Err(e) = std::fs::rename(&new, exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(e).context("installing the new agent");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers_are_validated() {
        let ok = AgentUpdate {
            path: "/agent/x86_64-unknown-linux-musl/fenrir-backup-agent".into(),
            sha256: "a".repeat(64),
        };
        assert!(valid_offer(&ok));
        assert!(!valid_offer(&AgentUpdate {
            path: "/agent/../../etc/passwd".into(),
            ..ok.clone()
        }));
        assert!(!valid_offer(&AgentUpdate {
            path: "https://evil.example/x".into(),
            ..ok.clone()
        }));
        assert!(!valid_offer(&AgentUpdate {
            sha256: "zz".into(),
            ..ok
        }));
    }

    #[test]
    fn install_swaps_the_file() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("fenrir-backup-agent");
        std::fs::write(&exe, b"old build").unwrap();
        install(&exe, b"new build").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        assert!(!sibling(&exe, ".new").exists());
        assert!(!TARGET.is_empty());
    }
}
