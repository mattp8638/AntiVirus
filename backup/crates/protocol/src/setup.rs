//! Settings appended to the Windows agent executable to make a
//! per-enrollment setup program (`Fenrir-Backup-Setup.exe`).
//!
//! Layout: `<agent exe> <settings JSON> <u32 LE length of the JSON> <MAGIC>`.
//! Windows loads a PE image by its headers and ignores data after it, so the
//! file still runs; the agent finds the block at its own end and installs
//! itself with these settings. Installed copies have the block removed, so
//! they are byte-identical to the server's agent build (self-update compares
//! hashes).

use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 16] = b"FENRIR-SETUP-V1\0";
/// Upper bound for the JSON; anything larger is not ours.
const MAX_JSON: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupConfig {
    pub server: String,
    /// SHA-256 of the server certificate (hex) for self-signed servers.
    #[serde(default)]
    pub pin: String,
    pub token: String,
    pub role: String,
}

/// `exe` with `cfg` appended.
pub fn append(exe: &[u8], cfg: &SetupConfig) -> Vec<u8> {
    let json = serde_json::to_vec(cfg).expect("serialisable");
    let mut out = Vec::with_capacity(exe.len() + json.len() + 20);
    out.extend_from_slice(exe);
    out.extend_from_slice(&json);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(MAGIC);
    out
}

/// The settings at the end of `file`, and the length of the executable
/// before them; `None` for a plain agent build.
pub fn read(file: &[u8]) -> Option<(SetupConfig, usize)> {
    let n = file.len();
    if n < MAGIC.len() + 4 || &file[n - MAGIC.len()..] != MAGIC {
        return None;
    }
    let len_at = n - MAGIC.len() - 4;
    let len = u32::from_le_bytes(file[len_at..len_at + 4].try_into().ok()?) as usize;
    if len == 0 || len > MAX_JSON || len > len_at {
        return None;
    }
    let start = len_at - len;
    let cfg = serde_json::from_slice(&file[start..len_at]).ok()?;
    Some((cfg, start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejects() {
        let exe = b"MZ\x90\x00 pretend this is a PE image".to_vec();
        let cfg = SetupConfig {
            server: "https://198.51.100.7:8443".into(),
            pin: "ab".repeat(32),
            token: "tok".into(),
            role: "workstation".into(),
        };
        let f = append(&exe, &cfg);
        let (got, at) = read(&f).unwrap();
        assert_eq!(got, cfg);
        assert_eq!(&f[..at], &exe[..], "stripping gives back the plain build");
        assert!(read(&exe).is_none(), "plain build");
        assert!(read(b"").is_none());
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - MAGIC.len() - 4..n - MAGIC.len()].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read(&bad).is_none(), "length out of range");
        let mut garbled = f.clone();
        garbled[exe.len()] = b'!';
        assert!(read(&garbled).is_none(), "not JSON");
    }
}
