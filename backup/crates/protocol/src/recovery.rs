//! Recovery media settings (design: phase-2 §2).
//!
//! The recovery ISO holds `/fenrir/recovery.json`: exactly [`BLOCK`] bytes,
//! starting with [`MARKER`]. The stock ISO has only the marker and padding.
//! A server personalises a download by replacing those bytes with
//! [`render`]ed settings, so the stick finds its server by itself.

use serde::{Deserialize, Serialize};

pub const MARKER: &[u8] = b"FENRIR-RECOVERY-CONFIG-V1\n";
pub const BLOCK: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Server base URL.
    pub server: String,
    /// SHA-256 of a self-signed server certificate (hex), or empty.
    #[serde(default)]
    pub pin: String,
    /// Enrolment token for role `recovery`.
    pub token: String,
    /// Unix seconds after which the token no longer works (informational).
    #[serde(default)]
    pub expires: u64,
}

/// The placeholder block of a stock ISO.
pub fn placeholder() -> Vec<u8> {
    let mut b = MARKER.to_vec();
    b.resize(BLOCK, b' ');
    b
}

/// The block for `cfg`: marker, JSON, space padding.
pub fn render(cfg: &RecoveryConfig) -> Result<Vec<u8>, String> {
    let mut b = MARKER.to_vec();
    b.extend(serde_json::to_vec(cfg).map_err(|e| e.to_string())?);
    b.push(b'\n');
    if b.len() > BLOCK {
        return Err("recovery settings do not fit in 4 KiB".into());
    }
    b.resize(BLOCK, b' ');
    Ok(b)
}

/// Read a settings file: a block (marker + JSON, or marker only for a stock
/// ISO: `Ok(None)`), or plain JSON (`fenrir-recovery.json` on a USB stick).
pub fn parse(bytes: &[u8]) -> Result<Option<RecoveryConfig>, String> {
    let body = bytes.strip_prefix(MARKER).unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_string())?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(text)
        .map(Some)
        .map_err(|e| format!("bad recovery settings: {e}"))
}

/// Offset of the (unconfigured) placeholder block in a stock ISO. The block
/// starts on a 2048-byte ISO sector and is the marker followed by spaces.
pub fn find_block(iso: &[u8]) -> Option<usize> {
    (0..iso.len().saturating_sub(BLOCK - 1))
        .step_by(2048)
        .find(|&o| {
            iso[o..].starts_with(MARKER)
                && iso[o + MARKER.len()..o + BLOCK].iter().all(|&b| b == b' ')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RecoveryConfig {
        RecoveryConfig {
            server: "https://backup.example.lan:8443".into(),
            pin: "ab".repeat(32),
            token: "fet_x".into(),
            expires: 1_800_000_000,
        }
    }

    #[test]
    fn placeholder_is_unconfigured() {
        let p = placeholder();
        assert_eq!(p.len(), BLOCK);
        assert_eq!(parse(&p).unwrap(), None);
    }

    #[test]
    fn render_and_parse() {
        let b = render(&cfg()).unwrap();
        assert_eq!(b.len(), BLOCK);
        assert_eq!(parse(&b).unwrap(), Some(cfg()));
        // A plain JSON file on a stick works too.
        assert_eq!(
            parse(serde_json::to_string(&cfg()).unwrap().as_bytes()).unwrap(),
            Some(cfg())
        );
        assert!(parse(b"{nope").is_err());
    }

    #[test]
    fn too_big_is_refused() {
        let mut c = cfg();
        c.server = "x".repeat(5000);
        assert!(render(&c).is_err());
    }

    #[test]
    fn finds_the_block_on_a_sector() {
        let mut iso = vec![0u8; 64 * 2048];
        iso[10 * 2048..10 * 2048 + BLOCK].copy_from_slice(&placeholder());
        // The marker text elsewhere (not sector aligned) is ignored.
        iso[3 * 2048 + 7..3 * 2048 + 7 + MARKER.len()].copy_from_slice(MARKER);
        assert_eq!(find_block(&iso), Some(10 * 2048));
        assert_eq!(find_block(&iso[..9 * 2048]), None);
        // A configured block is not a placeholder any more.
        let mut c = iso.clone();
        c[10 * 2048..10 * 2048 + BLOCK].copy_from_slice(&render(&cfg()).unwrap());
        assert_eq!(find_block(&c), None);
    }
}
