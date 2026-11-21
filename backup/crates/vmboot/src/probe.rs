//! Health signals that do not depend on QEMU: application-level port
//! probes and screenshot analysis. Pure functions where possible, so they
//! are unit-tested without a VM.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// A guest service we try to reach through a NAT port forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Ssh,
    Rdp,
    Http,
}

impl Service {
    pub fn guest_port(&self) -> u16 {
        match self {
            Service::Ssh => 22,
            Service::Rdp => 3389,
            Service::Http => 5985,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Service::Ssh => "SSH",
            Service::Rdp => "RDP",
            Service::Http => "WinRM/HTTP",
        }
    }
}

pub const SERVICES: [Service; 3] = [Service::Ssh, Service::Rdp, Service::Http];

/// X.224 Connection Request with an RDP negotiation request (TLS | CredSSP).
const RDP_CR: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
    0x00, 0x00, 0x00,
];

/// Does the reply prove a real service answered? A held-open connection
/// with no reply does not: QEMU's user-mode NAT accepts connections before
/// the guest's network is up.
pub fn reply_proves_service(s: Service, reply: &[u8]) -> bool {
    match s {
        Service::Ssh => reply.starts_with(b"SSH-"),
        // TPKT version 3 + X.224 Connection Confirm (0xD0).
        Service::Rdp => {
            reply.len() >= 6 && reply[0] == 0x03 && reply[1] == 0x00 && reply[5] & 0xF0 == 0xD0
        }
        Service::Http => reply.starts_with(b"HTTP/"),
    }
}

/// Probe one forwarded port; true only on an application-level answer.
pub fn probe(addr: SocketAddr, s: Service) -> bool {
    let Ok(mut c) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = c.set_read_timeout(Some(Duration::from_secs(4)));
    let request: &[u8] = match s {
        Service::Ssh => &[],
        Service::Rdp => &RDP_CR,
        Service::Http => b"GET /wsman HTTP/1.0\r\nHost: localhost\r\n\r\n",
    };
    if !request.is_empty() && c.write_all(request).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    while got.len() < 8 {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    reply_proves_service(s, &got)
}

/// A screenshot reduced to what the health check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenSummary {
    pub width: u32,
    pub height: u32,
    /// Coarse 32×24 grid of quantised luminance: equal grids = same screen,
    /// tolerant of a blinking cursor in one cell.
    pub grid: Vec<u8>,
    /// Share of grid cells that are not near-black, in percent.
    pub lit_percent: u32,
}

impl ScreenSummary {
    pub fn is_blank(&self) -> bool {
        self.lit_percent == 0
    }
    /// Same screen allowing up to 2 changed cells (cursor, clock).
    pub fn same_as(&self, other: &ScreenSummary) -> bool {
        self.grid.len() == other.grid.len()
            && self
                .grid
                .iter()
                .zip(&other.grid)
                .filter(|(a, b)| a != b)
                .count()
                <= 2
    }
}

/// Parse a binary PPM (P6, maxval 255) and summarise it.
pub fn summarise_ppm(data: &[u8]) -> Option<ScreenSummary> {
    // Header: "P6" ws width ws height ws maxval single-ws pixels.
    let mut fields = Vec::new();
    let mut i = 0;
    while fields.len() < 4 && i < data.len() {
        while i < data.len() && data[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < data.len() && data[i] == b'#' {
            while i < data.len() && data[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        while i < data.len() && !data[i].is_ascii_whitespace() {
            i += 1;
        }
        fields.push(std::str::from_utf8(&data[start..i]).ok()?.to_string());
    }
    if fields.len() < 4 || fields[0] != "P6" || fields[3] != "255" {
        return None;
    }
    let (w, h): (usize, usize) = (fields[1].parse().ok()?, fields[2].parse().ok()?);
    let px = data.get(i + 1..i + 1 + w * h * 3)?;
    if w == 0 || h == 0 {
        return None;
    }
    let (gw, gh) = (32usize, 24usize);
    let mut grid = Vec::with_capacity(gw * gh);
    let mut lit = 0;
    for gy in 0..gh {
        for gx in 0..gw {
            // Average luminance over the cell, sampled on a 4×4 lattice.
            let mut sum = 0u32;
            let mut n = 0u32;
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = (gx * w + (sx * w) / (4 * gw).max(1)) / gw;
                    let y = (gy * h + (sy * h) / (4 * gh).max(1)) / gh;
                    let o = (y.min(h - 1) * w + x.min(w - 1)) * 3;
                    let (r, g, b) = (px[o] as u32, px[o + 1] as u32, px[o + 2] as u32);
                    sum += (r * 299 + g * 587 + b * 114) / 1000;
                    n += 1;
                }
            }
            let avg = sum / n;
            if avg > 24 {
                lit += 1;
            }
            grid.push((avg / 32) as u8);
        }
    }
    Some(ScreenSummary {
        width: w as u32,
        height: h as u32,
        grid,
        lit_percent: (lit * 100 / (gw * gh)) as u32,
    })
}

/// Firmware messages that mean the guest never reached its boot loader.
pub const FIRMWARE_FAILURES: &[&str] = &[
    "No bootable device",
    "Boot failed: not a bootable disk",
    "BdsDxe: No bootable option or device was found",
    "UEFI Interactive Shell",
    "Booting from Hard Disk...\r\nBoot failed",
];

pub fn firmware_failure(log: &str) -> Option<&'static str> {
    FIRMWARE_FAILURES.iter().copied().find(|p| log.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ppm(w: usize, h: usize, f: impl Fn(usize, usize) -> [u8; 3]) -> Vec<u8> {
        let mut v = format!("P6\n# comment\n{w} {h}\n255\n").into_bytes();
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&f(x, y));
            }
        }
        v
    }

    #[test]
    fn screens() {
        let black = summarise_ppm(&ppm(640, 480, |_, _| [0, 0, 0])).unwrap();
        assert!(black.is_blank());
        let text = summarise_ppm(&ppm(640, 480, |x, y| {
            if (x / 8 + y / 16) % 7 == 0 {
                [200, 200, 200]
            } else {
                [0, 0, 0]
            }
        }))
        .unwrap();
        assert!(!text.is_blank());
        assert!(!text.same_as(&black));
        // One cursor cell changes: still the same screen.
        let cursor = summarise_ppm(&ppm(640, 480, |x, y| {
            if x > 600 && y > 460 {
                [255, 255, 255]
            } else if (x / 8 + y / 16) % 7 == 0 {
                [200, 200, 200]
            } else {
                [0, 0, 0]
            }
        }))
        .unwrap();
        assert!(text.same_as(&cursor));
        assert!(summarise_ppm(b"P5\n1 1\n255\n\0").is_none());
        assert!(
            summarise_ppm(b"P6\n10 10\n255\n\0\0").is_none(),
            "truncated"
        );
    }

    #[test]
    fn replies() {
        assert!(reply_proves_service(Service::Ssh, b"SSH-2.0-OpenSSH_9.6"));
        assert!(!reply_proves_service(Service::Ssh, b""));
        assert!(reply_proves_service(
            Service::Rdp,
            &[0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0]
        ));
        assert!(!reply_proves_service(Service::Rdp, &[0x03, 0x00]));
        assert!(reply_proves_service(
            Service::Http,
            b"HTTP/1.1 405 Method Not Allowed"
        ));
        assert_eq!(
            firmware_failure("...\nNo bootable device.\n"),
            Some("No bootable device")
        );
        assert_eq!(firmware_failure("Linux version 6.1"), None);
    }
}
