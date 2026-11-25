//! Minimal PNG encoder (RGB, 8-bit, uncompressed deflate blocks) for
//! screenshots that do not arrive as PNG, e.g. Hyper-V thumbnails.

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// Encode `rgb` (width × height × 3 bytes) as PNG.
pub fn encode_rgb(width: u32, height: u32, rgb: &[u8]) -> Option<Vec<u8>> {
    let row = width as usize * 3;
    if width == 0 || height == 0 || rgb.len() != row * height as usize {
        return None;
    }
    let mut raw = Vec::with_capacity((row + 1) * height as usize);
    for r in rgb.chunks(row) {
        raw.push(0); // filter: none
        raw.extend_from_slice(r);
    }
    let mut z = vec![0x78, 0x01];
    let mut blocks = raw.chunks(65535).peekable();
    while let Some(b) = blocks.next() {
        z.push(if blocks.peek().is_none() { 1 } else { 0 });
        z.extend_from_slice(&(b.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(b.len() as u16)).to_le_bytes());
        z.extend_from_slice(b);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    Some(out)
}

/// RGB565 little-endian pixels (Hyper-V thumbnails) to RGB888.
pub fn rgb565_to_rgb(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 * 3);
    for p in data.chunks_exact(2) {
        let v = u16::from_le_bytes([p[0], p[1]]);
        let (r, g, b) = ((v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F);
        out.extend_from_slice(&[
            ((r << 3) | (r >> 2)) as u8,
            ((g << 2) | (g >> 4)) as u8,
            ((b << 3) | (b >> 2)) as u8,
        ]);
    }
    out
}

/// PPM (P6) wrapper, for `probe::summarise_ppm`.
pub fn ppm(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let mut v = format!("P6\n{width} {height}\n255\n").into_bytes();
    v.extend_from_slice(rgb);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_encoding() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let rgb: Vec<u8> = (0..300 * 200 * 3).map(|i| (i % 251) as u8).collect();
        let png = encode_rgb(300, 200, &rgb).unwrap();
        assert!(png.starts_with(b"\x89PNG"));
        assert!(png.ends_with(&[0xAE, 0x42, 0x60, 0x82]));
        assert!(encode_rgb(3, 3, &[0; 5]).is_none());
        if let Some(p) = std::env::var_os("FENRIR_PNG_OUT") {
            std::fs::write(p, &png).unwrap();
        }
        assert_eq!(rgb565_to_rgb(&[0xFF, 0xFF]), vec![255, 255, 255]);
        assert_eq!(rgb565_to_rgb(&[0x00, 0xF8]), vec![255, 0, 0]);
    }
}
