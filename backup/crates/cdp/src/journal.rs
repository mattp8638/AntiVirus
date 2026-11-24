//! Reading and replaying a device-mapper `log-writes` journal
//! (docs/design/cdp.md; the kernel's Documentation/admin-guide/device-mapper/log-writes.rst).
//!
//! Layout (little-endian): one sector (the data device's logical sector size)
//! holding the super block {magic u64, version u64, nr_entries u64,
//! sectorsize u32}; then entries, each one sector holding {sector u64,
//! nr_sectors u64, flags u64, data_len u64} (a mark's name follows those 32
//! bytes in the same sector), followed for a write by its data,
//! `nr_sectors * sectorsize` bytes.

use std::io::{self, Read, Seek, SeekFrom, Write};

pub const MAGIC: u64 = 0x006a_7366_7773_6872;
pub const VERSION: u64 = 1;
pub const FLUSH: u64 = 1;
pub const FUA: u64 = 2;
pub const DISCARD: u64 = 4;
pub const MARK: u64 = 8;
pub const METADATA: u64 = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Super {
    pub nr_entries: u64,
    pub sectorsize: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    /// Bytes written at a byte offset of the data device.
    Write {
        offset: u64,
        len: u64,
        data_at: u64,
    },
    Discard {
        offset: u64,
        len: u64,
    },
    Mark(String),
    Flush,
}

fn le(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"))
}

pub fn read_super(r: &mut (impl Read + Seek)) -> io::Result<Super> {
    let mut b = [0u8; 28];
    r.seek(SeekFrom::Start(0))?;
    r.read_exact(&mut b)?;
    if le(&b, 0) != MAGIC || le(&b, 8) != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a log-writes journal (magic or version)",
        ));
    }
    let ss = u32::from_le_bytes(b[24..28].try_into().expect("4 bytes"));
    if !(512..=65536).contains(&ss) || !ss.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("journal sector size {ss}"),
        ));
    }
    Ok(Super {
        nr_entries: le(&b, 16),
        sectorsize: ss,
    })
}

/// Every entry the super block counts, with where its data is in the journal.
pub fn entries(r: &mut (impl Read + Seek)) -> io::Result<(Super, Vec<Entry>)> {
    let sup = read_super(r)?;
    let ss = sup.sectorsize as u64;
    let mut out = Vec::with_capacity(sup.nr_entries as usize);
    let mut pos = ss;
    let mut h = vec![0u8; ss as usize];
    for _ in 0..sup.nr_entries {
        r.seek(SeekFrom::Start(pos))?;
        r.read_exact(&mut h)?;
        let (sector, nr, flags, dlen) = (le(&h, 0), le(&h, 8), le(&h, 16), le(&h, 24));
        pos += ss;
        if flags & MARK != 0 {
            let n = (dlen as usize).min(h.len() - 32);
            out.push(Entry::Mark(
                String::from_utf8_lossy(&h[32..32 + n]).into_owned(),
            ));
        } else if flags & DISCARD != 0 {
            out.push(Entry::Discard {
                offset: sector * ss,
                len: nr * ss,
            });
        } else if nr > 0 {
            out.push(Entry::Write {
                offset: sector * ss,
                len: nr * ss,
                data_at: pos,
            });
            pos += nr * ss;
        } else {
            out.push(Entry::Flush);
        }
    }
    Ok((sup, out))
}

/// What a replay did.
#[derive(Debug, Default, PartialEq)]
pub struct Replayed {
    pub writes: u64,
    pub bytes: u64,
    pub discards: u64,
    /// The last mark applied, and whether replay stopped at the wanted mark.
    pub last_mark: Option<String>,
    pub stopped: bool,
}

/// Apply a journal's writes to `target` in order; stop right after the
/// mark for which `stop_at` is true (if any). Discarded ranges are zeroed.
pub fn replay(
    journal: &mut (impl Read + Seek),
    target: &mut (impl Write + Seek),
    stop_at: &dyn Fn(&str) -> bool,
) -> io::Result<Replayed> {
    let (_, list) = entries(journal)?;
    let end = list
        .iter()
        .position(|e| matches!(e, Entry::Mark(m) if stop_at(m)));
    let mut r = apply(journal, target, &list[..end.map_or(list.len(), |i| i + 1)])?;
    r.stopped = end.is_some();
    Ok(r)
}

/// Replay up to the last timestamp mark at or before `at` (writes after it
/// are of unknown time and left out). Returns what was applied and whether
/// the journal goes on past `at` (no later journal is then needed).
pub fn replay_until(
    journal: &mut (impl Read + Seek),
    target: &mut (impl Write + Seek),
    at: i64,
) -> io::Result<(Replayed, bool)> {
    let (_, list) = entries(journal)?;
    let times: Vec<(usize, i64)> = list
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            Entry::Mark(m) => mark_time(m).map(|t| (i, t)),
            _ => None,
        })
        .collect();
    let past = times.iter().any(|&(_, t)| t > at);
    match times.iter().rev().find(|&&(_, t)| t <= at) {
        Some(&(last, _)) => Ok((apply(journal, target, &list[..=last])?, past)),
        None => Ok((Replayed::default(), true)),
    }
}

/// Apply entries in order.
fn apply(
    journal: &mut (impl Read + Seek),
    target: &mut (impl Write + Seek),
    list: &[Entry],
) -> io::Result<Replayed> {
    let mut rep = Replayed::default();
    let mut buf = vec![0u8; 1 << 20];
    for e in list {
        match e {
            Entry::Write {
                offset,
                len,
                data_at,
            } => {
                journal.seek(SeekFrom::Start(*data_at))?;
                target.seek(SeekFrom::Start(*offset))?;
                let mut left = *len;
                while left > 0 {
                    let n = left.min(buf.len() as u64) as usize;
                    journal.read_exact(&mut buf[..n])?;
                    target.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                rep.writes += 1;
                rep.bytes += len;
            }
            Entry::Discard { offset, len } => {
                target.seek(SeekFrom::Start(*offset))?;
                io::copy(&mut io::repeat(0).take(*len), target)?;
                rep.discards += 1;
            }
            Entry::Mark(m) => rep.last_mark = Some(m.clone()),
            Entry::Flush => {}
        }
    }
    target.flush()?;
    Ok(rep)
}

/// Marks this tool writes: `fenrir-t<unix seconds>`.
pub fn time_mark(t: i64) -> String {
    format!("fenrir-t{t}")
}

pub fn mark_time(m: &str) -> Option<i64> {
    m.strip_prefix("fenrir-t")?.parse().ok()
}

/// A journal in the kernel's format (tests, and documentation of the format).
pub struct Writer {
    pub buf: Vec<u8>,
    ss: usize,
    n: u64,
}

impl Writer {
    pub fn new(sectorsize: usize) -> Writer {
        Writer {
            buf: vec![0u8; sectorsize],
            ss: sectorsize,
            n: 0,
        }
    }
    fn header(&mut self, sector: u64, nr: u64, flags: u64, data: &[u8]) {
        let mut h = vec![0u8; self.ss];
        h[0..8].copy_from_slice(&sector.to_le_bytes());
        h[8..16].copy_from_slice(&nr.to_le_bytes());
        h[16..24].copy_from_slice(&flags.to_le_bytes());
        h[24..32].copy_from_slice(&(data.len() as u64).to_le_bytes());
        h[32..32 + data.len()].copy_from_slice(data);
        self.buf.extend(h);
        self.n += 1;
    }
    pub fn write(&mut self, sector: u64, data: &[u8]) {
        assert_eq!(data.len() % self.ss, 0);
        self.header(sector, (data.len() / self.ss) as u64, 0, &[]);
        self.buf.extend_from_slice(data);
    }
    pub fn discard(&mut self, sector: u64, nr: u64) {
        self.header(sector, nr, DISCARD, &[]);
    }
    pub fn mark(&mut self, name: &str) {
        self.header(0, 0, MARK, name.as_bytes());
    }
    pub fn finish(mut self) -> Vec<u8> {
        self.buf[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        self.buf[8..16].copy_from_slice(&VERSION.to_le_bytes());
        self.buf[16..24].copy_from_slice(&self.n.to_le_bytes());
        self.buf[24..28].copy_from_slice(&(self.ss as u32).to_le_bytes());
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn replay_to_a_point_in_time() {
        let ss = 512;
        let mut w = Writer::new(ss);
        w.write(0, &[1u8; 1024]);
        w.mark(&time_mark(100));
        w.write(1, &[2u8; 512]);
        w.discard(0, 1);
        w.mark(&time_mark(110));
        w.write(3, &[3u8; 512]);
        let j = w.finish();
        let (sup, list) = entries(&mut Cursor::new(&j)).unwrap();
        assert_eq!(
            sup,
            Super {
                nr_entries: 6,
                sectorsize: 512
            }
        );
        assert_eq!(list[1], Entry::Mark("fenrir-t100".into()));
        assert_eq!(mark_time("fenrir-t110"), Some(110));

        // Up to t=100: only the first write.
        let mut disk = Cursor::new(vec![9u8; 4 * ss]);
        let r = replay(&mut Cursor::new(&j), &mut disk, &|m| {
            mark_time(m) == Some(100)
        })
        .unwrap();
        assert!(r.stopped && r.writes == 1);
        let d = disk.into_inner();
        assert_eq!(&d[..1024], &[1u8; 1024][..]);
        assert_eq!(&d[1024..], &[9u8; 1024][..]);

        // Up to t=110: the second write, and sector 0 discarded (zeros).
        let mut disk = Cursor::new(vec![9u8; 4 * ss]);
        replay(&mut Cursor::new(&j), &mut disk, &|m| {
            mark_time(m) == Some(110)
        })
        .unwrap();
        let d = disk.into_inner();
        assert_eq!(&d[..512], &[0u8; 512][..]);
        assert_eq!(&d[512..1024], &[2u8; 512][..]);
        assert_eq!(&d[1536..], &[9u8; 512][..]);

        // To a time: up to the last mark at or before it.
        let mut disk = Cursor::new(vec![9u8; 4 * ss]);
        let (r, past) = replay_until(&mut Cursor::new(&j), &mut disk, 105).unwrap();
        assert!(past && r.writes == 1 && r.last_mark.as_deref() == Some("fenrir-t100"));
        let mut disk = Cursor::new(vec![9u8; 4 * ss]);
        let (r, past) = replay_until(&mut Cursor::new(&j), &mut disk, 999).unwrap();
        assert!(
            !past && r.writes == 2,
            "the write after the last mark has no known time"
        );

        // Everything.
        let mut disk = Cursor::new(vec![9u8; 4 * ss]);
        let r = replay(&mut Cursor::new(&j), &mut disk, &|_| false).unwrap();
        assert!(!r.stopped && r.writes == 3 && r.discards == 1);
        assert_eq!(&disk.into_inner()[1536..], &[3u8; 512][..]);
    }

    #[test]
    fn garbage_is_refused() {
        assert!(read_super(&mut Cursor::new(vec![0u8; 4096])).is_err());
        let mut j = Writer::new(4096);
        j.mark("x");
        let mut b = j.finish();
        b[24..28].copy_from_slice(&1000u32.to_le_bytes());
        assert!(read_super(&mut Cursor::new(b)).is_err(), "odd sector size");
    }
}
