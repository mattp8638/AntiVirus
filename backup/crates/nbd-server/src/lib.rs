//! Read-only NBD server.
//!
//! Implements the server side of the NBD protocol as published by the NBD
//! project (`doc/proto.md`): fixed newstyle negotiation with
//! `NBD_OPT_EXPORT_NAME`, `NBD_OPT_GO`, `NBD_OPT_INFO`, `NBD_OPT_LIST` and
//! `NBD_OPT_ABORT`, and simple replies in the transmission phase. Every
//! export is read-only: writes, trims and write-zeroes fail with `EPERM`.
//!
//! [`ImageExport`] serves one disk of a backup image straight from the
//! chunk store, decrypting chunks on demand through an LRU cache.

#![forbid(unsafe_code)]

mod image;

pub use image::ImageExport;

use std::collections::BTreeMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Something that can be exported: fixed size, positional reads.
pub trait Export: Send + Sync {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454F_5054;
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

const FLAG_FIXED_NEWSTYLE: u16 = 1;
const FLAG_NO_ZEROES: u16 = 2;
const CFLAG_NO_ZEROES: u32 = 2;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_LIST: u32 = 3;
const OPT_INFO: u32 = 6;
const OPT_GO: u32 = 7;

const REP_ACK: u32 = 1;
const REP_SERVER: u32 = 2;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const REP_ERR_INVALID: u32 = 0x8000_0003;
const REP_ERR_UNKNOWN: u32 = 0x8000_0006;

const INFO_EXPORT: u16 = 0;
const INFO_BLOCK_SIZE: u16 = 3;

// Transmission flags.
const TF_HAS_FLAGS: u16 = 1;
const TF_READ_ONLY: u16 = 2;
const TF_CAN_MULTI_CONN: u16 = 1 << 8;

const CMD_READ: u16 = 0;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;

const EPERM: u32 = 1;
const EIO: u32 = 5;
const EINVAL: u32 = 22;

/// Largest read served in one request (as advertised).
pub const MAX_REQUEST: u32 = 32 * 1024 * 1024;

#[derive(Default, Debug)]
pub struct Stats {
    pub connections: AtomicU64,
    pub bytes_read: AtomicU64,
}

/// A running server. Stops (and closes its listener) when dropped.
pub struct NbdServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    pub stats: Arc<Stats>,
}

impl NbdServer {
    /// Serve `exports` on 127.0.0.1 at a random port.
    pub fn start(exports: BTreeMap<String, Arc<dyn Export>>) -> io::Result<NbdServer> {
        Self::start_on("127.0.0.1:0", exports)
    }

    pub fn start_on(
        bind: &str,
        exports: BTreeMap<String, Arc<dyn Export>>,
    ) -> io::Result<NbdServer> {
        let listener = TcpListener::bind(bind)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        let exports = Arc::new(exports);
        let (stop2, stats2) = (stop.clone(), stats.clone());
        let accept = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(conn) = conn else { continue };
                let _ = conn.set_nodelay(true);
                let (ex, st, sp) = (exports.clone(), stats2.clone(), stop2.clone());
                st.connections.fetch_add(1, Ordering::Relaxed);
                std::thread::spawn(move || {
                    let _ = serve(conn, &ex, &st, &sp);
                });
            }
        });
        Ok(NbdServer {
            addr,
            stop,
            accept: Some(accept),
            stats,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `nbd://127.0.0.1:<port>/<export>` as QEMU accepts it.
    pub fn url(&self, export: &str) -> String {
        format!("nbd://{}/{}", self.addr, export)
    }
}

impl Drop for NbdServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}
fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}
fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

fn opt_reply(w: &mut impl Write, opt: u32, kind: u32, data: &[u8]) -> io::Result<()> {
    w.write_all(&REPLY_MAGIC.to_be_bytes())?;
    w.write_all(&opt.to_be_bytes())?;
    w.write_all(&kind.to_be_bytes())?;
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

fn tflags() -> u16 {
    TF_HAS_FLAGS | TF_READ_ONLY | TF_CAN_MULTI_CONN
}

fn serve(
    conn: TcpStream,
    exports: &BTreeMap<String, Arc<dyn Export>>,
    stats: &Stats,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut r = BufReader::new(conn.try_clone()?);
    let mut w = BufWriter::new(conn);
    w.write_all(&NBDMAGIC.to_be_bytes())?;
    w.write_all(&IHAVEOPT.to_be_bytes())?;
    w.write_all(&(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes())?;
    w.flush()?;
    let cflags = read_u32(&mut r)?;
    let no_zeroes = cflags & CFLAG_NO_ZEROES != 0;

    // Option haggling.
    let export: Arc<dyn Export> = loop {
        if read_u64(&mut r)? != IHAVEOPT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad option magic",
            ));
        }
        let opt = read_u32(&mut r)?;
        let len = read_u32(&mut r)?;
        if len > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "option too long",
            ));
        }
        let mut data = vec![0u8; len as usize];
        r.read_exact(&mut data)?;
        match opt {
            OPT_EXPORT_NAME => {
                let name = String::from_utf8_lossy(&data).to_string();
                // No error reply exists for this option: close on unknown.
                let Some(e) = lookup(exports, &name) else {
                    return Ok(());
                };
                w.write_all(&e.size().to_be_bytes())?;
                w.write_all(&tflags().to_be_bytes())?;
                if !no_zeroes {
                    w.write_all(&[0u8; 124])?;
                }
                w.flush()?;
                break e;
            }
            OPT_ABORT => {
                opt_reply(&mut w, opt, REP_ACK, &[])?;
                return Ok(());
            }
            OPT_LIST => {
                if !data.is_empty() {
                    opt_reply(&mut w, opt, REP_ERR_INVALID, &[])?;
                    continue;
                }
                for name in exports.keys() {
                    let mut d = (name.len() as u32).to_be_bytes().to_vec();
                    d.extend_from_slice(name.as_bytes());
                    opt_reply(&mut w, opt, REP_SERVER, &d)?;
                }
                opt_reply(&mut w, opt, REP_ACK, &[])?;
            }
            OPT_INFO | OPT_GO => {
                if data.len() < 6 {
                    opt_reply(&mut w, opt, REP_ERR_INVALID, &[])?;
                    continue;
                }
                let nlen = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
                if data.len() < 4 + nlen + 2 {
                    opt_reply(&mut w, opt, REP_ERR_INVALID, &[])?;
                    continue;
                }
                let name = String::from_utf8_lossy(&data[4..4 + nlen]).to_string();
                let Some(e) = lookup(exports, &name) else {
                    opt_reply(&mut w, opt, REP_ERR_UNKNOWN, b"no such export")?;
                    continue;
                };
                let mut info = INFO_EXPORT.to_be_bytes().to_vec();
                info.extend_from_slice(&e.size().to_be_bytes());
                info.extend_from_slice(&tflags().to_be_bytes());
                opt_reply(&mut w, opt, REP_INFO, &info)?;
                let mut bs = INFO_BLOCK_SIZE.to_be_bytes().to_vec();
                bs.extend_from_slice(&1u32.to_be_bytes());
                bs.extend_from_slice(&4096u32.to_be_bytes());
                bs.extend_from_slice(&MAX_REQUEST.to_be_bytes());
                opt_reply(&mut w, opt, REP_INFO, &bs)?;
                opt_reply(&mut w, opt, REP_ACK, &[])?;
                if opt == OPT_GO {
                    break e;
                }
            }
            _ => opt_reply(&mut w, opt, REP_ERR_UNSUP, &[])?,
        }
    };

    // Transmission.
    let size = export.size();
    let mut buf = Vec::new();
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let magic = match read_u32(&mut r) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if magic != REQUEST_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad request magic",
            ));
        }
        let _flags = read_u16(&mut r)?;
        let cmd = read_u16(&mut r)?;
        let handle = read_u64(&mut r)?;
        let offset = read_u64(&mut r)?;
        let length = read_u32(&mut r)?;
        let reply = |w: &mut BufWriter<TcpStream>, err: u32| -> io::Result<()> {
            w.write_all(&SIMPLE_REPLY_MAGIC.to_be_bytes())?;
            w.write_all(&err.to_be_bytes())?;
            w.write_all(&handle.to_be_bytes())
        };
        match cmd {
            CMD_READ => {
                if length > MAX_REQUEST
                    || offset.checked_add(length as u64).is_none_or(|e| e > size)
                {
                    reply(&mut w, EINVAL)?;
                } else {
                    buf.resize(length as usize, 0);
                    match export.read_at(offset, &mut buf) {
                        Ok(()) => {
                            reply(&mut w, 0)?;
                            w.write_all(&buf)?;
                            stats.bytes_read.fetch_add(length as u64, Ordering::Relaxed);
                        }
                        Err(_) => reply(&mut w, EIO)?,
                    }
                }
            }
            CMD_DISC => {
                w.flush()?;
                return Ok(());
            }
            CMD_FLUSH => reply(&mut w, 0)?,
            1 => {
                // A write still carries its payload; consume it before refusing.
                io::copy(&mut (&mut r).take(length as u64), &mut io::sink())?;
                reply(&mut w, EPERM)?;
            }
            _ => reply(&mut w, EPERM)?,
        }
        w.flush()?;
    }
}

fn lookup(exports: &BTreeMap<String, Arc<dyn Export>>, name: &str) -> Option<Arc<dyn Export>> {
    // The empty name selects the first export, as QEMU's nbd://host:port does.
    if name.is_empty() {
        exports.values().next().cloned()
    } else {
        exports.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);
    impl Export for Mem {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
            b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
            Ok(())
        }
    }

    /// Minimal client: fixed newstyle + GO, then requests.
    fn client(addr: SocketAddr, name: &str) -> io::Result<(TcpStream, u64, u16)> {
        let mut s = TcpStream::connect(addr)?;
        assert_eq!(read_u64(&mut s)?, NBDMAGIC);
        assert_eq!(read_u64(&mut s)?, IHAVEOPT);
        let _ = read_u16(&mut s)?;
        s.write_all(&(1u32 | CFLAG_NO_ZEROES).to_be_bytes())?;
        let mut d = (name.len() as u32).to_be_bytes().to_vec();
        d.extend_from_slice(name.as_bytes());
        d.extend_from_slice(&0u16.to_be_bytes());
        s.write_all(&IHAVEOPT.to_be_bytes())?;
        s.write_all(&OPT_GO.to_be_bytes())?;
        s.write_all(&(d.len() as u32).to_be_bytes())?;
        s.write_all(&d)?;
        let mut size = 0;
        let mut flags = 0;
        loop {
            assert_eq!(read_u64(&mut s)?, REPLY_MAGIC);
            let _opt = read_u32(&mut s)?;
            let kind = read_u32(&mut s)?;
            let len = read_u32(&mut s)?;
            let mut data = vec![0u8; len as usize];
            s.read_exact(&mut data)?;
            match kind {
                REP_INFO if u16::from_be_bytes([data[0], data[1]]) == INFO_EXPORT => {
                    size = u64::from_be_bytes(data[2..10].try_into().unwrap());
                    flags = u16::from_be_bytes([data[10], data[11]]);
                }
                REP_INFO => {}
                REP_ACK => return Ok((s, size, flags)),
                k => return Err(io::Error::other(format!("option error {k:#x}"))),
            }
        }
    }

    fn request(
        s: &mut TcpStream,
        cmd: u16,
        off: u64,
        len: u32,
        payload: &[u8],
    ) -> io::Result<(u32, Vec<u8>)> {
        s.write_all(&REQUEST_MAGIC.to_be_bytes())?;
        s.write_all(&0u16.to_be_bytes())?;
        s.write_all(&cmd.to_be_bytes())?;
        s.write_all(&7u64.to_be_bytes())?;
        s.write_all(&off.to_be_bytes())?;
        s.write_all(&len.to_be_bytes())?;
        s.write_all(payload)?;
        assert_eq!(read_u32(s)?, SIMPLE_REPLY_MAGIC);
        let err = read_u32(s)?;
        assert_eq!(read_u64(s)?, 7);
        let mut data = vec![];
        if err == 0 && cmd == CMD_READ {
            data.resize(len as usize, 0);
            s.read_exact(&mut data)?;
        }
        Ok((err, data))
    }

    #[test]
    fn negotiate_read_and_refuse_writes() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut ex: BTreeMap<String, Arc<dyn Export>> = BTreeMap::new();
        ex.insert("disk0".into(), Arc::new(Mem(data.clone())));
        let srv = NbdServer::start(ex).unwrap();
        let (mut s, size, flags) = client(srv.addr(), "disk0").unwrap();
        assert_eq!(size, 100_000);
        assert!(flags & TF_READ_ONLY != 0);
        let (err, got) = request(&mut s, CMD_READ, 1000, 5000, &[]).unwrap();
        assert_eq!(err, 0);
        assert_eq!(got, &data[1000..6000]);
        // Out of range.
        assert_eq!(
            request(&mut s, CMD_READ, 99_000, 5000, &[]).unwrap().0,
            EINVAL
        );
        // Write refused, connection stays usable.
        assert_eq!(request(&mut s, 1, 0, 4, &[1, 2, 3, 4]).unwrap().0, EPERM);
        assert_eq!(
            request(&mut s, CMD_READ, 0, 10, &[]).unwrap().1,
            &data[..10]
        );
        assert!(client(srv.addr(), "nope").is_err());
        assert!(srv.stats.bytes_read.load(Ordering::Relaxed) >= 5010);
    }
}
