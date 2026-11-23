//! Minimal QMP (QEMU Machine Protocol) and guest-agent clients over Unix
//! sockets: JSON objects, one per line.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

pub struct Qmp {
    r: BufReader<UnixStream>,
    w: UnixStream,
}

impl Qmp {
    pub fn connect(path: &Path) -> std::io::Result<Qmp> {
        let s = UnixStream::connect(path)?;
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut q = Qmp {
            r: BufReader::new(s.try_clone()?),
            w: s,
        };
        // Greeting, then capabilities negotiation.
        let mut line = String::new();
        q.r.read_line(&mut line)?;
        q.execute("qmp_capabilities", json!({}))
            .map_err(std::io::Error::other)?;
        Ok(q)
    }

    /// Run a command; skips asynchronous events until the reply.
    pub fn execute(&mut self, cmd: &str, args: Value) -> Result<Value, String> {
        let msg = json!({ "execute": cmd, "arguments": args });
        writeln!(self.w, "{msg}").map_err(|e| e.to_string())?;
        loop {
            let mut line = String::new();
            if self.r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                return Err("QMP connection closed".into());
            }
            let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            if let Some(r) = v.get("return") {
                return Ok(r.clone());
            }
            if let Some(e) = v.get("error") {
                return Err(e["desc"].as_str().unwrap_or("QMP error").to_string());
            }
        }
    }
}

/// True if a QEMU guest agent in the VM answers `guest-sync`.
pub fn guest_ping(path: &Path) -> bool {
    let Ok(s) = UnixStream::connect(path) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let id = 0x4652_4e52u64 ^ std::process::id() as u64;
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return false,
    };
    if writeln!(
        w,
        "{}",
        json!({ "execute": "guest-sync", "arguments": { "id": id } })
    )
    .is_err()
    {
        return false;
    }
    let mut r = BufReader::new(s);
    let mut line = String::new();
    while r.read_line(&mut line).unwrap_or(0) > 0 {
        if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
            if v.get("return").and_then(Value::as_u64) == Some(id) {
                return true;
            }
        }
        line.clear();
    }
    false
}
