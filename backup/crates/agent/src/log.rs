//! JSON-lines log to stderr (journald / launchd capture it) and to
//! `agent.log` in the state directory (kept under 10 MiB, one rotation).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn init(dir: &std::path::Path) {
    *FILE.lock().unwrap() = Some(dir.join("agent.log"));
}

fn write(level: &str, msg: &str) {
    let line = serde_json::json!({ "ts": core_format::timefmt::rfc3339_utc(core_format::timefmt::now_unix()), "level": level, "msg": msg }).to_string();
    eprintln!("{line}");
    if let Some(p) = FILE.lock().unwrap().as_ref() {
        if std::fs::metadata(p)
            .map(|m| m.len() > 10 << 20)
            .unwrap_or(false)
        {
            let _ = std::fs::rename(p, p.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub fn info(msg: &str) {
    write("info", msg)
}
pub fn warn(msg: &str) {
    write("warn", msg)
}
pub fn error(msg: &str) {
    write("error", msg)
}
