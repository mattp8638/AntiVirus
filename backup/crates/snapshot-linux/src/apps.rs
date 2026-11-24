//! Application-aware live images on Linux (docs/design/app-aware-linux.md).
//!
//! Around the snapshots of a live backup:
//!
//! * hooks: executables in a root-owned folder (`/etc/fenrir-backup/hooks.d`)
//!   run with `freeze` before and `thaw` after, for anything else to quiesce;
//! * MySQL / MariaDB: `FLUSH TABLES WITH READ LOCK` held in one session for
//!   the whole snapshot window, then released;
//! * PostgreSQL: a `CHECKPOINT` first; then the cluster counts as
//!   coordinated when its data folder, write-ahead log and tablespaces are
//!   all in one snapshot (PostgreSQL recovers from such a snapshot as from a
//!   power cut, its documented way of taking file system snapshots).
//!
//! What was done is listed in the image like VSS writers on Windows.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use core_format::manifest::ApplicationInfo;

/// Where hooks live unless the options say otherwise.
pub const HOOKS_DIR: &str = "/etc/fenrir-backup/hooks.d";
/// MySQL client options (user, password, socket) when the default
/// (socket authentication as root) does not work.
pub const MYSQL_CNF: &str = "/etc/fenrir-backup/mysql.cnf";
const HOOK_TIMEOUT: Duration = Duration::from_secs(120);
const DB_TIMEOUT: Duration = Duration::from_secs(60);

/// Which snapshot unit (device) holds a path, if it is captured consistently.
pub type UnitOf<'a> = &'a dyn Fn(&Path) -> Option<String>;

/// Quiesced applications; `end` releases them. Dropping without `end`
/// releases them too (an error part way through a backup).
pub struct Quiesce {
    hooks: Vec<PathBuf>,
    mysql: Vec<MySqlLock>,
    pub applications: Vec<ApplicationInfo>,
    pub warnings: Vec<String>,
    ended: bool,
}

impl Quiesce {
    /// True when every application found was coordinated.
    pub fn all_included(&self) -> bool {
        self.applications.iter().all(|a| a.included)
    }

    /// Release everything (after the snapshots exist).
    pub fn end(mut self) -> (Vec<ApplicationInfo>, Vec<String>) {
        self.release();
        (
            std::mem::take(&mut self.applications),
            std::mem::take(&mut self.warnings),
        )
    }

    fn release(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        for m in std::mem::take(&mut self.mysql) {
            if let Err(e) = m.unlock() {
                self.warnings.push(format!("MySQL: {e}"));
            }
        }
        for h in self.hooks.iter().rev() {
            if let Err(e) = run_hook(h, "thaw") {
                self.warnings
                    .push(format!("hook {}: thaw: {e}", h.display()));
            }
        }
    }
}

impl Drop for Quiesce {
    fn drop(&mut self) {
        self.release();
    }
}

/// Quiesce what runs here. Never fails: what cannot be coordinated is
/// listed as not included, and the image is crash-consistent.
pub fn begin(hooks_dir: Option<&Path>, unit_of: UnitOf) -> Quiesce {
    let mut q = Quiesce {
        hooks: vec![],
        mysql: vec![],
        applications: vec![],
        warnings: vec![],
        ended: false,
    };
    if let Some(dir) = hooks_dir {
        hooks(&mut q, dir);
    }
    for pm in postmasters() {
        q.applications.extend(postgres(&pm, unit_of));
    }
    // Every MySQL / MariaDB server whose data is imaged (each through its own socket).
    for server in processes()
        .into_iter()
        .filter(|p| p.comm == "mysqld" || p.comm == "mariadbd")
    {
        if let Some((info, lock)) = mysql(&server, unit_of) {
            q.applications.push(info);
            q.mysql.extend(lock);
        }
    }
    q
}

// ---------------------------------------------------------------- hooks

/// Hooks must be root's and not writable by anyone else (they run as root).
fn trusted(p: &Path) -> Result<(), String> {
    let m = std::fs::metadata(p).map_err(|e| e.to_string())?;
    if m.uid() != 0 {
        return Err("not owned by root".into());
    }
    if m.mode() & 0o022 != 0 {
        return Err("writable by group or others".into());
    }
    Ok(())
}

fn hooks(q: &mut Quiesce, dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    if let Err(e) = trusted(dir) {
        q.warnings.push(format!(
            "hooks in {} not run: the folder is {e}",
            dir.display()
        ));
        return;
    }
    let mut list: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                && std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        })
        .collect();
    list.sort();
    for h in list {
        let name = h
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Err(e) = trusted(&h) {
            q.applications
                .push(app("hook", &name, false, format!("not run: {e}")));
            continue;
        }
        match run_hook(&h, "freeze") {
            Ok(()) => {
                q.hooks.push(h);
                q.applications.push(app(
                    "hook",
                    &name,
                    true,
                    "freeze before the snapshot, thaw after".into(),
                ));
            }
            Err(e) => {
                // It may have half-frozen something: thaw it anyway.
                let _ = run_hook(&h, "thaw");
                q.applications
                    .push(app("hook", &name, false, format!("freeze failed: {e}")));
            }
        }
    }
}

fn run_hook(h: &Path, phase: &str) -> Result<(), String> {
    let mut c = Command::new(h)
        .arg(phase)
        .env("FENRIR_PHASE", phase)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + HOOK_TIMEOUT;
    loop {
        match c.try_wait().map_err(|e| e.to_string())? {
            Some(st) if st.success() => return Ok(()),
            Some(st) => {
                let mut err = String::new();
                if let Some(mut s) = c.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut s, &mut err);
                }
                return Err(format!("{st}: {}", err.trim()));
            }
            None if Instant::now() > deadline => {
                let _ = c.kill();
                let _ = c.wait();
                return Err(format!("no answer in {} s", HOOK_TIMEOUT.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn app(writer: &str, component: &str, included: bool, note: String) -> ApplicationInfo {
    ApplicationInfo {
        writer: writer.into(),
        component: component.into(),
        caption: String::new(),
        included,
        note: Some(note),
        files: vec![],
    }
}

// ---------------------------------------------------------------- processes

struct Proc {
    pid: u32,
    comm: String,
    ppid: u32,
}

fn processes() -> Vec<Proc> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // pid (comm) state ppid ...
            let open = stat.find('(')?;
            let close = stat.rfind(')')?;
            let comm = stat[open + 1..close].to_string();
            let ppid = stat[close + 2..].split_whitespace().nth(1)?.parse().ok()?;
            Some(Proc { pid, comm, ppid })
        })
        .collect()
}

fn user_name(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
        })
}

/// Where an application's files are, as far as the snapshots go.
#[derive(Debug, PartialEq)]
enum Placement {
    /// All in one snapshot (or one frozen copy): consistent.
    One(String),
    /// Some captured, but not together: why.
    Split(String),
    /// None on the imaged disks: not this backup's business.
    Outside,
}

fn placement(paths: &[PathBuf], unit_of: UnitOf) -> Placement {
    let mut units = BTreeSet::new();
    let mut outside = Vec::new();
    for p in paths {
        let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        match unit_of(&real) {
            Some(u) => {
                units.insert(u);
            }
            None => outside.push(real.display().to_string()),
        }
    }
    if units.is_empty() {
        return Placement::Outside;
    }
    if !outside.is_empty() {
        return Placement::Split(format!(
            "{} is not on the imaged disks, or not on a volume that is snapshotted",
            outside.join(", ")
        ));
    }
    match units.len() {
        1 => Placement::One(units.into_iter().next().unwrap_or_default()),
        n => Placement::Split(format!(
            "its files are on {n} volumes ({}), snapshotted one after another; keep them on one logical volume",
            units.into_iter().collect::<Vec<_>>().join(", ")
        )),
    }
}

// ---------------------------------------------------------------- PostgreSQL

struct Postmaster {
    data: PathBuf,
    port: String,
    socket_dir: String,
    owner: Option<String>,
}

fn postmasters() -> Vec<Postmaster> {
    let procs = processes();
    procs
        .iter()
        .filter(|p| p.comm == "postgres" || p.comm == "postmaster")
        .filter(|p| {
            !procs
                .iter()
                .any(|q| q.pid == p.ppid && (q.comm == "postgres" || q.comm == "postmaster"))
        })
        .filter_map(|p| {
            let data = std::fs::read_link(format!("/proc/{}/cwd", p.pid)).ok()?;
            let pidfile = std::fs::read_to_string(data.join("postmaster.pid")).ok()?;
            let lines: Vec<&str> = pidfile.lines().collect();
            let owner = std::fs::metadata(&data)
                .ok()
                .and_then(|m| user_name(m.uid()));
            Some(Postmaster {
                port: lines
                    .get(3)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "5432".into()),
                socket_dir: lines
                    .get(4)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "/var/run/postgresql".into()),
                data,
                owner,
            })
        })
        .collect()
}

fn psql(pm: &Postmaster, sql: &str) -> Result<String, String> {
    let user = pm.owner.clone().unwrap_or_else(|| "postgres".into());
    let out = Command::new("runuser")
        .args(["-u", &user, "--", "psql", "-X", "-q", "-A", "-t"])
        .args([
            "-h",
            &pm.socket_dir,
            "-p",
            &pm.port,
            "-d",
            "postgres",
            "-c",
            sql,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("psql: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn postgres(pm: &Postmaster, unit_of: UnitOf) -> Option<ApplicationInfo> {
    let version = std::fs::read_to_string(pm.data.join("PG_VERSION"))
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let mut paths = vec![pm.data.clone(), pm.data.join("pg_wal")];
    if let Ok(rd) = std::fs::read_dir(pm.data.join("pg_tblspc")) {
        paths.extend(rd.flatten().map(|e| e.path()));
    }
    let place = placement(&paths, unit_of);
    if place == Placement::Outside {
        return None;
    }
    let checkpoint = psql(pm, "CHECKPOINT");
    let mut info = match place {
        Placement::One(unit) => app(
            "PostgreSQL",
            &pm.data.display().to_string(),
            true,
            format!("data, write-ahead log and tablespaces in one snapshot ({unit}); PostgreSQL recovers from it on start like after a power cut"),
        ),
        Placement::Split(why) => app(
            "PostgreSQL",
            &pm.data.display().to_string(),
            false,
            format!("not coordinated: {why}"),
        ),
        Placement::Outside => return None,
    };
    info.caption = format!("PostgreSQL {version} (port {})", pm.port);
    if let Err(e) = checkpoint {
        if let Some(n) = info.note.as_mut() {
            n.push_str(&format!(
                "; the checkpoint before it failed ({e}), so starting takes longer"
            ));
        }
    }
    Some(info)
}

// ---------------------------------------------------------------- MySQL / MariaDB

struct MySqlLock {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl MySqlLock {
    fn wait_for(&self, marker: &str) -> Result<String, String> {
        let deadline = Instant::now() + DB_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) if l.starts_with(marker) => return Ok(l),
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!("no answer in {} s", DB_TIMEOUT.as_secs()))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("the client exited (see the server's error log)".into())
                }
            }
        }
    }

    fn unlock(mut self) -> Result<(), String> {
        let r = writeln!(self.stdin, "UNLOCK TABLES;\nSELECT 'fenrir-unlocked';")
            .map_err(|e| e.to_string())
            .and_then(|_| self.wait_for("fenrir-unlocked").map(|_| ()));
        drop(self.stdin);
        // Closing the session releases the lock in any case.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return r;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        r
    }
}

/// The `--socket=` a server was started with, if any.
fn socket_of(pid: u32) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    cmdline
        .split(|b| *b == 0)
        .filter_map(|a| std::str::from_utf8(a).ok())
        .find_map(|a| a.strip_prefix("--socket=").map(str::to_string))
}

fn mysql_session(socket: Option<&str>) -> Result<MySqlLock, String> {
    let mut last = String::new();
    for client in ["mysql", "mariadb"] {
        let mut cmd = Command::new(client);
        if Path::new(MYSQL_CNF).is_file() {
            cmd.arg(format!("--defaults-extra-file={MYSQL_CNF}"));
        }
        if let Some(sock) = socket {
            cmd.arg(format!("--socket={sock}"));
        }
        cmd.args(["--batch", "--skip-column-names", "--unbuffered"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                last = format!("{client}: {e}");
                continue;
            }
        };
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let (tx, rx) = mpsc::channel();
        for out in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for l in BufReader::new(out).lines().map_while(Result::ok) {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
            });
        }
        return Ok(MySqlLock {
            child,
            stdin,
            lines: rx,
        });
    }
    Err(format!("no MySQL client ({last})"))
}

fn mysql(server: &Proc, unit_of: UnitOf) -> Option<(ApplicationInfo, Option<MySqlLock>)> {
    // The server runs in its data folder: skip it when that is not imaged.
    let cwd = std::fs::read_link(format!("/proc/{}/cwd", server.pid)).ok()?;
    if placement(&[cwd], unit_of) == Placement::Outside {
        return None;
    }
    let socket = socket_of(server.pid);
    let server = server.comm.as_str();
    let writer = if server == "mariadbd" {
        "MariaDB"
    } else {
        "MySQL"
    };
    let fail = |why: String| {
        Some((
            app(writer, "", false, format!("not coordinated: {why}")),
            None,
        ))
    };
    let mut s = match mysql_session(socket.as_deref()) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    // One line: datadir, InnoDB log and data folders (may be relative or empty).
    let ask = "FLUSH TABLES WITH READ LOCK;\n\
               SELECT CONCAT_WS('|', 'fenrir-locked', @@datadir, \
               IFNULL(@@innodb_log_group_home_dir, ''), IFNULL(@@innodb_data_home_dir, ''));\n";
    if let Err(e) = s.stdin.write_all(ask.as_bytes()) {
        return fail(e.to_string());
    }
    let line = match s.wait_for("fenrir-locked") {
        Ok(l) => l,
        Err(e) => {
            // Lines before it were the client's error, if any.
            let detail: Vec<String> = s.lines.try_iter().collect();
            let _ = s.child.kill();
            let _ = s.child.wait();
            let why = if detail.is_empty() {
                e
            } else {
                format!("{e}: {}", detail.join(" "))
            };
            return fail(format!(
                "could not lock the tables ({why}); give it access in {MYSQL_CNF} ([client] user=, password=)"
            ));
        }
    };
    // `|`: batch mode escapes tabs in values.
    let f: Vec<&str> = line.split('|').collect();
    let datadir = PathBuf::from(f.get(1).copied().unwrap_or(""));
    let mut paths = vec![datadir.clone()];
    for extra in f.iter().skip(2).filter(|x| !x.is_empty() && **x != "./") {
        let p = Path::new(extra);
        paths.push(if p.is_absolute() {
            p.to_path_buf()
        } else {
            datadir.join(p)
        });
    }
    let info = match placement(&paths, unit_of) {
        Placement::One(unit) => app(
            writer,
            &datadir.display().to_string(),
            true,
            format!("tables locked (FLUSH TABLES WITH READ LOCK) while the snapshot of {unit} was taken"),
        ),
        Placement::Split(why) => app(
            writer,
            &datadir.display().to_string(),
            false,
            format!("tables were locked during the snapshots, but {why}"),
        ),
        Placement::Outside => app(
            writer,
            &datadir.display().to_string(),
            false,
            "its data folder is not on the imaged disks".into(),
        ),
    };
    Some((info, Some(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_needs_every_path_on_the_same_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let same = |_: &Path| Some("vg/data".to_string());
        assert_eq!(
            placement(&[a.clone(), b.clone()], &same),
            Placement::One("vg/data".into())
        );
        let split = |p: &Path| Some(if p.ends_with("a") { "vg/a" } else { "vg/b" }.to_string());
        assert!(
            matches!(placement(&[a.clone(), b.clone()], &split), Placement::Split(w) if w.contains("2 volumes"))
        );
        let half = |p: &Path| p.ends_with("a").then(|| "vg/a".to_string());
        assert!(
            matches!(placement(&[a.clone(), b.clone()], &half), Placement::Split(w) if w.contains("not on the imaged disks"))
        );
        let none = |_: &Path| None;
        assert_eq!(placement(&[a], &none), Placement::Outside);
    }

    #[test]
    fn untrusted_hooks_are_not_run() {
        let d = tempfile::tempdir().unwrap();
        let h = d.path().join("10-app");
        std::fs::write(&h, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted(&h).is_err(), "world-writable");
    }
}
