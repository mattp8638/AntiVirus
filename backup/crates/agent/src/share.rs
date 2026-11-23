//! Repositories on network shares (SMB): sign in for the duration of a job.
//!
//! Paths are written `\\server\share\folder` (also accepted:
//! `//server/share/folder`, `smb://server/share/folder`).
//!
//! * Windows: `WNetAddConnection2` without a drive letter, inside the
//!   agent's own (SYSTEM) logon session: the share is not visible in any
//!   user's Explorer, so ransomware running as a user cannot reach it. With
//!   no credentials, Windows uses the computer account (domain-joined
//!   machines; grant `DOMAIN\NAME$` access on the share).
//! * Linux: a private CIFS mount under `/run/fenrir-backup-agent/smb`, credentials
//!   passed in a 0600 file that is deleted straight after mounting.
//!
//! `release_all` disconnects after each job.

use std::sync::Mutex;

use anyhow::{anyhow, bail};
use protocol::seal::{AgentKey, Sealed};
use protocol::ShareCredentials;

/// A share path split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unc {
    pub server: String,
    pub share: String,
    /// Folders below the share, without leading/trailing separators.
    pub rest: Vec<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Unc {
    pub fn root(&self) -> String {
        format!(r"\\{}\{}", self.server, self.share)
    }
    pub fn windows_path(&self) -> String {
        let mut p = self.root();
        for r in &self.rest {
            p.push('\\');
            p.push_str(r);
        }
        p
    }
}

/// Parse a share path; `None` for anything else (local paths).
pub fn parse_unc(path: &str) -> Option<Unc> {
    let p = path.trim();
    let body = match p.strip_prefix("smb://") {
        Some(b) => b,
        None => {
            let b = p.strip_prefix(r"\\").or_else(|| p.strip_prefix("//"))?;
            // Not the Win32 device namespaces \\?\ and \\.\
            if b.starts_with('?') || b.starts_with(".\\") || b.starts_with("./") {
                return None;
            }
            b
        }
    };
    let mut parts = body.split(['\\', '/']).filter(|s| !s.is_empty());
    let server = parts.next()?.to_string();
    let share = parts.next()?.to_string();
    let rest: Vec<String> = parts.map(str::to_string).collect();
    if rest.iter().any(|r| r == "..") {
        return None;
    }
    Some(Unc {
        server,
        share,
        rest,
    })
}

/// Windows user name for a sign-in: `DOMAIN\user`, or as typed when it
/// already names the domain (`user@domain`, `DOMAIN\user`).
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub fn windows_user(c: &ShareCredentials) -> String {
    let u = c.username.trim();
    if c.domain.trim().is_empty() || u.contains('\\') || u.contains('@') {
        u.to_string()
    } else {
        format!(r"{}\{}", c.domain.trim(), u)
    }
}

/// What a WNet error code means for someone setting up a share.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn wnet_error_text(code: u32) -> String {
    match code {
        5 => "access denied: the account may sign in but has no permission on this share or folder".into(),
        53 | 51 => "the server was not found or does not answer on the network (check the name, DNS and that file sharing is on)".into(),
        67 => "the server answered but has no share with that name".into(),
        86 | 1326 => "wrong username or password".into(),
        1219 => "this machine is already connected to that server with different credentials (for example a mapped drive or another program running as SYSTEM); use the same account, or connect by the server's other name or IP address".into(),
        1327 => "the account is not allowed to sign in this way (logon restrictions or an empty password)".into(),
        1330 => "the password of this account has expired".into(),
        1331 => "the account is disabled".into(),
        1909 => "the account is locked out".into(),
        1311 | 1355 => "no domain controller could be reached to check the account".into(),
        1244 => "the server requires a sign-in: give a username and password".into(),
        2202 => "the username is not valid".into(),
        1203 | 1222 => "no network path: the network is not available".into(),
        c => format!("Windows error {c}"),
    }
}

/// Connections opened for the current job.
static OPEN: Mutex<Vec<Opened>> = Mutex::new(Vec::new());

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields used per platform
struct Opened {
    remote: String,
    mount: Option<std::path::PathBuf>,
}

fn open_credentials(key: &AgentKey, sealed: &Sealed) -> anyhow::Result<ShareCredentials> {
    let pt = key
        .open(sealed)
        .map_err(|e| anyhow!("{e}. Enter the share sign-in again on the Repositories page."))?;
    let c: ShareCredentials = serde_json::from_slice(&pt)?;
    if c.username.trim().is_empty() {
        bail!("the share sign-in has no username");
    }
    Ok(c)
}

/// Make `path` usable: sign in to its share if it is one. Returns the path
/// to use locally (unchanged on Windows; the mount point on Linux).
pub fn prepare(key: &AgentKey, path: &str, sealed: Option<&Sealed>) -> anyhow::Result<String> {
    let Some(unc) = parse_unc(path) else {
        return Ok(path.to_string());
    };
    let creds = sealed.map(|s| open_credentials(key, s)).transpose()?;
    connect(&unc, creds.as_ref())
}

#[cfg(windows)]
fn connect(unc: &Unc, creds: Option<&ShareCredentials>) -> anyhow::Result<String> {
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::NetworkManagement::WNet::{
        WNetAddConnection2W, CONNECT_TEMPORARY, NETRESOURCEW, RESOURCETYPE_DISK,
    };
    let remote = unc.root();
    let Some(c) = creds else {
        // Computer account (SYSTEM on a domain-joined machine).
        return Ok(unc.windows_path());
    };
    if OPEN
        .lock()
        .unwrap()
        .iter()
        .any(|o| o.remote.eq_ignore_ascii_case(&remote))
    {
        return Ok(unc.windows_path());
    }
    let mut remote_w: Vec<u16> = remote.encode_utf16().chain([0]).collect();
    let nr = NETRESOURCEW {
        dwType: RESOURCETYPE_DISK,
        lpRemoteName: PWSTR(remote_w.as_mut_ptr()),
        ..Default::default()
    };
    let user = HSTRING::from(windows_user(c));
    let pass = HSTRING::from(c.password.as_str());
    let r = unsafe { WNetAddConnection2W(&nr, &pass, &user, CONNECT_TEMPORARY) };
    if r.0 != 0 {
        bail!(
            "signing in to {remote} as {}: {}",
            windows_user(c),
            wnet_error_text(r.0)
        );
    }
    OPEN.lock().unwrap().push(Opened {
        remote,
        mount: None,
    });
    Ok(unc.windows_path())
}

#[cfg(target_os = "linux")]
fn connect(unc: &Unc, creds: Option<&ShareCredentials>) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(c) = creds else {
        bail!("Linux machines need a username and password for network shares (the computer-account option is for Windows)");
    };
    let remote = format!("//{}/{}", unc.server, unc.share);
    let base = std::path::Path::new("/run/fenrir-backup-agent/smb");
    let id = hex::encode(&Sha256::digest(format!("{remote}\0{}", windows_user(c)).as_bytes())[..8]);
    let mnt = base.join(&id);
    let local = |m: &std::path::Path| {
        let mut p = m.to_path_buf();
        for r in &unc.rest {
            p.push(r);
        }
        p.display().to_string()
    };
    if OPEN
        .lock()
        .unwrap()
        .iter()
        .any(|o| o.mount.as_deref() == Some(mnt.as_path()))
    {
        return Ok(local(&mnt));
    }
    for f in [&c.username, &c.password, &c.domain] {
        if f.contains('\n') || f.contains('\r') {
            bail!("the share sign-in contains a line break");
        }
    }
    std::fs::create_dir_all(&mnt)?;
    let credfile = base.join(format!("{id}.cred"));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&credfile)?;
        writeln!(f, "username={}", c.username.trim())?;
        writeln!(f, "password={}", c.password)?;
        if !c.domain.trim().is_empty() {
            writeln!(f, "domain={}", c.domain.trim())?;
        }
    }
    let out = std::process::Command::new("mount")
        .args(["-t", "cifs", &remote])
        .arg(&mnt)
        .arg("-o")
        .arg(format!(
            "credentials={},uid=0,gid=0,file_mode=0600,dir_mode=0700,noperm",
            credfile.display()
        ))
        .output();
    let _ = std::fs::remove_file(&credfile);
    let out = out.map_err(|e| anyhow!("running mount: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let hint = if err.contains("wrong fs type")
            || err.contains("helper program")
            || err.contains("unknown filesystem")
        {
            " (install the cifs-utils package)"
        } else if err.contains("Permission denied") || err.contains("error(13)") {
            " (wrong username or password, or no permission on the share)"
        } else if err.contains("No such file") || err.contains("error(2)") {
            " (the share does not exist)"
        } else if err.contains("Host is down")
            || err.contains("error(112)")
            || err.contains("could not resolve")
        {
            " (the server is not reachable)"
        } else {
            ""
        };
        let _ = std::fs::remove_dir(&mnt);
        bail!("mounting {remote}: {}{hint}", err.trim());
    }
    OPEN.lock().unwrap().push(Opened {
        remote,
        mount: Some(mnt.clone()),
    });
    Ok(local(&mnt))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn connect(_: &Unc, _: Option<&ShareCredentials>) -> anyhow::Result<String> {
    bail!("network share repositories are supported on Windows and Linux agents; on this machine use a local path or a share mounted by the system")
}

/// Disconnect everything `prepare` opened (end of a job).
pub fn release_all() {
    let opened: Vec<Opened> = std::mem::take(&mut *OPEN.lock().unwrap());
    for o in opened {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::NetworkManagement::WNet::{
                WNetCancelConnection2W, NET_CONNECT_FLAGS,
            };
            let _ = WNetCancelConnection2W(
                &windows::core::HSTRING::from(o.remote.as_str()),
                NET_CONNECT_FLAGS(0),
                true,
            );
        }
        if let Some(m) = &o.mount {
            let ok = std::process::Command::new("umount")
                .arg(m)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                let _ = std::fs::remove_dir(m);
            } else {
                crate::log::warn(&format!("could not unmount {}", m.display()));
            }
        }
    }
}

/// Free and total bytes on the volume holding `path`.
pub fn space(path: &str) -> Option<(u64, u64)> {
    #[cfg(windows)]
    {
        let (mut free, mut total) = (0u64, 0u64);
        unsafe {
            windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                &windows::core::HSTRING::from(path),
                Some(&mut free),
                Some(&mut total),
                None,
            )
            .ok()?;
        }
        Some((free, total))
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("df")
            .args(["-Pk", path])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let line = s.lines().nth(1)?;
        let f: Vec<&str> = line.split_whitespace().collect();
        let total: u64 = f.get(1)?.parse().ok()?;
        let avail: u64 = f.get(3)?.parse().ok()?;
        Some((avail * 1024, total * 1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unc_paths() {
        let u = parse_unc(r"\\nas01\backups\fenrir\main").unwrap();
        assert_eq!((u.server.as_str(), u.share.as_str()), ("nas01", "backups"));
        assert_eq!(u.rest, vec!["fenrir", "main"]);
        assert_eq!(u.root(), r"\\nas01\backups");
        assert_eq!(u.windows_path(), r"\\nas01\backups\fenrir\main");
        assert_eq!(
            parse_unc("smb://10.0.0.5/b/x/").unwrap().windows_path(),
            r"\\10.0.0.5\b\x"
        );
        assert_eq!(parse_unc("//srv/share").unwrap().rest, Vec::<String>::new());
        for not in [
            r"D:\Backups",
            "/mnt/backups",
            r"\\?\C:\x",
            r"\\.\PhysicalDrive0",
            r"\\srv",
            r"\\srv\s\..\x",
        ] {
            assert!(parse_unc(not).is_none(), "{not}");
        }
    }

    #[test]
    fn user_names_and_errors() {
        let c = |d: &str, u: &str| ShareCredentials {
            domain: d.into(),
            username: u.into(),
            password: "p".into(),
        };
        assert_eq!(windows_user(&c("CORP", "backup-svc")), r"CORP\backup-svc");
        assert_eq!(windows_user(&c("", "admin")), "admin");
        assert_eq!(
            windows_user(&c("CORP", "svc@corp.example")),
            "svc@corp.example"
        );
        assert_eq!(windows_user(&c("CORP", r"OTHER\svc")), r"OTHER\svc");
        assert!(wnet_error_text(1326).contains("wrong username or password"));
        assert!(wnet_error_text(1219).contains("different credentials"));
        assert_eq!(wnet_error_text(4242), "Windows error 4242");
        assert!(
            !format!("{:?}", c("D", "u")).contains("\"p\""),
            "password not in Debug output"
        );
    }
}
