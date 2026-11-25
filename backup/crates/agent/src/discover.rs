//! Other backup software on this machine, so the console can show which
//! machines are (also) protected by something else. Nothing is matched by
//! product: installed programs and services whose names say what they are
//! (backup, replication, disaster recovery), and the operating system's own
//! backup features when they are set up. Collected at most every six hours.

use std::sync::Mutex;
use std::time::{Duration, Instant};

static CACHE: Mutex<Option<(Instant, Vec<String>)>> = Mutex::new(None);
const EVERY: Duration = Duration::from_secs(6 * 3600);

/// The last result; a refresh runs in the background when it is due, so
/// the heartbeat never waits for it (the first heartbeat reports nothing).
pub fn other_backup() -> Vec<String> {
    let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let due = g.as_ref().is_none_or(|(t, _)| t.elapsed() >= EVERY);
    let current = g.as_ref().map(|(_, v)| v.clone()).unwrap_or_default();
    if due {
        // Marks the refresh as started, so only one runs at a time.
        *g = Some((Instant::now(), current.clone()));
        std::thread::spawn(|| {
            let v = collect();
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), v));
        });
    }
    current
}

/// Whether a program or service name says it backs up or replicates.
pub fn looks_like_backup(name: &str) -> bool {
    let n = name.to_lowercase();
    if n.contains("fenrir") {
        return false;
    }
    ["backup", "back-up", "replication", "disaster recovery", "snapshot manager", "bmr"]
        .iter()
        .any(|k| n.contains(k))
        // Drivers and runtimes that only mention the word.
        && !["backup and restore center", "msbackup"].iter().any(|k| n.contains(k))
}

fn tidy(mut v: Vec<String>) -> Vec<String> {
    v.iter_mut()
        .for_each(|s| *s = s.trim().chars().take(120).collect());
    v.retain(|s| !s.is_empty());
    v.sort_by_key(|s| s.to_lowercase());
    v.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    v.truncate(20);
    v
}

#[cfg(windows)]
fn collect() -> Vec<String> {
    // Installed programs (both registry views), Windows Server Backup's
    // scheduled task and File History, by name only.
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName }
if (Get-ScheduledTask -TaskPath '\Microsoft\Windows\Backup\' -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' -and $_.TaskName -match 'Microsoft-Windows-WindowsBackup' }) {
  # Its last result, when the Windows Server Backup cmdlets are installed.
  $s = $null
  try { $s = Get-WBSummary -ErrorAction Stop } catch {}
  if ($s -and $s.LastSuccessfulBackupTime -and $s.LastSuccessfulBackupTime.Year -gt 2000) {
    $st = if ($s.LastBackupResultHR -eq 0) { 'last backup succeeded' } else { 'last backup FAILED' }
    "Windows Server Backup ($st; last success $($s.LastSuccessfulBackupTime.ToString('yyyy-MM-dd')))"
  } elseif ($s) { 'Windows Server Backup (no successful backup yet)' } else { 'Windows Server Backup' }
}
if (Test-Path "$env:LOCALAPPDATA\Microsoft\Windows\FileHistory\Configuration") { 'File History' }
"#;
    let out = crate::hyperv::run_ps(script).unwrap_or_default();
    tidy(
        out.lines()
            .map(str::trim)
            .filter(|l| {
                looks_like_backup(l)
                    || l.starts_with("Windows Server Backup")
                    || *l == "File History"
            })
            .map(str::to_string)
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn collect() -> Vec<String> {
    let out = std::process::Command::new("systemctl")
        .args([
            "list-unit-files",
            "--no-legend",
            "--no-pager",
            "--type=service,timer",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    tidy(
        out.lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|u| looks_like_backup(u))
            .map(|u| format!("{u} (systemd{})", unit_status(u)))
            .collect(),
    )
}

/// How a unit's last run went, when it has run: "; last run failed", or
/// "; last run succeeded".
#[cfg(target_os = "linux")]
fn unit_status(unit: &str) -> String {
    let unit = unit
        .strip_suffix(".timer")
        .map(|u| format!("{u}.service"))
        .unwrap_or_else(|| unit.to_string());
    let out = std::process::Command::new("systemctl")
        .args([
            "show",
            &unit,
            "--property=Result,ExecMainStartTimestampMonotonic",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    run_status(&out)
        .map(|s| format!("; {s}"))
        .unwrap_or_default()
}

/// `systemctl show` output to "last run succeeded" / "last run failed"
/// (None when the unit never ran).
#[cfg(any(target_os = "linux", test))]
pub fn run_status(show: &str) -> Option<&'static str> {
    let get = |k: &str| {
        show.lines()
            .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
            .map(str::trim)
    };
    if get("ExecMainStartTimestampMonotonic").is_none_or(|t| t == "0" || t.is_empty()) {
        return None;
    }
    Some(if get("Result") == Some("success") {
        "last run succeeded"
    } else {
        "last run FAILED"
    })
}

#[cfg(target_os = "macos")]
fn collect() -> Vec<String> {
    let out = std::process::Command::new("tmutil")
        .arg("destinationinfo")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut v: Vec<String> = out
        .lines()
        .filter_map(|l| {
            l.strip_prefix("Name")
                .and_then(|r| r.split_once(':'))
                .map(|(_, n)| n.trim())
        })
        .map(|n| format!("Time Machine ({n})"))
        .collect();
    if !v.is_empty() {
        // The latest backup's folder is named by its date (YYYY-MM-DD-HHMMSS).
        let latest = std::process::Command::new("tmutil")
            .arg("latestbackup")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let date = latest
            .rsplit('/')
            .next()
            .unwrap_or("")
            .get(..10)
            .unwrap_or("")
            .to_string();
        let note = if date.len() == 10 && date.as_bytes()[4] == b'-' {
            format!("latest backup {date}")
        } else {
            "no backup found".to_string()
        };
        for x in v.iter_mut() {
            *x = format!("{}; {note})", x.trim_end_matches(')'));
        }
    }
    if let Ok(rd) = std::fs::read_dir("/Applications") {
        v.extend(
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.file_name()
                        .to_str()
                        .map(|s| s.trim_end_matches(".app").to_string())
                })
                .filter(|n| looks_like_backup(n)),
        );
    }
    tidy(v)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn collect() -> Vec<String> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::{looks_like_backup, tidy};

    #[test]
    fn names_that_say_backup() {
        assert!(looks_like_backup("Contoso Backup Agent"));
        assert!(looks_like_backup("acme-replication.service"));
        assert!(looks_like_backup("Example Disaster Recovery Suite"));
        assert!(!looks_like_backup("Fenrir-Backup agent"));
        assert!(!looks_like_backup("Microsoft Edge"));
        let ran = "Result=success\nExecMainStartTimestampMonotonic=123\n";
        assert_eq!(super::run_status(ran), Some("last run succeeded"));
        assert_eq!(
            super::run_status("Result=exit-code\nExecMainStartTimestampMonotonic=9\n"),
            Some("last run FAILED")
        );
        assert_eq!(
            super::run_status("Result=success\nExecMainStartTimestampMonotonic=0\n"),
            None
        );
        assert_eq!(
            tidy(vec!["b".into(), "A".into(), "a".into(), " ".into()]),
            vec!["A", "b"]
        );
    }
}
