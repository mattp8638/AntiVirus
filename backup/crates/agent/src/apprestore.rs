//! Restoring one application database from an application-aware image
//! (design: docs/design/app-restore.md).
//!
//! The image records, for each VSS writer component, the file sets the
//! application listed (folder, name pattern, subfolders or not). Restoring a
//! component copies those files out of the image (`filebrowse`, nothing
//! mounted) into a folder on this machine, then:
//!
//! * SQL Server: attaches them as a new database under a chosen name, or
//!   writes the T-SQL to do so when attaching here is not possible;
//! * Exchange: writes a PowerShell script that mounts them as a recovery
//!   database and restores chosen mailboxes from it (single-mailbox restore);
//! * other applications: the files only.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use core_format::manifest::{AppFile, ApplicationInfo};
use core_format::{ManifestBody, Repository};
use protocol::{JobState, JobUpdate};
use serde_json::json;

use crate::jobs::{finished, Ctx, Reporter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    SqlServer,
    Exchange,
    Other,
}

pub fn kind_of(writer: &str) -> AppKind {
    let w = writer.to_ascii_lowercase();
    if w == "sqlserverwriter" {
        AppKind::SqlServer
    } else if w.contains("exchange") {
        AppKind::Exchange
    } else {
        AppKind::Other
    }
}

/// Where a file set is inside the image: the volume (by its mount point at
/// backup time) and the folder within it.
#[derive(Debug, Clone, PartialEq)]
pub struct Located {
    pub disk: u32,
    pub partition: u32,
    pub folder: String,
    pub spec: String,
    pub recursive: bool,
    pub role: String,
}

/// Map each file set to a volume of the image by the longest mount point
/// that contains its folder (`C:\`, or a volume mounted in a folder).
pub fn locate(volumes: &[filebrowse::Volume], files: &[AppFile]) -> anyhow::Result<Vec<Located>> {
    let mut out = Vec::new();
    for f in files {
        let path = f.path.replace('/', "\\");
        let lower = path.to_ascii_lowercase();
        let best = volumes
            .iter()
            .filter(|v| v.browsable)
            .flat_map(|v| v.mount_points.iter().map(move |m| (v, m)))
            .filter_map(|(v, m)| {
                let mut ml = m.replace('/', "\\").to_ascii_lowercase();
                if !ml.ends_with('\\') {
                    ml.push('\\');
                }
                (lower.starts_with(&ml) || format!("{lower}\\") == ml).then_some((v, ml.len()))
            })
            .max_by_key(|(_, n)| *n);
        let Some((v, n)) = best else {
            bail!("{path} is not on a volume of this image that can be read");
        };
        let rest = path.get(n.min(path.len())..).unwrap_or("");
        out.push(Located {
            disk: v.disk,
            partition: v.partition,
            folder: format!("/{}", rest.replace('\\', "/").trim_matches('/')),
            spec: f.spec.clone(),
            recursive: f.recursive,
            role: f.role.clone(),
        });
    }
    Ok(out)
}

/// Files in `folder` (and below, when `recursive`) matching `spec`.
pub fn matching(
    fs: &mut dyn filebrowse::Volumefs,
    folder: &str,
    spec: &str,
    recursive: bool,
) -> filebrowse::Result<Vec<String>> {
    let spec = if spec.is_empty() { "*" } else { spec }.to_lowercase();
    let mut out = Vec::new();
    let mut dirs = vec![folder.trim_end_matches('/').to_string()];
    while let Some(d) = dirs.pop() {
        let list = fs.list(if d.is_empty() { "/" } else { &d })?;
        for e in list {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let p = format!("{d}/{}", e.name);
            match e.kind {
                filebrowse::EntryKind::Dir if recursive => dirs.push(p),
                filebrowse::EntryKind::File if catalog::wildcard(&spec, &e.name.to_lowercase()) => {
                    out.push(p)
                }
                _ => {}
            }
        }
    }
    out.sort();
    Ok(out)
}

fn sql_ident(s: &str) -> String {
    format!("[{}]", s.replace(']', "]]"))
}

fn sql_str(s: &str) -> String {
    format!("N'{}'", s.replace('\'', "''"))
}

/// T-SQL that attaches the restored files as database `name`.
pub fn attach_sql(name: &str, data: &[PathBuf], logs: &[PathBuf]) -> String {
    let files: Vec<String> = data
        .iter()
        .chain(logs)
        .map(|p| format!("(FILENAME = {})", sql_str(&p.display().to_string())))
        .collect();
    format!(
        "CREATE DATABASE {} ON\n  {}\nFOR ATTACH;\n",
        sql_ident(name),
        files.join(",\n  ")
    )
}

/// SQL Server's service account for `instance` ("" or MSSQLSERVER = default).
pub fn sql_service_account(instance: &str) -> String {
    let i = instance.rsplit('\\').next().unwrap_or("").trim();
    if i.is_empty() || i.eq_ignore_ascii_case("MSSQLSERVER") {
        "NT SERVICE\\MSSQLSERVER".into()
    } else {
        format!("NT SERVICE\\MSSQL${i}")
    }
}

/// PowerShell that gives the SQL Server service access to `dir` and runs
/// `sql` on `server` with this machine's sign-in (the SQL text and names are
/// passed base64-encoded, never spliced into the script).
pub fn attach_script(server: &str, account: &str, dir: &Path, sql: &str) -> String {
    use base64::Engine;
    let b = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    format!(
        r#"$ErrorActionPreference = 'Stop'
function D($s) {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }}
$dir = D '{dir}'; $account = D '{account}'; $server = D '{server}'; $sql = D '{sql}'
& icacls.exe $dir /grant "$($account):(OI)(CI)F" /T /Q | Out-Null
$c = New-Object System.Data.SqlClient.SqlConnection "Server=$server;Integrated Security=SSPI;Connect Timeout=30"
$c.Open()
try {{ $cmd = $c.CreateCommand(); $cmd.CommandTimeout = 600; $cmd.CommandText = $sql; [void]$cmd.ExecuteNonQuery() }} finally {{ $c.Close() }}
'attached'
"#,
        dir = b(&dir.display().to_string()),
        account = b(account),
        server = b(server),
        sql = b(sql),
    )
}

/// PowerShell for the Exchange Management Shell: mount the restored files as
/// a recovery database and restore a mailbox from it.
pub fn exchange_script(db: &str, edb: &Path, log_dir: &Path) -> String {
    let q = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let rdb = format!(
        "Recovery-{}",
        db.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect::<String>()
    );
    format!(
        r#"# Restore mailboxes from the backup of Exchange database {db_q}, restored by Fenrir.
# Run in the Exchange Management Shell on a Mailbox server, after reading each step.
$Server = $env:COMPUTERNAME
$Edb = {edb}
$Logs = {logs}

# 1. Bring the database to a clean shutdown state (replays the restored logs).
#    eseutil /mh shows the state; it must read "Clean Shutdown" afterwards.
eseutil /r E00 /l $Logs /d (Split-Path $Edb) /i
eseutil /mh $Edb

# 2. Mount it as a recovery database (users cannot reach it; it does not count as a mailbox database).
New-MailboxDatabase -Recovery -Name {rdb} -Server $Server -EdbFilePath $Edb -LogFolderPath $Logs
Mount-Database {rdb}
Get-MailboxStatistics -Database {rdb} | Sort-Object DisplayName | Format-Table DisplayName, ItemCount, LastLogonTime

# 3. Restore one mailbox (change the names), into its own mailbox or a folder of another:
# New-MailboxRestoreRequest -SourceDatabase {rdb} -SourceStoreMailbox "Anna Smith" -TargetMailbox anna@example.com -TargetRootFolder "Restored"
# Get-MailboxRestoreRequest | Get-MailboxRestoreRequestStatistics

# 4. When finished:
# Dismount-Database {rdb} -Confirm:$false; Remove-MailboxDatabase {rdb} -Confirm:$false
"#,
        db_q = q(db),
        edb = q(&edb.display().to_string()),
        logs = q(&log_dir.display().to_string()),
        rdb = rdb,
    )
}

pub struct AppRestoreRequest<'a> {
    pub image_id: uuid::Uuid,
    pub component: &'a str,
    pub directory: &'a str,
    /// SQL Server: attach under this name on `sql_instance` ("" = default instance).
    pub attach_as: Option<&'a str>,
    pub sql_instance: &'a str,
}

pub fn run(
    ctx: &Ctx,
    repo: &Repository,
    req: &AppRestoreRequest,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let m: ManifestBody = repo.load_manifest(&req.image_id)?;
    let app: &ApplicationInfo = m
        .applications
        .iter()
        .find(|a| a.component.eq_ignore_ascii_case(req.component))
        .ok_or_else(|| anyhow!("the backup has no application component {}", req.component))?;
    if app.files.is_empty() {
        bail!("this backup does not list the files of {}; it was taken by an older agent: restore the volume or use Browse files", app.component);
    }
    let kind = kind_of(&app.writer);
    let name = app
        .component
        .rsplit('\\')
        .next()
        .unwrap_or(&app.component)
        .to_string();
    let target = PathBuf::from(req.directory.trim()).join(crate::restore::safe_name(&name));
    if !Path::new(req.directory.trim()).is_absolute() {
        bail!("the restore folder must be a full path on this machine");
    }
    if target.exists()
        && std::fs::read_dir(&target)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        bail!("{} already exists and is not empty", target.display());
    }
    std::fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
    let volumes = filebrowse::volumes(&m);
    let located = locate(&volumes, &app.files)?;

    let mut disks: Vec<(u32, Arc<nbd_server::ImageExport>)> = Vec::new();
    let (mut data, mut logs, mut others) = (Vec::new(), Vec::new(), Vec::new());
    let mut failed = Vec::new();
    for l in &located {
        let disk = match disks.iter().find(|(i, _)| *i == l.disk) {
            Some((_, d)) => d.clone(),
            None => {
                let d = Arc::new(nbd_server::ImageExport::new(repo, &m, l.disk, 64 << 20)?);
                disks.push((l.disk, d.clone()));
                d
            }
        };
        let mut fs = filebrowse::open(&m, disk, l.disk, l.partition)?;
        let paths = matching(fs.as_mut(), &l.folder, &l.spec, l.recursive)
            .map_err(|e| anyhow!("{}: {e}", l.folder))?;
        if paths.is_empty() {
            failed.push(format!(
                "{}\\{}: no such file in the backup",
                l.folder, l.spec
            ));
            continue;
        }
        rep.progress(
            "restoring",
            0,
            0,
            &format!("{} file(s) from {}", paths.len(), l.folder),
        );
        let ctl = ctx.ctl.clone();
        let r = filebrowse::restore(
            fs.as_mut(),
            &paths,
            &filebrowse::RestoreOptions {
                target: target.clone(),
                keep_structure: false,
                conflict: filebrowse::Conflict::Rename,
            },
            &|| ctl.is_cancelled(),
            &|_, _| {},
        )?;
        failed.extend(r.failed.iter().map(|f| format!("{}: {}", f.path, f.error)));
        let restored: Vec<PathBuf> = paths
            .iter()
            .map(|p| {
                target.join(filebrowse::restore::safe_component(
                    p.rsplit('/').next().unwrap_or(p),
                ))
            })
            .collect();
        match l.role.as_str() {
            "database" => data.extend(restored),
            "log" => logs.extend(restored),
            _ => others.extend(restored),
        }
    }
    if data.is_empty() && logs.is_empty() && others.is_empty() {
        bail!("nothing could be restored: {}", failed.join("; "));
    }

    let mut u = finished(if failed.is_empty() {
        JobState::Succeeded
    } else {
        JobState::Warning
    });
    u.warnings = failed;
    let mut result = json!({
        "component": app.component, "writer": app.writer, "folder": target.display().to_string(),
        "files": data.iter().chain(&logs).chain(&others).map(|p| p.display().to_string()).collect::<Vec<_>>(),
    });
    match kind {
        AppKind::SqlServer => {
            let as_name = req
                .attach_as
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .unwrap_or(format!("{name}_restored"));
            // Some writers list data and log files only as "database" files: sort them by extension.
            let (mut d, mut l): (Vec<PathBuf>, Vec<PathBuf>) = data
                .iter()
                .chain(&logs)
                .cloned()
                .partition(|p| !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ldf")));
            d.sort();
            l.sort();
            let sql = attach_sql(&as_name, &d, &l);
            std::fs::write(
                target.join(format!(
                    "attach-{}.sql",
                    crate::restore::safe_name(&as_name)
                )),
                &sql,
            )?;
            result["attach_sql"] = json!(sql);
            if req.attach_as.is_some() {
                let server = if req.sql_instance.trim().is_empty() {
                    ".".to_string()
                } else {
                    req.sql_instance.trim().to_string()
                };
                let script = attach_script(
                    &server,
                    &sql_service_account(req.sql_instance),
                    &target,
                    &sql,
                );
                match crate::hyperv::run_ps(&script) {
                    Ok(_) => result["attached"] = json!(as_name),
                    Err(e) => {
                        u.state = JobState::Warning;
                        u.warnings.push(format!(
                            "The files are restored, but attaching them as {as_name} failed ({e:#}). Run the attach-*.sql file in that folder as a SQL Server administrator."
                        ));
                    }
                }
            }
        }
        AppKind::Exchange => {
            let edb = data
                .iter()
                .find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("edb")))
                .cloned()
                .unwrap_or_else(|| target.join(format!("{name}.edb")));
            let script = exchange_script(&name, &edb, &target);
            let file = target.join(format!("recover-{}.ps1", crate::restore::safe_name(&name)));
            std::fs::write(&file, script)?;
            result["script"] = json!(file.display().to_string());
        }
        AppKind::Other => {}
    }
    u.result = Some(result);
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_format::fsdetect::FsType;

    fn vol(disk: u32, part: u32, mounts: &[&str]) -> filebrowse::Volume {
        filebrowse::Volume {
            disk,
            partition: part,
            filesystem: FsType::Ntfs,
            size: 1 << 30,
            mount_points: mounts.iter().map(|s| s.to_string()).collect(),
            name: String::new(),
            browsable: true,
            note: None,
        }
    }

    fn file(path: &str, spec: &str, role: &str) -> AppFile {
        AppFile {
            path: path.into(),
            spec: spec.into(),
            recursive: false,
            role: role.into(),
        }
    }

    #[test]
    fn file_sets_map_to_the_deepest_mount_point() {
        let vols = vec![
            vol(0, 3, &["C:\\"]),
            vol(1, 1, &["D:\\"]),
            vol(1, 2, &["C:\\SQLData\\"]),
        ];
        let l = locate(
            &vols,
            &[
                file(
                    r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA",
                    "sales.mdf",
                    "database",
                ),
                file(r"C:\SQLData\Logs", "sales_log.ldf", "log"),
                file(r"d:\exchange\db1", "*.log", "log"),
            ],
        )
        .unwrap();
        assert_eq!(
            (l[0].disk, l[0].partition, l[0].folder.as_str()),
            (
                0,
                3,
                "/Program Files/Microsoft SQL Server/MSSQL16.MSSQLSERVER/MSSQL/DATA"
            )
        );
        assert_eq!(
            (l[1].disk, l[1].partition, l[1].folder.as_str()),
            (1, 2, "/Logs")
        );
        assert_eq!(
            (l[2].disk, l[2].partition, l[2].folder.as_str()),
            (1, 1, "/exchange/db1")
        );
        assert!(locate(&vols, &[file(r"E:\x", "a", "file")]).is_err());
    }

    #[test]
    fn sql_and_scripts_quote_names_and_paths() {
        let sql = attach_sql(
            "sales]; DROP DATABASE x; --",
            &[PathBuf::from(r"D:\R\sales\O'Brien.mdf")],
            &[PathBuf::from(r"D:\R\sales\sales_log.ldf")],
        );
        assert!(sql.starts_with("CREATE DATABASE [sales]]; DROP DATABASE x; --] ON"));
        assert!(sql.contains(r"(FILENAME = N'D:\R\sales\O''Brien.mdf')"));
        assert!(sql.trim_end().ends_with("FOR ATTACH;"));
        let ps = attach_script(
            ".",
            &sql_service_account(""),
            Path::new(r"D:\R\sales"),
            &sql,
        );
        assert!(
            !ps.contains("DROP DATABASE"),
            "the SQL is passed encoded, not spliced"
        );
        assert_eq!(
            sql_service_account(r"SQL01\FINANCE"),
            r"NT SERVICE\MSSQL$FINANCE"
        );
        assert_eq!(
            sql_service_account("MSSQLSERVER"),
            r"NT SERVICE\MSSQLSERVER"
        );
        let ex = exchange_script(
            "Mailbox Database 01'",
            Path::new(r"D:\R\db\db.edb"),
            Path::new(r"D:\R\db"),
        );
        assert!(ex.contains("New-MailboxDatabase -Recovery -Name Recovery-MailboxDatabase01"));
        assert!(ex.contains(r"$Edb = 'D:\R\db\db.edb'"));
        assert!(ex.contains("'Mailbox Database 01'''"));
    }

    struct Mem(Vec<&'static str>);

    impl filebrowse::Volumefs for Mem {
        fn list(&mut self, path: &str) -> filebrowse::Result<Vec<filebrowse::Entry>> {
            let prefix = format!("{}/", path.trim_end_matches('/'));
            let mut out: Vec<filebrowse::Entry> = Vec::new();
            for p in &self.0 {
                if let Some(rest) = p.strip_prefix(&prefix) {
                    let (name, dir) = match rest.split_once('/') {
                        Some((n, _)) => (n, true),
                        None => (rest, false),
                    };
                    if !out.iter().any(|e| e.name == name) {
                        out.push(filebrowse::Entry {
                            name: name.into(),
                            kind: if dir {
                                filebrowse::EntryKind::Dir
                            } else {
                                filebrowse::EntryKind::File
                            },
                            size: 1,
                            modified: None,
                            hidden: false,
                        });
                    }
                }
            }
            Ok(out)
        }
        fn stat(&mut self, _: &str) -> filebrowse::Result<filebrowse::Entry> {
            unimplemented!()
        }
        fn copy(
            &mut self,
            _: &str,
            _: &mut dyn std::io::Write,
            _: &dyn Fn() -> bool,
        ) -> filebrowse::Result<u64> {
            unimplemented!()
        }
    }

    #[test]
    fn file_sets_are_matched_by_pattern_and_case() {
        let mut fs = Mem(vec![
            "/Exchange/DB1/DB1.edb",
            "/Exchange/DB1/E00.log",
            "/Exchange/DB1/E0000000A1.LOG",
            "/Exchange/DB1/E00.chk",
            "/Exchange/DB1/old/E000000001.log",
        ]);
        assert_eq!(
            matching(&mut fs, "/Exchange/DB1", "*.log", false).unwrap(),
            vec!["/Exchange/DB1/E00.log", "/Exchange/DB1/E0000000A1.LOG"]
        );
        assert_eq!(
            matching(&mut fs, "/Exchange/DB1", "*.log", true)
                .unwrap()
                .len(),
            3,
            "subfolders when recursive"
        );
        assert_eq!(
            matching(&mut fs, "/Exchange/DB1", "db1.EDB", false).unwrap(),
            vec!["/Exchange/DB1/DB1.edb"]
        );
    }

    #[test]
    fn writers_are_recognised() {
        assert_eq!(kind_of("SqlServerWriter"), AppKind::SqlServer);
        assert_eq!(kind_of("Microsoft Exchange Writer"), AppKind::Exchange);
        assert_eq!(kind_of("NTDS"), AppKind::Other);
    }
}
