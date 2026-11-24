//! Backups of chosen files and folders (design: docs/design/file-backup.md).
//!
//! A folder backup is stored like a SaaS backup (`saas::store`): an image of
//! two disks, the index (every file and folder, with its chunks) and the
//! files' bytes, each file starting on a chunk of its own. The image's OS
//! family is "files" and its machine is the backed-up machine, so it is
//! listed, retained, copied, verified and made immutable with that machine's
//! disk images.
//!
//! * Incremental forever: a file whose size and modification time are the
//!   same as in the previous folder backup of the machine is not read again;
//!   its chunks are taken from the previous index. Every backup still lists
//!   every file and restores on its own.
//! * Files are read through `open`, which the caller points at a snapshot
//!   (VSS on Windows) when there is one, so open and locked files are copied
//!   as they were at one moment.
//! * Files that cannot be read are reported and the rest are backed up.
//!
//! [`IndexVolume`] presents a folder backup as a browsable volume, so file
//! browsing, file restore, downloads and malware scans work on it as on
//! disk images.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use core_format::manifest::MachineInfo;
use core_format::{ManifestBody, Repository};
use filebrowse::{Entry, EntryKind, Volumefs};
use saas::store::{Index, Item, Writer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FAMILY: &str = "files";
pub const SERVICE: &str = "files";
/// Warnings listed at most; the count of the rest is given.
const MAX_WARNINGS: usize = 200;

/// Never worth backing up (Windows paging and hibernation files, the
/// recycle bin, restore points, and caches that rebuild themselves).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "$Recycle.Bin",
    "System Volume Information",
    "Thumbs.db",
    ".Trash-*",
    "lost+found",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub image_id: Uuid,
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    /// Files whose bytes were read (new or changed).
    pub files_read: u64,
    pub bytes_read: u64,
    /// Files taken unchanged from the previous folder backup.
    pub files_unchanged: u64,
    pub files_failed: u64,
    pub excluded: u64,
    pub warnings: Vec<String>,
}

/// Logical path as recorded: `/`-separated, a Windows drive as its first
/// part (`C:/Users/anna`), a network share under `UNC` (`UNC/server/share/...`).
pub fn logical(p: &str) -> String {
    let s = p.replace('\\', "/");
    let s = match s.strip_prefix("//") {
        Some(rest) => format!("UNC/{}", rest.trim_start_matches('/')),
        None => s,
    };
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        "/".into()
    } else {
        s.to_string()
    }
}

/// Whether `path` (logical) is excluded by `patterns`: a pattern with a `/`
/// excludes that path and everything under it; otherwise it is matched
/// against each file or folder name, with `*` and `?` wildcards. Matching
/// ignores case (Windows and SMB shares do).
pub fn excluded(path: &str, patterns: &[String]) -> bool {
    let lower = path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    patterns.iter().any(|p| {
        let p = logical(p).to_lowercase();
        if p.contains('/') {
            lower == p || lower.starts_with(&format!("{p}/"))
        } else {
            wildcard(&p, name)
        }
    })
}

fn wildcard(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn unix(t: io::Result<SystemTime>) -> i64 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Where to read: the caller maps a logical path to the file to open (the
/// path itself, or its place in a snapshot).
pub type Translate<'a> = &'a dyn Fn(&str) -> PathBuf;

pub struct Options<'a> {
    pub roots: &'a [String],
    pub excludes: &'a [String],
    pub label: Option<String>,
    pub cancel: &'a dyn Fn() -> bool,
    pub progress: &'a dyn Fn(&str, u64, u64),
}

/// The newest folder backup of `machine_id`, with its index.
pub fn previous(repo: &Repository, machine_id: &str) -> Option<Index> {
    let (all, _) = repo.load_all_manifests().ok()?;
    let m = all
        .into_iter()
        .filter(|m| m.machine.machine_id == machine_id && m.os.family == FAMILY)
        .max_by_key(|m| m.created_unix)?;
    saas::store::read_index(repo, &m).ok()
}

fn meta_of(md: &std::fs::Metadata) -> serde_json::Value {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        serde_json::json!({ "mode": md.mode() & 0o7777, "uid": md.uid(), "gid": md.gid() })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        serde_json::json!({ "attributes": md.file_attributes() })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = md;
        serde_json::Value::Null
    }
}

/// Back up `opts.roots` of the machine into `repo`.
pub fn backup(
    repo: &Repository,
    machine: MachineInfo,
    translate: Translate,
    opts: &Options,
) -> io::Result<Report> {
    let started = Instant::now();
    let prev: HashMap<String, Item> = previous(repo, &machine.machine_id)
        .map(|i| {
            i.items
                .into_iter()
                .filter(|it| it.kind == "file")
                .map(|it| (it.path.clone(), it))
                .collect()
        })
        .unwrap_or_default();
    let tenant = machine.hostname.clone();
    let mut w = Writer::with_identity(repo, FAMILY, machine, SERVICE, &tenant);
    let mut rep = Report::default();
    let mut warnings = Vec::new();
    let mut warn = |rep: &mut Report, m: String| {
        rep.files_failed += 1;
        if warnings.len() < MAX_WARNINGS {
            warnings.push(m);
        }
    };
    let mut excludes: Vec<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    excludes.extend(opts.excludes.iter().cloned());

    let mut stack: Vec<String> = opts.roots.iter().map(|r| logical(r)).rev().collect();
    let mut seen = std::collections::HashSet::new();
    while let Some(path) = stack.pop() {
        if (opts.cancel)() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if !seen.insert(path.to_lowercase()) {
            continue;
        }
        if excluded(&path, &excludes) {
            rep.excluded += 1;
            continue;
        }
        let real = translate(&path);
        let md = match std::fs::symlink_metadata(&real) {
            Ok(m) => m,
            Err(e) => {
                warn(&mut rep, format!("{path}: {e}"));
                continue;
            }
        };
        let modified = unix(md.modified()).to_string();
        let base = Item {
            account: String::new(),
            kind: String::new(),
            id: String::new(),
            path: path.clone(),
            modified,
            size: 0,
            hash: String::new(),
            meta: meta_of(&md),
            chunks: vec![],
        };
        if md.file_type().is_symlink() {
            let target = std::fs::read_link(&real)
                .map(|t| t.display().to_string())
                .unwrap_or_default();
            let mut it = base;
            it.kind = "link".into();
            it.meta = serde_json::json!({ "target": target });
            w.add(it, &[]).map_err(io::Error::other)?;
            continue;
        }
        if md.is_dir() {
            rep.folders += 1;
            let mut children: Vec<String> = match std::fs::read_dir(&real) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .map(|e| {
                        format!(
                            "{}/{}",
                            path.trim_end_matches('/'),
                            e.file_name().to_string_lossy()
                        )
                    })
                    .collect(),
                Err(e) => {
                    warn(&mut rep, format!("{path}: {e}"));
                    vec![]
                }
            };
            children.sort();
            stack.extend(children.into_iter().rev());
            let mut it = base;
            it.kind = "dir".into();
            w.add(it, &[]).map_err(io::Error::other)?;
            continue;
        }
        if !md.is_file() {
            continue; // devices, sockets, pipes
        }
        rep.files += 1;
        rep.bytes += md.len();
        (opts.progress)(&path, rep.bytes, rep.files);
        if let Some(p) = prev.get(&path) {
            if p.size == md.len() && p.modified == base.modified && !p.chunks.is_empty() {
                rep.files_unchanged += 1;
                let mut keep = p.clone();
                keep.meta = base.meta.clone();
                w.keep(keep);
                continue;
            }
        }
        let mut it = base;
        it.kind = "file".into();
        match std::fs::File::open(&real) {
            Ok(mut f) => match w.add_stream(it, &mut f) {
                Ok(()) => {
                    rep.files_read += 1;
                    rep.bytes_read += md.len();
                }
                Err(e) => warn(&mut rep, format!("{path}: {e}")),
            },
            Err(e) => warn(&mut rep, format!("{path}: {e}")),
        }
    }
    if rep.files_failed as usize > warnings.len() {
        warnings.push(format!(
            "and {} more files could not be read",
            rep.files_failed as usize - warnings.len()
        ));
    }
    w.index.warnings = warnings.clone();
    rep.warnings = warnings;
    rep.image_id = w
        .finish(opts.label.clone(), started)
        .map_err(io::Error::other)?;
    Ok(rep)
}

/// A folder backup as a browsable volume: paths are `/`-separated from a
/// root holding each backed-up drive or top folder (`/C:/Users/anna`,
/// `/home/anna`, `//nas/share`).
pub struct IndexVolume {
    repo: Repository,
    /// Folder (lowercase key) -> entries; files by path (lowercase key).
    dirs: BTreeMap<String, BTreeMap<String, Entry>>,
    files: HashMap<String, Item>,
}

fn key(p: &str) -> String {
    let parts = filebrowse::components(p).unwrap_or_default();
    filebrowse::join(&parts).to_lowercase()
}

impl IndexVolume {
    pub fn open(repo: &Repository, m: &ManifestBody) -> core_format::Result<Self> {
        let idx = saas::store::read_index(repo, m)?;
        Ok(Self::from_index(repo, idx))
    }

    pub fn from_index(repo: &Repository, idx: Index) -> Self {
        let mut dirs: BTreeMap<String, BTreeMap<String, Entry>> = BTreeMap::new();
        dirs.entry("/".into()).or_default();
        let mut files = HashMap::new();
        for it in idx.items {
            let parts: Vec<String> = it
                .path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if parts.is_empty() {
                continue;
            }
            // Every folder above it exists, even if not itself backed up.
            for i in 0..parts.len() {
                let parent = filebrowse::join(&parts[..i]).to_lowercase();
                let name = parts[i].clone();
                let last = i + 1 == parts.len();
                let kind = if !last || it.kind == "dir" {
                    EntryKind::Dir
                } else if it.kind == "link" {
                    EntryKind::Link
                } else {
                    EntryKind::File
                };
                let e = dirs.entry(parent).or_default();
                let entry = e.entry(name.to_lowercase()).or_insert(Entry {
                    name: name.clone(),
                    kind: kind.clone(),
                    size: 0,
                    modified: None,
                    hidden: name.starts_with('.'),
                });
                if last {
                    entry.kind = kind.clone();
                    entry.size = if it.kind == "file" { it.size } else { 0 };
                    entry.modified = it.modified.parse().ok();
                }
                if kind == EntryKind::Dir {
                    dirs.entry(filebrowse::join(&parts[..=i]).to_lowercase())
                        .or_default();
                }
            }
            if it.kind == "file" {
                files.insert(key(&it.path), it);
            }
        }
        IndexVolume {
            repo: repo.clone(),
            dirs,
            files,
        }
    }
}

impl Volumefs for IndexVolume {
    fn list(&mut self, path: &str) -> filebrowse::Result<Vec<Entry>> {
        self.dirs
            .get(&key(path))
            .map(|d| d.values().cloned().collect())
            .ok_or_else(|| {
                filebrowse::Error::NotFound(format!("{path} is not a folder in this backup"))
            })
    }

    fn stat(&mut self, path: &str) -> filebrowse::Result<Entry> {
        let k = key(path);
        if k == "/" {
            return Ok(Entry {
                name: String::new(),
                kind: EntryKind::Dir,
                size: 0,
                modified: None,
                hidden: false,
            });
        }
        let (parent, name) = k.rsplit_once('/').unwrap_or(("", &k));
        let parent = if parent.is_empty() { "/" } else { parent };
        self.dirs
            .get(parent)
            .and_then(|d| d.get(name))
            .cloned()
            .ok_or_else(|| filebrowse::Error::NotFound(format!("{path} is not in this backup")))
    }

    fn copy(
        &mut self,
        path: &str,
        out: &mut dyn Write,
        cancel: &dyn Fn() -> bool,
    ) -> filebrowse::Result<u64> {
        let it = self.files.get(&key(path)).ok_or_else(|| {
            filebrowse::Error::NotFound(format!("{path} is not a file in this backup"))
        })?;
        let mut h = blake3::Hasher::new();
        let mut n = 0u64;
        for c in &it.chunks {
            if cancel() {
                return Err(filebrowse::Error::Cancelled);
            }
            let data = self
                .repo
                .get_chunk(c)
                .map_err(|e| filebrowse::Error::Fs(format!("{path}: {e}")))?;
            h.update(&data);
            out.write_all(&data)?;
            n += data.len() as u64;
        }
        if h.finalize().to_hex().as_str() != it.hash {
            return Err(filebrowse::Error::Fs(format!(
                "{path} does not match its recorded hash"
            )));
        }
        Ok(n)
    }
}

/// Read a file of a folder backup into memory (tests and small files).
pub fn read_file(vol: &mut IndexVolume, path: &str) -> filebrowse::Result<Vec<u8>> {
    let mut out = Vec::new();
    vol.copy(path, &mut out, &|| false)?;
    Ok(out)
}

/// Identity translation: read the live files (`UNC/server/share` is the
/// share `\\\\server\\share`).
pub fn live(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("UNC/") {
        return PathBuf::from(format!("\\\\{}", rest.replace('/', "\\")));
    }
    if cfg!(windows) {
        PathBuf::from(p.replace('/', "\\"))
    } else {
        Path::new(p).to_path_buf()
    }
}

/// Bytes of a reader (helper for callers streaming small files).
pub fn read_all(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.read_to_end(&mut v)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_format::backend::{Backend, LocalBackend};
    use core_format::crypto::KdfParams;
    use core_format::InitOptions;
    use std::sync::Arc;

    fn repo(dir: &Path) -> Repository {
        let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.join("repo")).unwrap());
        Repository::init(
            b,
            b"pw",
            InitOptions {
                chunk_size: 64 * 1024,
                kdf: KdfParams::INSECURE_FAST,
                ..Default::default()
            },
        )
        .unwrap()
        .0
    }

    fn machine() -> MachineInfo {
        MachineInfo {
            machine_id: "machine-1".into(),
            hostname: "PM-ACER".into(),
        }
    }

    fn tree(root: &Path) {
        let d = root.join("Documents");
        std::fs::create_dir_all(d.join("Sub Folder")).unwrap();
        std::fs::create_dir_all(d.join("Empty")).unwrap();
        std::fs::create_dir_all(root.join("$Recycle.Bin")).unwrap();
        std::fs::write(d.join("report.txt"), b"quarterly figures").unwrap();
        std::fs::write(
            d.join("Sub Folder").join("big.bin"),
            vec![7u8; 200 * 1024 + 13],
        )
        .unwrap();
        std::fs::write(d.join("scratch.tmp"), b"temp").unwrap();
        std::fs::write(d.join("empty.txt"), b"").unwrap();
        std::fs::write(root.join("$Recycle.Bin").join("deleted.doc"), b"x").unwrap();
    }

    fn run(r: &Repository, roots: &[String], excludes: &[String]) -> Report {
        backup(
            r,
            machine(),
            &live,
            &Options {
                roots,
                excludes,
                label: None,
                cancel: &|| false,
                progress: &|_, _, _| {},
            },
        )
        .unwrap()
    }

    #[test]
    fn backs_up_and_restores_chosen_folders_incrementally() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        tree(&src);
        let r = repo(dir.path());
        let roots = vec![src.display().to_string()];
        let first = run(&r, &roots, &["*.tmp".into()]);
        assert_eq!(first.files, 3, "{first:?}");
        assert_eq!(first.files_read, 3);
        assert!(first.excluded >= 2, "*.tmp and the recycle bin: {first:?}");
        assert_eq!(first.files_failed, 0, "{:?}", first.warnings);

        // Browse and read back through the index.
        let m = r.load_manifest(&first.image_id).unwrap();
        assert_eq!(m.os.family, "files");
        assert_eq!(m.machine.machine_id, "machine-1");
        let mut v = IndexVolume::open(&r, &m).unwrap();
        let base = logical(&src.display().to_string());
        let docs = v.list(&format!("{base}/Documents")).unwrap();
        let names: Vec<_> = docs.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"report.txt")
                && names.contains(&"Sub Folder")
                && names.contains(&"Empty")
        );
        assert!(!names.contains(&"scratch.tmp"));
        assert_eq!(
            read_file(&mut v, &format!("{base}/Documents/report.txt")).unwrap(),
            b"quarterly figures"
        );
        assert_eq!(
            read_file(&mut v, &format!("{base}/documents/sub folder/BIG.bin"))
                .unwrap()
                .len(),
            200 * 1024 + 13
        );
        assert_eq!(
            read_file(&mut v, &format!("{base}/Documents/empty.txt")).unwrap(),
            b""
        );

        // Second run: only the changed file is read.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(
            src.join("Documents/report.txt"),
            b"quarterly figures, revised",
        )
        .unwrap();
        let second = run(&r, &roots, &["*.tmp".into()]);
        assert_eq!(second.files_read, 1, "{second:?}");
        assert_eq!(second.files_unchanged, 2);
        assert!(second.bytes_read < 100);
        let m2 = r.load_manifest(&second.image_id).unwrap();
        assert_eq!(m2.parent, Some(first.image_id));
        let mut v2 = IndexVolume::open(&r, &m2).unwrap();
        assert_eq!(
            read_file(&mut v2, &format!("{base}/Documents/report.txt")).unwrap(),
            b"quarterly figures, revised"
        );
        assert_eq!(
            read_file(&mut v2, &format!("{base}/Documents/Sub Folder/big.bin")).unwrap(),
            vec![7u8; 200 * 1024 + 13]
        );
        // The first backup still has the old version.
        assert_eq!(
            read_file(&mut v, &format!("{base}/Documents/report.txt")).unwrap(),
            b"quarterly figures"
        );

        // Restore through filebrowse, as file restore does for disk images.
        let out = dir.path().join("restored");
        let rr = filebrowse::restore(
            &mut v2,
            &[format!("{base}/Documents")],
            &filebrowse::RestoreOptions {
                target: out.clone(),
                keep_structure: false,
                conflict: filebrowse::Conflict::Rename,
            },
            &|| false,
            &|_, _| {},
        )
        .unwrap();
        assert!(rr.failed.is_empty(), "{rr:?}");
        assert_eq!(
            std::fs::read(out.join("Documents/report.txt")).unwrap(),
            b"quarterly figures, revised"
        );
        assert!(out.join("Documents/Empty").is_dir());
    }

    #[test]
    fn unreadable_paths_are_reported_and_the_rest_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        tree(&src);
        let r = repo(dir.path());
        let roots = vec![
            src.display().to_string(),
            dir.path().join("missing").display().to_string(),
        ];
        let rep = run(&r, &roots, &[]);
        assert_eq!(rep.files_failed, 1);
        assert!(rep.warnings[0].contains("missing"));
        assert_eq!(rep.files, 4);
    }

    #[test]
    fn a_damaged_chunk_is_detected_on_restore() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        tree(&src);
        let r = repo(dir.path());
        let rep = run(&r, &[src.display().to_string()], &[]);
        let m = r.load_manifest(&rep.image_id).unwrap();
        let mut idx = saas::store::read_index(&r, &m).unwrap();
        // Point report.txt at another file's chunks: its hash no longer matches.
        let other = idx
            .items
            .iter()
            .find(|i| i.path.ends_with("big.bin"))
            .unwrap()
            .chunks
            .clone();
        let it = idx
            .items
            .iter_mut()
            .find(|i| i.path.ends_with("report.txt"))
            .unwrap();
        it.chunks = other;
        let path = it.path.clone();
        let mut v = IndexVolume::from_index(&r, idx);
        assert!(read_file(&mut v, &path)
            .unwrap_err()
            .to_string()
            .contains("hash"));
    }

    #[test]
    fn exclusion_patterns() {
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(excluded(
            "C:/Users/anna/AppData/Local/Temp/x.dat",
            &p(&["C:\\Users\\anna\\AppData\\Local\\Temp"])
        ));
        assert!(!excluded(
            "C:/Users/anna/AppData/Local/Temporary/x",
            &p(&["C:/Users/anna/AppData/Local/Temp"])
        ));
        assert!(excluded("/home/a/file.TMP", &p(&["*.tmp"])));
        assert!(excluded("/home/a/~$report.docx", &p(&["~$*"])));
        assert!(excluded("/x/node_modules", &p(&["node_modules"])));
        assert!(!excluded("/x/report.docx", &p(&["*.tmp", "~$*"])));
        assert!(wildcard("a?c*", "abcdef") && !wildcard("a?c", "ac"));
        assert_eq!(
            logical("\\\\nas\\share\\Accounts\\"),
            "UNC/nas/share/Accounts"
        );
        assert_eq!(logical("C:\\Users\\anna"), "C:/Users/anna");
        assert_eq!(
            live("UNC/nas/share/a.txt"),
            PathBuf::from("\\\\nas\\share\\a.txt")
        );
    }
}
