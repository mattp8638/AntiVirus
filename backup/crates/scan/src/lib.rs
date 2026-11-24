//! Malware scanning of the files inside backup images.
//!
//! A scan walks the browsable volumes of an image (NTFS, ext2/3/4, through
//! `filebrowse`, read straight from the encrypted repository) and checks
//! each selected file against the platform's detection content, sent with
//! the job:
//!
//! * SHA-256 indicators marked malicious (threat intelligence);
//! * YARA rules, evaluated with `boreal`, a YARA engine written in Rust.
//!
//! File contents never leave the machine that scans; only findings (path,
//! size, SHA-256 and what matched) are reported.
//!
//! Unchanged files are not read again: a cache keyed by path, size and
//! modification time keeps each file's SHA-256 and the YARA matches for a
//! given rule set, so scanning the next backup of the same machine reads
//! only what changed. New indicators apply to cached files without reading
//! them; new rules read the files again.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};

use filebrowse::{EntryKind, Volumefs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One YARA rule source as sent by the server (a file may hold several rules).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub source: String,
}

/// Which files are scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    /// Programs, libraries, scripts, shortcuts and macro documents (by
    /// extension), and files without an extension in Unix program and
    /// temporary folders.
    #[default]
    Executables,
    /// Every file up to the size limit.
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// "hash" or "yara".
    pub kind: String,
    /// Rule name (`<rule file>:<rule>`), or "SHA-256 indicator".
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Volume as shown in the console ("C:\\", "/home" or "disk 0 partition 2").
    pub volume: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub detections: Vec<Detection>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    /// Files whose cached result was used (not read again).
    pub files_cached: u64,
    /// Files above the size limit, not scanned.
    pub files_skipped_large: u64,
    /// Files that could not be read (damaged, unsupported attribute).
    pub files_unreadable: u64,
    pub volumes_scanned: Vec<String>,
    /// Volumes that cannot be browsed (BitLocker, other file systems), with why.
    pub volumes_skipped: Vec<String>,
    /// Rules that did not compile, with why; the others were used.
    pub rule_errors: Vec<String>,
    pub rules_used: usize,
    pub indicators_used: usize,
    pub findings: Vec<Finding>,
    /// Stopped at `max_findings`.
    pub truncated: bool,
}

const EXEC_EXT: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "drv", "efi", "msi", "msp", "mst", "ps1",
    "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "lnk", "jar",
    "py", "sh", "so", "elf", "bin", "dylib", "docm", "dotm", "xlsm", "xltm", "xlam", "pptm",
    "potm", "ppam", "one", "iso", "img", "vhd", "apk", "reg", "inf", "chm", "url", "appx", "msix",
];

/// Folders nested deeper than this are not walked.
const MAX_DEPTH: usize = 128;

const UNIX_EXEC_DIRS: &[&str] = &["bin", "sbin", "libexec", "tmp", "shm"];

/// Whether `path` is scanned under `sel`.
pub fn selected(sel: Selection, path: &str) -> bool {
    if sel == Selection::All {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            EXEC_EXT.contains(&ext.to_ascii_lowercase().as_str())
        }
        _ => path
            .split('/')
            .rev()
            .skip(1)
            .any(|d| UNIX_EXEC_DIRS.contains(&d.to_ascii_lowercase().as_str())),
    }
}

/// Cached result of one file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub sha256: String,
    /// Rule-set digest the YARA matches belong to.
    pub rules: String,
    pub matches: Vec<String>,
}

/// Results of earlier scans of the same machine, by `<volume>|<path>|<size>|<mtime>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cache {
    pub files: BTreeMap<String, CacheEntry>,
    /// Keys used or added since loading (to keep the cache bounded).
    #[serde(skip)]
    pub touched: HashSet<String>,
}

impl Cache {
    /// Above `limit` files, keep only the ones used since loading.
    pub fn trim(&mut self, limit: usize) {
        if self.files.len() > limit {
            let t = std::mem::take(&mut self.touched);
            self.files.retain(|k, _| t.contains(k));
            self.touched = t;
        }
    }
}

/// Compiled detection content.
pub struct Scanner {
    yara: boreal::Scanner,
    rules_digest: String,
    hashes: HashSet<[u8; 32]>,
    pub rule_errors: Vec<String>,
    pub rules_used: usize,
}

impl Scanner {
    /// Compile `rules` (each in its own namespace, so one bad rule does not
    /// stop the others) and load the malicious SHA-256 values.
    pub fn new(indicators: &[String], rules: &[RuleSource]) -> Scanner {
        let mut c = boreal::Compiler::new();
        let mut errors = Vec::new();
        let mut used = 0;
        let mut digest = Sha256::new();
        for (i, r) in rules.iter().enumerate() {
            let ns = format!("r{i}");
            match c.add_rules_str_in_namespace(&r.source, &ns) {
                Ok(_) => {
                    used += 1;
                    digest.update(r.name.as_bytes());
                    digest.update([0]);
                    digest.update(r.source.as_bytes());
                    digest.update([0]);
                }
                Err(e) => errors.push(format!("{}: {}", r.name, short(&format!("{e:?}")))),
            }
        }
        let hashes = indicators
            .iter()
            .filter_map(|h| {
                let mut b = [0u8; 32];
                hex::decode_to_slice(h.trim(), &mut b).ok().map(|_| b)
            })
            .collect();
        Scanner {
            yara: c.finalize(),
            rules_digest: hex::encode(digest.finalize()),
            hashes,
            rule_errors: errors,
            rules_used: used,
        }
    }

    pub fn indicators(&self) -> usize {
        self.hashes.len()
    }

    /// Rule names (`<rule file>:<rule>`) that match `data`.
    fn yara(&self, data: &[u8], rules: &[RuleSource]) -> Vec<String> {
        let r = match self.yara.scan_mem(data) {
            Ok(r) => r,
            Err((_, r)) => r,
        };
        r.rules
            .iter()
            .map(|m| {
                let file = m
                    .namespace
                    .strip_prefix('r')
                    .and_then(|i| i.parse::<usize>().ok())
                    .and_then(|i| rules.get(i))
                    .map(|r| r.name.as_str())
                    .unwrap_or("rule");
                format!("{file}:{}", m.name)
            })
            .collect()
    }

    /// Detections for a file with these contents (or cached results).
    fn detect(&self, sha: &str, matches: &[String]) -> Vec<Detection> {
        let mut out = Vec::new();
        let mut b = [0u8; 32];
        if hex::decode_to_slice(sha, &mut b).is_ok() && self.hashes.contains(&b) {
            out.push(Detection {
                kind: "hash".into(),
                name: "SHA-256 indicator".into(),
            });
        }
        out.extend(matches.iter().map(|m| Detection {
            kind: "yara".into(),
            name: m.clone(),
        }));
        out
    }
}

fn short(s: &str) -> String {
    s.chars().take(300).collect()
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub selection: Selection,
    pub max_file_bytes: u64,
    pub max_findings: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            selection: Selection::Executables,
            max_file_bytes: 64 << 20,
            max_findings: 1000,
        }
    }
}

/// Collects a file's bytes up to a limit.
struct Capped {
    buf: Vec<u8>,
    limit: usize,
}

impl Write for Capped {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.buf.len() + b.len() > self.limit {
            return Err(io::Error::other("file larger than the scan limit"));
        }
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Scan one opened volume, adding to `report`. `progress` is called with
/// the path of each file scanned; `cancel` stops the walk.
#[allow(clippy::too_many_arguments)]
pub fn scan_volume(
    fs: &mut dyn Volumefs,
    volume: &str,
    scanner: &Scanner,
    rules: &[RuleSource],
    opts: &Options,
    cache: &mut Cache,
    report: &mut Report,
    progress: &mut dyn FnMut(&str, u64),
    cancel: &dyn Fn() -> bool,
) -> filebrowse::Result<()> {
    let mut dirs = vec![String::new()];
    while let Some(dir) = dirs.pop() {
        if cancel() {
            return Err(filebrowse::Error::Cancelled);
        }
        let entries = match fs.list(if dir.is_empty() { "/" } else { &dir }) {
            Ok(e) => e,
            Err(filebrowse::Error::Cancelled) => return Err(filebrowse::Error::Cancelled),
            Err(_) => {
                report.files_unreadable += 1;
                continue;
            }
        };
        for e in entries {
            // The NTFS root lists itself as "."; ext lists "." and "..".
            if e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains('/') {
                continue;
            }
            let path = format!("{dir}/{}", e.name);
            match e.kind {
                // Deeper than any real tree: a loop in a damaged file system.
                EntryKind::Dir if path.matches('/').count() > MAX_DEPTH => {
                    report.files_unreadable += 1
                }
                EntryKind::Dir => dirs.push(path.clone()),
                EntryKind::File => {}
                _ => continue,
            }
            if e.kind != EntryKind::File || !selected(opts.selection, &path) {
                continue;
            }
            if e.size > opts.max_file_bytes {
                report.files_skipped_large += 1;
                continue;
            }
            let key = format!("{volume}|{path}|{}|{}", e.size, e.modified.unwrap_or(0));
            let cached = cache
                .files
                .get(&key)
                .filter(|c| c.rules == scanner.rules_digest)
                .cloned();
            cache.touched.insert(key.clone());
            let entry = match cached {
                Some(c) => {
                    report.files_cached += 1;
                    c
                }
                None => {
                    if cancel() {
                        return Err(filebrowse::Error::Cancelled);
                    }
                    progress(&path, e.size);
                    let mut out = Capped {
                        buf: Vec::with_capacity(e.size as usize),
                        limit: opts.max_file_bytes as usize,
                    };
                    if fs.copy(&path, &mut out, cancel).is_err() {
                        if cancel() {
                            return Err(filebrowse::Error::Cancelled);
                        }
                        report.files_unreadable += 1;
                        continue;
                    }
                    report.bytes_scanned += out.buf.len() as u64;
                    let c = CacheEntry {
                        sha256: hex::encode(Sha256::digest(&out.buf)),
                        rules: scanner.rules_digest.clone(),
                        matches: scanner.yara(&out.buf, rules),
                    };
                    cache.files.insert(key, c.clone());
                    c
                }
            };
            report.files_scanned += 1;
            let detections = scanner.detect(&entry.sha256, &entry.matches);
            if !detections.is_empty() {
                if report.findings.len() >= opts.max_findings {
                    report.truncated = true;
                    continue;
                }
                report.findings.push(Finding {
                    volume: volume.to_string(),
                    path,
                    size: e.size,
                    sha256: entry.sha256,
                    detections,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebrowse::Entry;

    /// A volume held in memory: path -> contents ("/" separated).
    struct Mem(BTreeMap<String, Vec<u8>>, std::cell::Cell<u32>);

    impl Volumefs for Mem {
        fn list(&mut self, path: &str) -> filebrowse::Result<Vec<Entry>> {
            let prefix = if path == "/" {
                String::from("/")
            } else {
                format!("{path}/")
            };
            let mut out: BTreeMap<String, Entry> = BTreeMap::new();
            // Like NTFS, the root lists itself.
            if path == "/" {
                out.insert(
                    ".".into(),
                    Entry {
                        name: ".".into(),
                        kind: EntryKind::Dir,
                        size: 0,
                        modified: None,
                        hidden: false,
                    },
                );
            }
            for (p, d) in &self.0 {
                if let Some(rest) = p.strip_prefix(&prefix) {
                    let (name, dir) = match rest.split_once('/') {
                        Some((n, _)) => (n, true),
                        None => (rest, false),
                    };
                    out.entry(name.to_string()).or_insert(Entry {
                        name: name.to_string(),
                        kind: if dir { EntryKind::Dir } else { EntryKind::File },
                        size: if dir { 0 } else { d.len() as u64 },
                        modified: Some(1_700_000_000),
                        hidden: false,
                    });
                }
            }
            Ok(out.into_values().collect())
        }
        fn stat(&mut self, _: &str) -> filebrowse::Result<Entry> {
            unimplemented!()
        }
        fn copy(
            &mut self,
            path: &str,
            out: &mut dyn Write,
            _: &dyn Fn() -> bool,
        ) -> filebrowse::Result<u64> {
            self.1.set(self.1.get() + 1);
            let d = &self.0[path];
            out.write_all(d)?;
            Ok(d.len() as u64)
        }
    }

    fn volume() -> Mem {
        let mut m = BTreeMap::new();
        m.insert(
            "/Windows/System32/notepad.exe".into(),
            b"MZ harmless program".to_vec(),
        );
        m.insert(
            "/Users/anna/Downloads/invoice.pdf.exe".into(),
            b"MZ EVIL-PAYLOAD-7731 dropper".to_vec(),
        );
        m.insert(
            "/Users/anna/Documents/report.docx".into(),
            b"EVIL-PAYLOAD-7731 in a document".to_vec(),
        );
        m.insert(
            "/Users/anna/Documents/tool.ps1".into(),
            b"known bad script".to_vec(),
        );
        m.insert(
            "/usr/bin/sshd-helper".into(),
            b"\x7fELF EVIL-PAYLOAD-7731".to_vec(),
        );
        m.insert("/big/huge.exe".into(), vec![b'A'; 4096]);
        Mem(m, Default::default())
    }

    fn rules() -> Vec<RuleSource> {
        vec![
            RuleSource {
                name: "broken.yar".into(),
                source: "rule broken { strings: $a = \"x\" condition: $a and }".into(),
            },
            RuleSource {
                name: "test.yar".into(),
                source: "rule Test_Payload { strings: $a = \"EVIL-PAYLOAD-7731\" condition: $a }"
                    .into(),
            },
        ]
    }

    fn sha(d: &[u8]) -> String {
        hex::encode(Sha256::digest(d))
    }

    fn run(v: &mut Mem, s: &Scanner, r: &[RuleSource], o: &Options, cache: &mut Cache) -> Report {
        let mut rep = Report::default();
        scan_volume(v, "C:\\", s, r, o, cache, &mut rep, &mut |_, _| {}, &|| {
            false
        })
        .unwrap();
        rep
    }

    #[test]
    fn finds_yara_and_hash_matches_in_selected_files() {
        let mut v = volume();
        let r = rules();
        let s = Scanner::new(&[sha(b"known bad script")], &r);
        assert_eq!(s.rules_used, 1);
        assert_eq!(
            s.rule_errors.len(),
            1,
            "the broken rule is reported, the other used"
        );
        let o = Options {
            max_file_bytes: 1024,
            ..Default::default()
        };
        let rep = run(&mut v, &s, &r, &o, &mut Cache::default());
        let found: Vec<(&str, &str)> = rep
            .findings
            .iter()
            .flat_map(|f| {
                f.detections
                    .iter()
                    .map(move |d| (f.path.as_str(), d.name.as_str()))
            })
            .collect();
        assert!(found.contains(&(
            "/Users/anna/Downloads/invoice.pdf.exe",
            "test.yar:Test_Payload"
        )));
        assert!(found.contains(&("/Users/anna/Documents/tool.ps1", "SHA-256 indicator")));
        assert!(found.contains(&("/usr/bin/sshd-helper", "test.yar:Test_Payload")));
        // A .docx is not an executable: not scanned unless all files are.
        assert!(!found.iter().any(|(p, _)| p.ends_with("report.docx")));
        assert_eq!(rep.files_skipped_large, 1);
        assert_eq!(rep.files_scanned, 4);

        let all = Options {
            selection: Selection::All,
            ..o
        };
        let rep = run(&mut v, &s, &r, &all, &mut Cache::default());
        assert!(rep.findings.iter().any(|f| f.path.ends_with("report.docx")));
    }

    #[test]
    fn unchanged_files_are_not_read_again_and_new_indicators_still_apply() {
        let mut v = volume();
        let r = rules();
        let o = Options::default();
        let mut cache = Cache::default();
        let s = Scanner::new(&[], &r);
        let first = run(&mut v, &s, &r, &o, &mut cache);
        let reads = v.1.get();
        assert!(reads >= 4);
        // A new indicator for a file already scanned: found from the cache.
        let s2 = Scanner::new(&[sha(b"MZ harmless program")], &r);
        let second = run(&mut v, &s2, &r, &o, &mut cache);
        assert_eq!(v.1.get(), reads, "nothing read again");
        assert_eq!(second.files_cached, first.files_scanned);
        assert!(second
            .findings
            .iter()
            .any(|f| f.path.ends_with("notepad.exe")));
        // New rules: files are read again.
        let mut r2 = r.clone();
        r2.push(RuleSource {
            name: "more.yar".into(),
            source: "rule Harmless { strings: $a = \"harmless\" condition: $a }".into(),
        });
        let s3 = Scanner::new(&[], &r2);
        let third = run(&mut v, &s3, &r2, &o, &mut cache);
        assert!(v.1.get() > reads);
        assert!(third
            .findings
            .iter()
            .any(|f| f.detections.iter().any(|d| d.name == "more.yar:Harmless")));
        // Trimming keeps what was used.
        let n = cache.files.len();
        cache.files.insert(
            "old|/gone|1|1".into(),
            cache.files.values().next().unwrap().clone(),
        );
        cache.trim(n);
        assert_eq!(cache.files.len(), n);
        assert!(!cache.files.contains_key("old|/gone|1|1"));
    }

    #[test]
    fn selection_rules() {
        let e = Selection::Executables;
        for yes in [
            "/a/b.EXE",
            "/x/y.ps1",
            "/u/l/x.so",
            "/usr/sbin/daemon",
            "/tmp/payload",
            "/d/m.docm",
        ] {
            assert!(selected(e, yes), "{yes}");
        }
        for no in ["/a/b.txt", "/home/anna/notes", "/a/.exe", "/d/report.docx"] {
            assert!(!selected(e, no), "{no}");
        }
        assert!(selected(Selection::All, "/a/b.txt"));
    }

    #[test]
    fn findings_are_capped() {
        let mut v = volume();
        let r = rules();
        let s = Scanner::new(&[], &r);
        let o = Options {
            max_findings: 1,
            ..Default::default()
        };
        let rep = run(&mut v, &s, &r, &o, &mut Cache::default());
        assert_eq!(rep.findings.len(), 1);
        assert!(rep.truncated);
    }
}
