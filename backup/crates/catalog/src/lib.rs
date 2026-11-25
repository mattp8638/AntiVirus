//! File catalogues of backup images, for searching across backups
//! (design: docs/design/search.md).
//!
//! A catalogue lists every file and folder of an image's browsable volumes:
//! path, size and modification time, nothing of the contents. It is derived
//! from the image, which never changes, so it stays valid for the image's
//! life and can always be built again. Agents keep catalogues in their state
//! directory (zstd-compressed JSON) and search them on request; file names
//! reach the server only as the matches of a search.

use std::io;
use std::path::Path;

use filebrowse::{EntryKind, Volumefs};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
/// Folders nested deeper than this are not walked (a damaged file system).
const MAX_DEPTH: usize = 128;

/// A volume of the image, as the console opens it for browsing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeRef {
    pub label: String,
    pub disk: u32,
    pub partition: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Index into `Catalogue::volumes`.
    pub v: u16,
    /// Path from the volume root, `/`-separated.
    pub p: String,
    /// Size in bytes (0 for folders).
    pub s: u64,
    /// Modification time (Unix seconds), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<i64>,
    /// A folder.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub d: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Catalogue {
    pub version: u32,
    pub volumes: Vec<VolumeRef>,
    pub entries: Vec<Entry>,
    /// Volumes that could not be read, with why.
    #[serde(default)]
    pub skipped: Vec<String>,
}

impl Catalogue {
    pub fn new() -> Self {
        Catalogue {
            version: VERSION,
            ..Default::default()
        }
    }

    /// Add every file and folder of `fs` as volume `vol`.
    pub fn add_volume(
        &mut self,
        vol: VolumeRef,
        fs: &mut dyn Volumefs,
        cancel: &dyn Fn() -> bool,
    ) -> filebrowse::Result<()> {
        let v = self.volumes.len() as u16;
        self.volumes.push(vol);
        let mut dirs = vec![String::new()];
        while let Some(dir) = dirs.pop() {
            if cancel() {
                return Err(filebrowse::Error::Cancelled);
            }
            let Ok(list) = fs.list(if dir.is_empty() { "/" } else { &dir }) else {
                continue;
            };
            for e in list {
                if e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains('/') {
                    continue;
                }
                let p = format!("{dir}/{}", e.name);
                match e.kind {
                    EntryKind::Dir => {
                        if p.matches('/').count() <= MAX_DEPTH {
                            dirs.push(p.clone());
                        }
                        self.entries.push(Entry {
                            v,
                            p,
                            s: 0,
                            m: e.modified,
                            d: true,
                        });
                    }
                    EntryKind::File => self.entries.push(Entry {
                        v,
                        p,
                        s: e.size,
                        m: e.modified,
                        d: false,
                    }),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_vec(self)?;
        std::fs::write(&tmp, zstd::bulk::compress(&json, 9)?)?;
        std::fs::rename(&tmp, path)
    }

    pub fn load(path: &Path) -> io::Result<Catalogue> {
        let data = zstd::decode_all(std::fs::File::open(path)?)?;
        let c: Catalogue = serde_json::from_slice(&data)?;
        if c.version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "catalogue of another version",
            ));
        }
        Ok(c)
    }
}

/// What to look for: words in a file or folder name (all of them, any
/// order), or a pattern with `*` and `?`. With a `/` in it, the whole path
/// is matched instead of the name. Case is ignored.
#[derive(Debug, Clone)]
pub struct Query {
    pattern: String,
    path: bool,
    wildcard: bool,
    words: Vec<String>,
}

impl Query {
    pub fn parse(q: &str) -> Option<Query> {
        let pattern = q.trim().replace('\\', "/").to_lowercase();
        if pattern.is_empty() || pattern.chars().all(|c| c == '*' || c == '?' || c == '/') {
            return None;
        }
        let wildcard = pattern.contains('*') || pattern.contains('?');
        Some(Query {
            path: pattern.contains('/'),
            words: pattern.split_whitespace().map(String::from).collect(),
            wildcard,
            pattern,
        })
    }

    pub fn matches(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        let hay = if self.path {
            lower.as_str()
        } else {
            lower.rsplit('/').next().unwrap_or(&lower)
        };
        if self.wildcard {
            if self.path {
                // A path pattern may match any tail of the path.
                let p = self.pattern.trim_start_matches('/');
                hay.match_indices('/')
                    .map(|(i, _)| &hay[i + 1..])
                    .chain(std::iter::once(hay))
                    .any(|t| wildcard_in(p, t, true))
            } else {
                wildcard(&self.pattern, hay)
            }
        } else {
            self.words.iter().all(|w| hay.contains(w.as_str()))
        }
    }
}

/// `*` and `?` matching; in path patterns `*` and `?` do not match `/`.
pub fn wildcard(p: &str, s: &str) -> bool {
    wildcard_in(p, s, false)
}

fn wildcard_in(p: &str, s: &str, stop_at_slash: bool) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && ((p[pi] == '?' && !(stop_at_slash && s[si] == '/')) || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star.filter(|_| !(stop_at_slash && s[mark] == '/')) {
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

/// A match in one image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hit {
    pub volume: VolumeRef,
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    #[serde(default)]
    pub folder: bool,
}

/// Matches in `cat`, at most `limit`; the flag says whether there were more.
pub fn search(cat: &Catalogue, q: &Query, limit: usize) -> (Vec<Hit>, bool) {
    let mut out = Vec::new();
    for e in &cat.entries {
        if q.matches(&e.p) {
            if out.len() >= limit {
                return (out, true);
            }
            out.push(Hit {
                volume: cat.volumes[e.v as usize].clone(),
                path: e.p.clone(),
                size: e.s,
                modified: e.m,
                folder: e.d,
            });
        }
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebrowse::Entry as FEntry;
    use std::collections::BTreeMap;
    use std::io::Write;

    struct Mem(BTreeMap<String, u64>);

    impl Volumefs for Mem {
        fn list(&mut self, path: &str) -> filebrowse::Result<Vec<FEntry>> {
            let prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{path}/")
            };
            let mut out: BTreeMap<String, FEntry> = BTreeMap::new();
            if path == "/" {
                out.insert(
                    ".".into(),
                    FEntry {
                        name: ".".into(),
                        kind: EntryKind::Dir,
                        size: 0,
                        modified: None,
                        hidden: false,
                    },
                );
            }
            for (p, size) in &self.0 {
                if let Some(rest) = p.strip_prefix(&prefix) {
                    let (name, dir) = match rest.split_once('/') {
                        Some((n, _)) => (n, true),
                        None => (rest, false),
                    };
                    out.entry(name.into()).or_insert(FEntry {
                        name: name.into(),
                        kind: if dir { EntryKind::Dir } else { EntryKind::File },
                        size: if dir { 0 } else { *size },
                        modified: Some(1_700_000_000),
                        hidden: false,
                    });
                }
            }
            Ok(out.into_values().collect())
        }
        fn stat(&mut self, _: &str) -> filebrowse::Result<FEntry> {
            unimplemented!()
        }
        fn copy(
            &mut self,
            _: &str,
            _: &mut dyn Write,
            _: &dyn Fn() -> bool,
        ) -> filebrowse::Result<u64> {
            unimplemented!()
        }
    }

    fn cat() -> Catalogue {
        let mut m = BTreeMap::new();
        m.insert("/Users/anna/Documents/Budget 2026.xlsx".into(), 51_200);
        m.insert("/Users/anna/Documents/Old/budget-2025.xlsx".into(), 40_000);
        m.insert("/Users/anna/Pictures/holiday.jpg".into(), 2_000_000);
        m.insert("/Projects/budget/readme.txt".into(), 100);
        let mut c = Catalogue::new();
        c.add_volume(
            VolumeRef {
                label: "C:\\".into(),
                disk: 0,
                partition: 3,
            },
            &mut Mem(m),
            &|| false,
        )
        .unwrap();
        c
    }

    fn names(c: &Catalogue, q: &str) -> Vec<String> {
        search(c, &Query::parse(q).unwrap(), 100)
            .0
            .into_iter()
            .map(|h| h.path)
            .collect()
    }

    #[test]
    fn finds_by_words_patterns_and_paths() {
        let c = cat();
        assert!(
            !c.entries.iter().any(|e| e.p.ends_with("/.")),
            "the root's own entry is skipped"
        );
        assert_eq!(
            names(&c, "budget 2026"),
            vec!["/Users/anna/Documents/Budget 2026.xlsx"]
        );
        let budget = names(&c, "BUDGET");
        assert!(
            budget.contains(&"/Projects/budget".to_string()),
            "folders are found too"
        );
        assert_eq!(budget.len(), 3);
        assert_eq!(names(&c, "*.xlsx").len(), 2);
        assert_eq!(
            names(&c, "budget-202?.xlsx"),
            vec!["/Users/anna/Documents/Old/budget-2025.xlsx"]
        );
        assert_eq!(
            names(&c, "anna/pictures"),
            vec!["/Users/anna/Pictures", "/Users/anna/Pictures/holiday.jpg"]
        );
        assert_eq!(
            names(&c, "documents/*.xlsx"),
            vec!["/Users/anna/Documents/Budget 2026.xlsx"]
        );
        assert!(Query::parse("  ").is_none() && Query::parse("*").is_none());
        let h = &search(&c, &Query::parse("holiday").unwrap(), 10).0[0];
        assert_eq!(
            (h.size, h.volume.partition, h.folder),
            (2_000_000, 3, false)
        );
    }

    #[test]
    fn limits_and_round_trips() {
        let c = cat();
        let (hits, more) = search(&c, &Query::parse("a").unwrap(), 2);
        assert_eq!(hits.len(), 2);
        assert!(more);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x").join("cat.zst");
        c.save(&p).unwrap();
        assert_eq!(Catalogue::load(&p).unwrap(), c);
    }
}
