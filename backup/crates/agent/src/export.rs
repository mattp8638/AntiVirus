//! eDiscovery export of SaaS backup items (docs/design/ediscovery.md): the
//! chosen mail, files, records and messages are read from the backup (each
//! checked against the BLAKE3 hash it was stored with), written as files
//! with `fenrir-manifest.json` listing every item's SHA-256, packed and
//! encrypted for the browser like a file download.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::bail;
use protocol::{JobState, JobUpdate, RepoAccess};
use uuid::Uuid;

use crate::jobs::{finished, open_repo, Ctx, Reporter};

/// Which items: each list empty means "any".
pub struct Filter<'a> {
    pub accounts: &'a [String],
    pub kinds: &'a [String],
    pub items: &'a [String],
}

impl Filter<'_> {
    pub fn wants(&self, it: &saas::store::Item) -> bool {
        (self.accounts.is_empty()
            || self
                .accounts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&it.account)))
            && (self.kinds.is_empty() || self.kinds.contains(&it.kind))
            && (self.items.is_empty() || self.items.iter().any(|x| x == &it.id || x == &it.path))
    }
}

/// A file name for an item: its account and kind as folders, its path made
/// safe for every file system, and an extension for its format.
pub fn file_name(it: &saas::store::Item) -> PathBuf {
    let safe = |s: &str| -> String {
        let t: String = s
            .chars()
            .map(|c| {
                if c.is_control() || "<>:\"\\|?*".contains(c) {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        let t = t.trim().trim_matches('.').to_string();
        if t.is_empty() {
            "_".into()
        } else {
            t.chars().take(120).collect()
        }
    };
    let mut p = PathBuf::from(safe(&it.account));
    p.push(safe(&it.kind));
    let parts: Vec<&str> = it
        .path
        .split('/')
        .filter(|s| !s.is_empty() && *s != "..")
        .collect();
    for s in parts.iter().take(parts.len().saturating_sub(1)).take(12) {
        p.push(safe(s));
    }
    let leaf = safe(parts.last().copied().unwrap_or(&it.id));
    let ext = match it.kind.as_str() {
        "mail" => ".eml",
        "file" | "site-file" => "",
        _ => ".json",
    };
    p.push(if ext.is_empty() || leaf.to_lowercase().ends_with(ext) {
        leaf
    } else {
        format!("{leaf}{ext}")
    });
    p
}

/// `name`, or `name (2)`, `name (3)`... when taken.
fn unique(root: &Path, rel: PathBuf, used: &mut HashSet<PathBuf>) -> PathBuf {
    let mut cand = rel.clone();
    let mut n = 2;
    while used.contains(&cand) || root.join(&cand).exists() {
        let stem = rel
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ext = rel
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        cand = rel.with_file_name(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    used.insert(cand.clone());
    cand
}

/// What `write_items` produced: manifest entries, items that failed, the
/// service and tenant, and when the backup was taken.
pub struct Written {
    pub entries: Vec<serde_json::Value>,
    pub failed: Vec<serde_json::Value>,
    pub service: String,
    pub tenant: String,
    pub backed_up: String,
}

/// Read the chosen items of a SaaS backup into `root` (each checked
/// against its backup-time hash) and list them with their SHA-256.
pub fn write_items(
    repo: &core_format::Repository,
    image: Uuid,
    filter: &Filter,
    root: &Path,
    step: &dyn Fn(usize, usize, &str) -> anyhow::Result<()>,
) -> anyhow::Result<Written> {
    use sha2::{Digest, Sha256};
    let m = repo.load_manifest(&image)?;
    if m.os.family != "saas" {
        bail!("that backup is not of a cloud service; export its files with a file download");
    }
    let idx = saas::store::read_index(repo, &m)?;
    let chosen: Vec<&saas::store::Item> = idx.items.iter().filter(|i| filter.wants(i)).collect();
    if chosen.is_empty() {
        bail!("no item of this backup matches");
    }
    std::fs::create_dir_all(root)?;
    let (mut entries, mut failed, mut used) = (Vec::new(), Vec::new(), HashSet::new());
    let mut bytes = 0u64;
    for (n, it) in chosen.iter().enumerate() {
        step(n, chosen.len(), &it.path)?;
        // read_item checks the bytes against the hash recorded at backup time.
        match saas::store::read_item(repo, it) {
            Ok(data) => {
                bytes += data.len() as u64;
                if bytes > crate::download::MAX_BYTES {
                    bail!("the items come to more than a download carries (4 GiB): export fewer at a time");
                }
                let rel = unique(root, file_name(it), &mut used);
                std::fs::create_dir_all(root.join(&rel).parent().unwrap_or(root))?;
                std::fs::write(root.join(&rel), &data)?;
                entries.push(serde_json::json!({
                    "file": rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"),
                    "account": it.account, "kind": it.kind, "id": it.id, "path": it.path,
                    "modified": it.modified, "size": data.len(), "blake3": it.hash,
                    "sha256": crate::download::hex(&Sha256::digest(&data)), "meta": it.meta,
                }));
            }
            Err(e) => failed
                .push(serde_json::json!({ "id": it.id, "path": it.path, "error": e.to_string() })),
        }
    }
    Ok(Written {
        entries,
        failed,
        service: idx.service,
        tenant: idx.tenant,
        backed_up: m.created,
    })
}

pub fn export_saas(
    ctx: &Ctx,
    access: &RepoAccess,
    image: Uuid,
    filter: &Filter,
    recipient: &str,
    job: Uuid,
    rep: &Reporter,
) -> anyhow::Result<JobUpdate> {
    let repo = open_repo(ctx, access)?;
    let work = crate::config::state_dir()
        .join("downloads")
        .join(job.to_string());
    let _ = std::fs::remove_dir_all(&work);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(work.clone());
    let root = work.join("items");
    let w = write_items(&repo, image, filter, &root, &|n, total, path| {
        if ctx.ctl.is_cancelled() {
            bail!("cancelled");
        }
        rep.progress("reading", n as u64, total as u64, path);
        Ok(())
    })?;
    let failed = w.failed.len();
    let warnings: Vec<String> = w
        .failed
        .iter()
        .map(|f| {
            format!(
                "{}: {}",
                f["path"].as_str().unwrap_or(""),
                f["error"].as_str().unwrap_or("")
            )
        })
        .take(100)
        .collect();
    let (sha, count) = crate::download::write_manifest(
        &root,
        serde_json::json!({
            "image_id": image, "service": w.service, "tenant": w.tenant, "backed_up": w.backed_up,
            "filter": { "accounts": filter.accounts, "kinds": filter.kinds, "items": filter.items.len() },
            "failed": w.failed,
        }),
        w.entries,
    )?;
    rep.progress("packing", 0, 1, "");
    let tar = work.join("export.tar");
    crate::download::tar_dir(&root, &mut std::fs::File::create(&tar)?)?;
    let header = crate::browse::send_archive(
        ctx,
        rep,
        job,
        &tar,
        recipient,
        &format!("ediscovery-{}.tar", &image.to_string()[..8]),
    )?;
    let mut u = finished(if failed == 0 {
        JobState::Succeeded
    } else {
        JobState::Warning
    });
    u.warnings = warnings;
    u.result = Some(serde_json::json!({
        "download": header, "manifest_sha256": sha, "manifest_files": count, "failed": failed,
    }));
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::{file_name, Filter};
    use std::path::PathBuf;

    fn item(kind: &str, path: &str) -> saas::store::Item {
        saas::store::Item {
            account: "ann@contoso.com".into(),
            kind: kind.into(),
            id: "AAMk1".into(),
            path: path.into(),
            modified: String::new(),
            size: 1,
            hash: String::new(),
            meta: serde_json::Value::Null,
            chunks: vec![],
        }
    }

    #[test]
    fn names_and_filters() {
        assert_eq!(
            file_name(&item("mail", "Inbox/Budget: Q3?")),
            PathBuf::from("ann@contoso.com/mail/Inbox/Budget_ Q3_.eml")
        );
        assert_eq!(
            file_name(&item("file", "/Documents/../plan.xlsx")),
            PathBuf::from("ann@contoso.com/file/Documents/plan.xlsx")
        );
        assert_eq!(
            file_name(&item("record", "Account/001")),
            PathBuf::from("ann@contoso.com/record/Account/001.json")
        );
        let none: Vec<String> = vec![];
        let mail = vec!["mail".to_string()];
        let f = Filter {
            accounts: &["ANN@contoso.com".into()],
            kinds: &mail,
            items: &none,
        };
        assert!(f.wants(&item("mail", "x")) && !f.wants(&item("file", "x")));
        let ids = vec!["AAMk1".to_string()];
        assert!(Filter {
            accounts: &none,
            kinds: &none,
            items: &ids
        }
        .wants(&item("file", "y")));
    }
}
