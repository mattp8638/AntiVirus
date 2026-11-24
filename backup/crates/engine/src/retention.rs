//! Retention ("forget") and space reclamation ("prune").
//!
//! Forget deletes image manifests a policy no longer keeps; it never
//! deletes chunks, so it is instant and safe under a shared lock. Prune
//! takes the exclusive lock, reads every manifest, and deletes only chunks
//! that no manifest references. If any manifest cannot be read and
//! verified, prune refuses to delete anything.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use core_format::lock::LockKind;
use core_format::timefmt::{civil_from_days, iso_week};
use core_format::{ManifestBody, Repository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::JobControl;
use crate::{EngineError, Result};

/// Grandfather-father-son retention. Zero turns a rule off; all zero keeps
/// everything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    #[serde(default)]
    pub keep_last: u32,
    /// One image per clock hour (UTC), for the newest this many hours that
    /// have one.
    #[serde(default)]
    pub keep_hourly: u32,
    #[serde(default)]
    pub keep_daily: u32,
    #[serde(default)]
    pub keep_weekly: u32,
    #[serde(default)]
    pub keep_monthly: u32,
    #[serde(default)]
    pub keep_yearly: u32,
}

impl RetentionPolicy {
    pub fn keeps_everything(&self) -> bool {
        self.keep_last == 0
            && self.keep_hourly == 0
            && self.keep_daily == 0
            && self.keep_weekly == 0
            && self.keep_monthly == 0
            && self.keep_yearly == 0
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub image_id: Uuid,
    pub machine_id: String,
    pub created_unix: i64,
    /// The image this one was taken after (orders backups made in the
    /// same second).
    pub parent: Option<Uuid>,
}

/// Indices of `items` (one machine's images), newest first: by time, then
/// by position in the parent chain (backups taken within the same second),
/// then by ID for determinism.
pub fn newest_first<T>(items: &[T], key: impl Fn(&T) -> (Uuid, i64, Option<Uuid>)) -> Vec<usize> {
    let keys: Vec<(Uuid, i64, Option<Uuid>)> = items.iter().map(&key).collect();
    let pos: BTreeMap<Uuid, usize> = keys.iter().enumerate().map(|(i, k)| (k.0, i)).collect();
    // Length of the parent chain within this set (bounded against cycles).
    let depth = |mut i: usize| {
        let mut d = 0usize;
        while let Some(p) = keys[i].2.and_then(|p| pos.get(&p)) {
            d += 1;
            i = *p;
            if d > keys.len() {
                break;
            }
        }
        d
    };
    let depths: Vec<usize> = (0..keys.len()).map(depth).collect();
    let mut idx: Vec<usize> = (0..keys.len()).collect();
    idx.sort_by(|&a, &b| {
        keys[b]
            .1
            .cmp(&keys[a].1)
            .then(depths[b].cmp(&depths[a]))
            .then(keys[b].0.cmp(&keys[a].0))
    });
    idx
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub image_id: Uuid,
    pub machine_id: String,
    pub created_unix: i64,
    pub keep: bool,
    /// Rules that keep it ("last", "daily", ... or "newest").
    pub reasons: Vec<&'static str>,
}

/// Apply `p` to `images` (any machines; each machine is judged on its own).
pub fn select(images: &[Candidate], p: &RetentionPolicy) -> Vec<Decision> {
    let mut by_machine: BTreeMap<&str, Vec<&Candidate>> = BTreeMap::new();
    for c in images {
        by_machine.entry(&c.machine_id).or_default().push(c);
    }
    let mut out = Vec::new();
    for (_, list) in by_machine {
        let order = newest_first(&list, |c| (c.image_id, c.created_unix, c.parent));
        let list: Vec<&Candidate> = order.into_iter().map(|i| list[i]).collect();
        let mut reasons: Vec<Vec<&'static str>> = vec![vec![]; list.len()];
        if p.keeps_everything() {
            for r in &mut reasons {
                r.push("policy keeps everything");
            }
        } else {
            reasons[0].push("newest");
            let rules = [
                ("last", p.keep_last),
                ("hourly", p.keep_hourly),
                ("daily", p.keep_daily),
                ("weekly", p.keep_weekly),
                ("monthly", p.keep_monthly),
                ("yearly", p.keep_yearly),
            ];
            for (name, n) in rules {
                if n == 0 {
                    continue;
                }
                let mut last_key = None;
                let mut kept = 0;
                for (i, c) in list.iter().enumerate() {
                    // keep_last counts images, not periods.
                    let k = if name == "last" {
                        i as i64
                    } else {
                        period(name, c.created_unix)
                    };
                    if last_key != Some(k) {
                        reasons[i].push(name);
                        last_key = Some(k);
                        kept += 1;
                        if kept == n {
                            break;
                        }
                    }
                }
            }
        }
        for (c, r) in list.iter().zip(reasons) {
            out.push(Decision {
                image_id: c.image_id,
                machine_id: c.machine_id.clone(),
                created_unix: c.created_unix,
                keep: !r.is_empty(),
                reasons: r,
            });
        }
    }
    out
}

/// Period an image falls in for a rule (UTC).
fn period(rule: &str, t: i64) -> i64 {
    let day = t.div_euclid(86_400);
    match rule {
        "hourly" => t.div_euclid(3600),
        "daily" => day,
        "weekly" => {
            let (y, w) = iso_week(day);
            y * 100 + w as i64
        }
        "monthly" => {
            let (y, m, _) = civil_from_days(day);
            y * 100 + m as i64
        }
        "yearly" => civil_from_days(day).0,
        _ => t,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ForgetReport {
    pub kept: usize,
    pub removed: Vec<Uuid>,
    /// No longer kept by the policy, but the storage's object lock keeps
    /// them until it expires; removed by a later run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub retained: Vec<Uuid>,
    pub decisions: Vec<Decision>,
    pub dry_run: bool,
}

/// Delete manifests of `machine_ids` (all machines if empty) that `p` does
/// not keep.
pub fn forget(
    repo: &Repository,
    machine_ids: &[String],
    p: &RetentionPolicy,
    dry_run: bool,
) -> Result<ForgetReport> {
    let _lock = repo.lock(LockKind::Shared)?;
    let (all, _unreadable) = repo.load_all_manifests()?;
    let cands: Vec<Candidate> = all
        .iter()
        .filter(|m| machine_ids.is_empty() || machine_ids.contains(&m.machine.machine_id))
        .map(|m| Candidate {
            image_id: m.image_id,
            machine_id: m.machine.machine_id.clone(),
            created_unix: m.created_unix,
            parent: m.parent,
        })
        .collect();
    let decisions = select(&cands, p);
    let mut removed = Vec::new();
    let mut retained = Vec::new();
    for d in decisions.iter().filter(|d| !d.keep) {
        if !dry_run {
            match repo.delete_image(&d.image_id) {
                Ok(()) => {}
                Err(core_format::Error::Retained(_)) => {
                    retained.push(d.image_id);
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        removed.push(d.image_id);
    }
    Ok(ForgetReport {
        kept: decisions.iter().filter(|d| d.keep).count(),
        removed,
        retained,
        decisions,
        dry_run,
    })
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PruneReport {
    pub images: usize,
    pub chunks_total: usize,
    pub chunks_referenced: usize,
    pub chunks_deleted: usize,
    pub bytes_deleted: u64,
    /// Unreferenced, but kept by the storage's object lock until it expires.
    pub chunks_retained: usize,
    /// Objects whose object lock was moved forward (storage with locks).
    pub locks_extended: usize,
    pub dry_run: bool,
}

/// Delete every chunk no manifest references. Exclusive lock.
pub fn prune(repo: &Repository, dry_run: bool, ctl: &JobControl) -> Result<PruneReport> {
    let _lock = repo.lock(LockKind::Exclusive)?;
    let (all, unreadable) = repo.load_all_manifests()?;
    if let Some((id, e)) = unreadable.first() {
        return Err(EngineError::Safety(format!(
            "manifest {id} cannot be read ({e}); its chunks are unknown, so nothing was deleted. Run a full verify and investigate before pruning"
        )));
    }
    let mut referenced: HashSet<String> = all
        .iter()
        .flat_map(ManifestBody::chunk_ids)
        .map(|c| c.object_key())
        .collect();
    // A dedup group member: chunks are shared, so every member's images count
    // (their chunk lists; docs/design/dedup-groups.md). Lists of this
    // member's deleted images go.
    let group = repo.group_references().map_err(|e| {
        EngineError::Safety(format!(
            "{e}; the group's chunks in use are unknown, so nothing was deleted"
        ))
    })?;
    if let Some((live, orphans)) = &group {
        referenced.extend(live.iter().cloned());
        if !dry_run {
            for k in orphans {
                match repo.backend().delete(k) {
                    Ok(()) | Err(core_format::Error::Retained(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let stored: BTreeSet<String> = repo.backend().list("chunks")?.into_iter().collect();
    let mut r = PruneReport {
        images: all.len(),
        chunks_total: stored.len(),
        chunks_referenced: referenced.len(),
        dry_run,
        ..Default::default()
    };
    for k in stored.iter().filter(|k| !referenced.contains(*k)) {
        if !ctl.checkpoint() {
            return Err(EngineError::Cancelled);
        }
        let size = repo.backend().size(k).unwrap_or(0);
        if !dry_run {
            match repo.backend().delete(k) {
                Ok(()) => {}
                Err(core_format::Error::Retained(_)) => {
                    r.chunks_retained += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        r.bytes_deleted += size;
        r.chunks_deleted += 1;
    }
    // Storage with object locks: everything still in use keeps a full lock
    // from now (design: phase-4-storage §5).
    if !dry_run && repo.backend().lock_days().is_some() {
        let mut keep: Vec<String> = stored
            .iter()
            .filter(|k| referenced.contains(*k))
            .cloned()
            .collect();
        for prefix in ["manifests", "keys", "signers"] {
            keep.extend(repo.backend().list(prefix)?);
        }
        keep.push("config.json".into());
        if repo.config().group.is_some() {
            keep.push(core_format::group::MEMBER_KEY_FILE.into());
            keep.extend(
                repo.backend()
                    .list(&format!("refs/{}", repo.config().repo_id))?,
            );
        }
        for k in keep {
            if !ctl.checkpoint() {
                return Err(EngineError::Cancelled);
            }
            match repo.backend().extend_lock(&k) {
                Ok(true) => r.locks_extended += 1,
                Ok(false) | Err(core_format::Error::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_format::timefmt::days_from_civil;

    fn at(y: i64, m: u32, d: u32, h: i64) -> i64 {
        days_from_civil(y, m, d) * 86_400 + h * 3600
    }

    fn c(t: i64) -> Candidate {
        Candidate {
            image_id: Uuid::from_u128(t as u128),
            machine_id: "m".into(),
            created_unix: t,
            parent: None,
        }
    }

    fn kept(d: &[Decision]) -> Vec<i64> {
        let mut v: Vec<i64> = d
            .iter()
            .filter(|x| x.keep)
            .map(|x| x.created_unix)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn keep_everything_by_default() {
        let imgs: Vec<_> = (0..5).map(|i| c(at(2026, 1, 1 + i, 1))).collect();
        assert!(select(&imgs, &RetentionPolicy::default())
            .iter()
            .all(|d| d.keep));
    }

    #[test]
    fn daily_keeps_newest_per_day() {
        // Two backups a day for 5 days.
        let mut imgs = vec![];
        for d in 1..=5 {
            imgs.push(c(at(2026, 3, d, 2)));
            imgs.push(c(at(2026, 3, d, 14)));
        }
        let p = RetentionPolicy {
            keep_daily: 3,
            ..Default::default()
        };
        assert_eq!(
            kept(&select(&imgs, &p)),
            vec![at(2026, 3, 3, 14), at(2026, 3, 4, 14), at(2026, 3, 5, 14)]
        );
    }

    #[test]
    fn hourly_keeps_one_per_hour() {
        // A backup every 15 minutes for 10 hours.
        let base = days_from_civil(2026, 6, 1) * 86_400;
        let imgs: Vec<_> = (0..40).map(|i| c(base + i * 900)).collect();
        let p = RetentionPolicy {
            keep_hourly: 4,
            ..Default::default()
        };
        let k = kept(&select(&imgs, &p));
        // The newest of each of the last 4 hours (9:45, 8:45, 7:45, 6:45).
        assert_eq!(k.len(), 4);
        for h in 6..10 {
            assert!(k.contains(&(base + h * 3600 + 2700)), "hour {h}");
        }
    }

    #[test]
    fn gfs_over_a_year() {
        // One backup per day for 2026.
        let imgs: Vec<_> = (0..365)
            .map(|i| c(days_from_civil(2026, 1, 1) * 86_400 + i * 86_400 + 3600))
            .collect();
        let p = RetentionPolicy {
            keep_last: 2,
            keep_hourly: 0,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            keep_yearly: 1,
        };
        let d = select(&imgs, &p);
        let k = kept(&d);
        // Last 7 days, plus newest of the 4 latest ISO weeks (3 more than the
        // daily ones cover), plus month ends Jul..Nov, plus the year (Dec 31).
        assert!(k.contains(&at(2026, 12, 31, 1)));
        assert!(k.contains(&at(2026, 12, 25, 1)));
        assert!(!k.contains(&at(2026, 12, 24, 1)));
        for (m, last) in [(7u32, 31u32), (8, 31), (9, 30), (10, 31), (11, 30)] {
            assert!(k.contains(&at(2026, m, last, 1)), "month end {m}");
        }
        assert!(!k.contains(&at(2026, 6, 30, 1)), "only 6 months");
        assert!(k.len() < 25);
        // Reasons are recorded.
        let newest = d
            .iter()
            .find(|x| x.created_unix == at(2026, 12, 31, 1))
            .unwrap();
        assert!(newest.reasons.contains(&"newest") && newest.reasons.contains(&"yearly"));
    }

    #[test]
    fn machines_are_independent_and_newest_always_kept() {
        let mut imgs = vec![c(at(2026, 1, 1, 0)), c(at(2026, 1, 2, 0))];
        imgs.push(Candidate {
            image_id: Uuid::from_u128(1),
            machine_id: "other".into(),
            created_unix: at(2020, 1, 1, 0),
            parent: None,
        });
        let p = RetentionPolicy {
            keep_last: 1,
            keep_hourly: 0,
            ..Default::default()
        };
        let d = select(&imgs, &p);
        assert_eq!(kept(&d), vec![at(2020, 1, 1, 0), at(2026, 1, 2, 0)]);
    }

    #[test]
    fn same_second_backups_follow_the_parent_chain() {
        // Three backups in one second; IDs deliberately in the wrong order.
        let (a, b, cc) = (
            Uuid::from_u128(30),
            Uuid::from_u128(20),
            Uuid::from_u128(10),
        );
        let mk = |id, parent| Candidate {
            image_id: id,
            machine_id: "m".into(),
            created_unix: 100,
            parent,
        };
        let imgs = vec![mk(a, None), mk(b, Some(a)), mk(cc, Some(b))];
        let d = select(
            &imgs,
            &RetentionPolicy {
                keep_last: 1,
                keep_hourly: 0,
                ..Default::default()
            },
        );
        let kept: Vec<Uuid> = d.iter().filter(|x| x.keep).map(|x| x.image_id).collect();
        assert_eq!(kept, vec![cc]);
        // A parent cycle (corrupt data) must not hang.
        let cyc = vec![mk(a, Some(b)), mk(b, Some(a))];
        assert_eq!(
            newest_first(&cyc, |c| (c.image_id, c.created_unix, c.parent)).len(),
            2
        );
    }
}
