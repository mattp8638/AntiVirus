//! Hyper-V Resilient Change Tracking (RCT) for VM backups
//! (design: docs/design/frequent-backups.md §3).
//!
//! After a VM is backed up, its recovery checkpoint is converted to a
//! *reference point* (`Msvm_VirtualSystemSnapshotService.ConvertToReferencePoint`)
//! instead of being destroyed: Hyper-V merges the differencing disks as
//! before, and keeps an RCT identifier for each virtual disk. On the next
//! backup, `Msvm_ImageManagementService.GetVirtualDiskChanges` with that
//! identifier lists the byte ranges written since, and the engine reads only
//! the chunks those ranges touch; the rest is taken from the previous image.
//!
//! Every way this can go wrong reads the disks in full instead: no record
//! for the VM in this repository, a disk added, replaced or resized, RCT not
//! available (VM configuration version below 6.2), the previous image gone,
//! a query that fails. The disks are also read in full once a week, and
//! about one chunk in 64 reported unchanged is read anyway and compared with
//! the previous image; a difference fails the tracked run and the agent
//! backs up again reading everything.
//!
//! What this module records is kept in `hyperv-rct.json` in the state
//! directory, per repository and VM. Script text and output parsing are
//! platform-independent and unit-tested; only running them needs Windows.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context};
use core_format::extent::Extent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::hyperv::CheckpointDisk;

/// Read every disk in full at least this often, whatever the tracker says.
pub const FULL_READ_EVERY_SECS: i64 = 7 * 24 * 3600;
/// Spot-check about one in this many chunks reported unchanged.
pub const SPOT_CHECK_ONE_IN: u32 = 64;

const STATE_FILE: &str = "hyperv-rct.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// Key: `<repository id>/<VM id>`.
    #[serde(default)]
    pub vms: BTreeMap<String, Entry>,
}

/// The reference point left after the last image of a VM in a repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// The image taken at the reference point.
    pub image_id: Uuid,
    pub reference_point_id: String,
    pub disks: Vec<TrackedDisk>,
    /// When the disks were last read in full (Unix seconds).
    pub full_read_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackedDisk {
    pub path: String,
    pub disk_id: String,
    pub size: u64,
    pub rct_id: String,
}

pub fn key(repo_id: Uuid, vm_id: &str) -> String {
    format!("{repo_id}/{}", vm_id.to_ascii_lowercase())
}

pub fn load(dir: &Path) -> State {
    std::fs::read(dir.join(STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(dir: &Path, s: &State) -> anyhow::Result<()> {
    let p = dir.join(STATE_FILE);
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    std::fs::rename(&tmp, &p).with_context(|| format!("saving {}", p.display()))
}

fn norm_id(s: &str) -> String {
    s.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase()
}

/// One query per disk that can be tracked; `None` reads that disk in full.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub base_image: Uuid,
    pub queries: Vec<Option<Query>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Query {
    pub path: String,
    pub limit_id: String,
    #[serde(skip)]
    pub size: u64,
}

/// What to ask Hyper-V for, or why the disks are read in full.
pub fn plan(entry: Option<&Entry>, disks: &[CheckpointDisk], now: i64) -> Result<Plan, String> {
    let e = entry.ok_or("no reference point recorded for this VM in this repository")?;
    if now - e.full_read_unix >= FULL_READ_EVERY_SECS {
        return Err("the weekly full read is due".into());
    }
    let queries: Vec<Option<Query>> = disks
        .iter()
        .map(|d| {
            let t = e.disks.iter().find(|t| {
                let same_disk = if !d.disk_id.is_empty() && !t.disk_id.is_empty() {
                    norm_id(&d.disk_id) == norm_id(&t.disk_id)
                } else {
                    d.path.eq_ignore_ascii_case(&t.path)
                };
                same_disk && d.size != 0 && d.size == t.size && rct_id_ok(&t.rct_id)
            })?;
            Some(Query {
                path: d.path.clone(),
                limit_id: t.rct_id.clone(),
                size: d.size,
            })
        })
        .collect();
    if queries.iter().all(|q| q.is_none()) {
        return Err("none of the VM's disks match the ones recorded at the last backup".into());
    }
    Ok(Plan {
        base_image: e.image_id,
        queries,
    })
}

/// RCT identifiers look like `rctX:<GUID>:<number>`; only such characters
/// reach a script, and they are passed base64-encoded in any case.
fn rct_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'{' | b'}'))
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

const PS_CHANGES: &str = r#"
$req = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQ__')) | ConvertFrom-Json)
$ims = Get-WmiObject -Namespace $ns -Class Msvm_ImageManagementService
$out = @(foreach ($d in $req) {
  try {
    $size = [uint64](Get-VHD -Path $d.path).Size
    $off = [uint64]0
    $list = New-Object System.Collections.Generic.List[string]
    while ($off -lt $size) {
      $in = $ims.GetMethodParameters('GetVirtualDiskChanges')
      $in.Path = $d.path
      $in.LimitId = $d.limit_id
      $in.ByteOffset = $off
      $in.ByteLength = $size - $off
      $r = $ims.InvokeMethod('GetVirtualDiskChanges', $in, $null)
      if ($r.ReturnValue -ne 0) { throw "GetVirtualDiskChanges returned $($r.ReturnValue)" }
      $offs = @($r.ByteOffsets); $lens = @($r.ByteLengths)
      if ($offs.Count -ne $lens.Count) { throw 'GetVirtualDiskChanges returned mismatched lists' }
      for ($i = 0; $i -lt $offs.Count; $i++) { $list.Add("$($offs[$i]),$($lens[$i])") }
      $done = [uint64]$r.ProcessedByteLength
      if ($done -eq 0) { throw 'GetVirtualDiskChanges made no progress' }
      $off += $done
    }
    [pscustomobject]@{ path = $d.path; size = $size; ranges = ($list -join ';'); error = $null }
  } catch {
    [pscustomobject]@{ path = $d.path; size = 0; ranges = ''; error = $_.Exception.Message }
  }
})
ConvertTo-Json -InputObject $out -Depth 3 -Compress
"#;

/// Changed ranges of the frozen disks since each disk's `limit_id`.
pub fn changes_script(queries: &[&Query]) -> anyhow::Result<String> {
    if queries.iter().any(|q| !rct_id_ok(&q.limit_id)) {
        bail!("invalid change tracking id");
    }
    let req = serde_json::to_string(queries)?;
    Ok(format!(
        "{}{}",
        crate::hyperv::PS_PRELUDE,
        PS_CHANGES.replace("__REQ__", &b64(&req))
    ))
}

#[derive(Debug, Deserialize)]
struct PsChanges {
    path: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    ranges: String,
    error: Option<String>,
}

/// Per query (same order): the changed ranges, or why that disk is read in
/// full. Ranges must lie inside the disk.
pub fn parse_changes(
    json: &str,
    queries: &[&Query],
) -> anyhow::Result<Vec<Result<Vec<Extent>, String>>> {
    let v = serde_json::from_str::<serde_json::Value>(json.trim())
        .context("unexpected change tracking output from PowerShell")?;
    let rows: Vec<PsChanges> = match v {
        serde_json::Value::Array(_) => serde_json::from_value(v)?,
        other => vec![serde_json::from_value(other)?],
    };
    Ok(queries
        .iter()
        .map(|q| {
            let r = rows
                .iter()
                .find(|r| r.path.eq_ignore_ascii_case(&q.path))
                .ok_or_else(|| format!("no answer for {}", q.path))?;
            if let Some(e) = &r.error {
                return Err(e.clone());
            }
            if r.size != q.size {
                return Err(format!("{} changed size", q.path));
            }
            let mut out = Vec::new();
            for part in r.ranges.split(';').filter(|p| !p.is_empty()) {
                let (o, l) = part
                    .split_once(',')
                    .and_then(|(o, l)| {
                        Some((o.trim().parse::<u64>().ok()?, l.trim().parse::<u64>().ok()?))
                    })
                    .ok_or_else(|| format!("unreadable range {part:?}"))?;
                if o.checked_add(l).is_none_or(|end| end > q.size) {
                    return Err(format!("range {o}+{l} is outside the disk"));
                }
                out.push(Extent(o, l));
            }
            Ok(out)
        })
        .collect())
}

const PS_TO_REFERENCE: &str = r#"
$SnapId = '__SNAPID__'
$snap = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSettingData -Filter "InstanceID='$SnapId'"
if (-not $snap) { throw 'The recovery checkpoint was not found' }
$svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSnapshotService
$in = $svc.GetMethodParameters('ConvertToReferencePoint')
$in.AffectedSnapshot = $snap.__PATH
$r = $svc.InvokeMethod('ConvertToReferencePoint', $in, $null)
$rp = $null
if ($r.ReturnValue -eq 0 -and $r.ResultingReferencePoint) {
  $rp = [wmi]$r.ResultingReferencePoint
} else {
  Wait-WmiJob $r 'Converting the checkpoint to a reference point'
  if ($r.ResultingReferencePoint) { $rp = [wmi]$r.ResultingReferencePoint }
  elseif ($r.Job) { $rp = @(([wmi]$r.Job).GetRelated('Msvm_VirtualSystemReferencePoint')) | Select-Object -First 1 }
}
if (-not $rp) { throw 'The reference point was not found after converting the checkpoint' }
[pscustomobject]@{
  reference_point_id = [string]$rp.InstanceID
  rct_ids = @($rp.ResilientChangeTrackingIdentifiers | ForEach-Object { [string]$_ })
  disk_ids = @($rp.VirtualDiskIdentifiers | ForEach-Object { [string]$_ })
} | ConvertTo-Json -Depth 3 -Compress
"#;

const PS_DESTROY_REFERENCE: &str = r#"
$RpId = '__RPID__'
$rp = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemReferencePoint -Filter "InstanceID='$($RpId.Replace('\','\\'))'"
if ($rp) {
  $svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemReferencePointService
  $in = $svc.GetMethodParameters('DestroyReferencePoint')
  $in.AffectedReferencePoint = $rp.__PATH
  Wait-WmiJob ($svc.InvokeMethod('DestroyReferencePoint', $in, $null)) 'Removing the previous reference point'
}
'{"ok":true}'
"#;

/// Instance IDs of checkpoints and reference points: "Microsoft:<GUID>",
/// sometimes with further ":<GUID>" or "\" parts.
fn instance_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'\\'))
}

pub fn to_reference_script(snapshot_id: &str) -> anyhow::Result<String> {
    if !instance_id_ok(snapshot_id) {
        bail!("invalid snapshot id {snapshot_id:?}");
    }
    Ok(format!(
        "{}{}",
        crate::hyperv::PS_PRELUDE,
        PS_TO_REFERENCE.replace("__SNAPID__", snapshot_id)
    ))
}

pub fn destroy_reference_script(id: &str) -> anyhow::Result<String> {
    if !instance_id_ok(id) {
        bail!("invalid reference point id {id:?}");
    }
    Ok(format!(
        "{}{}",
        crate::hyperv::PS_PRELUDE,
        PS_DESTROY_REFERENCE.replace("__RPID__", id)
    ))
}

#[derive(Debug, Deserialize)]
struct PsReference {
    reference_point_id: String,
    #[serde(default)]
    rct_ids: serde_json::Value,
    #[serde(default)]
    disk_ids: serde_json::Value,
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

/// The reference point and the RCT identifier of each backed-up disk. A
/// disk whose identifier cannot be matched is left out (read in full next
/// time).
pub fn parse_reference(
    json: &str,
    disks: &[CheckpointDisk],
) -> anyhow::Result<(String, Vec<TrackedDisk>)> {
    let p: PsReference = serde_json::from_str(json.trim())
        .context("unexpected reference point output from PowerShell")?;
    if !instance_id_ok(&p.reference_point_id) {
        bail!("unexpected reference point id {:?}", p.reference_point_id);
    }
    let rct = strings(&p.rct_ids);
    let ids = strings(&p.disk_ids);
    let mut out = Vec::new();
    for d in disks {
        let rct_id = if ids.len() == rct.len() && !d.disk_id.is_empty() {
            ids.iter()
                .position(|i| norm_id(i) == norm_id(&d.disk_id))
                .map(|i| rct[i].clone())
        } else if disks.len() == 1 && rct.len() == 1 {
            Some(rct[0].clone())
        } else {
            None
        };
        if let Some(rct_id) = rct_id.filter(|r| rct_id_ok(r)) {
            out.push(TrackedDisk {
                path: d.path.clone(),
                disk_id: d.disk_id.clone(),
                size: d.size,
                rct_id,
            });
        }
    }
    Ok((p.reference_point_id, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(path: &str, id: &str, size: u64) -> CheckpointDisk {
        CheckpointDisk {
            path: path.into(),
            controller: "SCSI 0:0".into(),
            disk_id: id.into(),
            size,
        }
    }

    fn entry() -> Entry {
        Entry {
            image_id: Uuid::from_u128(9),
            reference_point_id: "Microsoft:RP1".into(),
            disks: vec![TrackedDisk {
                path: r"D:\VMs\web.vhdx".into(),
                disk_id: "{AAAA-1}".into(),
                size: 1 << 30,
                rct_id: "rctX:aaaa-1:5".into(),
            }],
            full_read_unix: 1_000,
        }
    }

    #[test]
    fn plans_queries_only_for_disks_that_match() {
        let e = entry();
        let disks = [
            disk(r"D:\VMs\web.vhdx", "aaaa-1", 1 << 30),
            disk(r"D:\VMs\new.vhdx", "bbbb-2", 1 << 30),
        ];
        let p = plan(Some(&e), &disks, 2_000).unwrap();
        assert_eq!(p.base_image, e.image_id);
        assert_eq!(p.queries[0].as_ref().unwrap().limit_id, "rctX:aaaa-1:5");
        assert!(p.queries[1].is_none(), "a new disk is read in full");
    }

    #[test]
    fn reads_in_full_when_nothing_is_recorded_resized_or_a_week_old() {
        let disks = [disk(r"D:\VMs\web.vhdx", "aaaa-1", 1 << 30)];
        assert!(plan(None, &disks, 2_000).is_err());
        let e = entry();
        assert!(plan(Some(&e), &disks, 1_000 + FULL_READ_EVERY_SECS)
            .unwrap_err()
            .contains("weekly"));
        let grown = [disk(r"D:\VMs\web.vhdx", "aaaa-1", 2 << 30)];
        assert!(plan(Some(&e), &grown, 2_000).is_err());
        let replaced = [disk(r"D:\VMs\web.vhdx", "cccc-3", 1 << 30)];
        assert!(
            plan(Some(&e), &replaced, 2_000).is_err(),
            "same path, another disk"
        );
    }

    #[test]
    fn change_query_is_passed_as_data() {
        let q = Query {
            path: r"D:\VMs\it's.vhdx".into(),
            limit_id: "rctX:aaaa-1:5".into(),
            size: 1,
        };
        let s = changes_script(&[&q]).unwrap();
        assert!(!s.contains("it's"));
        let bad = Query {
            limit_id: "x'; Remove-Item C:\\".into(),
            ..q
        };
        assert!(changes_script(&[&bad]).is_err());
        assert!(to_reference_script("Microsoft:x' or 1=1").is_err());
        assert!(destroy_reference_script("Microsoft:AB-12\\CD").is_ok());
    }

    #[test]
    fn parses_changes_and_refuses_ranges_outside_the_disk() {
        let a = Query {
            path: "a.vhdx".into(),
            limit_id: "rct:1".into(),
            size: 1000,
        };
        let b = Query {
            path: "b.vhdx".into(),
            limit_id: "rct:2".into(),
            size: 1000,
        };
        let c = Query {
            path: "c.vhdx".into(),
            limit_id: "rct:3".into(),
            size: 1000,
        };
        let out = r#"[{"path":"A.VHDX","size":1000,"ranges":"0,512;900,100","error":null},
                      {"path":"b.vhdx","size":0,"ranges":"","error":"GetVirtualDiskChanges returned 32768"},
                      {"path":"c.vhdx","size":1000,"ranges":"900,101","error":null}]"#;
        let r = parse_changes(out, &[&a, &b, &c]).unwrap();
        assert_eq!(
            r[0].as_ref().unwrap(),
            &vec![Extent(0, 512), Extent(900, 100)]
        );
        assert!(r[1].as_ref().unwrap_err().contains("32768"));
        assert!(r[2].as_ref().unwrap_err().contains("outside"));
        // One disk: PowerShell may emit an object, not an array; no changes.
        let one = r#"{"path":"a.vhdx","size":1000,"ranges":"","error":null}"#;
        assert_eq!(
            parse_changes(one, &[&a]).unwrap()[0].as_ref().unwrap(),
            &vec![]
        );
    }

    #[test]
    fn maps_rct_ids_to_disks_by_virtual_disk_id() {
        let disks = [disk("a.vhdx", "{AAAA-1}", 10), disk("b.vhdx", "bbbb-2", 20)];
        let out = r#"{"reference_point_id":"Microsoft:RP2","rct_ids":["rctX:b:1","rctX:a:1"],"disk_ids":["BBBB-2","aaaa-1"]}"#;
        let (id, t) = parse_reference(out, &disks).unwrap();
        assert_eq!(id, "Microsoft:RP2");
        assert_eq!(t.len(), 2);
        assert_eq!(
            (t[0].path.as_str(), t[0].rct_id.as_str()),
            ("a.vhdx", "rctX:a:1")
        );
        assert_eq!(
            (t[1].path.as_str(), t[1].rct_id.as_str()),
            ("b.vhdx", "rctX:b:1")
        );
        // Without disk identifiers, only a single disk can be matched.
        let out = r#"{"reference_point_id":"Microsoft:RP3","rct_ids":["rctX:b:1","rctX:a:1"],"disk_ids":[]}"#;
        assert!(parse_reference(out, &disks).unwrap().1.is_empty());
        let out = r#"{"reference_point_id":"Microsoft:RP4","rct_ids":"rctX:a:1","disk_ids":null}"#;
        assert_eq!(parse_reference(out, &disks[..1]).unwrap().1.len(), 1);
    }

    #[test]
    fn state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = load(dir.path());
        assert!(s.vms.is_empty());
        s.vms.insert(
            key(Uuid::from_u128(1), "6B2F7C1E-9F2A-4B8E-9D5F-0A1B2C3D4E5F"),
            entry(),
        );
        save(dir.path(), &s).unwrap();
        let back = load(dir.path());
        assert_eq!(
            back.vms
                .get("00000000-0000-0000-0000-000000000001/6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f"),
            Some(&entry())
        );
    }
}
