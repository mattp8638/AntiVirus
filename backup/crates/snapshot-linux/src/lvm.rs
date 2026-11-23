//! LVM reports (`pvs`, `lvs --segments`, `vgs` with `--reportformat json`)
//! and where each logical volume segment lies on its physical volume.
//!
//! Portable parsing only; running the commands is in `live`.

use std::collections::BTreeMap;

use serde_json::Value;

/// A physical volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pv {
    /// Device path as LVM names it, e.g. `/dev/sda2`.
    pub name: String,
    pub vg: String,
    /// Byte offset of the first physical extent.
    pub pe_start: u64,
    pub pe_count: u64,
}

/// One segment of a logical volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub vg: String,
    pub lv: String,
    /// e.g. `-wi-ao----`; see lvs(8).
    pub attr: String,
    pub dm_path: String,
    /// `linear`, `striped`, `thin`, `raid1`, ...
    pub segtype: String,
    /// Byte offset of the segment in the logical volume.
    pub lv_offset: u64,
    pub len: u64,
    pub extent_size: u64,
    /// (physical volume, first extent, last extent) for each stripe.
    pub pe_ranges: Vec<(String, u64, u64)>,
    /// Origin of a snapshot; empty otherwise.
    pub origin: String,
    pub lv_size: u64,
}

impl Segment {
    pub fn active(&self) -> bool {
        self.attr.as_bytes().get(4) == Some(&b'a')
    }
    /// A classic (thick) snapshot: its extents hold copy-on-write data.
    pub fn is_snapshot(&self) -> bool {
        matches!(self.attr.as_bytes().first(), Some(b's') | Some(b'S'))
    }
    /// Internal volumes LVM shows in brackets (`[lvol0_pmspare]`).
    pub fn hidden(&self) -> bool {
        self.lv.starts_with('[')
    }
    /// The segment as a plain range on one physical volume.
    pub fn linear(&self) -> Option<(&str, u64)> {
        match (self.segtype.as_str(), self.pe_ranges.as_slice()) {
            ("linear" | "striped", [(pv, first, last)]) if last >= first => {
                (((last - first + 1) * self.extent_size) == self.len)
                    .then_some((pv.as_str(), *first))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vg {
    pub name: String,
    pub free: u64,
    pub extent_size: u64,
}

fn rows(json: &str) -> Result<Vec<BTreeMap<String, String>>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("LVM report: {e}"))?;
    let mut out = Vec::new();
    for rep in v["report"].as_array().into_iter().flatten() {
        // The key is the report type ("pv", "seg", "vg"...): take whichever array is there.
        for (_, list) in rep.as_object().into_iter().flatten() {
            for row in list.as_array().into_iter().flatten() {
                let mut m = BTreeMap::new();
                for (k, v) in row.as_object().into_iter().flatten() {
                    m.insert(k.clone(), v.as_str().unwrap_or_default().to_string());
                }
                out.push(m);
            }
        }
    }
    Ok(out)
}

fn num(m: &BTreeMap<String, String>, k: &str) -> Result<u64, String> {
    let s = m.get(k).map(String::as_str).unwrap_or("");
    // `--units b --nosuffix` gives plain bytes; tolerate a trailing B.
    s.trim_end_matches(['B', 'b'])
        .parse()
        .map_err(|_| format!("LVM report: {k} = {s:?} is not a number"))
}

fn text(m: &BTreeMap<String, String>, k: &str) -> String {
    m.get(k).cloned().unwrap_or_default()
}

/// `pvs --reportformat json --units b --nosuffix -o pv_name,vg_name,pe_start,pv_pe_count`
pub fn parse_pvs(json: &str) -> Result<Vec<Pv>, String> {
    rows(json)?
        .iter()
        .map(|m| {
            Ok(Pv {
                name: text(m, "pv_name"),
                vg: text(m, "vg_name"),
                pe_start: num(m, "pe_start")?,
                pe_count: num(m, "pv_pe_count")?,
            })
        })
        .collect()
}

pub const SEGMENT_FIELDS: &str = "vg_name,lv_name,lv_attr,lv_dm_path,segtype,seg_start,seg_size,seg_pe_ranges,vg_extent_size,origin,lv_size";

/// `lvs -a --segments --reportformat json --units b --nosuffix -o SEGMENT_FIELDS`
pub fn parse_segments(json: &str) -> Result<Vec<Segment>, String> {
    rows(json)?
        .iter()
        .map(|m| {
            let mut pe_ranges = Vec::new();
            for r in text(m, "seg_pe_ranges").split_whitespace() {
                // "/dev/sda2:0-255"; the device name may itself contain ':'.
                let (dev, range) = r
                    .rsplit_once(':')
                    .ok_or_else(|| format!("LVM report: extent range {r:?}"))?;
                let (a, b) = range
                    .split_once('-')
                    .ok_or_else(|| format!("LVM report: extent range {r:?}"))?;
                let p = |s: &str| {
                    s.parse::<u64>()
                        .map_err(|_| format!("LVM report: extent range {r:?}"))
                };
                pe_ranges.push((dev.to_string(), p(a)?, p(b)?));
            }
            Ok(Segment {
                vg: text(m, "vg_name"),
                lv: text(m, "lv_name"),
                attr: text(m, "lv_attr"),
                dm_path: text(m, "lv_dm_path"),
                segtype: text(m, "segtype"),
                lv_offset: num(m, "seg_start")?,
                len: num(m, "seg_size")?,
                extent_size: num(m, "vg_extent_size")?,
                pe_ranges,
                origin: text(m, "origin"),
                lv_size: num(m, "lv_size")?,
            })
        })
        .collect()
}

/// `vgs --reportformat json --units b --nosuffix -o vg_name,vg_free,vg_extent_size`
pub fn parse_vgs(json: &str) -> Result<Vec<Vg>, String> {
    rows(json)?
        .iter()
        .map(|m| {
            Ok(Vg {
                name: text(m, "vg_name"),
                free: num(m, "vg_free")?,
                extent_size: num(m, "vg_extent_size")?,
            })
        })
        .collect()
}

/// A range of a physical volume, relative to the start of the PV device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PvRange {
    pub pv_offset: u64,
    pub len: u64,
    /// Offset of the same bytes in the logical volume.
    pub lv_offset: u64,
}

/// Where `seg` lies on `pv`, if it is a linear segment there.
pub fn on_pv(seg: &Segment, pv: &Pv) -> Option<PvRange> {
    let (name, first) = seg.linear()?;
    (name == pv.name).then(|| PvRange {
        pv_offset: pv.pe_start + first * seg.extent_size,
        len: seg.len,
        lv_offset: seg.lv_offset,
    })
}

/// Does the segment use `pv` at all (whatever its layout)?
pub fn touches(seg: &Segment, pv: &Pv) -> bool {
    seg.pe_ranges.iter().any(|(n, _, _)| n == &pv.name)
}

/// Copy-on-write space for a snapshot of an LV of `lv_size` bytes: 10 %,
/// at least 64 MiB, rounded up to whole extents.
pub fn snapshot_size(lv_size: u64, extent_size: u64) -> u64 {
    let want = (lv_size / 10).max(64 << 20).min(lv_size.max(extent_size));
    let e = extent_size.max(1);
    want.div_ceil(e) * e
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real output of lvm2 2.03 for a VG on /dev/loop0 whose root LV was
    // extended after a swap LV was created (two segments).
    const SEGS: &str = r#"  {
      "report": [
          {
              "seg": [
                  {"vg_name":"fvg", "lv_name":"root", "lv_attr":"-wi-ao----", "lv_dm_path":"/dev/mapper/fvg-root", "segtype":"linear", "seg_start":"0", "seg_size":"104857600", "seg_pe_ranges":"/dev/loop0:0-24", "vg_extent_size":"4194304", "origin":"", "lv_size":"125829120"},
                  {"vg_name":"fvg", "lv_name":"root", "lv_attr":"-wi-ao----", "lv_dm_path":"/dev/mapper/fvg-root", "segtype":"linear", "seg_start":"104857600", "seg_size":"20971520", "seg_pe_ranges":"/dev/loop0:35-39", "vg_extent_size":"4194304", "origin":"", "lv_size":"125829120"},
                  {"vg_name":"fvg", "lv_name":"swap", "lv_attr":"-wi-ao----", "lv_dm_path":"/dev/mapper/fvg-swap", "segtype":"linear", "seg_start":"0", "seg_size":"41943040", "seg_pe_ranges":"/dev/loop0:25-34", "vg_extent_size":"4194304", "origin":"", "lv_size":"41943040"},
                  {"vg_name":"fvg", "lv_name":"fenrir-snap-root-1", "lv_attr":"swi-a-s---", "lv_dm_path":"/dev/mapper/fvg-fenrir--snap--root--1", "segtype":"linear", "seg_start":"0", "seg_size":"67108864", "seg_pe_ranges":"/dev/loop0:40-55", "vg_extent_size":"4194304", "origin":"root", "lv_size":"67108864"},
                  {"vg_name":"fvg", "lv_name":"data", "lv_attr":"-wi-a-----", "lv_dm_path":"/dev/mapper/fvg-data", "segtype":"striped", "seg_start":"0", "seg_size":"8388608", "seg_pe_ranges":"/dev/loop0:56-56 /dev/loop1:0-0", "vg_extent_size":"4194304", "origin":"", "lv_size":"8388608"}
              ]
          }
      ]
  }"#;

    const PVS: &str = r#"{"report":[{"pv":[{"pv_name":"/dev/loop0", "vg_name":"fvg", "pe_start":"1048576", "pv_pe_count":"74"}]}]}"#;

    #[test]
    fn parses_reports_and_maps_segments() {
        let pvs = parse_pvs(PVS).unwrap();
        assert_eq!(
            pvs,
            vec![Pv {
                name: "/dev/loop0".into(),
                vg: "fvg".into(),
                pe_start: 1 << 20,
                pe_count: 74
            }]
        );
        let segs = parse_segments(SEGS).unwrap();
        assert_eq!(segs.len(), 5);
        let pv = &pvs[0];
        let m = |i: usize| on_pv(&segs[i], pv);
        assert_eq!(
            m(0),
            Some(PvRange {
                pv_offset: 1 << 20,
                len: 100 << 20,
                lv_offset: 0
            })
        );
        assert_eq!(
            m(1),
            Some(PvRange {
                pv_offset: (1 << 20) + 35 * (4 << 20),
                len: 20 << 20,
                lv_offset: 100 << 20
            })
        );
        assert!(segs[0].active() && !segs[0].is_snapshot());
        assert!(segs[3].is_snapshot() && segs[3].origin == "root");
        // Two stripes: not a plain range, but it uses the PV.
        assert_eq!(m(4), None);
        assert!(touches(&segs[4], pv));
    }

    #[test]
    fn vgs_and_snapshot_size() {
        let v = parse_vgs(r#"{"report":[{"vg":[{"vg_name":"fvg", "vg_free":"310378496", "vg_extent_size":"4194304"}]}]}"#).unwrap();
        assert_eq!(v[0].free, 310378496);
        let e = 4 << 20;
        assert_eq!(snapshot_size(100 << 20, e), 64 << 20, "at least 64 MiB");
        assert_eq!(snapshot_size(10 << 30, e), 1024 << 20, "10 %");
        assert_eq!(snapshot_size(8 << 20, e), 8 << 20, "never more than the LV");
        assert_eq!(snapshot_size(1001 << 20, e) % e, 0, "whole extents");
    }

    #[test]
    fn bad_reports_are_errors() {
        assert!(parse_pvs("not json").is_err());
        assert!(parse_pvs(
            r#"{"report":[{"pv":[{"pv_name":"x","pe_start":"lots","pv_pe_count":"1"}]}]}"#
        )
        .is_err());
        assert!(parse_segments(r#"{"report":[{"seg":[{"seg_pe_ranges":"nocolon","seg_start":"0","seg_size":"0","vg_extent_size":"1","lv_size":"0"}]}]}"#).is_err());
        assert!(parse_pvs(r#"{"report":[]}"#).unwrap().is_empty());
    }
}
