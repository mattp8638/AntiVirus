//! Byte extents (offset, length) and normalised extent lists.

use serde::{Deserialize, Serialize};

/// A half-open byte range `[offset, offset + len)`.
/// Serialised as a two-element array `[offset, len]` to keep manifests small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Extent(pub u64, pub u64);

impl Extent {
    pub fn new(offset: u64, len: u64) -> Self {
        Extent(offset, len)
    }
    pub fn offset(&self) -> u64 {
        self.0
    }
    pub fn len(&self) -> u64 {
        self.1
    }
    pub fn is_empty(&self) -> bool {
        self.1 == 0
    }
    pub fn end(&self) -> u64 {
        self.0.saturating_add(self.1)
    }
    pub fn intersect(&self, other: &Extent) -> Option<Extent> {
        let s = self.0.max(other.0);
        let e = self.end().min(other.end());
        (s < e).then(|| Extent(s, e - s))
    }
}

/// Sort, drop empties, merge overlapping and adjacent extents.
pub fn normalize(mut v: Vec<Extent>) -> Vec<Extent> {
    v.retain(|e| !e.is_empty());
    v.sort();
    let mut out: Vec<Extent> = Vec::with_capacity(v.len());
    for e in v {
        if let Some(last) = out.last_mut() {
            if e.0 <= last.end() {
                let end = last.end().max(e.end());
                last.1 = end - last.0;
                continue;
            }
        }
        out.push(e);
    }
    out
}

/// Remove `holes` from `v`. Both must be normalised; result is normalised.
pub fn subtract(v: &[Extent], holes: &[Extent]) -> Vec<Extent> {
    let mut out = Vec::new();
    let mut hi = 0;
    for e in v {
        let mut cur = e.0;
        let end = e.end();
        while hi < holes.len() && holes[hi].end() <= cur {
            hi += 1;
        }
        let mut j = hi;
        while j < holes.len() && holes[j].0 < end {
            let h = holes[j];
            if h.0 > cur {
                out.push(Extent(cur, h.0 - cur));
            }
            cur = cur.max(h.end());
            j += 1;
        }
        if cur < end {
            out.push(Extent(cur, end - cur));
        }
    }
    out
}

/// Ranges present in both normalised lists.
pub fn intersect(a: &[Extent], b: &[Extent]) -> Vec<Extent> {
    subtract(a, &subtract(a, b))
}

/// Clip a normalised list to `range`.
pub fn clip(v: &[Extent], range: Extent) -> Vec<Extent> {
    v.iter().filter_map(|e| e.intersect(&range)).collect()
}

pub fn total_len(v: &[Extent]) -> u64 {
    v.iter().map(|e| e.1).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_merges() {
        let v = normalize(vec![
            Extent(10, 5),
            Extent(0, 5),
            Extent(5, 5),
            Extent(30, 0),
            Extent(12, 10),
        ]);
        assert_eq!(v, vec![Extent(0, 22)]);
    }

    #[test]
    fn subtract_holes() {
        let v = vec![Extent(0, 100), Extent(200, 100)];
        let h = vec![Extent(10, 10), Extent(90, 120), Extent(290, 50)];
        assert_eq!(
            subtract(&v, &h),
            vec![Extent(0, 10), Extent(20, 70), Extent(210, 80)]
        );
        assert_eq!(subtract(&v, &[]), v);
    }

    #[test]
    fn intersect_lists() {
        let a = vec![Extent(0, 100), Extent(200, 100)];
        let b = vec![Extent(50, 200), Extent(290, 5)];
        assert_eq!(
            intersect(&a, &b),
            vec![Extent(50, 50), Extent(200, 50), Extent(290, 5)]
        );
        assert!(intersect(&a, &[]).is_empty());
    }

    #[test]
    fn clip_range() {
        let v = vec![Extent(0, 10), Extent(20, 10)];
        assert_eq!(clip(&v, Extent(5, 20)), vec![Extent(5, 5), Extent(20, 5)]);
    }
}
