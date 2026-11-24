//! Reading chosen files from VSS snapshots (folder backups): which snapshot
//! a logical path (`C:/Users/anna/report.docx`) is read from. The mapping
//! is portable and tested everywhere; taking the snapshots is in `win`.

use std::path::PathBuf;

/// Snapshot devices by the mount point they stand for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PathMap {
    /// (`c:/` lowercase, `/`-separated with a trailing `/`; device such as
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7`).
    pub mounts: Vec<(String, String)>,
}

impl PathMap {
    pub fn add(&mut self, mount: &str, device: &str) {
        let mut m = mount.replace('\\', "/").to_lowercase();
        if !m.ends_with('/') {
            m.push('/');
        }
        self.mounts
            .push((m, device.trim_end_matches('\\').to_string()));
        // Longest (deepest) mount point first.
        self.mounts.sort_by_key(|m| std::cmp::Reverse(m.0.len()));
    }

    /// Where to read `logical` from: inside a snapshot when one covers it,
    /// else the live path (Windows separators).
    pub fn translate(&self, logical: &str) -> PathBuf {
        let l = logical.replace('\\', "/");
        let lower = l.to_lowercase();
        for (m, dev) in &self.mounts {
            let bare = m.trim_end_matches('/');
            if lower == bare || lower.starts_with(m.as_str()) {
                let rest = l.get(m.len().min(l.len())..).unwrap_or("");
                return PathBuf::from(format!("{dev}\\{}", rest.replace('/', "\\")));
            }
        }
        PathBuf::from(l.replace('/', "\\"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_map_into_the_snapshot_of_their_volume() {
        let mut m = PathMap::default();
        m.add("C:\\", r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7");
        m.add(
            "C:\\Data\\",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8",
        );
        assert_eq!(
            m.translate("C:/Users/anna/report.docx"),
            PathBuf::from(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\Users\anna\report.docx"
            )
        );
        assert_eq!(
            m.translate("c:/data/sales.xlsx"),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\sales.xlsx"),
            "a volume mounted in a folder uses its own snapshot"
        );
        assert_eq!(
            m.translate("C:"),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\")
        );
        assert_eq!(
            m.translate("//nas/share/x"),
            PathBuf::from(r"\\nas\share\x"),
            "shares are read live"
        );
        assert_eq!(
            m.translate("D:/x"),
            PathBuf::from(r"D:\x"),
            "no snapshot: live"
        );
    }
}
