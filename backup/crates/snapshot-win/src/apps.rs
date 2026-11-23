//! Which VSS writer components a whole-system image includes
//! (docs/design/app-aware.md). Portable, so it is tested everywhere; the
//! VSS calls are in `win::vss`.
//!
//! A component-mode backup must add every component it wants writers to
//! treat as backed up. Adding a component implicitly includes its
//! subcomponents, so only top-level components are added: those with no
//! ancestor component of the same writer. A component is added only when
//! every file it lists is on a volume in the snapshot set (a writer refuses
//! a component whose files are not snapshotted).

use core_format::manifest::ApplicationInfo;

/// VSS writers left out of whole-system images: the Hyper-V writer would
/// take a checkpoint of every VM, which `backup_hyperv` does on purpose and
/// per VM.
pub const SKIPPED_WRITERS: &[(&str, &str)] = &[(
    "66841cd4-6ded-4f4b-8f17-fd23f8ddc3de",
    "virtual machines are backed up from the host's Hyper-V backup, one VM at a time",
)];

const ON_PURPOSE: &str = "not coordinated: virtual machines";

fn is_skipped_on_purpose(a: &ApplicationInfo) -> bool {
    a.note.as_deref().is_some_and(|n| n.starts_with(ON_PURPOSE))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    /// Writer class id, lower case without braces.
    pub writer_id: String,
    pub writer: String,
    pub logical_path: String,
    pub name: String,
    pub caption: String,
    /// VSS_COMPONENT_TYPE.
    pub kind: i32,
    pub selectable: bool,
    /// Volume GUID names (`\\?\Volume{...}\`) of the files it lists; `None`
    /// for a file whose volume could not be found.
    pub volumes: Vec<Option<String>>,
}

impl Component {
    /// Logical path and name, as VSS identifies the component.
    pub fn full_path(&self) -> String {
        if self.logical_path.is_empty() {
            self.name.clone()
        } else {
            format!("{}\\{}", self.logical_path, self.name)
        }
    }

    fn is_below(&self, other: &Component) -> bool {
        if self.writer_id != other.writer_id {
            return false;
        }
        let p = other.full_path().to_ascii_lowercase();
        let l = self.logical_path.to_ascii_lowercase();
        l == p || l.starts_with(&format!("{p}\\"))
    }
}

#[derive(Debug, Default)]
pub struct Selection {
    /// Indexes into the component list, to add to the backup.
    pub add: Vec<usize>,
    /// What the image records about application data.
    pub report: Vec<ApplicationInfo>,
}

fn same_volume(a: &str, b: &str) -> bool {
    a.trim_end_matches('\\')
        .eq_ignore_ascii_case(b.trim_end_matches('\\'))
}

/// Choose the components to add. `snapshot` holds the volume GUID names in
/// the snapshot set.
pub fn select(components: &[Component], snapshot: &[String]) -> Selection {
    let mut sel = Selection::default();
    for (i, c) in components.iter().enumerate() {
        if components
            .iter()
            .enumerate()
            .any(|(j, o)| j != i && c.is_below(o))
        {
            continue; // included with its top-level component
        }
        let subs = components.iter().filter(|o| o.is_below(c)).count();
        let mut info = ApplicationInfo {
            writer: c.writer.clone(),
            component: c.full_path(),
            caption: c.caption.clone(),
            included: false,
            note: None,
        };
        if let Some((_, why)) = SKIPPED_WRITERS
            .iter()
            .find(|(id, _)| c.writer_id.eq_ignore_ascii_case(id))
        {
            info.note = Some(format!("not coordinated: {why}"));
        } else if c.volumes.iter().any(|v| v.is_none()) {
            info.note = Some(
                "not coordinated: some of its files are on a volume Windows could not identify"
                    .into(),
            );
        } else if let Some(v) = c
            .volumes
            .iter()
            .flatten()
            .find(|v| !snapshot.iter().any(|s| same_volume(s, v)))
        {
            info.note = Some(format!(
                "not coordinated: its files are on {v}, which is not on the disks being imaged (add that disk to the backup)"
            ));
        } else {
            info.included = true;
            if subs > 0 {
                info.note = Some(format!("with {subs} subcomponent(s)"));
            }
            sel.add.push(i);
        }
        sel.report.push(info);
    }
    sel
}

/// A warning for the job and the image when some application data was not
/// coordinated (writers left out on purpose, such as Hyper-V, do not count).
pub fn summary(report: &[ApplicationInfo]) -> Option<String> {
    let mut by_writer: Vec<(&str, usize, usize)> = Vec::new();
    for a in report.iter().filter(|a| !is_skipped_on_purpose(a)) {
        match by_writer.iter_mut().find(|(w, _, _)| *w == a.writer) {
            Some(e) => {
                e.1 += a.included as usize;
                e.2 += 1;
            }
            None => by_writer.push((&a.writer, a.included as usize, 1)),
        }
    }
    let partial: Vec<String> = by_writer
        .iter()
        .filter(|(_, inc, all)| inc < all)
        .map(|(w, inc, all)| format!("{w} ({inc} of {all} components)"))
        .collect();
    (!partial.is_empty()).then(|| {
        format!(
            "application data not fully coordinated with the snapshot, crash-consistent only: {}",
            partial.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = r"\\?\Volume{c}\";
    const D: &str = r"\\?\Volume{d}\";

    fn comp(writer: &str, path: &str, name: &str, vols: &[&str]) -> Component {
        Component {
            writer_id: format!("{writer}-id"),
            writer: writer.into(),
            logical_path: path.into(),
            name: name.into(),
            caption: name.into(),
            kind: 1,
            selectable: true,
            volumes: vols.iter().map(|v| Some(v.to_string())).collect(),
        }
    }

    #[test]
    fn adds_top_level_components_on_snapshotted_volumes() {
        let comps = vec![
            // SQL Server: instance \ database, databases are components below the instance.
            comp("SqlServerWriter", "", "SQL01", &[]),
            comp("SqlServerWriter", "SQL01", "master", &[C]),
            comp("SqlServerWriter", "SQL01", "sales", &[D]),
            // Registry writer: one component on C:.
            comp("Registry Writer", "", "Registry", &[C]),
            // A writer whose data is only on D:.
            comp("Exchange", "", "Mailbox DB", &[D, C]),
        ];
        let s = select(&comps, &[C.to_string(), r"\\?\VOLUME{X}".into()]);
        assert_eq!(
            s.add,
            vec![0, 3],
            "the SQL instance (with its databases) and the registry"
        );
        assert_eq!(s.report.len(), 3, "only top-level components are reported");
        assert!(
            s.report[0].included && s.report[0].note.as_deref() == Some("with 2 subcomponent(s)")
        );
        assert!(!s.report[2].included);
        assert!(s.report[2].note.as_ref().unwrap().contains(D));
        assert!(summary(&s.report).unwrap().contains("Exchange (0 of 1"));
    }

    #[test]
    fn nested_paths_and_case() {
        let comps = vec![
            comp("W", r"A", "B", &[C]),
            comp("W", r"a\b", "C", &[C]),
            comp("W", r"A\B\C", "D", &[C]),
            comp("W", "", "AB", &[C]), // not an ancestor of A\B
        ];
        let s = select(&comps, &[C.to_lowercase()]);
        assert_eq!(s.add, vec![0, 3]);
        assert_eq!(s.report[0].note.as_deref(), Some("with 2 subcomponent(s)"));
        assert_eq!(summary(&s.report), None, "everything included");
    }

    #[test]
    fn skips_the_hyper_v_writer_and_unknown_volumes() {
        let mut hv = comp("Microsoft Hyper-V VSS Writer", "", "vm1", &[C]);
        hv.writer_id = "66841CD4-6DED-4F4B-8F17-FD23F8DDC3DE".into();
        let mut odd = comp("W", "", "x", &[C]);
        odd.volumes.push(None);
        let s = select(&[hv, odd], &[C.into()]);
        assert!(s.add.is_empty());
        assert!(s.report[0]
            .note
            .as_ref()
            .unwrap()
            .contains("Hyper-V backup"));
        assert_eq!(
            summary(&s.report[..1]),
            None,
            "leaving the Hyper-V writer out is on purpose, not a warning"
        );
        assert!(s.report[1]
            .note
            .as_ref()
            .unwrap()
            .contains("could not identify"));
    }
}
