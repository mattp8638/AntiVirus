//! The block device tree from `lsblk --json` (disk → partition → LV / crypt
//! / RAID), and which disks hold the running system.

use serde_json::Value;

/// `lsblk` columns we ask for.
pub const COLUMNS: &str = "NAME,TYPE,FSTYPE,MOUNTPOINT,SIZE";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    /// Full path (`lsblk -p`), e.g. `/dev/sda2`, `/dev/mapper/vg-root`.
    pub name: String,
    /// `disk`, `part`, `lvm`, `crypt`, `loop`, `raid1`, ...
    pub kind: String,
    pub fstype: String,
    /// Mount point, `[SWAP]` for active swap, empty if not mounted.
    pub mountpoint: String,
    pub size: u64,
    pub children: Vec<Node>,
}

impl Node {
    pub fn is_swap(&self) -> bool {
        self.mountpoint == "[SWAP]"
    }
    pub fn mounted(&self) -> bool {
        !self.mountpoint.is_empty() && !self.is_swap()
    }
    /// This node and everything below it.
    pub fn walk(&self) -> Vec<&Node> {
        let mut v = vec![self];
        for c in &self.children {
            v.extend(c.walk());
        }
        v
    }
    /// Mount points (and `[SWAP]`) at or below this node.
    pub fn mounts(&self) -> Vec<&str> {
        self.walk()
            .into_iter()
            .filter(|n| !n.mountpoint.is_empty())
            .map(|n| n.mountpoint.as_str())
            .collect()
    }
}

fn node(v: &Value) -> Node {
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Node {
        name: s("name"),
        kind: s("type"),
        fstype: s("fstype"),
        mountpoint: s("mountpoint"),
        // -b gives a number (newer lsblk) or a string (older).
        size: v["size"]
            .as_u64()
            .or_else(|| v["size"].as_str().and_then(|x| x.parse().ok()))
            .unwrap_or(0),
        children: v["children"]
            .as_array()
            .map(|a| a.iter().map(node).collect())
            .unwrap_or_default(),
    }
}

/// `lsblk --json -b -p -o COLUMNS`
pub fn parse(json: &str) -> Result<Vec<Node>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("lsblk: {e}"))?;
    Ok(v["blockdevices"]
        .as_array()
        .map(|a| a.iter().map(node).collect())
        .unwrap_or_default())
}

/// Mount points that make a disk part of "the system".
pub fn is_system_mount(m: &str) -> bool {
    m == "[SWAP]"
        || m == "/"
        || [
            "/boot", "/efi", "/usr", "/var", "/home", "/opt", "/srv", "/root",
        ]
        .iter()
        .any(|p| m == *p || m.starts_with(&format!("{p}/")))
}

/// Whole disks (`disk` or `loop`) holding a system mount.
pub fn system_disks(tree: &[Node]) -> Vec<&Node> {
    tree.iter()
        .filter(|d| matches!(d.kind.as_str(), "disk" | "loop"))
        .filter(|d| d.mounts().iter().any(|m| is_system_mount(m)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &str = r#"{
   "blockdevices": [
      {"name":"/dev/sda", "type":"disk", "fstype":null, "mountpoint":null, "size":21474836480,
         "children": [
            {"name":"/dev/sda1", "type":"part", "fstype":"vfat", "mountpoint":"/boot/efi", "size":536870912},
            {"name":"/dev/sda2", "type":"part", "fstype":"ext4", "mountpoint":"/boot", "size":1073741824},
            {"name":"/dev/sda3", "type":"part", "fstype":"LVM2_member", "mountpoint":null, "size":19862126592,
               "children": [
                  {"name":"/dev/mapper/ubuntu--vg-ubuntu--lv", "type":"lvm", "fstype":"ext4", "mountpoint":"/", "size":10737418240},
                  {"name":"/dev/mapper/ubuntu--vg-swap", "type":"lvm", "fstype":"swap", "mountpoint":"[SWAP]", "size":2147483648}
               ]
            }
         ]
      },
      {"name":"/dev/sdb", "type":"disk", "fstype":"ext4", "mountpoint":"/mnt/backups", "size":"107374182400"},
      {"name":"/dev/sr0", "type":"rom", "fstype":null, "mountpoint":null, "size":1073741312}
   ]
}"#;

    #[test]
    fn parses_tree_and_finds_system_disks() {
        let t = parse(TREE).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t[1].size, 107374182400, "size given as a string");
        let sda = &t[0];
        assert_eq!(sda.children[2].children[0].mountpoint, "/");
        assert!(sda.children[2].children[1].is_swap());
        assert_eq!(sda.mounts(), vec!["/boot/efi", "/boot", "/", "[SWAP]"]);
        let sys: Vec<_> = system_disks(&t).iter().map(|d| d.name.clone()).collect();
        assert_eq!(
            sys,
            vec!["/dev/sda"],
            "a data disk is not part of the system"
        );
        assert!(
            is_system_mount("/var/lib/mysql")
                && !is_system_mount("/variable")
                && !is_system_mount("/mnt")
        );
    }
}
