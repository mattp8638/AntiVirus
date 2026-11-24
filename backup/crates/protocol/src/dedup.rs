//! Paths of dedup group members (docs/design/dedup-groups.md): a member of
//! the group at `<group>` lives in `<group>/repos/<repository id>`. The same
//! rules as `core_format::group` (checked by a test in the agent), here for
//! the servers, which do not read repositories.

use uuid::Uuid;

pub const MEMBERS: &str = "repos";

/// `<group>/repos/<uuid>` → (`<group>`, uuid).
pub fn split_member_path(path: &str) -> Option<(String, Uuid)> {
    let p = path.trim_end_matches(['/', '\\']);
    let (rest, id) = p.rsplit_once(['/', '\\'])?;
    let id = Uuid::parse_str(id).ok()?;
    let (root, members) = rest.rsplit_once(['/', '\\'])?;
    (members == MEMBERS && !root.is_empty()).then(|| (root.to_string(), id))
}

/// The path of member `id` in the group at `root`.
pub fn member_path(root: &str, id: &Uuid) -> String {
    let sep = if root.contains('\\') && !root.contains('/') {
        '\\'
    } else {
        '/'
    };
    format!(
        "{}{sep}{MEMBERS}{sep}{id}",
        root.trim_end_matches(['/', '\\'])
    )
}
