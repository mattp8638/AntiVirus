//! Names of the agent on disk and in the service manager, all specific to
//! Fenrir-Backup so they cannot collide with other products (an earlier
//! version used `FenrirAgent`, `C:\Program Files\Fenrir` and
//! `fenrir-agent`, which other software also uses).
//!
//! An agent installed under the old names and updated in place keeps
//! running there: `legacy_install` recognises it by its file name, and it
//! keeps its old service name and state folder.

// Most names are only used by the Windows code.
#![cfg_attr(not(windows), allow(dead_code))]

/// Executable name without extension.
pub const EXE_STEM: &str = "fenrir-backup-agent";
pub const LEGACY_EXE_STEM: &str = "fenrir-agent";
/// Windows service name.
pub const WIN_SERVICE: &str = "FenrirBackupAgent";
pub const LEGACY_WIN_SERVICE: &str = "FenrirAgent";
pub const WIN_SERVICE_DISPLAY: &str = "Fenrir-Backup Agent";
/// Folder under `Program Files` and `ProgramData`.
pub const WIN_FOLDER: &str = "Fenrir-Backup";

/// True when this executable is a pre-rename install updated in place.
pub fn legacy_install() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
        })
        .is_some_and(|s| s == LEGACY_EXE_STEM)
}

/// The Windows service this process runs as.
pub fn win_service() -> &'static str {
    if legacy_install() {
        LEGACY_WIN_SERVICE
    } else {
        WIN_SERVICE
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn names_are_product_specific() {
        for n in [super::EXE_STEM, super::WIN_SERVICE, super::WIN_FOLDER] {
            assert!(n.to_ascii_lowercase().contains("backup"), "{n}");
        }
        assert!(
            !super::legacy_install(),
            "test binaries are not legacy installs"
        );
    }
}
