//! Machine facts: identity, OS version, firmware, boot entries, drivers,
//! volumes. Read-only queries.

use std::ffi::c_void;

use core_format::manifest::{BootConfig, DriverInfo, Firmware, OsInfo, UefiBootEntry};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeNameForVolumeMountPointW,
    GetVolumePathNameW, GetVolumePathNamesForVolumeNameW,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{
    FirmwareTypeBios, FirmwareTypeUefi, GetFirmwareType, GetSystemWindowsDirectoryW, FIRMWARE_TYPE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

use super::ioctl::wide;
use crate::parse;

const EFI_GLOBAL_VARIABLE: &str = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Enable a privilege on the process token; returns whether it worked.
pub fn enable_privilege(name: PCWSTR) -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let mut luid = LUID::default();
        let ok = LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid).is_ok() && {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_ok()
                && windows::Win32::Foundation::GetLastError().is_ok()
        };
        let _ = CloseHandle(token);
        ok
    }
}

pub fn reg_string(subkey: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(subkey), wide(value));
    let mut buf = vec![0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut c_void),
            Some(&mut len),
        )
    };
    r.is_ok().then(|| from_wide(&buf))
}

pub fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(subkey), wide(value));
    let mut d = 0u32;
    let mut len = 4u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut d as *mut u32 as *mut c_void),
            Some(&mut len),
        )
    };
    r.is_ok().then_some(d)
}

pub fn machine_id() -> String {
    reg_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid").unwrap_or_default()
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

pub fn os_info() -> OsInfo {
    let k = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let build = reg_string(k, "CurrentBuild").unwrap_or_default();
    let ubr = reg_dword(k, "UBR")
        .map(|u| format!(".{u}"))
        .unwrap_or_default();
    OsInfo {
        family: "windows".into(),
        name: reg_string(k, "ProductName").unwrap_or_default(),
        version: reg_string(k, "DisplayVersion").unwrap_or_default(),
        build: format!("{build}{ubr}"),
        arch: std::env::consts::ARCH.into(),
    }
}

fn firmware_var(name: &str) -> Option<Vec<u8>> {
    let (n, g) = (wide(name), wide(EFI_GLOBAL_VARIABLE));
    let mut buf = vec![0u8; 8192];
    let len = unsafe {
        GetFirmwareEnvironmentVariableW(
            PCWSTR(n.as_ptr()),
            PCWSTR(g.as_ptr()),
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
        )
    };
    (len > 0).then(|| {
        buf.truncate(len as usize);
        buf
    })
}

/// Firmware type, Secure Boot state and UEFI boot entries. Reading
/// firmware variables needs SeSystemEnvironmentPrivilege; without it the
/// entries are simply left empty with a note.
pub fn boot_config() -> BootConfig {
    let mut b = BootConfig::default();
    let mut ft = FIRMWARE_TYPE::default();
    if unsafe { GetFirmwareType(&mut ft) }.is_ok() {
        b.firmware = if ft == FirmwareTypeUefi {
            Firmware::Uefi
        } else if ft == FirmwareTypeBios {
            Firmware::Bios
        } else {
            Firmware::Unknown
        };
    }
    if b.firmware == Firmware::Uefi {
        b.secure_boot = reg_dword(
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        )
        .map(|v| v != 0);
        match firmware_var("BootOrder") {
            Some(order) => {
                b.boot_order = parse::parse_boot_order(&order);
                for name in b.boot_order.clone() {
                    if let Some(o) = firmware_var(&name)
                        .as_deref()
                        .and_then(parse::parse_load_option)
                    {
                        b.uefi_entries.push(UefiBootEntry {
                            name,
                            description: o.description,
                            path: o.device_path_hex,
                        });
                    }
                }
            }
            None => b.notes.push(
                "UEFI boot entries not read (SeSystemEnvironmentPrivilege unavailable)".into(),
            ),
        }
    }
    b
}

/// Kernel drivers with boot start type: the ones a restored system needs
/// to reach its disk. Full driver inventory is a Phase 5 item.
pub fn boot_start_drivers() -> Vec<DriverInfo> {
    let mut out = Vec::new();
    let base = r"SYSTEM\CurrentControlSet\Services";
    let wb = wide(base);
    let mut key = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wb.as_ptr()),
            Some(0),
            KEY_READ,
            &mut key,
        )
    }
    .is_err()
    {
        return out;
    }
    for i in 0.. {
        let mut name = vec![0u16; 256];
        let mut len = name.len() as u32;
        let r = unsafe {
            RegEnumKeyExW(
                key,
                i,
                Some(windows::core::PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if r.is_err() {
            break;
        }
        let svc = from_wide(&name);
        let sk = format!(r"{base}\{svc}");
        if reg_dword(&sk, "Start") == Some(0) && reg_dword(&sk, "Type") == Some(1) {
            out.push(DriverInfo {
                name: svc,
                provider: String::new(),
                version: String::new(),
                class: reg_string(&sk, "Group").unwrap_or_default(),
                inf: reg_string(&sk, "ImagePath").unwrap_or_default(),
            });
        }
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    out
}

/// Volume GUID path (`\\?\Volume{...}\`) holding the Windows directory.
pub fn system_volume() -> std::io::Result<String> {
    let mut win = vec![0u16; 512];
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut win)) } as usize;
    if n == 0 || n >= win.len() {
        return Err(std::io::Error::other("GetSystemWindowsDirectory failed"));
    }
    let mut mount = vec![0u16; 512];
    unsafe { GetVolumePathNameW(PCWSTR(win.as_ptr()), &mut mount) }
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut vol = vec![0u16; 64];
    unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(mount.as_ptr()), &mut vol) }
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(from_wide(&vol))
}

/// All volume GUID paths (with trailing backslash).
pub fn list_volumes() -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = vec![0u16; 64];
    let Ok(h) = (unsafe { FindFirstVolumeW(&mut buf) }) else {
        return out;
    };
    loop {
        out.push(from_wide(&buf));
        buf.fill(0);
        if unsafe { FindNextVolumeW(h, &mut buf) }.is_err() {
            break;
        }
    }
    unsafe {
        let _ = FindVolumeClose(h);
    }
    out
}

pub fn mount_points(volume: &str) -> Vec<String> {
    let w = wide(volume);
    let mut buf = vec![0u16; 4096];
    let mut len = 0u32;
    if unsafe { GetVolumePathNamesForVolumeNameW(PCWSTR(w.as_ptr()), Some(&mut buf), &mut len) }
        .is_err()
    {
        return vec![];
    }
    buf[..len as usize]
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}
