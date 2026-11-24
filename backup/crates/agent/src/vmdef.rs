//! VM definitions written next to restored disk files, so the backup can be
//! started on another hypervisor: a VMware `.vmx`, a QEMU/KVM start script
//! and a VirtualBox script that registers the VM with `VBoxManage`. Hyper-V
//! VMs are created directly (`hyperv.rs`).
//!
//! The settings come from the image: CPUs and memory recorded for a VM
//! (defaults otherwise), UEFI or BIOS as the system booted, Secure Boot when
//! it was on, and the guest family. Disks are attached to a SATA (AHCI)
//! controller, which Windows and Linux start without extra drivers, and one
//! network adapter is added (NAT).

use anyhow::bail;
use core_format::ManifestBody;

/// Which hypervisor the files are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hypervisor {
    Qemu,
    VirtualBox,
    Vmware,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmSettings {
    pub name: String,
    pub uefi: bool,
    pub secure_boot: bool,
    pub cpus: u32,
    pub memory_mb: u64,
    /// "windows", "windows-server", "linux" or "other".
    pub guest: &'static str,
    /// Disk file names, in the directory of the definition, in order.
    pub disks: Vec<String>,
}

/// VM names are used in file names and inside scripts: letters, digits,
/// spaces, dots, hyphens and underscores only.
pub fn check_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 80
        || name.trim() != name
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
    {
        bail!("VM names must be 1 to 80 letters, digits, spaces, dots, hyphens or underscores");
    }
    Ok(())
}

pub fn settings(m: &ManifestBody, name: &str, disks: Vec<String>) -> VmSettings {
    let vm = m.vm.clone().unwrap_or_default();
    let uefi = match m
        .disks
        .first()
        .and_then(|d| crate::restore::image_firmware(m, d))
    {
        Some(f) => f == "uefi",
        None => vm.generation == 2,
    };
    let os = m.os.family.to_ascii_lowercase();
    let guest = if os == "windows" {
        if m.os.name.to_ascii_lowercase().contains("server") {
            "windows-server"
        } else {
            "windows"
        }
    } else if os == "linux" {
        "linux"
    } else {
        "other"
    };
    VmSettings {
        name: name.to_string(),
        uefi,
        secure_boot: uefi && (m.boot.secure_boot == Some(true) || vm.secure_boot == Some(true)),
        cpus: if vm.cpu_count > 0 {
            vm.cpu_count.min(64)
        } else {
            2
        },
        memory_mb: if vm.memory_mb >= 512 {
            vm.memory_mb
        } else {
            4096
        },
        guest,
        disks,
    }
}

/// File name and contents of the definition for `h`. `windows_host`: the
/// restoring machine runs Windows (the VirtualBox script is then a .cmd).
pub fn definition(h: Hypervisor, s: &VmSettings, windows_host: bool) -> (String, String) {
    match h {
        Hypervisor::Vmware => (format!("{}.vmx", s.name), vmx(s)),
        Hypervisor::Qemu => (format!("start-{}.sh", s.name), qemu_sh(s)),
        Hypervisor::VirtualBox if windows_host => {
            (format!("register-{}.cmd", s.name), virtualbox(s, true))
        }
        Hypervisor::VirtualBox => (format!("register-{}.sh", s.name), virtualbox(s, false)),
    }
}

fn vmx(s: &VmSettings) -> String {
    let guest = match s.guest {
        "windows" => "windows9-64",
        "windows-server" => "windows2019srv-64",
        "linux" => "other5xlinux-64",
        _ => "other-64",
    };
    let mut v = vec![
        ".encoding = \"UTF-8\"".to_string(),
        "config.version = \"8\"".into(),
        "virtualHW.version = \"16\"".into(),
        format!("displayName = \"{}\"", s.name),
        format!("guestOS = \"{guest}\""),
        format!("firmware = \"{}\"", if s.uefi { "efi" } else { "bios" }),
    ];
    if s.secure_boot {
        v.push("uefi.secureBoot.enabled = \"TRUE\"".into());
    }
    v.push(format!("memsize = \"{}\"", s.memory_mb));
    v.push(format!("numvcpus = \"{}\"", s.cpus));
    v.push("sata0.present = \"TRUE\"".into());
    for (i, d) in s.disks.iter().enumerate() {
        v.push(format!("sata0:{i}.present = \"TRUE\""));
        v.push(format!("sata0:{i}.fileName = \"{d}\""));
    }
    v.extend([
        "ethernet0.present = \"TRUE\"".to_string(),
        "ethernet0.virtualDev = \"e1000e\"".into(),
        "ethernet0.connectionType = \"nat\"".into(),
        "ethernet0.addressType = \"generated\"".into(),
        "usb.present = \"TRUE\"".into(),
        "ehci.present = \"TRUE\"".into(),
        "svga.present = \"TRUE\"".into(),
    ]);
    v.join("\n") + "\n"
}

fn qemu_sh(s: &VmSettings) -> String {
    let mut drives = String::new();
    for (i, d) in s.disks.iter().enumerate() {
        drives += &format!(
            "  -drive file=\"$DIR/{d}\",format=qcow2,if=none,id=d{i} -device ide-hd,drive=d{i},bus=ide.{i} \\\n"
        );
    }
    let firmware = if s.uefi {
        format!(
            r#"# UEFI: OVMF, with a copy of its variable store kept next to the disks.
CODE=""
for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.fd; do
  [ -f "$f" ] && CODE="$f" && break
done
[ -n "$CODE" ] || {{ echo "UEFI firmware (OVMF) not found: install the ovmf (or edk2-ovmf) package" >&2; exit 1; }}
VARS="$DIR/{name}-uefi-vars.fd"
[ -f "$VARS" ] || cp "$(echo "$CODE" | sed 's/CODE/VARS/')" "$VARS" || exit 1
FIRMWARE="-drive if=pflash,format=raw,readonly=on,file=$CODE -drive if=pflash,format=raw,file=$VARS"
"#,
            name = s.name
        )
    } else {
        "FIRMWARE=\"\"  # BIOS (SeaBIOS)\n".into()
    };
    format!(
        r#"#!/bin/sh
# Start "{name}" restored by Fenrir. Needs qemu-system-x86_64 (KVM is used when available).
# With libvirt instead: virt-install --import --name "{name}" --memory {mem} --vcpus {cpus} --disk "<file>",bus=sata{boot} --osinfo detect=on,require=off
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
{firmware}# shellcheck disable=SC2086
exec qemu-system-x86_64 -name "{name}" -machine q35,accel=kvm:tcg -cpu max -smp {cpus} -m {mem} $FIRMWARE \
{drives}  -nic user,model=e1000e -vga std "$@"
"#,
        name = s.name,
        mem = s.memory_mb,
        cpus = s.cpus,
        boot = if s.uefi { " --boot uefi" } else { "" },
    )
}

fn virtualbox(s: &VmSettings, cmd: bool) -> String {
    let os = match s.guest {
        "windows" => "Windows10_64",
        "windows-server" => "Windows2019_64",
        "linux" => "Linux_64",
        _ => "Other_64",
    };
    let (vbox, dir, rem) = if cmd {
        ("VBoxManage", "%~dp0", "REM")
    } else {
        ("VBoxManage", "$DIR/", "#")
    };
    let mut l = vec![];
    if cmd {
        l.push("@echo off".to_string());
        l.push("setlocal".into());
        l.push(r#"if exist "%ProgramFiles%\Oracle\VirtualBox\VBoxManage.exe" set "PATH=%ProgramFiles%\Oracle\VirtualBox;%PATH%""#.into());
    } else {
        l.push("#!/bin/sh".into());
        l.push("set -e".into());
        l.push(r#"DIR="$(cd "$(dirname "$0")" && pwd)""#.into());
    }
    l.push(format!("{rem} Register \"{}\" restored by Fenrir in VirtualBox, then start it from VirtualBox Manager.", s.name));
    let n = &s.name;
    l.push(format!(
        "{vbox} createvm --name \"{n}\" --ostype {os} --register"
    ));
    l.push(format!(
        "{vbox} modifyvm \"{n}\" --memory {} --cpus {} --firmware {} --ioapic on --nic1 nat --nictype1 82540EM",
        s.memory_mb,
        s.cpus,
        if s.uefi { "efi" } else { "bios" }
    ));
    l.push(format!(
        "{vbox} storagectl \"{n}\" --name SATA --add sata --controller IntelAhci --portcount {}",
        s.disks.len().max(1)
    ));
    for (i, d) in s.disks.iter().enumerate() {
        l.push(format!(
            "{vbox} storageattach \"{n}\" --storagectl SATA --port {i} --device 0 --type hdd --medium \"{dir}{d}\""
        ));
    }
    if s.secure_boot {
        l.push(format!(
            "{rem} Secure Boot was on: VirtualBox 7 can turn it on with"
        ));
        l.push(format!("{rem}   {vbox} modifynvram \"{n}\" inituefivarstore && {vbox} modifynvram \"{n}\" enrollmssignatures && {vbox} modifynvram \"{n}\" secureboot --enable"));
    }
    if cmd {
        l.push(format!("echo \"{n}\" is registered in VirtualBox."));
        l.join("\r\n") + "\r\n"
    } else {
        l.push(format!("echo '\"{n}\" is registered in VirtualBox.'"));
        l.join("\n") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(uefi: bool) -> VmSettings {
        VmSettings {
            name: "PM-ACER restored".into(),
            uefi,
            secure_boot: uefi,
            cpus: 4,
            memory_mb: 8192,
            guest: "windows",
            disks: vec!["PM-ACER-disk0.vmdk".into(), "PM-ACER-disk1.vmdk".into()],
        }
    }

    #[test]
    fn names_are_safe_for_files_and_scripts() {
        assert!(check_name("PM-ACER restored 2026.11").is_ok());
        for bad in [
            "",
            " lead",
            "a\"b",
            "a;rm -rf /",
            "a$(x)",
            "a&b",
            "a%PATH%",
            "x".repeat(81).as_str(),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn vmware_definition() {
        let (file, v) = definition(Hypervisor::Vmware, &s(true), false);
        assert_eq!(file, "PM-ACER restored.vmx");
        assert!(v.contains("firmware = \"efi\""));
        assert!(v.contains("uefi.secureBoot.enabled = \"TRUE\""));
        assert!(v.contains("sata0:1.fileName = \"PM-ACER-disk1.vmdk\""));
        assert!(v.contains("memsize = \"8192\"") && v.contains("numvcpus = \"4\""));
        let (_, b) = definition(Hypervisor::Vmware, &s(false), false);
        assert!(b.contains("firmware = \"bios\"") && !b.contains("secureBoot"));
    }

    #[test]
    fn qemu_script_uses_ovmf_only_for_uefi() {
        let mut q = s(true);
        q.disks = vec!["a.qcow2".into()];
        let (file, sh) = definition(Hypervisor::Qemu, &q, true);
        assert_eq!(file, "start-PM-ACER restored.sh");
        assert!(sh.starts_with("#!/bin/sh\n"));
        assert!(
            sh.contains("OVMF_CODE") && sh.contains("-drive file=\"$DIR/a.qcow2\",format=qcow2")
        );
        assert!(sh.contains("-smp 4 -m 8192"));
        let (_, bios) = definition(Hypervisor::Qemu, &s(false), false);
        assert!(!bios.contains("OVMF"));
    }

    #[test]
    fn virtualbox_script_for_the_restoring_platform() {
        let (file, cmd) = definition(Hypervisor::VirtualBox, &s(true), true);
        assert_eq!(file, "register-PM-ACER restored.cmd");
        assert!(cmd.contains("\r\n") && cmd.contains("--firmware efi"));
        assert!(cmd.contains("--medium \"%~dp0PM-ACER-disk1.vmdk\""));
        let (file, sh) = definition(Hypervisor::VirtualBox, &s(false), false);
        assert_eq!(file, "register-PM-ACER restored.sh");
        assert!(sh.contains("--firmware bios") && sh.contains("--port 1 --device 0"));
        assert!(!sh.contains("\r\n"));
    }
}
