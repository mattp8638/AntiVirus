//! Hyper-V host backups.
//!
//! For each VM: create a *recovery checkpoint* through WMI
//! (`Msvm_VirtualSystemSnapshotService.CreateSnapshot`, SnapshotType
//! 32768), which quiesces the guest through integration services and
//! freezes the VM's virtual disks while writes go to new `.avhdx` files.
//! Read the frozen VHDX files with Fenrir's own reader, store one image per
//! VM, then destroy the checkpoint so Hyper-V merges the differencing disks.
//!
//! WMI is driven through Windows PowerShell 5.1 (always present on Hyper-V
//! hosts). Script text and output parsing are platform-independent and
//! unit-tested; only `run_ps` needs Windows.

use anyhow::{bail, Context};
use core_format::manifest::{Consistency, VmDisk, VmInfo, VmNetworkAdapter};
use serde::Deserialize;

const PS_PRELUDE: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ns = 'root\virtualization\v2'
function Wait-WmiJob($r, $what) {
  if ($r.ReturnValue -eq 4096) {
    $job = [wmi]$r.Job
    while ($job.JobState -eq 3 -or $job.JobState -eq 4) { Start-Sleep -Milliseconds 500; $job = [wmi]$r.Job }
    if ($job.JobState -ne 7) { throw "$what failed: $($job.ErrorDescription) (error $($job.ErrorCode))" }
  } elseif ($r.ReturnValue -ne 0) { throw "$what failed with code $($r.ReturnValue)" }
}
"#;

const PS_LIST: &str = r#"
Import-Module Hyper-V
$out = @(Get-VM | ForEach-Object {
  $vm = $_
  $disks = @(Get-VMHardDiskDrive -VM $vm | Where-Object { $_.Path } | ForEach-Object { $_.Path })
  $bytes = [int64]0
  foreach ($d in $disks) { try { $bytes += (Get-Item -LiteralPath $d).Length } catch {} }
  [pscustomobject]@{ id = $vm.Id.ToString(); name = $vm.Name; state = $vm.State.ToString(); generation = [int]$vm.Generation; disk_bytes = $bytes; disks = $disks }
})
ConvertTo-Json -InputObject $out -Depth 4 -Compress
"#;

const PS_CHECKPOINT: &str = r#"
Import-Module Hyper-V
$VmId = '__VMID__'
$vm = Get-WmiObject -Namespace $ns -Class Msvm_ComputerSystem -Filter "Name='$VmId'"
if (-not $vm) { throw "VM $VmId not found" }
$svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSnapshotService
function New-Recovery($level) {
  $ssd = ([wmiclass]"\\.\root\virtualization\v2:Msvm_VirtualSystemSnapshotSettingData").CreateInstance()
  $ssd.ConsistencyLevel = $level
  $ssd.IgnoreNonSnapshottableDisks = $true
  Wait-WmiJob ($svc.CreateSnapshot($vm.__PATH, $ssd.GetText(2), 32768)) 'Creating the recovery checkpoint'
}
$consistency = 'application'
$note = $null
try { New-Recovery 1 } catch {
  # Guest without working integration services / VSS: fall back to crash-consistent.
  $note = $_.Exception.Message
  $consistency = 'crash'
  New-Recovery 2
}
$snap = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSettingData -Filter "VirtualSystemIdentifier='$VmId' AND VirtualSystemType='Microsoft:Hyper-V:Snapshot:Recovery'" |
  Sort-Object { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } -Descending | Select-Object -First 1
if (-not $snap) { throw 'The recovery checkpoint was not found after creating it' }
$frozen = @($snap.GetRelated('Msvm_StorageAllocationSettingData') | Where-Object { $_.ResourceType -eq 31 } | ForEach-Object { $_.HostResource[0] })
$v = Get-VM -Id $VmId
$drives = @(Get-VMHardDiskDrive -VM $v | ForEach-Object {
  $p = $null; try { $p = (Get-VHD -Path $_.Path).ParentPath } catch {}
  [pscustomobject]@{ controller = "$($_.ControllerType) $($_.ControllerNumber):$($_.ControllerLocation)"; current = $_.Path; parent = $p }
})
$disks = @(foreach ($f in $frozen) {
  $d = $drives | Where-Object { $_.parent -eq $f -or $_.current -eq $f } | Select-Object -First 1
  [pscustomobject]@{ path = $f; controller = $(if ($d) { $d.controller } else { '' }) }
})
$nets = @(Get-VMNetworkAdapter -VM $v | ForEach-Object { [pscustomobject]@{ name = $_.Name; switch = [string]$_.SwitchName; mac = [string]$_.MacAddress } })
$sb = $null
if ($v.Generation -eq 2) { $sb = ((Get-VMFirmware -VM $v).SecureBoot -eq 'On') }
[pscustomobject]@{
  snapshot_id = $snap.InstanceID; consistency = $consistency; note = $note; disks = $disks
  vm = [pscustomobject]@{ name = $v.Name; generation = [int]$v.Generation; cpu_count = [int]$v.ProcessorCount;
       memory_mb = [int64]($v.MemoryStartup / 1MB); secure_boot = $sb; config_version = [string]$v.Version; network_adapters = $nets }
} | ConvertTo-Json -Depth 6 -Compress
"#;

const PS_DESTROY: &str = r#"
$SnapId = '__SNAPID__'
$snap = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSettingData -Filter "InstanceID='$SnapId'"
if ($snap) {
  $svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSnapshotService
  Wait-WmiJob ($svc.DestroySnapshot($snap.__PATH)) 'Removing the recovery checkpoint'
}
'{"ok":true}'
"#;

fn guid_ok(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok() && s.len() == 36
}

/// Snapshot instance IDs look like "Microsoft:<GUID>" (sometimes with a
/// further ":<GUID>"). Only those characters may reach the script.
fn snapshot_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-' || b == b'\\')
}

pub fn checkpoint_script(vm_id: &str) -> anyhow::Result<String> {
    if !guid_ok(vm_id) {
        bail!("invalid VM id {vm_id:?}");
    }
    Ok(format!(
        "{PS_PRELUDE}{}",
        PS_CHECKPOINT.replace("__VMID__", vm_id)
    ))
}

pub fn destroy_script(snapshot_id: &str) -> anyhow::Result<String> {
    if !snapshot_id_ok(snapshot_id) {
        bail!("invalid snapshot id {snapshot_id:?}");
    }
    Ok(format!(
        "{PS_PRELUDE}{}",
        PS_DESTROY.replace("__SNAPID__", snapshot_id)
    ))
}

pub fn list_script() -> String {
    format!("{PS_PRELUDE}{PS_LIST}")
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckpointDisk {
    pub path: String,
    #[serde(default)]
    pub controller: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PsVm {
    name: String,
    generation: u32,
    cpu_count: u32,
    memory_mb: u64,
    secure_boot: Option<bool>,
    #[serde(default)]
    config_version: String,
    #[serde(default, deserialize_with = "one_or_many")]
    network_adapters: Vec<PsNet>,
}

#[derive(Debug, Clone, Deserialize)]
struct PsNet {
    name: String,
    #[serde(default)]
    switch: String,
    #[serde(default)]
    mac: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PsCheckpoint {
    snapshot_id: String,
    consistency: String,
    note: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    disks: Vec<CheckpointDisk>,
    vm: PsVm,
}

/// PowerShell's ConvertTo-Json turns one-element arrays into objects in
/// some cases; accept both.
fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(vec![]),
        serde_json::Value::Array(_) => serde_json::from_value(v).map_err(serde::de::Error::custom),
        other => Ok(vec![
            serde_json::from_value(other).map_err(serde::de::Error::custom)?
        ]),
    }
}

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub snapshot_id: String,
    pub consistency: Consistency,
    pub warning: Option<String>,
    pub disks: Vec<CheckpointDisk>,
    pub vm: VmInfo,
}

pub fn parse_checkpoint(json: &str, host: &str, vm_id: &str) -> anyhow::Result<Checkpoint> {
    let p: PsCheckpoint = serde_json::from_str(json.trim())
        .context("unexpected checkpoint output from PowerShell")?;
    if !snapshot_id_ok(&p.snapshot_id) {
        bail!("unexpected snapshot id {:?}", p.snapshot_id);
    }
    let consistency = if p.consistency == "application" {
        Consistency::Application
    } else {
        Consistency::Crash
    };
    let warning = (consistency == Consistency::Crash).then(|| {
        format!(
            "VM '{}': application-consistent checkpoint failed ({}); this image is crash-consistent. Check the guest's integration services.",
            p.vm.name,
            p.note.clone().unwrap_or_default()
        )
    });
    let vm = VmInfo {
        hypervisor: "hyper-v".into(),
        host: host.into(),
        vm_id: vm_id.into(),
        name: p.vm.name.clone(),
        generation: p.vm.generation,
        cpu_count: p.vm.cpu_count,
        memory_mb: p.vm.memory_mb,
        secure_boot: p.vm.secure_boot,
        disks: p
            .disks
            .iter()
            .map(|d| VmDisk {
                controller: d.controller.clone(),
                path: d.path.clone(),
            })
            .collect(),
        network_adapters: p
            .vm
            .network_adapters
            .iter()
            .map(|n| VmNetworkAdapter {
                name: n.name.clone(),
                switch: n.switch.clone(),
                mac: n.mac.clone(),
            })
            .collect(),
        config_version: p.vm.config_version.clone(),
    };
    Ok(Checkpoint {
        snapshot_id: p.snapshot_id,
        consistency,
        warning,
        disks: p.disks,
        vm,
    })
}

pub fn parse_vm_list(json: &str) -> anyhow::Result<Vec<protocol::VmSummary>> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        name: String,
        state: String,
        #[serde(default)]
        generation: u32,
        #[serde(default)]
        disk_bytes: u64,
        #[serde(default, deserialize_with = "one_or_many")]
        disks: Vec<String>,
    }
    let t = json.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    let v: serde_json::Value = serde_json::from_str(t)?;
    let rows: Vec<Row> = match v {
        serde_json::Value::Array(_) => serde_json::from_value(v)?,
        other => vec![serde_json::from_value(other)?],
    };
    Ok(rows
        .into_iter()
        .map(|r| protocol::VmSummary {
            id: r.id,
            name: r.name,
            state: r.state.to_lowercase(),
            generation: r.generation,
            disk_bytes: r.disk_bytes,
            disks: r.disks,
        })
        .collect())
}

/// Parameters for creating a VM from restored disks. Passed to PowerShell
/// as base64-encoded JSON, so no value is ever parsed as script.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NewVm {
    pub name: String,
    pub path: String,
    pub generation: u32,
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub secure_boot: Option<bool>,
    pub disks: Vec<NewVmDisk>,
    pub switch: Option<String>,
    pub adapters: u32,
    pub start: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NewVmDisk {
    pub path: String,
    /// "SCSI 0:1", "IDE 0:0" or empty (next free slot).
    pub controller: String,
}

const PS_NEW_VM: &str = r#"
Import-Module Hyper-V
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SPEC__')) | ConvertFrom-Json
if (Get-VM -Name $p.name -ErrorAction SilentlyContinue) { throw "A VM named '$($p.name)' already exists" }
$warn = @()
$vm = New-VM -Name $p.name -Generation $p.generation -MemoryStartupBytes ([int64]$p.memory_mb * 1MB) -NoVHD -Path $p.path
Set-VMProcessor -VM $vm -Count $p.cpu_count
$nextIde = 0; $nextScsi = 0
foreach ($d in $p.disks) {
  $type = $null; $num = 0; $loc = 0
  if ($d.controller -match '^(SCSI|IDE) (\d+):(\d+)$') { $type = $Matches[1]; $num = [int]$Matches[2]; $loc = [int]$Matches[3] }
  if ($type -eq 'IDE' -and $p.generation -eq 2) { $type = $null }
  if (-not $type) {
    if ($p.generation -eq 1 -and $nextIde -lt 4) { $type = 'IDE'; $num = [math]::Floor($nextIde / 2); $loc = $nextIde % 2; $nextIde++ }
    else { $type = 'SCSI'; $num = 0; $loc = $nextScsi; $nextScsi++ }
  }
  if ($type -eq 'SCSI') {
    while (@(Get-VMScsiController -VM $vm).Count -le $num) { Add-VMScsiController -VM $vm }
  }
  Add-VMHardDiskDrive -VM $vm -ControllerType $type -ControllerNumber $num -ControllerLocation $loc -Path $d.path
}
if ($p.generation -eq 2) {
  Set-VMFirmware -VM $vm -FirstBootDevice (Get-VMHardDiskDrive -VM $vm | Select-Object -First 1)
  if ($p.secure_boot -eq $false) { Set-VMFirmware -VM $vm -EnableSecureBoot Off }
}
for ($i = @(Get-VMNetworkAdapter -VM $vm).Count; $i -lt $p.adapters; $i++) { Add-VMNetworkAdapter -VM $vm }
if ($p.switch) {
  if (Get-VMSwitch -Name $p.switch -ErrorAction SilentlyContinue) { Get-VMNetworkAdapter -VM $vm | Connect-VMNetworkAdapter -SwitchName $p.switch }
  else { $warn += "Virtual switch '$($p.switch)' does not exist on this host; network adapters are disconnected." }
}
if ($p.start) { Start-VM -VM $vm }
[pscustomobject]@{ vm_id = $vm.Id.ToString(); warnings = $warn } | ConvertTo-Json -Compress
"#;

const PS_VM_EXISTS: &str = r#"
Import-Module Hyper-V
$n = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__NAME__'))
if (Get-VM -Name $n -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }
"#;

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

pub fn check_vm_name(name: &str) -> anyhow::Result<()> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 || n.chars().any(|c| c.is_control()) || n != name {
        bail!("VM names must be 1 to 100 printable characters without leading or trailing spaces");
    }
    Ok(())
}

pub fn new_vm_script(spec: &NewVm) -> anyhow::Result<String> {
    check_vm_name(&spec.name)?;
    if spec.generation != 1 && spec.generation != 2 {
        bail!("generation must be 1 or 2");
    }
    Ok(format!(
        "{PS_PRELUDE}{}",
        PS_NEW_VM.replace("__SPEC__", &b64(&serde_json::to_string(spec)?))
    ))
}

pub fn vm_exists(name: &str) -> anyhow::Result<bool> {
    check_vm_name(name)?;
    Ok(run_ps(&format!(
        "{PS_PRELUDE}{}",
        PS_VM_EXISTS.replace("__NAME__", &b64(name))
    ))?
    .trim()
        == "yes")
}

const PS_BOOT_CHECK: &str = r#"
Import-Module Hyper-V
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SPEC__')) | ConvertFrom-Json
$vm = Get-VM -Name $p.name
Get-VMNetworkAdapter -VM $vm | Disconnect-VMNetworkAdapter
Start-VM -VM $vm
$sw = [Diagnostics.Stopwatch]::StartNew()
$outcome = 'timeout'; $msg = 'no heartbeat before the time limit'
while ($sw.Elapsed.TotalSeconds -lt $p.timeout) {
  Start-Sleep -Seconds 5
  $vm = Get-VM -Id $vm.Id
  if ($vm.State -ne 'Running') { $outcome = 'stopped'; $msg = "the VM stopped (state $($vm.State))"; break }
  if ("$($vm.Heartbeat)" -like 'Ok*') { $outcome = 'heartbeat'; $msg = "the Hyper-V heartbeat service reported $($vm.Heartbeat)"; break }
}
$thumb = $null
try {
  $ms = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
  $vs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemSettingData -Filter "ConfigurationID='$($vm.Id)' AND VirtualSystemType='Microsoft:Hyper-V:System:Realized'"
  $r = Invoke-CimMethod -CimInstance $ms -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $vs; WidthPixels = [uint16]$p.width; HeightPixels = [uint16]$p.height }
  if ($r.ImageData) { $thumb = [Convert]::ToBase64String([byte[]]$r.ImageData) }
} catch {}
[pscustomobject]@{ outcome = $outcome; message = $msg; seconds = [int]$sw.Elapsed.TotalSeconds; thumb = $thumb } | ConvertTo-Json -Compress
"#;

const PS_REMOVE_VM: &str = r#"
Import-Module Hyper-V
$n = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__NAME__'))
$vm = Get-VM -Name $n -ErrorAction SilentlyContinue
if ($vm) { Stop-VM -VM $vm -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -VM $vm -Force }
"#;

pub const THUMB_W: u32 = 800;
pub const THUMB_H: u32 = 600;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct HvBootResult {
    /// "heartbeat", "stopped" or "timeout".
    pub outcome: String,
    pub message: String,
    pub seconds: u64,
    /// RGB565 thumbnail, base64.
    #[serde(default)]
    pub thumb: Option<String>,
}

/// Start an existing (disconnected) VM and wait for its heartbeat.
pub fn boot_check_vm(name: &str, timeout_secs: u64) -> anyhow::Result<HvBootResult> {
    check_vm_name(name)?;
    let spec = serde_json::json!({ "name": name, "timeout": timeout_secs, "width": THUMB_W, "height": THUMB_H });
    let out = run_ps(&format!(
        "{PS_PRELUDE}{}",
        PS_BOOT_CHECK.replace("__SPEC__", &b64(&spec.to_string()))
    ))?;
    parse_boot_result(&out)
}

pub fn parse_boot_result(out: &str) -> anyhow::Result<HvBootResult> {
    let line = out
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow::anyhow!("no result from the boot check script"))?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(test)]
fn boot_check_script_for_test(name: &str) -> String {
    let spec =
        serde_json::json!({ "name": name, "timeout": 1, "width": THUMB_W, "height": THUMB_H });
    PS_BOOT_CHECK.replace("__SPEC__", &b64(&spec.to_string()))
}

/// Turn off and delete a VM (not its files).
pub fn remove_vm(name: &str) -> anyhow::Result<()> {
    check_vm_name(name)?;
    run_ps(&format!(
        "{PS_PRELUDE}{}",
        PS_REMOVE_VM.replace("__NAME__", &b64(name))
    ))?;
    Ok(())
}

/// The message of a failed PowerShell run: its error stream, which arrives
/// as serialized CLIXML (`#< CLIXML` then `<S S="Error">` lines) when its
/// output is redirected, or as text; else the last line of its output.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn ps_error(stderr: &str, stdout: &str) -> String {
    let text = if stderr.trim_start().starts_with("#< CLIXML") {
        let mut parts = Vec::new();
        let mut rest = stderr;
        while let Some(i) = rest.find("<S S=\"Error\">") {
            rest = &rest[i + 13..];
            let end = rest.find("</S>").unwrap_or(rest.len());
            parts.push(
                rest[..end]
                    .replace("_x000D__x000A_", "\n")
                    .replace("_x000A_", "\n")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
                    .replace("&quot;", "\"")
                    .replace("&apos;", "'"),
            );
            rest = &rest[end..];
        }
        parts.concat()
    } else {
        stderr.to_string()
    };
    text.lines()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && !l.starts_with("At line")
                && !l.starts_with('+')
                && !l.starts_with("CategoryInfo")
                && !l.starts_with("FullyQualifiedErrorId")
        })
        .map(str::to_string)
        .or_else(|| {
            stdout
                .lines()
                .map(str::trim)
                .rfind(|l| !l.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "PowerShell failed".into())
}

/// Run a script with Windows PowerShell; returns stdout.
pub fn run_ps(script: &str) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let utf16: Vec<u8> = script
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let enc = base64::engine::general_purpose::STANDARD.encode(utf16);
        let out = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &enc,
            ])
            .output()
            .context("starting powershell.exe")?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            bail!(
                "{}",
                ps_error(&String::from_utf8_lossy(&out.stderr), &stdout)
            );
        }
        Ok(stdout)
    }
    #[cfg(not(windows))]
    {
        let _ = script;
        bail!("Hyper-V backups run on Windows hosts only")
    }
}

pub fn list_vms() -> anyhow::Result<Vec<protocol::VmSummary>> {
    parse_vm_list(&run_ps(&list_script())?)
}

/// Is Hyper-V installed here (the Virtual Machine Management service), whatever
/// role the agent was installed with?
pub fn host_present() -> bool {
    if !cfg!(windows) {
        return false;
    }
    static PRESENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PRESENT.get_or_init(|| {
        std::process::Command::new("sc.exe")
            .args(["query", "vmms"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// A Hyper-V host: installed as one, or a machine where Hyper-V is installed.
pub fn is_host(role: &str) -> bool {
    cfg!(windows) && (role == "hyperv" || host_present())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_check_output() {
        let r = parse_boot_result("WARNING: noise\r\n{\"outcome\":\"heartbeat\",\"message\":\"ok\",\"seconds\":42,\"thumb\":null}\r\n").unwrap();
        assert_eq!(
            (r.outcome.as_str(), r.seconds, r.thumb),
            ("heartbeat", 42, None)
        );
        assert!(parse_boot_result("").is_err());
        let s = boot_check_script_for_test("fenrir-check-1234abcd");
        assert!(
            !s.contains("fenrir-check-1234abcd"),
            "name travels base64-encoded"
        );
    }

    #[test]
    fn scripts_refuse_injection() {
        assert!(checkpoint_script("x'; Remove-Item C:\\ -Recurse; '").is_err());
        assert!(checkpoint_script("6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f")
            .unwrap()
            .contains("$VmId = '6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f'"));
        assert!(destroy_script("Microsoft:6B2F7C1E-9F2A-4B8E-9D5F-0A1B2C3D4E5F").is_ok());
        assert!(destroy_script("Microsoft:x' or 1=1").is_err());
    }

    #[test]
    fn parses_checkpoint_output_single_and_multi() {
        // PowerShell emits one-element arrays as plain objects.
        let one = r#"{"snapshot_id":"Microsoft:AAAA-1","consistency":"application","note":null,
            "disks":{"path":"D:\\VMs\\web.vhdx","controller":"SCSI 0:0"},
            "vm":{"name":"web","generation":2,"cpu_count":4,"memory_mb":8192,"secure_boot":true,"config_version":"10.0",
                  "network_adapters":{"name":"Network Adapter","switch":"LAN","mac":"00155D010203"}}}"#;
        let c = parse_checkpoint(one, "hv01", "6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f").unwrap();
        assert_eq!(c.consistency, Consistency::Application);
        assert!(c.warning.is_none());
        assert_eq!(c.disks.len(), 1);
        assert_eq!(c.vm.disks[0].controller, "SCSI 0:0");
        assert_eq!(c.vm.network_adapters[0].switch, "LAN");
        assert_eq!(c.vm.secure_boot, Some(true));

        let many = r#"{"snapshot_id":"Microsoft:B","consistency":"crash","note":"VSS in guest failed",
            "disks":[{"path":"a.vhdx","controller":"IDE 0:0"},{"path":"b.vhdx","controller":"IDE 0:1"}],
            "vm":{"name":"old","generation":1,"cpu_count":1,"memory_mb":1024,"secure_boot":null,"network_adapters":[]}}"#;
        let c = parse_checkpoint(many, "hv01", "6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f").unwrap();
        assert_eq!(c.consistency, Consistency::Crash);
        assert!(c.warning.unwrap().contains("VSS in guest failed"));
        assert_eq!(c.disks.len(), 2);
    }

    #[test]
    fn new_vm_spec_is_embedded_as_data() {
        let spec = NewVm {
            name: "evil'; Remove-Item C:\\ -Recurse; '".into(),
            path: "D:\\Restores".into(),
            generation: 2,
            cpu_count: 4,
            memory_mb: 8192,
            secure_boot: Some(true),
            disks: vec![NewVmDisk {
                path: "D:\\Restores\\a.vhdx".into(),
                controller: "SCSI 0:0".into(),
            }],
            switch: Some("LAN".into()),
            adapters: 1,
            start: false,
        };
        let s = new_vm_script(&spec).unwrap();
        assert!(
            !s.contains("Remove-Item"),
            "names never appear as script text"
        );
        let b = s
            .split("FromBase64String('")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        use base64::Engine;
        let json: serde_json::Value =
            serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(b).unwrap())
                .unwrap();
        assert_eq!(json["generation"], 2);
        assert_eq!(json["disks"][0]["controller"], "SCSI 0:0");
        assert!(check_vm_name(" padded").is_err());
        assert!(check_vm_name("ok name (restored)").is_ok());
        assert!(new_vm_script(&NewVm {
            generation: 3,
            ..spec
        })
        .is_err());
    }

    #[test]
    fn parses_vm_lists() {
        assert!(parse_vm_list("").unwrap().is_empty());
        let one = r#"{"id":"6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f","name":"dc01","state":"Running","generation":2,"disk_bytes":42,"disks":"C:\\dc.vhdx"}"#;
        let v = parse_vm_list(one).unwrap();
        assert_eq!(v[0].state, "running");
        assert_eq!(v[0].disks, vec!["C:\\dc.vhdx"]);
        let two = r#"[{"id":"a","name":"x","state":"Off","disks":[]},{"id":"b","name":"y","state":"Saved","disks":["1","2"]}]"#;
        assert_eq!(parse_vm_list(two).unwrap().len(), 2);
    }
}

#[cfg(test)]
mod ps_error_tests {
    #[test]
    fn clixml_errors_are_decoded() {
        let err = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Size Not Supported _x000D__x000A_</S><S S=\"Error\">At line:5 char:1_x000D__x000A_</S></Objs>";
        assert_eq!(super::ps_error(err, ""), "Size Not Supported");
        assert_eq!(super::ps_error("", "a\nlast words\n"), "last words");
        assert_eq!(
            super::ps_error("plain &amp; simple\nAt line:1", ""),
            "plain &amp; simple"
        );
    }
}
