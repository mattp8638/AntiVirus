import subprocess
import platform
import psutil


def run_ps(cmd):
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], capture_output=True, text=True, timeout=20)
        return (result.stdout or result.stderr or "").strip()
    except Exception:
        return ""


def as_bool(value, true_tokens=("true", "1", "on", "enabled", "yes")):
    return str(value or "").strip().lower() in true_tokens


def collect_windows_baseline():
    defender = as_bool(run_ps("(Get-MpComputerStatus).AntivirusEnabled"))
    defender_rt = as_bool(run_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled"))
    firewall = as_bool(run_ps("((Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}).Count -gt 0)"))
    bitlocker = "On" in run_ps("try { (Get-BitLockerVolume | Select-Object -First 1).ProtectionStatus } catch { 'Unknown' }")
    rdp = "0" in run_ps("try { (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections } catch { '1' }")
    smb = "Enabled" in run_ps("try { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State } catch { 'Disabled' }")
    admins = run_ps("try { (Get-LocalGroupMember Administrators).Count } catch { 1 }")
    try:
        admins = int(admins)
    except Exception:
        admins = 1
    secure_boot_raw = run_ps("try { Confirm-SecureBootUEFI } catch { 'False' }")
    secure_boot = as_bool(secure_boot_raw)
    update_raw = run_ps("try { (Get-Service wuauserv).Status } catch { 'Unknown' }")
    windows_update_enabled = str(update_raw).strip().lower() in {"running", "startpending"}
    controlled_folder_raw = run_ps("try { (Get-MpPreference).EnableControlledFolderAccess } catch { '0' }")
    controlled_folder_access_enabled = str(controlled_folder_raw).strip() in {"1", "Enabled", "true", "True"}
    ps_logging_raw = run_ps("$a=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging; $b=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames' -ErrorAction SilentlyContinue); if($a -eq 1 -or $b){'True'}else{'False'}")
    powershell_logging = as_bool(ps_logging_raw)
    audit_raw = run_ps("try { auditpol /get /category:* | Select-String -Pattern 'Success|Failure' | Measure-Object | Select-Object -ExpandProperty Count } catch { 0 }")
    try:
        audit_policy = int(str(audit_raw).strip() or "0") > 10
    except Exception:
        audit_policy = True
    tamper_raw = run_ps("try { (Get-MpComputerStatus).IsTamperProtected } catch { 'False' }")
    defender_tamper_protection_enabled = as_bool(tamper_raw)
    return {
        "defender_enabled": defender,
        "defender_realtime_enabled": defender_rt,
        "firewall_enabled": firewall,
        "bitlocker_enabled": bitlocker,
        "rdp_enabled": rdp,
        "smb_v1_enabled": smb,
        "local_admin_count": admins,
        "powershell_logging_enabled": powershell_logging,
        "audit_policy_enabled": audit_policy,
        "secure_boot_enabled": secure_boot,
        "windows_update_enabled": windows_update_enabled,
        "controlled_folder_access_enabled": controlled_folder_access_enabled,
        "defender_tamper_protection_enabled": defender_tamper_protection_enabled,
    }


def collect(agent_id):
    hostname = platform.node()
    os_name = platform.platform()
    if platform.system().lower() == "windows":
        baseline = collect_windows_baseline()
    else:
        baseline = {
            "defender_enabled": False,
            "defender_realtime_enabled": False,
            "firewall_enabled": False,
            "bitlocker_enabled": False,
            "rdp_enabled": False,
            "smb_v1_enabled": False,
            "local_admin_count": 1,
            "powershell_logging_enabled": False,
            "audit_policy_enabled": False,
            "secure_boot_enabled": False,
            "windows_update_enabled": False,
            "controlled_folder_access_enabled": False,
            "defender_tamper_protection_enabled": False,
        }
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "operating_system": os_name,
        **baseline,
        "risky_services": 0,
        "cpu_usage": cpu,
        "memory_usage": mem
    }
