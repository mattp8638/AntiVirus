# name: Windows 11 readiness
# description: Checks the main Windows 11 requirements: TPM 2.0, Secure Boot, CPU, memory and disk.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$sb = try { Confirm-SecureBootUEFI } catch { $false }
$mem = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$disk = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB
[pscustomobject]@{ TPM2 = [bool]($tpm -and $tpm.SpecVersion -match '^2'); SecureBoot = $sb; MemoryGB = [math]::Round($mem,1)
  Memory4GB = $mem -ge 3.8; DiskGB = [math]::Round($disk); Disk64GB = $disk -ge 64; CPU = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name } | Format-List
