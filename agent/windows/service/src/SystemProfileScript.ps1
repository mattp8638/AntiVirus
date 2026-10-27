# Fenrir system profile (Windows). Run as SYSTEM by the agent every 6 hours and on demand; prints one JSON
# document: {"profile": {...}, "recoveryKeys": [...]}. Every section is independent: a failing query leaves that
# section empty instead of failing the whole profile. Windows PowerShell 5.1 compatible.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# The agent reads stdout as UTF-8; without this, accented names arrive in the OEM code page and break the JSON.
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
function Section([scriptblock]$Block) { try { & $Block } catch { $null } }
function Iso($Value) { if ($Value -is [datetime] -and $Value.Year -gt 1601) { $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function Gb($Bytes) { if ($Bytes) { [math]::Round([double]$Bytes / 1GB, 1) } else { $null } }

$profile = [ordered]@{ collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); platform = 'windows' }
# Sections run in a child scope, so shared results use reference types (a list, a hashtable).
$recoveryKeys = New-Object System.Collections.ArrayList

# --- Hardware ---------------------------------------------------------------------------------------------------
$profile.hardware = Section {
  $cs = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $enclosure = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  $modules = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    [ordered]@{ slot = $_.DeviceLocator; sizeGb = Gb $_.Capacity; speedMhz = $_.ConfiguredClockSpeed; manufacturer = "$($_.Manufacturer)".Trim(); partNumber = "$($_.PartNumber)".Trim() } })
  $chassisNames = @{ 3='Desktop'; 4='Desktop'; 6='Mini tower'; 7='Tower'; 8='Portable'; 9='Laptop'; 10='Notebook'; 13='All in one'; 14='Sub notebook'; 30='Tablet'; 31='Convertible'; 32='Detachable'; 35='Mini PC'; 36='Stick PC' }
  $tpm = Section { $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm
    if ($t) { [ordered]@{ present = $true; ready = [bool]($t.IsEnabled_InitialValue -and $t.IsActivated_InitialValue); version = ("$($t.SpecVersion)" -split ',')[0].Trim(); manufacturer = "$($t.ManufacturerIdTxt)" } }
    else { [ordered]@{ present = $false } } }
  $secureBoot = Section { Confirm-SecureBootUEFI }
  [ordered]@{
    manufacturer = $cs.Manufacturer; model = $cs.Model; serial = "$($bios.SerialNumber)".Trim()
    chassis = $(if ($enclosure.ChassisTypes) { $chassisNames[[int]$enclosure.ChassisTypes[0]] })
    biosVersion = $bios.SMBIOSBIOSVersion; biosDate = Iso $bios.ReleaseDate
    cpu = [ordered]@{ name = "$($cpu.Name)".Trim(); cores = $cpu.NumberOfCores; threads = $cpu.NumberOfLogicalProcessors; maxMhz = $cpu.MaxClockSpeed }
    memory = [ordered]@{ totalGb = Gb $cs.TotalPhysicalMemory; slotsUsed = $modules.Count; modules = $modules }
    gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { [ordered]@{ name = $_.Name; driverVersion = $_.DriverVersion; memoryGb = Gb $_.AdapterRAM } })
    tpm = $tpm; secureBoot = $secureBoot
  }
}

# --- Operating system -------------------------------------------------------------------------------------------
$profile.os = Section {
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $reasons = @()
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Windows servicing' }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
  if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations) { $reasons += 'File rename' }
  $join = 'Workgroup'
  $dsreg = Section { dsregcmd /status }
  if ($dsreg -match 'AzureAdJoined\s*:\s*YES') { $join = $(if ($cs.PartOfDomain) { 'Hybrid Entra joined' } else { 'Entra joined' }) }
  elseif ($cs.PartOfDomain) { $join = 'Domain joined' }
  $activation = Section {
    $lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" | Select-Object -First 1
    if ($lic) { @{ 0='Unlicensed'; 1='Licensed'; 2='Out of box grace'; 3='Out of tolerance grace'; 4='Non-genuine grace'; 5='Notification'; 6='Extended grace' }[[int]$lic.LicenseStatus] } }
  [ordered]@{
    name = $os.Caption; version = $os.Version; build = "$($cv.CurrentBuild).$($cv.UBR)"; displayVersion = $cv.DisplayVersion
    architecture = $os.OSArchitecture; installDate = Iso $os.InstallDate; lastBoot = Iso $os.LastBootUpTime
    timezone = (Get-TimeZone).Id; domain = $(if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }); joinType = $join
    activation = $activation; rebootPending = ($reasons.Count -gt 0); rebootReasons = $reasons
    lastUpdateInstalled = Iso ((Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn)
  }
}

# --- Disks and SMART --------------------------------------------------------------------------------------------
$profile.disks = Section {
  @(Get-PhysicalDisk | ForEach-Object {
    $r = $_ | Get-StorageReliabilityCounter
    [ordered]@{
      name = $_.FriendlyName; model = $_.Model; serial = "$($_.SerialNumber)".Trim(); mediaType = "$($_.MediaType)"; busType = "$($_.BusType)"
      sizeGb = Gb $_.Size; health = "$($_.HealthStatus)"; status = "$($_.OperationalStatus)"
      temperatureC = $r.Temperature; temperatureMaxC = $r.TemperatureMax; wearPercent = $r.Wear; powerOnHours = $r.PowerOnHours
      readErrors = $r.ReadErrorsTotal; writeErrors = $r.WriteErrorsTotal; startStopCount = $r.StartStopCycleCount
    } })
}

# --- Volumes and BitLocker --------------------------------------------------------------------------------------
$bitlocker = @{}
Section {
  foreach ($v in Get-BitLockerVolume) {
    $bitlocker[$v.MountPoint.TrimEnd('\')] = $v
    foreach ($p in $v.KeyProtector) {
      if ("$($p.KeyProtectorType)" -eq 'RecoveryPassword' -and $p.RecoveryPassword) {
        [void]$recoveryKeys.Add([ordered]@{ volume = $v.MountPoint.TrimEnd('\'); keyId = "$($p.KeyProtectorId)"; recoveryPassword = $p.RecoveryPassword; kind = 'bitlocker' })
      }
    }
  }
} | Out-Null
$systemDrive = $env:SystemDrive
$profile.volumes = Section {
  @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Size -gt 1GB } | ForEach-Object {
    $mount = $(if ($_.DriveLetter) { "$($_.DriveLetter):" } else { $_.FileSystemLabel })
    $b = $bitlocker[$mount]
    [ordered]@{
      mount = $mount; label = $_.FileSystemLabel; fileSystem = $_.FileSystem; sizeGb = Gb $_.Size; freeGb = Gb $_.SizeRemaining
      health = "$($_.HealthStatus)"; system = ($mount -eq $systemDrive)
      encryption = $(if ($b) { [ordered]@{ status = "$($b.VolumeStatus)"; protection = "$($b.ProtectionStatus)"; percent = $b.EncryptionPercentage;
                                            method = "$($b.EncryptionMethod)"; protectors = @($b.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) } })
    } })
}

# --- Users ------------------------------------------------------------------------------------------------------
$profile.users = Section {
  $admins = @(Section { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.SID)" } })
  $local = @(Get-LocalUser | ForEach-Object {
    [ordered]@{ name = $_.Name; fullName = $_.FullName; enabled = $_.Enabled; admin = ($admins -contains "$($_.SID)")
                lastLogon = Iso $_.LastLogon; passwordLastSet = Iso $_.PasswordLastSet; passwordExpires = Iso $_.PasswordExpires
                passwordRequired = $_.PasswordRequired; description = $_.Description } })
  $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
    $name = Section { ([System.Security.Principal.SecurityIdentifier]$_.SID).Translate([System.Security.Principal.NTAccount]).Value }
    [ordered]@{ name = $(if ($name) { $name } else { $_.SID }); sid = $_.SID; path = $_.LocalPath; lastUse = Iso $_.LastUseTime; loaded = $_.Loaded } })
  $sessions = @(Section {
    (quser 2>$null) | Select-Object -Skip 1 | ForEach-Object {
      $line = $_.Trim() -replace '^>', ''
      $parts = $line -split '\s{2,}'
      if ($parts.Count -ge 5) { [ordered]@{ user = $parts[0]; session = $(if ($parts.Count -ge 6) { $parts[1] } else { '' }); state = $parts[-3]; idle = $parts[-2]; logonTime = $parts[-1] } }
    } })
  [ordered]@{ local = $local; profiles = $profiles; sessions = $sessions; administratorsGroup = @(Section { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name } }) }
}

# --- Network ----------------------------------------------------------------------------------------------------
$profile.network = Section {
  $wifi = Section { (netsh wlan show interfaces) -match '^\s*SSID\s*:' | ForEach-Object { ($_ -split ':', 2)[1].Trim() } | Select-Object -First 1 }
  [ordered]@{
    adapters = @(Get-NetAdapter -Physical | ForEach-Object {
      $cfg = Get-NetIPConfiguration -InterfaceIndex $_.ifIndex
      $wireless = ($_.PhysicalMediaType -match '802.11') -or ($_.InterfaceDescription -match 'Wi-?Fi|Wireless')
      [ordered]@{ name = $_.Name; description = $_.InterfaceDescription; mac = $_.MacAddress; status = "$($_.Status)"; speed = $_.LinkSpeed
                  ipv4 = @($cfg.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }); ipv6 = @($cfg.IPv6Address | ForEach-Object { $_.IPAddress })
                  gateway = @($cfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop }); dns = @($cfg.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses })
                  dhcp = "$((Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).Dhcp)"; wifiSsid = $(if ($wireless -and $_.Status -eq 'Up') { $wifi }) } })
  }
}

# --- Battery ----------------------------------------------------------------------------------------------------
$profile.battery = Section {
  $battery = Get-CimInstance Win32_Battery | Select-Object -First 1
  if (-not $battery) { return [ordered]@{ present = $false } }
  $design = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData | Select-Object -First 1).DesignedCapacity
  $full = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity | Select-Object -First 1).FullChargedCapacity
  $cycles = (Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount | Select-Object -First 1).CycleCount
  [ordered]@{ present = $true; chargePercent = $battery.EstimatedChargeRemaining; status = @{ 1='Discharging'; 2='On AC power'; 3='Fully charged'; 6='Charging' }[[int]$battery.BatteryStatus]
              designCapacity = $design; fullChargeCapacity = $full; cycleCount = $cycles
              healthPercent = $(if ($design -and $full) { [math]::Round(100.0 * $full / $design) }) }
}

# --- Security posture -------------------------------------------------------------------------------------------
$profile.security = Section {
  $av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    $state = [int]$_.productState
    [ordered]@{ name = $_.displayName; enabled = ((($state -shr 12) -band 0xF) -eq 1); upToDate = ((($state -shr 4) -band 0xF) -eq 0) } })
  $defender = Section { Get-MpComputerStatus }
  [ordered]@{
    antivirus = $av
    defender = $(if ($defender) { [ordered]@{ realtime = $defender.RealTimeProtectionEnabled; signatureAgeDays = $defender.AntivirusSignatureAge; tamperProtection = $defender.IsTamperProtected; passive = ("$($defender.AMRunningMode)" -ne 'Normal') } })
    firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = "$($_.Name)"; enabled = [bool]$_.Enabled } })
    uac = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -eq 1)
    rdpEnabled = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
    smb1 = [bool](Section { (Get-SmbServerConfiguration).EnableSMB1Protocol })
    lsaProtection = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL -ge 1)
  }
}

# --- Event log problems -----------------------------------------------------------------------------------------
$profile.events = Section {
  $day = (Get-Date).AddDays(-1); $week = (Get-Date).AddDays(-7)
  $critical = @(Get-WinEvent -FilterHashtable @{ LogName = 'System','Application'; Level = 1,2; StartTime = $day } -MaxEvents 500)
  $shutdowns = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41,6008; StartTime = $week } -MaxEvents 100)
  $diskErrors = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'disk','Ntfs','stornvme','storahci'; Level = 1,2,3; StartTime = $week } -MaxEvents 200)
  $bsod = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $week } -MaxEvents 20)
  [ordered]@{
    errorsLast24h = ($critical | Where-Object Level -eq 2).Count; criticalLast24h = ($critical | Where-Object Level -eq 1).Count
    unexpectedShutdowns7d = $shutdowns.Count; diskErrors7d = $diskErrors.Count; bluescreens7d = $bsod.Count
    recent = @($critical + $shutdowns + $diskErrors | Sort-Object TimeCreated -Descending | Select-Object -First 25 | ForEach-Object {
      [ordered]@{ time = Iso $_.TimeCreated; log = $_.LogName; id = $_.Id; source = $_.ProviderName; level = "$($_.LevelDisplayName)"
                  message = ("$($_.Message)" -split "`n")[0].Trim() } })
  }
}

# --- Services, startup, printers, monitors, shares --------------------------------------------------------------
$profile.services = Section {
  [ordered]@{ autoStopped = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" |
    Where-Object { $_.Name -notmatch '^(gupdate|edgeupdate|MapsBroker|sppsvc|RemoteRegistry|WbioSrvc|TrustedInstaller|BITS|wuauserv|UsoSvc|CDPSvc|tiledatamodelsvc|GoogleUpdater.*|clr_optimization.*|DoSvc|WaaSMedicSvc)' } |
    ForEach-Object { $_.DisplayName } | Select-Object -First 40) }
}
$profile.startup = Section { @(Get-CimInstance Win32_StartupCommand | Select-Object -First 60 | ForEach-Object { [ordered]@{ name = $_.Name; command = $_.Command; location = $_.Location; user = $_.User } }) }
$profile.printers = Section { @(Get-Printer | ForEach-Object { [ordered]@{ name = $_.Name; driver = $_.DriverName; port = $_.PortName; shared = $_.Shared; type = "$($_.Type)" } }) }
$profile.monitors = Section {
  $text = { param($codes) (($codes | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ }) -join '').Trim() }
  @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID | ForEach-Object {
    [ordered]@{ manufacturer = & $text $_.ManufacturerName; model = & $text $_.UserFriendlyName; serial = & $text $_.SerialNumberID; year = $_.YearOfManufacture } })
}
$profile.shares = Section { @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { [ordered]@{ name = $_.Name; path = $_.Path; description = $_.Description } }) }

[ordered]@{ profile = $profile; recoveryKeys = @($recoveryKeys) } | ConvertTo-Json -Depth 8 -Compress
