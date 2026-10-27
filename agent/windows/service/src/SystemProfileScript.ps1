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

# --- Role: workstation, server or domain controller (re-detected every run, so promotions show up) ----------------
$profile.role = Section {
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $domainRoles = @{ 0='Standalone workstation'; 1='Member workstation'; 2='Standalone server'; 3='Member server'; 4='Backup domain controller'; 5='Primary domain controller' }
  $kind = switch ([int]$os.ProductType) { 2 { 'domain-controller' } 3 { 'server' } default { 'workstation' } }
  $features = @()
  if ($kind -ne 'workstation') {
    $features = @(Section { Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { $_.DisplayName } })
  }
  # Workloads recognised from their services, so roles show up on workstations and when Get-WindowsFeature is missing.
  $known = [ordered]@{ NTDS='Active Directory Domain Services'; DNS='DNS Server'; DHCPServer='DHCP Server'; CertSvc='Certificate Services';
    W3SVC='IIS web server'; MSSQLSERVER='SQL Server'; MSExchangeIS='Exchange Server'; vmms='Hyper-V'; LanmanServer='File sharing';
    TermService='Remote Desktop'; Spooler='Print spooler'; WSUSService='WSUS'; ADSync='Entra Connect (Azure AD Connect)'; ADFSSrv='AD FS' }
  $running = @{}
  Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $running[$_.Name] = $true }
  $workloads = @($known.Keys | Where-Object { $running[$_] -or ($_ -eq 'MSSQLSERVER' -and ($running.Keys -match '^MSSQL\$')) } | ForEach-Object { $known[$_] })
  [ordered]@{ kind = $kind; productType = [int]$os.ProductType; domainRole = $domainRoles[[int]$cs.DomainRole]; domainRoleId = [int]$cs.DomainRole
    partOfDomain = [bool]$cs.PartOfDomain; domain = $cs.Domain; serverRoles = $features; workloads = $workloads }
}

# --- Audit policy that Active Directory and sign-in detections depend on ---------------------------------------------
$profile.auditPolicy = Section {
  $wanted = @{ '{0CCE923B-69AE-11D9-BED3-505054503030}'='Directory Service Access'; '{0CCE923C-69AE-11D9-BED3-505054503030}'='Directory Service Changes';
    '{0CCE9237-69AE-11D9-BED3-505054503030}'='Security Group Management'; '{0CCE9235-69AE-11D9-BED3-505054503030}'='User Account Management';
    '{0CCE9236-69AE-11D9-BED3-505054503030}'='Computer Account Management'; '{0CCE9242-69AE-11D9-BED3-505054503030}'='Kerberos Authentication Service';
    '{0CCE9240-69AE-11D9-BED3-505054503030}'='Kerberos Service Ticket Operations'; '{0CCE923F-69AE-11D9-BED3-505054503030}'='Credential Validation';
    '{0CCE9215-69AE-11D9-BED3-505054503030}'='Logon' }
  $rows = auditpol /get /category:* /r | ConvertFrom-Csv
  @($rows | Where-Object { $wanted.ContainsKey("$($_.'Subcategory GUID')".ToUpper()) } | ForEach-Object {
    $value = "$($_.'Setting Value')"
    if (-not $value) { $text = "$($_.'Inclusion Setting')"; $value = "$([int]($text -match 'Success') + 2 * [int]($text -match 'Failure'))" }
    [ordered]@{ guid = "$($_.'Subcategory GUID')".ToUpper(); name = $wanted["$($_.'Subcategory GUID')".ToUpper()]
      success = ($value -eq '1' -or $value -eq '3'); failure = ($value -eq '2' -or $value -eq '3'); setting = $_.'Inclusion Setting' } })
}

# --- Active Directory (domain controllers only) ------------------------------------------------------------------------
if ($profile.role -and $profile.role.kind -eq 'domain-controller') {
  $profile.activeDirectory = Section {
    Import-Module ActiveDirectory -ErrorAction Stop
    $now = Get-Date
    $domain = Get-ADDomain; $forest = Get-ADForest
    $ageDays = { param($when) if ($when -is [datetime] -and $when.Year -gt 1601) { [int]($now - $when).TotalDays } else { $null } }
    $userProps = 'Enabled','LastLogonDate','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','AllowReversiblePasswordEncryption','DoesNotRequirePreAuth','ServicePrincipalName','AdminCount','TrustedForDelegation','TrustedToAuthForDelegation','SIDHistory','Description','whenCreated','UserPrincipalName','msDS-SupportedEncryptionTypes'
    $users = @(Get-ADUser -Filter * -Properties $userProps -ResultSetSize 100000)
    $computers = @(Get-ADComputer -Filter * -Properties Enabled,LastLogonDate,OperatingSystem,OperatingSystemVersion,TrustedForDelegation,TrustedToAuthForDelegation,PrimaryGroupID,'msDS-AllowedToActOnBehalfOfOtherIdentity','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime' -ResultSetSize 100000)
    $brief = { param($u) [ordered]@{ sam = $u.SamAccountName; name = $u.Name; enabled = [bool]$u.Enabled; lastLogon = Iso $u.LastLogonDate
      passwordLastSet = Iso $u.PasswordLastSet; passwordAgeDays = & $ageDays $u.PasswordLastSet; passwordNeverExpires = [bool]$u.PasswordNeverExpires
      spn = @($u.ServicePrincipalName | Select-Object -First 5); dn = $u.DistinguishedName } }
    # Privileged groups by well-known SID so renamed or localised groups are still found. Enterprise and Schema
    # Admins live in the forest root domain.
    $rootSid = Section { (Get-ADDomain -Identity $forest.RootDomain).DomainSID.Value }
    if (-not $rootSid) { $rootSid = $sid }
    $privileged = [ordered]@{ 'Domain Admins'="$sid-512"; 'Enterprise Admins'="$rootSid-519"; 'Schema Admins'="$rootSid-518"
      'Administrators'='S-1-5-32-544'; 'Account Operators'='S-1-5-32-548'; 'Server Operators'='S-1-5-32-549'; 'Backup Operators'='S-1-5-32-551'
      'Print Operators'='S-1-5-32-550'; 'Group Policy Creator Owners'="$sid-520"; 'Cert Publishers'="$sid-517"; 'Key Admins'="$sid-526"; 'Enterprise Key Admins'="$rootSid-527" }
    $groups = @()
    foreach ($label in @($privileged.Keys)) {
      $server = $domain.DNSRoot
      if ($privileged[$label].StartsWith("$rootSid-") -and $rootSid -ne $sid) { $server = $forest.RootDomain }
      $g = Section { Get-ADGroup -Identity $privileged[$label] -Server $server }
      if (-not $g) { continue }
      $members = @(Section { Get-ADGroupMember -Identity $g -Recursive -Server $server })
      $groups += [ordered]@{ name = $g.Name; label = $label; sid = $g.SID.Value; memberCount = $members.Count
        members = @($members | Select-Object -First 100 | ForEach-Object { [ordered]@{ sam = $_.SamAccountName; name = $_.Name; type = $_.objectClass } }) }
    }
    $dnsAdmins = Section { Get-ADGroup -Filter "Name -eq 'DnsAdmins'" }
    if ($dnsAdmins) { $m = @(Section { Get-ADGroupMember $dnsAdmins -Recursive }); $groups += [ordered]@{ name = $dnsAdmins.Name; label = 'DnsAdmins'; sid = $dnsAdmins.SID.Value; memberCount = $m.Count; members = @($m | Select-Object -First 100 | ForEach-Object { [ordered]@{ sam = $_.SamAccountName; name = $_.Name; type = $_.objectClass } }) } }
    $protectedUsers = Section { @(Get-ADGroupMember -Identity "$sid-525").Count }
    $privilegedSams = @{}
    foreach ($g in $groups) { foreach ($m in $g.members) { if ($m.type -eq 'user') { $privilegedSams[$m.sam] = $true } } }
    $enabledUsers = @($users | Where-Object { $_.Enabled })
    $staleCutoff = $now.AddDays(-90)
    $isStale = { param($u) (-not $u.LastLogonDate -and $u.whenCreated -lt $staleCutoff) -or ($u.LastLogonDate -and $u.LastLogonDate -lt $staleCutoff) }
    $krbtgt = $users | Where-Object { $_.SamAccountName -eq 'krbtgt' } | Select-Object -First 1
    $builtinAdmin = $users | Where-Object { $_.SID.Value -eq "$sid-500" } | Select-Object -First 1
    $guest = $users | Where-Object { $_.SID.Value -eq "$sid-501" } | Select-Object -First 1
    $policy = Get-ADDefaultDomainPasswordPolicy
    $dcs = @(Get-ADDomainController -Filter * | ForEach-Object { [ordered]@{ name = $_.HostName; site = $_.Site; os = $_.OperatingSystem; osVersion = $_.OperatingSystemVersion
      ipv4 = $_.IPv4Address; globalCatalog = [bool]$_.IsGlobalCatalog; readOnly = [bool]$_.IsReadOnly; roles = @($_.OperationMasterRoles | ForEach-Object { "$_" }) } })
    $dcNames = @{}; foreach ($dc in $dcs) { $dcNames[("$($dc.name)".Split('.')[0]).ToUpper()] = $true }
    $recycleBin = Section { [bool]((Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes.Count -gt 0) }
    $schemaAttrs = Section { $schema = (Get-ADRootDSE).schemaNamingContext
      [ordered]@{ legacyLaps = [bool](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)'); windowsLaps = [bool](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=msLAPS-Password)') } }
    $lapsCovered = @($computers | Where-Object { $_.Enabled -and $_.PrimaryGroupID -ne 516 -and ($_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'msLAPS-PasswordExpirationTime') }).Count
    $gpos = Section { @(Get-GPO -All | Sort-Object ModificationTime -Descending | ForEach-Object { [ordered]@{ name = $_.DisplayName; id = "$($_.Id)"; modified = Iso $_.ModificationTime; status = "$($_.GpoStatus)" } }) }
    $trusts = Section { @(Get-ADTrust -Filter * | ForEach-Object { [ordered]@{ name = $_.Name; direction = "$($_.Direction)"; type = "$($_.TrustType)"; sidFilteringQuarantined = [bool]$_.SIDFilteringQuarantined; sidFilteringForestAware = [bool]$_.SIDFilteringForestAware; selectiveAuth = [bool]$_.SelectiveAuthentication; forestTransitive = [bool]$_.ForestTransitive } }) }
    $fgpp = Section { @(Get-ADFineGrainedPasswordPolicy -Filter *).Count }
    [ordered]@{
      domain = [ordered]@{ dnsName = $domain.DNSRoot; netbios = $domain.NetBIOSName; dn = $domain.DistinguishedName; sid = $sid; mode = "$($domain.DomainMode)"
        forest = $forest.Name; forestMode = "$($forest.ForestMode)"; pdcEmulator = $domain.PDCEmulator; ridMaster = $domain.RIDMaster; infrastructureMaster = $domain.InfrastructureMaster
        schemaMaster = $forest.SchemaMaster; domainNamingMaster = $forest.DomainNamingMaster; sites = @($forest.Sites); domains = @($forest.Domains) }
      domainControllers = $dcs
      counts = [ordered]@{ users = $users.Count; enabledUsers = $enabledUsers.Count; computers = $computers.Count; enabledComputers = @($computers | Where-Object { $_.Enabled }).Count
        groups = Section { @(Get-ADGroup -Filter * -ResultSetSize 100000).Count }; gpos = @($gpos).Count; protectedUsers = $protectedUsers; fineGrainedPolicies = $fgpp }
      privilegedGroups = $groups
      passwordPolicy = [ordered]@{ minLength = $policy.MinPasswordLength; complexity = [bool]$policy.ComplexityEnabled; maxAgeDays = [int]$policy.MaxPasswordAge.TotalDays
        historyCount = $policy.PasswordHistoryCount; lockoutThreshold = $policy.LockoutThreshold; lockoutMinutes = [int]$policy.LockoutDuration.TotalMinutes; reversibleEncryption = [bool]$policy.ReversibleEncryptionEnabled }
      krbtgt = [ordered]@{ passwordLastSet = Iso $krbtgt.PasswordLastSet; passwordAgeDays = & $ageDays $krbtgt.PasswordLastSet }
      builtinAdministrator = $(if ($builtinAdmin) { [ordered]@{ sam = $builtinAdmin.SamAccountName; enabled = [bool]$builtinAdmin.Enabled; lastLogon = Iso $builtinAdmin.LastLogonDate; passwordAgeDays = & $ageDays $builtinAdmin.PasswordLastSet } })
      guestEnabled = [bool]$guest.Enabled
      risky = [ordered]@{
        kerberoastable = @($enabledUsers | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' } | Select-Object -First 200 | ForEach-Object { $b = & $brief $_; $b.privileged = [bool]$privilegedSams[$_.SamAccountName]; $b })
        asrepRoastable = @($enabledUsers | Where-Object { $_.DoesNotRequirePreAuth } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        passwordNotRequired = @($enabledUsers | Where-Object { $_.PasswordNotRequired } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        reversibleEncryption = @($enabledUsers | Where-Object { $_.AllowReversiblePasswordEncryption } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        privilegedPasswordNeverExpires = @($enabledUsers | Where-Object { $_.PasswordNeverExpires -and $privilegedSams[$_.SamAccountName] } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        privilegedStale = @($enabledUsers | Where-Object { $privilegedSams[$_.SamAccountName] -and (& $isStale $_) } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        privilegedOldPassword = @($enabledUsers | Where-Object { $privilegedSams[$_.SamAccountName] -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $now.AddDays(-365) } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        sidHistory = @($users | Where-Object { $_.SIDHistory.Count -gt 0 } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        adminCountOrphans = @($enabledUsers | Where-Object { $_.AdminCount -eq 1 -and -not $privilegedSams[$_.SamAccountName] -and $_.SamAccountName -ne 'krbtgt' } | Select-Object -First 200 | ForEach-Object { & $brief $_ })
        staleUsers = @($enabledUsers | Where-Object { & $isStale $_ }).Count
        staleComputers = @($computers | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $staleCutoff }).Count
        unconstrainedDelegation = @($computers | Where-Object { $_.Enabled -and $_.TrustedForDelegation -and -not $dcNames[("$($_.Name)").ToUpper()] } | Select-Object -First 200 | ForEach-Object { [ordered]@{ sam = $_.SamAccountName; name = $_.Name; os = $_.OperatingSystem; dn = $_.DistinguishedName } }) + @($enabledUsers | Where-Object { $_.TrustedForDelegation } | Select-Object -First 50 | ForEach-Object { & $brief $_ })
        resourceBasedDelegation = @($computers | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } | Select-Object -First 200 | ForEach-Object { [ordered]@{ sam = $_.SamAccountName; name = $_.Name; dn = $_.DistinguishedName } })
        unsupportedOs = @($computers | Where-Object { $_.Enabled -and $_.OperatingSystem -match 'Windows (XP|Vista|7|8 |8\.1|Server 2003|Server 2008|Server 2012)' } | Select-Object -First 200 | ForEach-Object { [ordered]@{ name = $_.Name; os = $_.OperatingSystem; lastLogon = Iso $_.LastLogonDate } })
      }
      laps = [ordered]@{ legacySchema = $schemaAttrs.legacyLaps; windowsSchema = $schemaAttrs.windowsLaps; coveredComputers = $lapsCovered
        eligibleComputers = @($computers | Where-Object { $_.Enabled -and $_.PrimaryGroupID -ne 516 }).Count }
      recycleBin = $recycleBin
      gpos = @($gpos | Select-Object -First 300)
      trusts = $trusts
    }
  }
}

[ordered]@{ profile = $profile; recoveryKeys = @($recoveryKeys) } | ConvertTo-Json -Depth 8 -Compress
