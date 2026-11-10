# Runs the real Active Directory section of SystemProfileScript.ps1 against stand-ins for the ActiveDirectory module
# (the CI runner is not a domain controller). The stand-ins behave like Active Directory where it matters:
# Get-ADComputer rejects the whole query when asked for a LAPS attribute the schema does not have. That alone used to
# throw away the entire snapshot.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\service\src\SystemProfileScript.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$section = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and
  $node.Clauses[0].Item1.Extent.Text -match "domain-controller" -and $node.Extent.Text -match 'activeDirectory' }, $false) | Select-Object -First 1
if (-not $section) { throw 'The Active Directory section was not found' }

function Section([scriptblock]$Block) { try { & $Block } catch { $null } }
function Iso($Value) { if ($Value -is [datetime] -and $Value.Year -gt 1601) { $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }

$domainSid = 'S-1-5-21-1111-2222-3333'
function Sid($value) { [pscustomobject]@{ Value = $value } }
function Import-Module { param([string]$Name) if ($Name -eq 'ActiveDirectory' -and $script:noModule) { throw "The specified module 'ActiveDirectory' was not loaded because no valid module file was found." }
  if ($Name -eq 'GroupPolicy') { throw "The specified module 'GroupPolicy' was not loaded." } }
function Get-ADDomain { [CmdletBinding()] param($Identity, $Server)
  if ($script:noAdws) { throw 'Unable to find a default server with Active Directory Web Services running.' }
  [pscustomobject]@{ DNSRoot = 'contoso.example'; NetBIOSName = 'CONTOSO'; DistinguishedName = 'DC=contoso,DC=example'; DomainSID = (Sid $domainSid)
    DomainMode = 'Windows2016Domain'; PDCEmulator = 'DC01.contoso.example'; RIDMaster = 'DC01.contoso.example'; InfrastructureMaster = 'DC01.contoso.example' } }
function Get-ADForest { [CmdletBinding()] param()
  [pscustomobject]@{ Name = 'contoso.example'; RootDomain = 'contoso.example'; ForestMode = 'Windows2016Forest'; SchemaMaster = 'DC01.contoso.example'
    DomainNamingMaster = 'DC01.contoso.example'; Sites = @('Default-First-Site-Name'); Domains = @('contoso.example') } }
function Get-ADRootDSE { [CmdletBinding()] param() [pscustomobject]@{ schemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=example' } }
function Get-ADObject { [CmdletBinding()] param($SearchBase, $LDAPFilter)
  if ($LDAPFilter -match 'ms-Mcs-AdmPwd' -and $script:legacyLaps) { [pscustomobject]@{ Name = 'ms-Mcs-AdmPwd' } }
  if ($LDAPFilter -match 'msLAPS-Password' -and $script:windowsLaps) { [pscustomobject]@{ Name = 'msLAPS-Password' } } }
function User($sam, $rid, [bool]$enabled = $true, $spn = $null, $lastLogon = (Get-Date).AddDays(-2)) {
  [pscustomobject]@{ SamAccountName = $sam; Name = $sam; Enabled = $enabled; SID = (Sid "$domainSid-$rid"); LastLogonDate = $lastLogon
    PasswordLastSet = (Get-Date).AddDays(-400); PasswordNeverExpires = $false; PasswordNotRequired = $false; AllowReversiblePasswordEncryption = $false
    DoesNotRequirePreAuth = $false; ServicePrincipalName = $spn; AdminCount = 0; TrustedForDelegation = $false; SIDHistory = @()
    whenCreated = (Get-Date).AddDays(-900); DistinguishedName = "CN=$sam,CN=Users,DC=contoso,DC=example" } }
function Get-ADUser { [CmdletBinding()] param($Filter, $Properties, $ResultSetSize)
  User 'Administrator' 500; User 'Guest' 501 $false; User 'krbtgt' 502 $false; User 'svc-sql' 1105 $true @('MSSQLSvc/sql01:1433'); User 'jo' 1106 }
function Get-ADComputer { [CmdletBinding()] param($Filter, $Properties, $ResultSetSize)
  if (($Properties -contains 'ms-Mcs-AdmPwdExpirationTime' -and -not $script:legacyLaps) -or ($Properties -contains 'msLAPS-PasswordExpirationTime' -and -not $script:windowsLaps)) {
    throw [System.ArgumentException]::new('One or more properties are invalid.') }
  [pscustomobject]@{ Name = 'DC01'; SamAccountName = 'DC01$'; Enabled = $true; LastLogonDate = (Get-Date); OperatingSystem = 'Windows Server 2022'; PrimaryGroupID = 516; TrustedForDelegation = $true }
  [pscustomobject]@{ Name = 'PC01'; SamAccountName = 'PC01$'; Enabled = $true; LastLogonDate = (Get-Date); OperatingSystem = 'Windows 11 Pro'; PrimaryGroupID = 515
    TrustedForDelegation = $false; 'msLAPS-PasswordExpirationTime' = $(if ($script:windowsLaps) { 1 }) } }
function Get-ADGroup { [CmdletBinding()] param($Identity, $Filter, $Server, $ResultSetSize)
  if ($Filter -eq '*') { 1..7 | ForEach-Object { [pscustomobject]@{ Name = "Group $_" } }; return }
  if ($Filter) { return }
  switch ($Identity) {
    "$domainSid-512" { return [pscustomobject]@{ Name = 'Domain Admins'; SID = (Sid "$domainSid-512") } }
    'S-1-5-32-544' { return [pscustomobject]@{ Name = 'Administrators'; SID = (Sid 'S-1-5-32-544') } }
  }
  throw "Cannot find an object with identity: '$Identity'" }
function Get-ADGroupMember { [CmdletBinding()] param([Parameter(Position = 0)] $Identity, [switch]$Recursive, $Server)
  if ("$($Identity.Name)" -in @('Domain Admins', 'Administrators')) { [pscustomobject]@{ SamAccountName = 'Administrator'; Name = 'Administrator'; objectClass = 'user' } }
  elseif ("$Identity" -eq "$domainSid-525") { } else { throw 'not found' } }
function Get-ADDefaultDomainPasswordPolicy { [CmdletBinding()] param()
  [pscustomobject]@{ MinPasswordLength = 7; ComplexityEnabled = $true; MaxPasswordAge = [timespan]::FromDays(42); PasswordHistoryCount = 24; LockoutThreshold = 0
    LockoutDuration = [timespan]::FromMinutes(10); ReversibleEncryptionEnabled = $false } }
function Get-ADDomainController { [CmdletBinding()] param($Filter)
  [pscustomobject]@{ HostName = 'DC01.contoso.example'; Site = 'Default-First-Site-Name'; OperatingSystem = 'Windows Server 2022'; OperatingSystemVersion = '10.0 (20348)'
    IPv4Address = '10.0.0.10'; IsGlobalCatalog = $true; IsReadOnly = $false; OperationMasterRoles = @('PDCEmulator', 'RIDMaster') } }
function Get-ADOptionalFeature { [CmdletBinding()] param($Filter) [pscustomobject]@{ EnabledScopes = @() } }
function Get-ADTrust { [CmdletBinding()] param($Filter) }
function Get-ADFineGrainedPasswordPolicy { [CmdletBinding()] param($Filter) }

function Snapshot {
  $profile = [ordered]@{ role = [ordered]@{ kind = 'domain-controller' } }
  Invoke-Expression $section.Extent.Text
  $json = [ordered]@{ profile = $profile } | ConvertTo-Json -Depth 8 -Compress
  ($json | ConvertFrom-Json).profile.activeDirectory
}
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw "FAILED: $what" } ; Write-Host "ok: $what" }

# 1. No LAPS schema (most small domains): the snapshot still arrives in full.
$script:legacyLaps = $false; $script:windowsLaps = $false; $script:noModule = $false; $script:noAdws = $false
$ad = Snapshot
Check ($null -ne $ad -and -not $ad.error) 'a domain without the LAPS schema still sends a snapshot'
Check ($ad.domain.dnsName -eq 'contoso.example' -and $ad.domain.sid -eq $domainSid) 'the domain and its SID are reported'
Check ($ad.counts.users -eq 5 -and $ad.counts.computers -eq 2 -and $ad.counts.groups -eq 7) 'users, computers and groups are counted'
$admins = $ad.privilegedGroups | Where-Object { $_.label -eq 'Domain Admins' }
Check ($admins.memberCount -eq 1 -and $admins.members[0].sam -eq 'Administrator') 'Domain Admins is found by its SID, with its members'
Check ($ad.risky.kerberoastable.Count -eq 1 -and $ad.risky.kerberoastable[0].sam -eq 'svc-sql') 'Kerberoastable accounts are found'
Check ($ad.builtinAdministrator.sam -eq 'Administrator') 'the built-in Administrator is found by its SID'
Check ($ad.passwordPolicy.minLength -eq 7 -and $ad.domainControllers[0].name -eq 'DC01.contoso.example') 'password policy and domain controllers are reported'
Check ($ad.laps.windowsSchema -eq $false -and $ad.laps.coveredComputers -eq 0) 'LAPS is reported as not deployed'
Check (@($ad.collectionErrors | Where-Object { $_ -like 'group policies:*' }).Count -eq 1) 'a missing GroupPolicy module is named, not fatal'
Check (@($ad.collectionErrors | Where-Object { $_ -like 'computers:*' }).Count -eq 0) 'computers are read without asking for missing attributes'

# 2. Windows LAPS deployed: its attribute is asked for and coverage is counted.
$script:windowsLaps = $true
$ad = Snapshot
Check ($ad.laps.windowsSchema -eq $true -and $ad.laps.coveredComputers -eq 1 -and $ad.laps.eligibleComputers -eq 1) 'Windows LAPS coverage is counted when the schema has it'

# 3. No ActiveDirectory module: an explanation instead of silence.
$script:noModule = $true
$ad = Snapshot
Check ($ad.error -match 'RSAT-AD-PowerShell') 'a missing ActiveDirectory module says how to install it'

# 4. Active Directory Web Services stopped.
$script:noModule = $false; $script:noAdws = $true
$ad = Snapshot
Check ($ad.error -match 'Active Directory Web Services') 'a stopped ADWS is explained'
Write-Host 'Active Directory snapshot: all checks passed.'
