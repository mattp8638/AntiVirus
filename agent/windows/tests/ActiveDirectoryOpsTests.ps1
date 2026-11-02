# Runs the real ActiveDirectoryOpsScript.ps1 against stand-ins for the ActiveDirectory and ADSync modules (the CI
# runner is not a domain controller) and checks every operation hybrid onboarding and offboarding use.
$ErrorActionPreference = 'Stop'
$script = Resolve-Path (Join-Path $PSScriptRoot '..\service\src\ActiveDirectoryOpsScript.ps1')
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

$script:calls = New-Object System.Collections.ArrayList
$script:users = @{}
$script:noModule = $false
$script:exchangeSchema = $false
function NewUser($sam, $upn) {
  [pscustomobject]@{ SamAccountName = $sam; UserPrincipalName = $upn; DisplayName = $sam; Enabled = $true; ObjectGUID = [guid]::NewGuid()
    DistinguishedName = "CN=$sam,OU=Staff,DC=acme,DC=example"; mail = $upn; Title = ''; Department = ''; Manager = $null; Description = ''
    MemberOf = @('CN=Sales AD,OU=Groups,DC=acme,DC=example', 'CN=VPN Users,OU=Groups,DC=acme,DC=example'); LastLogonDate = (Get-Date) }
}
$script:users['jo'] = NewUser 'jo' 'jo@acme.example'
$script:users["o'brien"] = NewUser "o'brien" 'obrien@acme.example'

function Import-Module { param([string]$Name, $ErrorAction)
  if ($Name -eq 'ActiveDirectory' -and $script:noModule) { throw "The specified module 'ActiveDirectory' was not loaded" }
  if ($Name -eq 'ADSync') { throw "The specified module 'ADSync' was not loaded" } }
function Get-ADDomain { [CmdletBinding()] param() [pscustomobject]@{ DNSRoot = 'acme.example'; NetBIOSName = 'ACME'; UsersContainer = 'CN=Users,DC=acme,DC=example' } }
function Get-ADForest { [CmdletBinding()] param() [pscustomobject]@{ UPNSuffixes = @('acme.co.uk') } }
function Get-ADOrganizationalUnit { [CmdletBinding()] param($Filter, $ResultSetSize)
  [pscustomobject]@{ DistinguishedName = 'OU=Staff,DC=acme,DC=example'; Name = 'Staff' }
  [pscustomobject]@{ DistinguishedName = 'OU=Leavers,DC=acme,DC=example'; Name = 'Leavers' } }
function Get-ADGroup { [CmdletBinding()] param($Filter, $Properties, $ResultSetSize)
  [pscustomobject]@{ DistinguishedName = 'CN=Sales AD,OU=Groups,DC=acme,DC=example'; Name = 'Sales AD'; GroupCategory = 'Security'; GroupScope = 'Global'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-1104' } }
  [pscustomobject]@{ DistinguishedName = 'CN=Domain Admins,CN=Users,DC=acme,DC=example'; Name = 'Domain Admins'; GroupCategory = 'Security'; GroupScope = 'Global'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-512' } }
  [pscustomobject]@{ DistinguishedName = 'CN=Administrators,CN=Builtin,DC=acme,DC=example'; Name = 'Administrators'; GroupCategory = 'Security'; GroupScope = 'DomainLocal'; SID = [pscustomobject]@{ Value = 'S-1-5-32-544' } } }
function Get-ADUser { [CmdletBinding()] param($Filter, $Properties)
  $names = [regex]::Matches("$Filter", "-eq '((?:[^']|'')*)'") | ForEach-Object { $_.Groups[1].Value.Replace("''", "'") }
  foreach ($u in $script:users.Values) { if ($names -contains $u.SamAccountName -or $names -contains $u.UserPrincipalName) { $u } } }
function New-ADUser { [CmdletBinding()] param($Name, $SamAccountName, $UserPrincipalName, $DisplayName, $Path, $AccountPassword, $Enabled, $ChangePasswordAtLogon,
  [switch]$PassThru, $GivenName, $Surname, $Title, $Department, $Office, $OfficePhone, $EmailAddress)
  $plain = [System.Net.NetworkCredential]::new('', $AccountPassword).Password
  [void]$script:calls.Add(@{ op = 'New-ADUser'; sam = $SamAccountName; path = $Path; password = $plain; change = $ChangePasswordAtLogon })
  $u = NewUser $SamAccountName $UserPrincipalName; $u.MemberOf = @(); $u.DistinguishedName = "CN=$Name,$Path"
  $script:users[$SamAccountName] = $u; $u }
function Set-ADUser { [CmdletBinding()] param($Identity, $Manager, $Description, $Replace, $ChangePasswordAtLogon)
  [void]$script:calls.Add(@{ op = 'Set-ADUser'; description = $Description; replace = $Replace }) }
function Add-ADGroupMember { [CmdletBinding()] param($Identity, $Members) [void]$script:calls.Add(@{ op = 'Add-ADGroupMember'; group = "$Identity" }) }
function Remove-ADGroupMember { [CmdletBinding()] param($Identity, $Members, [switch]$Confirm) [void]$script:calls.Add(@{ op = 'Remove-ADGroupMember'; group = "$Identity" }) }
function Disable-ADAccount { [CmdletBinding()] param($Identity) [void]$script:calls.Add(@{ op = 'Disable-ADAccount'; sam = $Identity.SamAccountName }); $Identity.Enabled = $false }
function Enable-ADAccount { [CmdletBinding()] param($Identity) $Identity.Enabled = $true }
function Unlock-ADAccount { [CmdletBinding()] param($Identity) }
function Set-ADAccountPassword { [CmdletBinding()] param($Identity, [switch]$Reset, $NewPassword)
  [void]$script:calls.Add(@{ op = 'Set-ADAccountPassword'; password = [System.Net.NetworkCredential]::new('', $NewPassword).Password }) }
function Move-ADObject { [CmdletBinding()] param($Identity, $TargetPath) [void]$script:calls.Add(@{ op = 'Move-ADObject'; target = $TargetPath }) }
function Get-ADRootDSE { [CmdletBinding()] param() [pscustomobject]@{ schemaNamingContext = 'CN=Schema,CN=Configuration,DC=acme,DC=example' } }
function Get-ADObject { [CmdletBinding()] param($SearchBase, $LDAPFilter) if ($script:exchangeSchema) { [pscustomobject]@{ Name = 'msExchHideFromAddressLists' } } }

function Op($Operation, $Params, [string]$Secret = '') {
  $request = Join-Path $env:TEMP "fenrir-ad-test-$([guid]::NewGuid()).json"
  [ordered]@{ operation = $Operation; params = $Params } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $request -Encoding UTF8
  $secretFile = ''
  if ($Secret) { $secretFile = "$request.secret"; [IO.File]::WriteAllText($secretFile, $Secret) }
  $script:calls.Clear()
  $out = & { . $script $request $secretFile }
  foreach ($file in @($request, $secretFile)) { if ($file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue } }
  ($out | Select-Object -Last 1) | ConvertFrom-Json
}
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw "FAILED: $what" }; Write-Host "ok: $what" }

$r = Op 'options' @{}
Check ($r.ok -and $r.domain -eq 'acme.example' -and ($r.upnSuffixes -contains 'acme.co.uk')) 'options: domain and UPN suffixes'
Check (@($r.ous).Count -eq 2 -and (@($r.groups).name -contains 'Sales AD') -and -not (@($r.groups).name -contains 'Domain Admins') -and -not (@($r.groups).name -contains 'Administrators')) 'options: OUs and groups, without privileged or built-in groups'

$r = Op 'create' @{ sam = 'nnew'; upn = 'nia@acme.example'; givenName = 'Nia'; surname = 'New'; displayName = 'Nia New'; ou = 'OU=Staff,DC=acme,DC=example'
  groups = @('CN=Sales AD,OU=Groups,DC=acme,DC=example'); mustChange = $true } 'Temp-Pass-12345!'
$created = $script:calls | Where-Object { $_.op -eq 'New-ADUser' }
Check ($r.ok -and $r.user.sam -eq 'nnew') 'create: the account is made'
Check ($created.password -eq 'Temp-Pass-12345!' -and $created.change -eq $true -and $created.path -eq 'OU=Staff,DC=acme,DC=example') 'create: the one-time password from its own file, change at next sign-in, chosen OU'
Check (@($script:calls | Where-Object { $_.op -eq 'Add-ADGroupMember' }).Count -eq 1) 'create: added to the chosen group'
$r = Op 'create' @{ sam = 'nnew'; upn = 'nia2@acme.example'; displayName = 'Again' } 'Temp-Pass-12345!'
Check (-not $r.ok -and $r.error -match 'already exists') 'create: refuses an existing logon name'
$r = Op 'create' @{ sam = 'bad name'; upn = 'x@acme.example'; displayName = 'Bad' } 'Temp-Pass-12345!'
Check (-not $r.ok -and $r.error -match 'logon name') 'create: refuses an invalid logon name'
$r = Op 'create' @{ sam = 'nopass'; upn = 'nopass@acme.example'; displayName = 'No password' }
Check (-not $r.ok -and $r.error -match 'password') 'create: refuses to run without the one-time password'

$r = Op 'disable' @{ identity = 'jo' }
Check ($r.ok -and $r.user.enabled -eq $false -and ($script:calls | Where-Object { $_.op -eq 'Disable-ADAccount' })) 'disable'
$r = Op 'scramble' @{ identity = 'jo' }
$scrambled = ($script:calls | Where-Object { $_.op -eq 'Set-ADAccountPassword' }).password
Check ($r.ok -and $scrambled.Length -ge 32 -and -not ("$r" -match [regex]::Escape($scrambled))) 'scramble: a long random password, never returned'
$r = Op 'remove_groups' @{ identity = 'jo' }
Check ($r.ok -and @($r.removed).Count -eq 2 -and ($r.removed -contains 'Sales AD')) 'remove_groups: every group the account was in'
$r = Op 'move' @{ identity = 'jo'; ou = 'OU=Leavers,DC=acme,DC=example' }
Check ($r.ok -and ($script:calls | Where-Object { $_.op -eq 'Move-ADObject' }).target -eq 'OU=Leavers,DC=acme,DC=example') 'move to the leavers OU'
$r = Op 'describe' @{ identity = 'jo'; text = 'Left 02 Nov 2026' }
Check ($r.ok -and ($script:calls | Where-Object { $_.op -eq 'Set-ADUser' }).description -eq 'Left 02 Nov 2026') 'describe'
$r = Op 'hide_gal' @{ identity = 'jo' }
Check ($r.ok -and $r.skipped) 'hide_gal: skipped where AD has no Exchange attributes'
$script:exchangeSchema = $true
$r = Op 'hide_gal' @{ identity = 'jo' }
Check ($r.ok -and -not $r.skipped -and ($script:calls | Where-Object { $_.op -eq 'Set-ADUser' }).replace.msExchHideFromAddressLists -eq $true) 'hide_gal: set where Exchange attributes exist'
$r = Op 'disable' @{ identity = "o'brien" }
Check ($r.ok) 'a quote in a name is escaped, not executed'
$r = Op 'disable' @{ identity = 'nobody' }
Check (-not $r.ok -and $r.error -match 'No Active Directory user') 'an unknown user is reported'
$r = Op 'sync' @{}
Check (-not $r.ok -and $r.error -match 'Entra Connect') 'sync: explains when Entra Connect is not on this server'
$r = Op 'format_c' @{}
Check (-not $r.ok -and $r.error -match 'Unknown operation') 'only listed operations exist'
$script:noModule = $true
$r = Op 'disable' @{ identity = 'jo' }
Check (-not $r.ok -and $r.error -match 'RSAT-AD-PowerShell') 'a missing ActiveDirectory module says how to install it'
Write-Host 'Active Directory operations: all checks passed.'
