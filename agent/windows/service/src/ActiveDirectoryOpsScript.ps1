# Fenrir Active Directory operations (Windows domain controllers). Run as SYSTEM by the agent for one ad.directory
# command: reads a JSON request from the file named by the first argument and prints one JSON result,
# {"ok": true, ...} or {"ok": false, "error": "..."}. Only the operations below exist; every value arrives as data
# (never as script text). Windows PowerShell 5.1 compatible.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

function Iso($Value) { if ($Value -is [datetime] -and $Value.Year -gt 1601) { $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function Done($Data) { $out = [ordered]@{ ok = $true }; if ($Data) { foreach ($k in $Data.Keys) { $out[$k] = $Data[$k] } }; $out | ConvertTo-Json -Depth 6 -Compress }
function Fail([string]$Message) { [ordered]@{ ok = $false; error = $Message } | ConvertTo-Json -Compress }
function Text($Value, [int]$Max = 256) { $s = "$Value".Trim(); if ($s.Length -gt $Max) { $s.Substring(0, $Max) } else { $s } }
function RandomPassword([int]$Length = 32) {
  $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*?@-+='
  $bytes = New-Object byte[] $Length
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $chars = foreach ($b in $bytes) { $alphabet[$b % $alphabet.Length] }
  # Guarantee every character class Windows complexity checks for.
  'Aa2!' + (-join $chars)
}
function Find-User([string]$Identity) {
  $id = Text $Identity 256
  if (-not $id) { throw 'No user was named' }
  $props = 'Enabled','DisplayName','UserPrincipalName','mail','Title','Department','Manager','MemberOf','PrimaryGroup','LastLogonDate','whenCreated','ObjectGUID','Description'
  $escaped = $id.Replace("'", "''")
  $user = Get-ADUser -Filter "SamAccountName -eq '$escaped' -or UserPrincipalName -eq '$escaped'" -Properties $props
  if (-not $user) { throw "No Active Directory user '$id'" }
  if (@($user).Count -gt 1) { throw "More than one Active Directory user matches '$id'" }
  $user
}
function UserView($u) {
  [ordered]@{ sam = $u.SamAccountName; upn = $u.UserPrincipalName; displayName = $u.DisplayName; enabled = [bool]$u.Enabled
    dn = $u.DistinguishedName; ou = ($u.DistinguishedName -replace '^CN=.+?(?<!\\),', ''); guid = "$($u.ObjectGUID)"; mail = $u.mail
    title = $u.Title; department = $u.Department; manager = $u.Manager; lastLogon = Iso $u.LastLogonDate; description = $u.Description
    groups = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) }
}

try {
  $request = Get-Content -LiteralPath $args[0] -Raw -Encoding UTF8 | ConvertFrom-Json
  $op = "$($request.operation)"
  $p = $request.params
  if (-not $p) { $p = New-Object psobject }
  # A one-time secret (a new starter's temporary password) arrives in its own file, never in the request.
  if ($args.Count -gt 1 -and "$($args[1])") {
    $p | Add-Member -NotePropertyName password -NotePropertyValue ([IO.File]::ReadAllText($args[1], [Text.Encoding]::UTF8).Trim()) -Force
  }
  if ($op -eq 'sync') {
    try { Import-Module ADSync -ErrorAction Stop } catch { Fail 'Entra Connect (ADSync) is not installed on this server.'; return }
    $result = Start-ADSyncSyncCycle -PolicyType Delta
    Done ([ordered]@{ result = "$($result.Result)" }); return
  }
  try { Import-Module ActiveDirectory -ErrorAction Stop }
  catch { Fail 'The ActiveDirectory PowerShell module is not installed on this server. Install it: Install-WindowsFeature RSAT-AD-PowerShell'; return }
  $domain = Get-ADDomain

  switch ($op) {
    'options' {
      $forest = Get-ADForest
      $suffixes = @($domain.DNSRoot) + @($forest.UPNSuffixes | ForEach-Object { "$_" }) | Select-Object -Unique
      $ous = @(Get-ADOrganizationalUnit -Filter * -ResultSetSize 2000 | Sort-Object DistinguishedName | Select-Object -First 1000 |
        ForEach-Object { [ordered]@{ dn = $_.DistinguishedName; name = $_.Name } })
      $groups = @(Get-ADGroup -Filter * -Properties Description -ResultSetSize 5000 |
        Where-Object { $_.GroupCategory -eq 'Security' -or $_.GroupCategory -eq 'Distribution' } |
        Where-Object { $_.DistinguishedName -notlike '*,CN=Builtin,*' -and $_.SID.Value -notmatch '-(512|518|519|520|525|526|527)$' } |
        Sort-Object Name | Select-Object -First 2000 |
        ForEach-Object { [ordered]@{ dn = $_.DistinguishedName; name = $_.Name; category = "$($_.GroupCategory)"; scope = "$($_.GroupScope)" } })
      $adsync = [bool](Get-Service -Name ADSync -ErrorAction SilentlyContinue)
      Done ([ordered]@{ domain = $domain.DNSRoot; netbios = $domain.NetBIOSName; usersContainer = $domain.UsersContainer
        upnSuffixes = @($suffixes); ous = $ous; groups = $groups; adsyncHere = $adsync })
    }
    'lookup' { Done ([ordered]@{ user = (UserView (Find-User $p.identity)) }) }
    'create' {
      $sam = Text $p.sam 20
      $upn = Text $p.upn 256
      if (-not $sam -or $sam -notmatch '^[A-Za-z0-9._-]+$') { throw 'The logon name (sAMAccountName) may use letters, numbers, dot, dash and underscore, up to 20 characters' }
      if ($upn -notmatch '^[^@\s]+@[^@\s]+$') { throw 'The sign-in name must look like name@domain' }
      $escapedSam = $sam.Replace("'", "''"); $escapedUpn = $upn.Replace("'", "''")
      if (Get-ADUser -Filter "SamAccountName -eq '$escapedSam' -or UserPrincipalName -eq '$escapedUpn'") { throw "An Active Directory user with logon name $sam or sign-in name $upn already exists" }
      if (-not "$($p.password)") { throw 'No temporary password was supplied' }
      $secure = ConvertTo-SecureString "$($p.password)" -AsPlainText -Force
      $path = if ("$($p.ou)") { Text $p.ou 512 } else { $domain.UsersContainer }
      $given = Text $p.givenName 64; $surname = Text $p.surname 64
      $display = if ("$($p.displayName)") { Text $p.displayName 256 } else { "$given $surname".Trim() }
      $create = @{ Name = $display; SamAccountName = $sam; UserPrincipalName = $upn; DisplayName = $display; Path = $path
        AccountPassword = $secure; Enabled = $true; ChangePasswordAtLogon = ($p.mustChange -ne $false); PassThru = $true }
      if ($given) { $create.GivenName = $given }
      if ($surname) { $create.Surname = $surname }
      if ("$($p.title)") { $create.Title = Text $p.title 128 }
      if ("$($p.department)") { $create.Department = Text $p.department 64 }
      if ("$($p.office)") { $create.Office = Text $p.office 128 }
      if ("$($p.phone)") { $create.OfficePhone = Text $p.phone 64 }
      if ("$($p.mail)") { $create.EmailAddress = Text $p.mail 256 }
      $user = New-ADUser @create
      $notes = New-Object System.Collections.ArrayList
      if ("$($p.manager)") {
        try { Set-ADUser -Identity $user -Manager (Find-User $p.manager) } catch { [void]$notes.Add("manager not set: $($_.Exception.Message)") }
      }
      foreach ($g in @($p.groups)) {
        if (-not "$g") { continue }
        try { Add-ADGroupMember -Identity "$g" -Members $user } catch { [void]$notes.Add("not added to ${g}: $($_.Exception.Message)") }
      }
      Done ([ordered]@{ user = (UserView (Find-User $sam)); notes = @($notes) })
    }
    'disable' { $u = Find-User $p.identity; Disable-ADAccount -Identity $u; Done ([ordered]@{ user = (UserView (Find-User $p.identity)) }) }
    'enable' { $u = Find-User $p.identity; Enable-ADAccount -Identity $u; Done ([ordered]@{ user = (UserView (Find-User $p.identity)) }) }
    'scramble' {
      # A random password nobody is told: generated here, never sent anywhere.
      $u = Find-User $p.identity
      Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString (RandomPassword) -AsPlainText -Force)
      Done ([ordered]@{ sam = $u.SamAccountName })
    }
    'set_password' {
      $u = Find-User $p.identity
      if (-not "$($p.password)") { throw 'No password was supplied' }
      Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString "$($p.password)" -AsPlainText -Force)
      if ($p.mustChange -ne $false) { Set-ADUser -Identity $u -ChangePasswordAtLogon $true }
      Unlock-ADAccount -Identity $u -ErrorAction SilentlyContinue
      Done ([ordered]@{ sam = $u.SamAccountName })
    }
    'remove_groups' {
      $u = Find-User $p.identity
      $removed = New-Object System.Collections.ArrayList; $kept = New-Object System.Collections.ArrayList
      foreach ($dn in @($u.MemberOf)) {
        $name = ($dn -split ',')[0] -replace '^CN=', ''
        try { Remove-ADGroupMember -Identity $dn -Members $u -Confirm:$false; [void]$removed.Add($name) }
        catch { [void]$kept.Add("${name}: $($_.Exception.Message)") }
      }
      Done ([ordered]@{ removed = @($removed); kept = @($kept) })
    }
    'move' {
      $u = Find-User $p.identity
      $target = Text $p.ou 512
      if (-not $target) { throw 'No organisational unit was chosen' }
      Move-ADObject -Identity $u.DistinguishedName -TargetPath $target
      Done ([ordered]@{ user = (UserView (Find-User $p.identity)) })
    }
    'describe' { $u = Find-User $p.identity; Set-ADUser -Identity $u -Description (Text $p.text 1024); Done ([ordered]@{ sam = $u.SamAccountName }) }
    'hide_gal' {
      $u = Find-User $p.identity
      $schema = (Get-ADRootDSE).schemaNamingContext
      if (-not (Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=msExchHideFromAddressLists)')) {
        Done ([ordered]@{ skipped = 'This directory has no Exchange attributes, so there is no address book setting to change here.' }); return
      }
      Set-ADUser -Identity $u -Replace @{ msExchHideFromAddressLists = $true }
      Done ([ordered]@{ sam = $u.SamAccountName })
    }
    default { Fail "Unknown operation '$op'" }
  }
} catch {
  Fail ("$($_.Exception.Message)" -replace '\s+', ' ')
}
