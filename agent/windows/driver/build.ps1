<#
.SYNOPSIS
  Builds AntivirusMinifilter.sys, its INF and catalog with the Windows Driver Kit.

.DESCRIPTION
  Run from a Visual Studio x64 developer prompt (cl.exe and link.exe on PATH) on a machine with the WDK installed.
  Output: <OutDir>\AntivirusMinifilter.sys, .inf (DriverVer stamped), .cat (unsigned), .pdb and build.json.

  The files are left unsigned on purpose. Fenrir's server signs them with its code-signing certificate when it
  builds the installer (deploy/sign-windows.sh); a Microsoft attestation signature replaces that for production.

.PARAMETER Version
  Driver version for DriverVer, for example 1.0.42.0.
#>
param(
  [string]$OutDir = (Join-Path $PSScriptRoot 'out\x64'),
  [string]$Version = '1.0.0.0'
)
$ErrorActionPreference = 'Stop'

$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$wdkVersion = Get-ChildItem (Join-Path $kits 'Include') -Directory |
  Where-Object { Test-Path (Join-Path $_.FullName 'km\fltKernel.h') } |
  Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $wdkVersion) { throw "The Windows Driver Kit is not installed (no km\fltKernel.h under $kits\Include)." }
$ver = $wdkVersion.Name
$inc = Join-Path $kits "Include\$ver"
$lib = Join-Path $kits "Lib\$ver\km\x64"
$bin = Join-Path $kits "bin\$ver\x86"
if (-not (Test-Path (Join-Path $lib 'fltmgr.lib'))) { throw "fltmgr.lib is missing from $lib." }
if (-not $env:VCToolsInstallDir) { throw 'Run this from a Visual Studio x64 developer prompt (VCToolsInstallDir is not set).' }
Write-Host "WDK $ver"

$src = Join-Path $PSScriptRoot 'src'
$shared = Resolve-Path (Join-Path $PSScriptRoot '..\shared\include')
$obj = Join-Path $OutDir 'obj'
New-Item -ItemType Directory -Force -Path $OutDir, $obj | Out-Null

# Kernel compile: no standard include paths (/X), so only the kernel headers, the shared protocol header and a
# stdint shim are visible, with the compiler's own intrinsics headers last.
$clArgs = @(
  '/nologo', '/c', '/kernel', '/W4', '/WX', '/wd4201', '/wd4214', '/wd4324', '/O2', '/Oy-', '/GS', '/Gy', '/GF', '/Zi', '/Zp8',
  '/Gm-', '/GR-', '/EHs-c-', '/Zc:wchar_t', '/X',
  '/D_AMD64_', '/DAMD64', '/D_WIN64', '/DNTDDI_VERSION=0x0A000008', '/D_WIN32_WINNT=0x0A00', '/DWINVER=0x0A00',
  '/DWINNT=1', '/DNDEBUG',
  "/I$src\kmshim", "/I$shared", "/I$inc\km", "/I$inc\km\crt", "/I$inc\shared", "/I$env:VCToolsInstallDir\include",
  "/Fo$obj\", "/Fd$obj\vc.pdb",
  (Join-Path $src 'AntivirusMinifilter.c')
)
$clOutput = & cl.exe @clArgs 2>&1
$clExit = $LASTEXITCODE
# Show our own diagnostics first; header noise is only shown when there is nothing else to explain a failure.
$own = $clOutput | Where-Object { "$_" -notmatch 'Windows Kits' }
$own | ForEach-Object { Write-Host $_ }
if ($clExit -ne 0) {
  if (-not ($own | Where-Object { "$_" -match '(error|warning) C\d+' })) { $clOutput | Select-Object -Last 40 | ForEach-Object { Write-Host $_ } }
  throw "cl.exe failed ($clExit)"
}

$sys = Join-Path $OutDir 'AntivirusMinifilter.sys'
$linkArgs = @(
  '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE,10.00', '/ENTRY:GsDriverEntry', '/NODEFAULTLIB', '/MACHINE:X64',
  '/OPT:REF', '/OPT:ICF', '/RELEASE', '/DEBUG', '/NXCOMPAT', '/DYNAMICBASE', '/INCREMENTAL:NO',
  "/PDB:$OutDir\AntivirusMinifilter.pdb", "/OUT:$sys", "/LIBPATH:$lib",
  (Join-Path $obj 'AntivirusMinifilter.obj'),
  'ntoskrnl.lib', 'hal.lib', 'fltmgr.lib', 'BufferOverflowFastFailK.lib'
)
& link.exe @linkArgs
if ($LASTEXITCODE -ne 0) { throw "link.exe failed ($LASTEXITCODE)" }

# Only kernel imports: a user-mode DLL import here would stop the driver loading.
$imports = & dumpbin.exe /nologo /imports $sys | Select-String -Pattern '^\s+(\S+\.(sys|dll|exe))\s*$' |
  ForEach-Object { $_.Matches[0].Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique
Write-Host "Imports: $($imports -join ', ')"
$unexpected = $imports | Where-Object { $_ -notin @('ntoskrnl.exe', 'hal.dll', 'fltmgr.sys') }
if ($unexpected) { throw "Unexpected driver imports: $($unexpected -join ', ')" }

$inf = Join-Path $OutDir 'AntivirusMinifilter.inf'
Copy-Item (Join-Path $PSScriptRoot 'AntivirusMinifilter.inf') $inf -Force
& (Join-Path $bin 'stampinf.exe') -f $inf -d '*' -v $Version -a 'amd64'
if ($LASTEXITCODE -ne 0) { throw "stampinf failed ($LASTEXITCODE)" }

$infVerif = Join-Path $kits "Tools\$ver\x64\infverif.exe"
if (Test-Path $infVerif) {
  & $infVerif /v /w $inf
  if ($LASTEXITCODE -ne 0) { throw "infverif reported problems ($LASTEXITCODE)" }
}

# The catalog covers the INF and SYS; Inf2Cat insists on a folder holding only the package.
$package = Join-Path $OutDir 'package'
Remove-Item $package -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $package | Out-Null
Copy-Item $inf, $sys $package
& (Join-Path $bin 'Inf2Cat.exe') "/driver:$package" '/os:10_X64'
if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed ($LASTEXITCODE)" }
Copy-Item (Join-Path $package 'AntivirusMinifilter.cat') $OutDir -Force

$sourceFiles = @(
  (Join-Path $src 'AntivirusMinifilter.c'), (Join-Path $src 'kmshim\stdint.h'),
  (Join-Path $PSScriptRoot 'AntivirusMinifilter.inf'), (Join-Path $shared 'RealtimeProtectionProtocol.h')
)
$sourceHash = ($sourceFiles | ForEach-Object {
    (Get-FileHash $_ -Algorithm SHA256).Hash + '  ' + (Split-Path $_ -Leaf)
  }) -join "`n"
$sourceHash = [BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($sourceHash))).Replace('-', '').ToLowerInvariant()
@{
  version    = $Version
  wdk        = $ver
  sourceHash = $sourceHash
  sys        = (Get-FileHash $sys -Algorithm SHA256).Hash.ToLowerInvariant()
  signed     = $false
} | ConvertTo-Json | Set-Content (Join-Path $OutDir 'build.json') -Encoding utf8
Write-Host "Built $sys (version $Version, source $sourceHash)"
