$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '../service/src/RmmExecutors.cpp') -Raw
$scripts = [regex]::Matches($source, '(?s)R"PS\((.*?)\)PS"')
if ($scripts.Count -eq 0) { throw 'No embedded RMM PowerShell scripts found' }
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($script.Groups[1].Value, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
}
Write-Host "PASS: $($scripts.Count) embedded RMM PowerShell scripts parse."

# An existing but invalid executable must not inherit a stale/native exit code
# and produce a successful patch result. Run only the WinGet branch, with an
# empty temporary binary: no real package manager or Windows Update is invoked.
$install = [regex]::Match($source, '(?s)const char kPatchInstallScript\[\] = R"PS\((.*?)\)PS";')
if (-not $install.Success) { throw 'Patch install script not found' }
$root = Join-Path ([IO.Path]::GetTempPath()) ('fenrir-winget-launch-' + [guid]::NewGuid())
$priorWinget = $env:FENRIR_WINGET
$priorIds = $env:FENRIR_PATCH_IDS
try {
    [void](New-Item -ItemType Directory -Path $root)
    $binary = Join-Path $root 'invalid.exe'
    [IO.File]::WriteAllBytes($binary, [byte[]]@())
    $file = Join-Path $root 'install.ps1'
    Set-Content -Path $file -Value $install.Groups[1].Value -Encoding UTF8
    $env:FENRIR_WINGET = $binary
    $env:FENRIR_PATCH_IDS = 'winget:Google.Chrome'
    $ErrorActionPreference = 'Continue' # the invalid test binary intentionally emits a native error
    $output = & powershell.exe -NoProfile -File $file 2>$null
    $ErrorActionPreference = 'Stop'
    $result = ($output -join "`n") | ConvertFrom-Json
    if (@($result.results).Count -ne 1 -or $result.results[0].success -ne $false) {
        throw 'A WinGet launch failure was not recorded as a failed patch'
    }
    Write-Host 'PASS: WinGet launch failure cannot report patch success.'
} finally {
    $env:FENRIR_WINGET = $priorWinget
    $env:FENRIR_PATCH_IDS = $priorIds
    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
}
