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
