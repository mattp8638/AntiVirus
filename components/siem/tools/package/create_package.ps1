<#
Developer packaging script.
- Builds the UI (`ui` folder) using npm
- Creates `package_tmp` containing `ui/dist`, `backend/` (source) and packaging scripts
- Produces `tamsilcms-installer.zip`

Run from repo root in PowerShell:
    .\tools\package\create_package.ps1
#>

param(
    [string]$Output = "tamsilcms-installer.zip"
)

Set-StrictMode -Version Latest
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $here\..\..
$repoRoot = Get-Location

Write-Host "Building UI..."
if (Test-Path ui\package.json) {
    Push-Location ui
    npm ci
    npm run build
    Pop-Location
} else {
    Write-Host "No ui/package.json found; skipping UI build"
}

$tmp = Join-Path $repoRoot "package_tmp"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Path $tmp | Out-Null

Write-Host "Copying UI build..."
if (Test-Path ui\dist) {
    Copy-Item -Recurse ui\dist (Join-Path $tmp "ui\dist")
}

Write-Host "Copying backend source..."
Copy-Item -Recurse backend (Join-Path $tmp "backend")

# Copy packaging helpers
Copy-Item -Recurse tools\package\bootstrap.ps1 (Join-Path $tmp "bootstrap.ps1")
Copy-Item -Recurse tools\package\run-backend.bat (Join-Path $tmp "run-backend.bat")

Write-Host "Creating ZIP: $Output"
if (Test-Path $Output) { Remove-Item $Output }
Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $Output -Force

Write-Host "Package created: $Output"

# Try to build an installer .exe with Inno Setup if available
Write-Host "Checking for Inno Setup Compiler (ISCC.exe)..."
$innoPaths = @(
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)
$ISCC = $null
foreach ($p in $innoPaths) { if (Test-Path $p) { $ISCC = $p; break } }
if (-not $ISCC) { $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue; if ($cmd) { $ISCC = $cmd.Source } }
if ($ISCC) {
    Write-Host "Found ISCC: $ISCC -- building installer exe..."
    Push-Location $here\installer
    $builder = Join-Path $here "installer\build_installer.ps1"
    if (Test-Path $builder) {
        & $builder -ISCC $ISCC -SourceDir $tmp -OutDir $repoRoot
    } else {
        Write-Host "Installer builder not found: $builder"
    }
    Pop-Location
} else {
    Write-Host "Inno Setup not found; skipping .exe installer build. Install Inno Setup and re-run the builder at tools/package/installer/build_installer.ps1"
}
Pop-Location
