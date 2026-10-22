param(
    [string]$ISCC,
    [string]$SourceDir = "",
    [string]$OutDir = ""
)

Set-StrictMode -Version Latest
if (-not $ISCC) {
    Write-Error "ISCC (Inno Setup Compiler) path is required."
    exit 2
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$iss = Join-Path $here "tamsilcms-installer.iss"
if (-not (Test-Path $iss)) {
    Write-Error "Installer script not found: $iss"
    exit 2
}

if (-not $SourceDir) {
    Write-Error "SourceDir (package_tmp) must be provided"
    exit 2
}

# Ensure absolute paths
$SourceDir = (Resolve-Path $SourceDir).Path
if ($OutDir -eq "") { $OutDir = (Get-Location).ProviderPath }
$OutDir = (Resolve-Path $OutDir).Path

Write-Host "Building Inno Setup installer..."
Write-Host "ISCC: $ISCC"
Write-Host "SourceDir: $SourceDir"
Write-Host "OutDir: $OutDir"
# Generate a temporary .iss with SourceDir expanded to literal paths to avoid preprocessor quoting issues
$issContent = Get-Content -Raw -Path $iss
$safeSource = $SourceDir
# Replace occurrences of {#SourceDir} with the literal path using a literal string replace
$issContent = $issContent.Replace('{#SourceDir}', $safeSource)

$tempIss = Join-Path $here "tamsilcms-installer.tmp.iss"
Set-Content -Path $tempIss -Value $issContent -Encoding UTF8

Write-Host "Running ISCC on temporary script: $tempIss"
$proc = Start-Process -FilePath $ISCC -ArgumentList "`"$tempIss`"" -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "ISCC failed with exit code $($proc.ExitCode)"
    Remove-Item -Force $tempIss -ErrorAction SilentlyContinue
    exit $proc.ExitCode
}

# Copy the built installer to OutDir if present
$outputExe = Join-Path $here "Output\tamsilcms-installer.exe"
if (Test-Path $outputExe) {
    Copy-Item -Force $outputExe -Destination (Join-Path $OutDir "tamsilcms-installer.exe")
    Write-Host "Installer copied to: " (Join-Path $OutDir "tamsilcms-installer.exe")
} else {
    Write-Host "Installer built but expected output not found at: $outputExe"
}

Remove-Item -Force $tempIss -ErrorAction SilentlyContinue
Write-Host "Installer build complete."
