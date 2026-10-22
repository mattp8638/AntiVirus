param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$DevOutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\install'),
    [string]$DriverArtifactRoot = '',
    [string]$DriverPackageRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'driver\minifilter\package'),
    [switch]$SkipMinifilterBuild,
    [string]$DriverSigningCertificateThumbprint = '',
    [string]$DriverSigningPfxPath = '',
    [string]$DriverSigningPfxPassword = '',
    [switch]$AllowUnsignedMinifilterBuild,
    [switch]$AllowMissingMinifilterPayload,
    [string]$WebView2RuntimeInstallerPath = '',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Copy-IfPresent {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Required installer payload is missing: $Source"
    }

    Ensure-Directory -Path (Split-Path -Parent $Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Resolve-FirstExistingPath {
    param([string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if (-not $candidate) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    return ''
}

function Stage-MinifilterPayload {
    param(
        [string]$WindowsRoot,
        [string]$DevOutputRoot,
        [string]$DriverArtifactRoot,
        [string]$DriverPackageRoot,
        [bool]$RequireCompletePayload
    )

    $driverSourceRoot = Join-Path $WindowsRoot 'driver\minifilter'
    $driverOutputRoot = Join-Path $DevOutputRoot 'driver'
    Ensure-Directory -Path $driverOutputRoot

    Copy-IfPresent -Source (Join-Path $driverSourceRoot 'AntivirusMinifilter.inf') -Destination (Join-Path $driverOutputRoot 'AntivirusMinifilter.inf')
    Copy-IfPresent -Source (Join-Path $driverSourceRoot 'README.md') -Destination (Join-Path $driverOutputRoot 'README.md')

    $artifactRoot = ''
    if ($DriverArtifactRoot) {
        if (-not (Test-Path -LiteralPath $DriverArtifactRoot)) {
            throw "Configured DriverArtifactRoot does not exist: $DriverArtifactRoot"
        }
        $artifactRoot = (Resolve-Path -LiteralPath $DriverArtifactRoot).Path
    }

    $packageRoot = ''
    if ($DriverPackageRoot) {
        $packageCandidate = $DriverPackageRoot
        if (-not [System.IO.Path]::IsPathRooted($packageCandidate)) {
            $packageCandidate = Join-Path $WindowsRoot $packageCandidate
        }

        $packageCandidate = [System.IO.Path]::GetFullPath($packageCandidate)
        if (Test-Path -LiteralPath $packageCandidate) {
            $packageRoot = $packageCandidate
        }
    }

    foreach ($name in @('AntivirusMinifilter.sys', 'AntivirusMinifilter.cat')) {
        $targetPath = Join-Path $driverOutputRoot $name
        $sourcePath = Resolve-FirstExistingPath -Candidates @(
            $(if ($artifactRoot) { Join-Path $artifactRoot $name } else { '' }),
            $(if ($packageRoot) { Join-Path $packageRoot $name } else { '' })
        )

        if ($sourcePath) {
            Copy-IfPresent -Source $sourcePath -Destination $targetPath
            continue
        }

        if (Test-Path -LiteralPath $targetPath) {
            continue
        }

        if ($RequireCompletePayload) {
            throw "Required minifilter payload artifact is missing: $name. Supply -DriverArtifactRoot or provide a complete package under $DriverPackageRoot."
        }
    }
}

function Invoke-MinifilterBuildIfNeeded {
    param(
        [string]$WindowsRoot,
        [string]$DriverPackageRoot,
        [string]$DriverSigningCertificateThumbprint,
        [string]$DriverSigningPfxPath,
        [string]$DriverSigningPfxPassword,
        [switch]$AllowUnsignedMinifilterBuild
    )

    $packageRoot = $DriverPackageRoot
    if (-not [System.IO.Path]::IsPathRooted($packageRoot)) {
        $packageRoot = Join-Path $WindowsRoot $packageRoot
    }
    $packageRoot = [System.IO.Path]::GetFullPath($packageRoot)

    $sysPath = Join-Path $packageRoot 'AntivirusMinifilter.sys'
    $catPath = Join-Path $packageRoot 'AntivirusMinifilter.cat'
    if ((Test-Path -LiteralPath $sysPath) -and (Test-Path -LiteralPath $catPath)) {
        return
    }

    $buildScriptPath = Join-Path $WindowsRoot 'driver\minifilter\BuildMinifilterDriver.ps1'
    if (-not (Test-Path -LiteralPath $buildScriptPath)) {
        throw "Minifilter build script was not found: $buildScriptPath"
    }

    $buildArgs = @{
        OutputRoot = $packageRoot
    }
    if ($DriverSigningCertificateThumbprint) {
        $buildArgs.SigningCertificateThumbprint = $DriverSigningCertificateThumbprint
    }
    if ($DriverSigningPfxPath) {
        $buildArgs.SigningPfxPath = $DriverSigningPfxPath
    }
    if ($DriverSigningPfxPassword) {
        $buildArgs.SigningPfxPassword = $DriverSigningPfxPassword
    }
    if ($AllowUnsignedMinifilterBuild) {
        $buildArgs.AllowUnsignedArtifacts = $true
    }

    & $buildScriptPath @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Minifilter build failed with exit code $LASTEXITCODE"
    }
}

function Remove-LegacyBuildOutputs {
    param([string]$BuildRoot)

    foreach ($name in @(
        'fenrir-agent-service.exe',
        'fenrir-amsi-provider.dll',
        'fenrir-remote.exe',
        'fenrir-amsitestcli.exe',
        'fenrir-endpoint-client.exe',
        'fenrir-etwtestcli.exe',
        'fenrir-pam.exe',
        'fenrir-scannercli.exe',
        'fenrir-wfptestcli.exe',
        'FenrirSetup.exe',
        'WebView2Loader.dll'
    )) {
        $candidate = Join-Path $BuildRoot $name
        if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Force
        }
    }
}

$windowsRoot = Split-Path $PSScriptRoot -Parent
$serviceSourceRoot = Join-Path $windowsRoot 'service'
$buildRootFull = [System.IO.Path]::GetFullPath($BuildRoot)
$devOutputRootFull = [System.IO.Path]::GetFullPath($DevOutputRoot)
$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)
$requireMinifilterPayload = -not $AllowMissingMinifilterPayload.IsPresent
$webView2RuntimeInstallerFullPath = ''

if ($WebView2RuntimeInstallerPath) {
    $webView2RuntimeInstallerFullPath = [System.IO.Path]::GetFullPath($WebView2RuntimeInstallerPath)
    if (-not (Test-Path -LiteralPath $webView2RuntimeInstallerFullPath)) {
        throw "Configured WebView2 runtime installer was not found: $webView2RuntimeInstallerFullPath"
    }
}

if ($Clean -and (Test-Path -LiteralPath $outputRootFull)) {
    Remove-Item -LiteralPath $outputRootFull -Recurse -Force
}

Ensure-Directory -Path $buildRootFull
Ensure-Directory -Path $devOutputRootFull
Ensure-Directory -Path $outputRootFull

if (-not $SkipMinifilterBuild -and -not $DriverArtifactRoot) {
    Invoke-MinifilterBuildIfNeeded -WindowsRoot $windowsRoot -DriverPackageRoot $DriverPackageRoot -DriverSigningCertificateThumbprint $DriverSigningCertificateThumbprint -DriverSigningPfxPath $DriverSigningPfxPath -DriverSigningPfxPassword $DriverSigningPfxPassword -AllowUnsignedMinifilterBuild:$AllowUnsignedMinifilterBuild
}

Stage-MinifilterPayload -WindowsRoot $windowsRoot -DevOutputRoot $devOutputRootFull -DriverArtifactRoot $DriverArtifactRoot -DriverPackageRoot $DriverPackageRoot -RequireCompletePayload $requireMinifilterPayload

$cmakeConfigureArgs = @(
    '-S', $serviceSourceRoot,
    '-B', $buildRootFull,
    "-DANTIVIRUS_DEV_OUTPUT_ROOT=$devOutputRootFull",
    "-DANTIVIRUS_INSTALL_OUTPUT_ROOT=$outputRootFull",
    "-DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD:BOOL=$(if ($requireMinifilterPayload) { 'ON' } else { 'OFF' })",
    "-DANTIVIRUS_WEBVIEW2_BOOTSTRAPPER:FILEPATH=$webView2RuntimeInstallerFullPath"
)

cmake @cmakeConfigureArgs | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

cmake --build $buildRootFull --target antivirus-setup | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE"
}

$setupTarget = Join-Path $outputRootFull 'FenrirSetup.exe'
if (-not (Test-Path -LiteralPath $setupTarget)) {
    throw "Installer output was not produced: $setupTarget"
}

Remove-LegacyBuildOutputs -BuildRoot $buildRootFull

Write-Host "Installer bundle written to $setupTarget"
