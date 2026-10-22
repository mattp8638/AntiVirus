param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$InstallerOutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\install'),
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
        throw "Required release artifact is missing: $Source"
    }

    Ensure-Directory -Path (Split-Path -Parent $Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Get-RelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathFull.Substring($rootFull.Length).TrimStart('\\')
    }

    return $pathFull
}

function Get-CMakeCacheValue {
    param(
        [string]$CachePath,
        [string]$VariableName
    )

    if (-not (Test-Path -LiteralPath $CachePath)) {
        return ''
    }

    $match = Select-String -Path $CachePath -Pattern "^${VariableName}:.*=(.+)$" | Select-Object -First 1
    if ($null -eq $match) {
        return ''
    }

    return $match.Matches[0].Groups[1].Value.Trim()
}

function Assert-PathPresent {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required release artifact is missing: $Path"
    }
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
        [string]$OutputRoot,
        [string]$DriverArtifactRoot,
        [string]$DriverPackageRoot,
        [bool]$RequireCompletePayload
    )

    $driverSourceRoot = Join-Path $WindowsRoot 'driver\minifilter'
    $driverOutputRoot = Join-Path $OutputRoot 'driver'
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

function Find-MinGwRuntimeDll {
    param(
        [string]$BuildRoot,
        [string]$DllName
    )

    $cachePath = Join-Path $BuildRoot 'CMakeCache.txt'
    $compilerPath = Get-CMakeCacheValue -CachePath $cachePath -VariableName 'CMAKE_CXX_COMPILER'
    if (-not $compilerPath) {
        return ''
    }

    $compilerDir = Split-Path -Parent $compilerPath
    foreach ($candidate in @(
        (Join-Path $compilerDir $DllName),
        (Join-Path (Join-Path $compilerDir '..\\bin') $DllName)
    )) {
        $fullCandidate = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $fullCandidate) {
            return $fullCandidate
        }
    }

    return ''
}

function Test-PathWithin {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.Length -lt $rootFull.Length) {
        return $false
    }

    return $pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

$windowsRoot = Split-Path $PSScriptRoot -Parent
$serviceSourceRoot = Join-Path $windowsRoot 'service'
$buildRoot = [System.IO.Path]::GetFullPath($BuildRoot)
$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$installerOutputRoot = [System.IO.Path]::GetFullPath($InstallerOutputRoot)
$requireMinifilterPayload = -not $AllowMissingMinifilterPayload.IsPresent
$webView2RuntimeInstallerFullPath = ''

if ($WebView2RuntimeInstallerPath) {
    $webView2RuntimeInstallerFullPath = [System.IO.Path]::GetFullPath($WebView2RuntimeInstallerPath)
    if (-not (Test-Path -LiteralPath $webView2RuntimeInstallerFullPath)) {
        throw "Configured WebView2 runtime installer was not found: $webView2RuntimeInstallerFullPath"
    }
}

if ($Clean -and (Test-Path -LiteralPath $outputRoot)) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}

Ensure-Directory -Path $buildRoot
Ensure-Directory -Path $outputRoot
Ensure-Directory -Path (Join-Path $outputRoot 'driver')

if (-not $SkipMinifilterBuild -and -not $DriverArtifactRoot) {
    Invoke-MinifilterBuildIfNeeded -WindowsRoot $windowsRoot -DriverPackageRoot $DriverPackageRoot -DriverSigningCertificateThumbprint $DriverSigningCertificateThumbprint -DriverSigningPfxPath $DriverSigningPfxPath -DriverSigningPfxPassword $DriverSigningPfxPassword -AllowUnsignedMinifilterBuild:$AllowUnsignedMinifilterBuild
}

Stage-MinifilterPayload -WindowsRoot $windowsRoot -OutputRoot $outputRoot -DriverArtifactRoot $DriverArtifactRoot -DriverPackageRoot $DriverPackageRoot -RequireCompletePayload $requireMinifilterPayload

$cmakeConfigureArgs = @(
    '-S', $serviceSourceRoot,
    '-B', $buildRoot,
    "-DANTIVIRUS_DEV_OUTPUT_ROOT=$outputRoot",
    "-DANTIVIRUS_INSTALL_OUTPUT_ROOT=$installerOutputRoot",
    "-DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD:BOOL=$(if ($requireMinifilterPayload) { 'ON' } else { 'OFF' })",
    "-DANTIVIRUS_WEBVIEW2_BOOTSTRAPPER:FILEPATH=$webView2RuntimeInstallerFullPath"
)

cmake @cmakeConfigureArgs | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

cmake --build $buildRoot --target antivirus-agent-service antivirus-endpoint-client antivirus-pam-client antivirus-amsi-provider antivirus-scannercli antivirus-amsitestcli antivirus-etwtestcli antivirus-wfptestcli | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE"
}

Ensure-Directory -Path $outputRoot
Ensure-Directory -Path (Join-Path $outputRoot 'tools')
Ensure-Directory -Path (Join-Path $outputRoot 'signatures')
Ensure-Directory -Path (Join-Path $outputRoot 'driver')
Ensure-Directory -Path (Join-Path $outputRoot 'docs')

$requiredBuiltArtifacts = @(
    (Join-Path $outputRoot 'fenrir-agent-service.exe'),
    (Join-Path $outputRoot 'fenrir-endpoint-client.exe'),
    (Join-Path $outputRoot 'fenrir-pam.exe'),
    (Join-Path $outputRoot 'fenrir-amsi-provider.dll'),
    (Join-Path $outputRoot 'fenrir-remote.exe'),
    (Join-Path $outputRoot 'WebView2Loader.dll'),
    (Join-Path $outputRoot 'tools\fenrir-scannercli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-amsitestcli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-etwtestcli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-wfptestcli.exe')
)

foreach ($artifactPath in $requiredBuiltArtifacts) {
    Assert-PathPresent -Path $artifactPath
}

$artifactMap = @(
    @{ Source = (Join-Path $windowsRoot 'service\README.md'); Target = (Join-Path $outputRoot 'docs\service-README.md') },
    @{ Source = (Join-Path $windowsRoot 'tools\endpointui\README.md'); Target = (Join-Path $outputRoot 'docs\endpoint-client-README.md') },
    @{ Source = (Join-Path $windowsRoot 'installer\README.md'); Target = (Join-Path $outputRoot 'docs\installer-README.md') },
    @{ Source = (Join-Path $windowsRoot 'signatures\default-signatures.tsv'); Target = (Join-Path $outputRoot 'signatures\default-signatures.tsv') }
)

foreach ($artifact in $artifactMap) {
    Copy-IfPresent -Source $artifact.Source -Destination $artifact.Target
}

$winpthreadRuntime = Find-MinGwRuntimeDll -BuildRoot $buildRoot -DllName 'libwinpthread-1.dll'
if ($winpthreadRuntime) {
    Copy-IfPresent -Source $winpthreadRuntime -Destination (Join-Path $outputRoot 'libwinpthread-1.dll')
    Copy-IfPresent -Source $winpthreadRuntime -Destination (Join-Path $outputRoot 'tools\libwinpthread-1.dll')
}

$inventory = @()
$inventoryCandidates = @()
foreach ($entry in (Get-ChildItem -LiteralPath $outputRoot -Force)) {
    if (Test-PathWithin -Root $buildRoot -Path $entry.FullName) {
        continue
    }

    if ($entry.PSIsContainer) {
        $inventoryCandidates += Get-ChildItem -LiteralPath $entry.FullName -Recurse -File
    }
    else {
        $inventoryCandidates += $entry
    }
}

foreach ($file in $inventoryCandidates) {
    $relativePath = Get-RelativePath -Root $outputRoot -Path $file.FullName
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $inventory += [pscustomobject]@{
        path = $relativePath
        sizeBytes = $file.Length
        sha256 = $hash
    }
}

$inventoryPath = Join-Path $outputRoot 'release-inventory.json'
$inventoryDocument = [pscustomobject]@{
    generatedAt = [DateTime]::UtcNow.ToString('o')
    buildRoot = $buildRoot
    outputRoot = $outputRoot
    artifacts = $inventory
}
$inventoryDocument | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $inventoryPath -Encoding utf8

Remove-LegacyBuildOutputs -BuildRoot $buildRoot

Write-Host "Release layout written to $outputRoot"
Write-Host "Inventory written to $inventoryPath"
