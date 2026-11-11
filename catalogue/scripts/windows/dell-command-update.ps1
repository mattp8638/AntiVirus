# name: Dell Command Update - install updates
# description: Installs Dell BIOS, firmware, driver and application updates with Dell Command Update, or only lists them if no install option is chosen (changes the system). Can install Dell Command Update 5.7.2 and .NET 10 first, and restart the device when an update needs it.
# category: Windows / Patching and updates / Action
# platforms: windows
# timeout: 7200
# param: InstallDcuAndDotnet10IfNeeded | Install or upgrade Dell Command Update and .NET 10 if needed | boolean | false | optional
# param: InstallAllUpdates | Install all available updates | boolean | false | optional
# param: InstallUpdatesByPackageID | Install these package IDs (comma separated) | string |  | optional
# param: InstallUpdatesByCategory | Install updates in this category | string |  | optional
# param: InstallUpdatesBySeverity | Install updates of this severity (Recommended, Urgent, Optional) | string |  | optional
# param: InstallUpdatesByType | Install updates of this type (BIOS, Firmware, Driver, Application) | string |  | optional
# param: SuspendBitLockerAndRebootIfNeeded | Suspend BitLocker and reboot if an update needs it | boolean | false | optional
# param: SortUpdatesBy | Sort the update list by (Name, Type, Category, ReleaseDate, Severity) | string | Severity | optional
# param: DestinationFolderPath | Folder for output files (blank = ProgramData\Dell\UpdateService) | string |  | optional
# param: CountFieldName | Custom field for the number of available updates (blank = none) | string |  | optional
# param: SummaryFieldName | Custom field for a one-line list of available updates (blank = none) | string |  | optional
# param: BIOSPassword | BIOS setup password, only needed for BIOS updates (blank = use the bios_password field) | string |  | optional
#
# Fenrir version of the Dell Command Update script (based on v1.7).
# - Fenrir puts each parameter at the top of the script as a variable ($InstallAllUpdates = 'true'), so there is no
#   param() block. Booleans arrive as the text 'true' or 'false'.
# - Custom fields are written by printing "FENRIR-FIELD key=value" lines. Field keys are lower case, for example
#   dell_updates_available. The field must already exist in Settings > Custom fields; unknown fields are skipped.
# - The BIOS password is never built into the script. Give it as the BIOSPassword parameter, or keep it in a device
#   custom field with the key bios_password (read here as $env:FENRIR_CF_BIOS_PASSWORD). It is never printed.
# - Runs as SYSTEM, which is Fenrir's default for scripts.
# - Stops starting new installs after 90 minutes, so the 2-hour script limit never interrupts a BIOS or firmware update.
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.

$ErrorActionPreference = 'Continue'
$ExitCode = 0
# Fenrir stops the script (and anything it started) at the 7200-second limit. New installs only start before this point.
$ScriptClock = [System.Diagnostics.Stopwatch]::StartNew()
$StopStartingInstallsAfterSeconds = 5400

# --------------------------------------------------------------------------- parameters

function ConvertTo-FenrirBool {
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    return ([string]$Value).Trim().ToLowerInvariant() -in @('true', '1', 'yes', 'on')
}

function Get-FenrirParam {
    # The variable Fenrir set at the top of the script, or the FENRIR_<NAME> environment variable when the script
    # is run another way (for example by hand for testing).
    param([string]$Name, [string]$Default = '')
    $Variable = Get-Variable -Name $Name -Scope Script -ErrorAction SilentlyContinue
    if ($Variable -and $null -ne $Variable.Value -and [string]$Variable.Value -ne '') { return [string]$Variable.Value }
    $FromEnv = [System.Environment]::GetEnvironmentVariable("FENRIR_$($Name.ToUpperInvariant())")
    if (-not [string]::IsNullOrEmpty($FromEnv)) { return $FromEnv }
    return $Default
}

$installDcuAndDotnet10IfNeeded = ConvertTo-FenrirBool (Get-FenrirParam 'InstallDcuAndDotnet10IfNeeded' 'false')
$InstallAllUpdates = ConvertTo-FenrirBool (Get-FenrirParam 'InstallAllUpdates' 'false')
$SuspendBitLockerAndRebootIfNeeded = ConvertTo-FenrirBool (Get-FenrirParam 'SuspendBitLockerAndRebootIfNeeded' 'false')
$InstallUpdatesByPackageID = Get-FenrirParam 'InstallUpdatesByPackageID'
$InstallUpdatesByCategory = Get-FenrirParam 'InstallUpdatesByCategory'
$InstallUpdatesBySeverity = Get-FenrirParam 'InstallUpdatesBySeverity'
$InstallUpdatesByType = Get-FenrirParam 'InstallUpdatesByType'
$SortUpdatesBy = Get-FenrirParam 'SortUpdatesBy' 'Severity'
$DestinationFolderPath = Get-FenrirParam 'DestinationFolderPath'
$CountFieldName = Get-FenrirParam 'CountFieldName'
$SummaryFieldName = Get-FenrirParam 'SummaryFieldName'
$BIOSPassword = Get-FenrirParam 'BIOSPassword'
if ([string]::IsNullOrWhiteSpace($BIOSPassword)) { $BIOSPassword = $env:FENRIR_CF_BIOS_PASSWORD }
if ($BIOSPassword) { $BIOSPassword = $BIOSPassword.Trim() }
if ([string]::IsNullOrWhiteSpace($BIOSPassword)) { $BIOSPassword = $null }

Write-Host ""

if ([System.Environment]::OSVersion.Version.Build -lt 10240) {
    Write-Host -Object "[Warning] The minimum OS version supported by this script is Windows 10 (10240)."
    Write-Host -Object "[Warning] OS build '$([System.Environment]::OSVersion.Version.Build)' detected. This could lead to errors or unexpected results.`n"
}

if ($DestinationFolderPath) {
    $DestinationFolderPath = $DestinationFolderPath.Trim()

    if ([string]::IsNullOrWhiteSpace($DestinationFolderPath)) {
        Write-Host -Object "[Error] The 'Destination Folder Path' parameter contains only spaces. Please provide a valid folder path or leave it blank to use the default of '$env:ProgramData\Dell\UpdateService'."
        exit 1
    }

    if (
        $DestinationFolderPath -match '[/*?"<>|]' -or
        ($DestinationFolderPath.Length -gt 3 -and $DestinationFolderPath.Substring(3) -match ':')
    ) {
        Write-Host -Object "[Error] The 'Destination Folder Path' of '$DestinationFolderPath' contains one of the following invalid characters: '/*?`"<>|:'"
        exit 1
    }

    if ($DestinationFolderPath -notmatch '^[a-zA-Z]:\\') {
        Write-Host -Object "[Error] The 'Destination Folder Path' of '$DestinationFolderPath' is not valid. Please provide a full folder path starting with a drive letter, for example: C:\Folder\Subfolder."
        exit 1
    }

    $ForbiddenFolderPaths = @(
        $env:WinDir,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        "$env:SystemDrive\Users\Public",
        $env:ProgramData,
        "$env:ProgramData\UpdateService\Clients"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($ForbiddenFolderPath in $ForbiddenFolderPaths) {
        $ForbiddenFolderRegex = "^$([regex]::Escape($ForbiddenFolderPath))($|\\)"
        if (
            $DestinationFolderPath -match $ForbiddenFolderRegex -and
            $DestinationFolderPath -notmatch "^$([regex]::Escape($env:ProgramData))\\Dell($|\\)"
        ) {
            Write-Host -Object "[Error] The 'Destination Folder Path' of '$DestinationFolderPath' is not allowed. Please choose a different folder path."
            exit 1
        }
    }

    $DestinationFolderPath = $DestinationFolderPath.TrimEnd("\")
}
else {
    $DestinationFolderPath = "$env:ProgramData\Dell\UpdateService"
}

if ($SortUpdatesBy -notin @("Name", "Type", "Category", "ReleaseDate", "Severity")) {
    Write-Host -Object "[Error] The 'Sort Updates By' value of '$SortUpdatesBy' is invalid. It must be one of the following values: Name, Type, Category, ReleaseDate, Severity."
    exit 1
}

# Fenrir custom field keys: lower case letters, digits and underscores, starting with a letter.
foreach ($FieldParam in @(@{ Label = 'Count Field Name'; Name = 'CountFieldName' }, @{ Label = 'Summary Field Name'; Name = 'SummaryFieldName' })) {
    $FieldValue = (Get-Variable -Name $FieldParam.Name -ValueOnly)
    if ($FieldValue) {
        $FieldValue = $FieldValue.Trim().ToLowerInvariant()
        if ($FieldValue -notmatch '^[a-z][a-z0-9_]{0,59}$') {
            Write-Host -Object "[Error] The '$($FieldParam.Label)' of '$FieldValue' is not a valid Fenrir custom field key. Use lower case letters, digits and underscores, starting with a letter (for example dell_updates_available)."
            exit 1
        }
        Set-Variable -Name $FieldParam.Name -Value $FieldValue
    }
}

if ($InstallAllUpdates -and ($InstallUpdatesByPackageID -or $InstallUpdatesByCategory -or $InstallUpdatesBySeverity -or $InstallUpdatesByType)) {
    Write-Host -Object "[Warning] Only the 'Install All Updates' parameter will be used. All other 'Install' parameters will be ignored."
    $InstallUpdatesByPackageID = $null
    $InstallUpdatesByCategory = $null
    $InstallUpdatesBySeverity = $null
    $InstallUpdatesByType = $null
}

if ($InstallUpdatesByPackageID -and ($InstallUpdatesByCategory -or $InstallUpdatesBySeverity -or $InstallUpdatesByType)) {
    Write-Host -Object "[Warning] Only the 'Install Updates By Package ID' parameter will be used. All other 'Install' parameters will be ignored."
    $InstallUpdatesByCategory = $null
    $InstallUpdatesBySeverity = $null
    $InstallUpdatesByType = $null
}

$ValidatedPackageIDs = New-Object System.Collections.Generic.List[string]
$InvalidPackageIDs = New-Object System.Collections.Generic.List[string]

if ($InstallUpdatesByPackageID) {
    $InstallUpdatesByPackageID = $InstallUpdatesByPackageID.Trim()

    if ([string]::IsNullOrWhiteSpace($InstallUpdatesByPackageID)) {
        Write-Host -Object "[Error] The 'Package IDs to Install' parameter contains only spaces. Please provide a comma-separated list of Package IDs or leave it blank."
        exit 1
    }

    $AddNewLine = $false

    foreach ($PackageID in ($InstallUpdatesByPackageID -split ",")) {
        $PackageID = $PackageID.Trim()

        if ($PackageID -match "[^0-9A-Z]") {
            Write-Host -Object "[Warning] The package ID '$PackageID' contains invalid characters. Only alphanumeric characters are allowed."
            $InvalidPackageIDs.Add($PackageID)
            $AddNewLine = $true
            continue
        }

        if ($PackageID -notmatch "^[0-9A-Z]{5}$") {
            Write-Host -Object "[Warning] The package ID '$PackageID' is not valid. Package IDs must be exactly 5 alphanumeric characters."
            $InvalidPackageIDs.Add($PackageID)
            $AddNewLine = $true
            continue
        }

        $ValidatedPackageIDs.Add($PackageID)
    }

    if ($AddNewLine) { Write-Host "" }

    if ($ValidatedPackageIDs.Count -eq 0) {
        Write-Host -Object "[Error] No valid package IDs were provided. Please provide a comma-separated list of valid Package IDs or leave it blank."
        exit 1
    }
}

if ($InstallUpdatesByCategory) {
    $InstallUpdatesByCategory = $InstallUpdatesByCategory.Trim()

    if ([string]::IsNullOrWhiteSpace($InstallUpdatesByCategory)) {
        Write-Host -Object "[Error] The 'Install Updates By Category' parameter contains only spaces. Please provide a valid category or leave it blank."
        exit 1
    }

    if ($InstallUpdatesByCategory -match "[,;]") {
        Write-Host -Object "[Error] The 'Install Updates By Category' parameter only accepts a single category value. Please provide a valid category or leave it blank."
        exit 1
    }
}

if ($InstallUpdatesBySeverity) {
    $InstallUpdatesBySeverity = $InstallUpdatesBySeverity.Trim()

    if ($InstallUpdatesBySeverity -match "[,;\s]") {
        Write-Host -Object "[Error] The 'Install Updates By Severity' parameter only accepts a single severity value. Please provide one of the valid severities (Recommended, Urgent, Optional) or leave it blank."
        exit 1
    }

    if ($InstallUpdatesBySeverity -notin @("Recommended", "Urgent", "Optional")) {
        Write-Host -Object "[Error] '$InstallUpdatesBySeverity' is not a valid update severity. Please provide a valid severity (Recommended, Urgent, Optional) or leave it blank."
        exit 1
    }
}

if ($InstallUpdatesByType) {
    $InstallUpdatesByType = $InstallUpdatesByType.Trim()

    if ($InstallUpdatesByType -match "[,;\s]") {
        Write-Host -Object "[Error] The 'Install Updates By Type' parameter only accepts a single type value. Please provide one of the valid types (BIOS, Firmware, Driver, Application) or leave it blank."
        exit 1
    }

    if ($InstallUpdatesByType -notin @("BIOS", "Firmware", "Driver", "Application")) {
        Write-Host -Object "[Error] '$InstallUpdatesByType' is not a valid update type. Please provide a valid type (BIOS, Firmware, Driver, Application) or leave it blank."
        exit 1
    }
}

# --------------------------------------------------------------------------- functions

function Set-FenrirField {
    # Fenrir reads these lines from the script output and stores them in the device's custom fields.
    param([string]$Key, [string]$Value)
    $OneLine = ($Value -replace '[\r\n]+', ' ').Trim()
    Write-Output "FENRIR-FIELD $Key=$OneLine"
}

function Write-FenrirFields {
    # The count and one-line summary of updates still to install, for the fields named in the parameters.
    # Fenrir keeps the last value printed for each field.
    param($Updates)
    if (-not $script:CountFieldName -and -not $script:SummaryFieldName) { return }
    $Outstanding = @($Updates | Where-Object { $_.Status -notmatch "^Installed" })

    if ($script:CountFieldName) {
        Set-FenrirField -Key $script:CountFieldName -Value ([string]$Outstanding.Count)
    }

    if ($script:SummaryFieldName) {
        if ($Outstanding.Count -gt 0) {
            $Summary = ($Outstanding | ForEach-Object { "$($_.PackageID) $($_.Name) ($($_.Severity))" }) -join '; '
            if ($Summary.Length -gt 900) { $Summary = $Summary.Substring(0, 897) + '...' }
        }
        else {
            $Summary = "No Dell updates available as of $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        }
        Set-FenrirField -Key $script:SummaryFieldName -Value $Summary
    }
}

function Invoke-Download {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$URL,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$Attempts = 3,

        [Parameter()]
        [switch]$SkipSleep,

        [Parameter()]
        [switch]$Overwrite,

        [Parameter()]
        [ValidateSet("Chrome", "Edge", "Firefox", "Firefox ESR", "Safari", "InternetExplorer", "Opera")]
        [string]$UserAgent,

        [Parameter()]
        [switch]$Quiet
    )

    $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
    if (($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12')) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
    }
    elseif ($SupportedTLSversions -contains 'Tls12') {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    else {
        Write-Host -Object "[Warning] TLS 1.2 and/or TLS 1.3 are not supported on this system. This download may fail!"
    }

    if ($Path) { $Path = $Path.Trim() }

    if (-not $URL) { throw [System.ArgumentNullException]::new("You must provide a URL.") }
    if (-not $Path) { throw [System.ArgumentNullException]::new("You must provide a file path.") }

    if ($URL -notmatch "^http") {
        try {
            $URL = [System.Uri]"https://$URL"
        }
        catch {
            throw [System.UriFormatException]::new("[Error] The URL '$($URL.OriginalString)' is not valid. Please ensure it starts with http:// or https:// and is properly formatted.")
        }
        Write-Host -Object "[Warning] The URL given is missing http(s). The URL has been modified to the following: '$($URL.AbsoluteUri)'."
    }
    elseif (-not $Quiet) {
        Write-Host -Object "URL '$($URL.AbsoluteUri)' was given."
    }

    if ($Path -match '[/*?"<>|]' -or ($Path.Length -ge 3 -and $Path.Substring(2) -match ':')) {
        throw [System.IO.InvalidDataException]::new("[Error] The file path specified '$Path' contains one of the following invalid characters: '/*?`"<>|:'")
    }

    $Path -split '\\' | ForEach-Object {
        $Folder = $_.Trim()
        if ($Folder -match '^(CON|PRN|AUX|NUL)$' -or $Folder -match '^(LPT|COM)\d+$') {
            throw [System.IO.InvalidDataException]::new("[Error] An invalid folder name was given in '$Path'. The following folder names are reserved: CON, PRN, AUX, NUL, COM1-9, LPT1-9")
        }
    }

    $PreviousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    if (($Path | Split-Path -Leaf) -notmatch "[.]") {
        $ProgressPreference = $PreviousProgressPreference
        throw [System.IO.FileNotFoundException]::new("A file name is required in '$Path'.")
    }

    if ((Test-Path -Path $Path -ErrorAction SilentlyContinue) -and -not $Overwrite) {
        $ProgressPreference = $PreviousProgressPreference
        throw [System.IO.IOException]::new("A file already exists at the path '$Path'.")
    }

    $Path = $Path -replace '\\+', '\'
    $DestinationFolder = Split-Path $Path

    if (-not (Test-Path -Path $DestinationFolder -ErrorAction SilentlyContinue)) {
        try {
            New-Item -Path $DestinationFolder -ItemType Directory -ErrorAction Stop | Out-Null
        }
        catch {
            $ProgressPreference = $PreviousProgressPreference
            throw $_
        }
    }

    if ($UserAgent) {
        $UserAgentString = switch ($UserAgent) {
            "Chrome"            { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36" }
            "Edge"              { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.3405.86" }
            "Firefox"           { "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0" }
            "Firefox ESR"       { "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0" }
            "InternetExplorer"  { "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)" }
            "Opera"             { "Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1" }
            "Safari"            { "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16" }
        }
    }

    for ($DownloadAttempt = 1; $DownloadAttempt -le $Attempts; $DownloadAttempt++) {
        if (-not $SkipSleep) {
            Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 15)
        }

        $File = $false

        try {
            $WebRequestArgs = @{
                Uri                = $URL
                OutFile            = $Path
                MaximumRedirection = 10
                UseBasicParsing    = $true
            }
            if ($UserAgent) { $WebRequestArgs.Add("UserAgent", $UserAgentString) }
            Invoke-WebRequest @WebRequestArgs

            $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host -Object "[Warning] An error has occurred while downloading!"
            Write-Host -Object "[Warning] $($_.Exception.Message)"

            if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
            }

            $File = $false
        }

        if ($File) {
            break
        }
        elseif ($DownloadAttempt -lt $Attempts) {
            Write-Host -Object "[Warning] File failed to download. Retrying...`n"
        }
    }

    $ProgressPreference = $PreviousProgressPreference

    if (-not (Test-Path $Path)) {
        throw [System.IO.FileNotFoundException]::new("[Error] Failed to download file. Please verify the URL of '$URL'.")
    }

    return $Path
}

function Invoke-LegacyConsoleTool {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$FilePath,

        [Parameter()]
        [string[]]$ArgumentList,

        [Parameter()]
        [int]$Timeout = 30
    )

    if ([string]::IsNullOrWhiteSpace($FilePath) -or -not (Test-Path -Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue)) {
        throw (New-Object System.IO.FileNotFoundException("Unable to find '$FilePath'."))
    }

    if ($Timeout -lt 30) {
        throw (New-Object System.ArgumentOutOfRangeException("You must provide a timeout value that is greater than or equal to 30 seconds."))
    }

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $FilePath
    if ($ArgumentList) { $ProcessInfo.Arguments = $ArgumentList -join " " }
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null

    # Read both streams in the background so a full buffer cannot stall the tool.
    $StdOutTask = $Process.StandardOutput.ReadToEndAsync()
    $StdErrTask = $Process.StandardError.ReadToEndAsync()

    if (-not $Process.WaitForExit($Timeout * 1000)) {
        try { $Process.Kill() } catch {}
        $global:LASTEXITCODE = 1
        $Process.Dispose()
        throw (New-Object System.TimeoutException("'$FilePath' did not finish within $Timeout seconds."))
    }

    $Process.WaitForExit()
    $global:LASTEXITCODE = $Process.ExitCode

    $StdErr = $StdErrTask.Result
    if (-not [string]::IsNullOrWhiteSpace($StdErr)) {
        $StdErr.Trim() | Write-Error -Category FromStdErr
    }

    $Output = $StdOutTask.Result
    $Process.Dispose()

    if ([string]::IsNullOrWhiteSpace($Output)) { return $null }
    return ($Output -split "`r?`n")
}

function Get-DellSupportedModels {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$DestinationFolder
    )

    if ([string]::IsNullOrWhiteSpace($DestinationFolder)) {
        throw [System.ArgumentException]::new("A valid DestinationFolder is required to store the files this function downloads.")
    }

    $SupportedModelsCabPath = "$DestinationFolder\CatalogIndexPC.cab"
    $SupportedModelsXmlPath = "$DestinationFolder\SupportedModels.xml"
    $CatalogURL = "https://downloads.dell.com/catalog/CatalogIndexPC.cab"

    Invoke-Download -URL $CatalogURL -Path $SupportedModelsCabPath -Attempts 3 -SkipSleep -Overwrite -Quiet -ErrorAction Stop | Out-Null
    Invoke-LegacyConsoleTool -FilePath "$env:SystemRoot\System32\expand.exe" -ArgumentList "`"$SupportedModelsCabPath`" `"$SupportedModelsXmlPath`"" -ErrorAction Stop | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw [System.Exception]::new("Unable to extract the SupportedModels.xml file from the downloaded CatalogIndexPC.cab file.")
    }

    if (-not (Test-Path $SupportedModelsXmlPath)) {
        throw [System.IO.FileNotFoundException]::new("The extracted SupportedModels.xml file was not found at the expected path of '$SupportedModelsXmlPath'.")
    }

    try {
        $SupportedModelsXml = [xml](Get-Content -Path $SupportedModelsXmlPath -Raw -ErrorAction Stop)
    }
    catch {
        throw [System.InvalidCastException]::new("Failed to read or parse the SupportedModels.xml file at '$SupportedModelsXmlPath'.")
    }

    $SupportedModelsObject = New-Object System.Collections.Generic.List[PSObject]

    foreach ($Model in $SupportedModelsXml.ManifestIndex.GroupManifest) {
        $SupportedModelsObject.Add([PSCustomObject]@{
            SKU     = $Model.SupportedSystems.Brand.Model.systemID
            Brand   = $Model.SupportedSystems.Brand.Display."#cdata-section"
            Model   = $Model.SupportedSystems.Brand.Model.Display."#cdata-section"
            URL     = $Model.ManifestInformation.path
            Version = $Model.ManifestInformation.version
        })
    }

    return $SupportedModelsObject
}

function Get-DellAvailableUpdates {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$SystemSKU,

        [Parameter()]
        [ValidateSet("CatalogDownload", "CLI")]
        [string]$Method,

        [Parameter()]
        [string]$DestinationFolder,

        [Parameter()]
        [switch]$Latest
    )

    if ([string]::IsNullOrWhiteSpace($DestinationFolder)) {
        throw [System.ArgumentException]::new("A valid DestinationFolder is required to store the files this function downloads.")
    }

    $AvailableUpdatesList = New-Object System.Collections.Generic.List[PSObject]

    if ($Method -eq "CatalogDownload") {
        if ([string]::IsNullOrWhiteSpace($SystemSKU)) {
            throw [System.ArgumentException]::new("A SystemSKU is required when using the CatalogDownload method.")
        }

        if (-not $script:SupportedModels) {
            $script:SupportedModels = Get-DellSupportedModels -DestinationFolder $DestinationFolder -ErrorAction Stop
        }

        $UpdateURL = ($script:SupportedModels | Where-Object { $_.SKU -eq $SystemSKU } | Select-Object -First 1 -ExpandProperty URL)

        if ([string]::IsNullOrWhiteSpace($UpdateURL)) {
            throw [System.Exception]::new("Could not find an update catalog for the model with SKU of '$SystemSKU'. This model may not be supported by Dell Command Update.")
        }

        $UpdatesFromCatalogCabPath = "$DestinationFolder\CatalogIndexModel.cab"
        $UpdatesFromCatalogXMLPath = "$DestinationFolder\UpdatesFromCatalog.xml"

        Invoke-Download -URL "https://downloads.dell.com/$UpdateURL" -Path $UpdatesFromCatalogCabPath -Attempts 3 -SkipSleep -Overwrite -Quiet -ErrorAction Stop | Out-Null

        try {
            Invoke-LegacyConsoleTool -FilePath "$env:SystemRoot\System32\expand.exe" -ArgumentList "`"$UpdatesFromCatalogCabPath`" `"$UpdatesFromCatalogXMLPath`"" -ErrorAction Stop | Out-Null
        }
        catch {
            throw [System.Exception]::new("Unable to extract the UpdatesFromCatalog.xml file for the model with SKU of '$SystemSKU'.")
        }

        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $UpdatesFromCatalogXMLPath)) {
            throw [System.Exception]::new("Unable to extract the UpdatesFromCatalog.xml file for the model with SKU of '$SystemSKU'.")
        }

        try {
            $UpdatesFromCatalogXML = [xml](Get-Content -Path $UpdatesFromCatalogXMLPath -Raw -ErrorAction Stop)
        }
        catch {
            throw [System.InvalidCastException]::new("Failed to read or parse the UpdatesFromCatalog.xml file at '$UpdatesFromCatalogXMLPath'.")
        }

        $BaseUpdateURL = $UpdatesFromCatalogXML.Manifest.baseLocation

        foreach ($Update in $UpdatesFromCatalogXML.Manifest.SoftwareComponent) {
            $AvailableUpdatesList.Add([PSCustomObject]@{
                PackageID          = $Update.packageID
                Name               = $Update.Name.Display."#cdata-section"
                Type               = $Update.ComponentType.Display."#cdata-section"
                Category           = $Update.Category.Display."#cdata-section"
                DellVersion        = $Update.dellVersion
                VendorVersion      = $Update.VendorVersion
                PackageType        = $Update.PackageType
                ReleaseDate        = ([datetime]$Update.releaseDate).ToShortDateString()
                Description        = $Update.Description.Display."#cdata-section"
                DownloadURL        = "https://$BaseUpdateURL/$($Update.path)"
                DownloadHashSha256 = ($Update.Cryptography.Hash | Where-Object { $_.algorithm -eq "SHA256" })."#text"
                DownloadHashMD5    = ($Update.Cryptography.Hash | Where-Object { $_.algorithm -eq "MD5" })."#text"
                DownloadHashSha1   = ($Update.Cryptography.Hash | Where-Object { $_.algorithm -eq "SHA1" })."#text"
                Severity           = $Update.Criticality.Display."#cdata-section"
            })
        }

        if ($Latest) {
            $LatestUpdates = $AvailableUpdatesList |
                Group-Object Name |
                ForEach-Object {
                    $_.Group | Sort-Object { [datetime]::Parse($_.ReleaseDate) } -Descending | Select-Object -First 1
                }

            $AvailableUpdatesList = New-Object System.Collections.Generic.List[PSObject]
            foreach ($Item in $LatestUpdates) { $AvailableUpdatesList.Add($Item) }
        }
    }

    if ($Method -eq "CLI") {
        $InventoryPath = "$env:ProgramData\Dell\UpdateService\Temp\Inventory.xml"

        if (Test-Path $InventoryPath) {
            try {
                Remove-Item -Path $InventoryPath -Force -ErrorAction Stop
                Restart-Service -Name "DellClientManagementService" -Force -ErrorAction Stop | Out-Null
            }
            catch {
                throw [System.Exception]::new("Unable to reset the Dell Command Update inventory.`n$($_.Exception.Message)")
            }
        }

        $ScannedUpdatesXMLPath = "$DestinationFolder\DCUApplicableUpdates.xml"
        $ScannedUpdatesLogFilePath = "$DestinationFolder\DCUScan.log"

        $DCUCLIArguments = "/scan -silent -report=`"$DestinationFolder`" -outputLog=`"$ScannedUpdatesLogFilePath`""
        Invoke-LegacyConsoleTool -FilePath $script:DCUCLIPath -ArgumentList $DCUCLIArguments -Timeout 1200 -ErrorAction Stop | Out-Null

        switch ($LASTEXITCODE) {
            0   {}
            5   { throw [System.Exception]::new("Unable to scan for updates because a reboot is required. Please reboot the device then run the script again.") }
            6   { throw [System.Exception]::new("Dell Command Update is already running. Please stop other instances of DCU then run the script again.") }
            107 { throw [System.Exception]::new("Dell Command Update rejected the command line arguments. This is likely due to an invalid destination folder.") }
            500 {
                if (-not (Test-Path $ScannedUpdatesXMLPath)) {
                    return $AvailableUpdatesList
                }
            }
            default { throw [System.Exception]::new("Dell Command Update scan exited with code $LASTEXITCODE.") }
        }

        if (-not (Test-Path $ScannedUpdatesXMLPath)) {
            throw [System.IO.FileNotFoundException]::new("The DCUApplicableUpdates.xml file was not found at the expected path of '$ScannedUpdatesXMLPath'.")
        }

        try {
            $ScannedUpdatesXML = [xml](Get-Content -Path $ScannedUpdatesXMLPath -Raw -ErrorAction Stop)
        }
        catch {
            throw [System.InvalidCastException]::new("Failed to read or parse the available updates scan file at '$ScannedUpdatesXMLPath'.")
        }

        foreach ($Update in $ScannedUpdatesXML.updates.update) {
            $AvailableUpdatesList.Add([PSCustomObject]@{
                PackageID   = $Update.release
                Name        = $Update.name
                Type        = $Update.type
                Category    = $Update.category
                Version     = $Update.version
                ReleaseDate = ([datetime]$Update.date).ToShortDateString()
                DownloadURL = "https://downloads.dell.com/$($Update.file)"
                Severity    = $Update.urgency
                Size        = $Update.bytes
                Status      = "Not installed"
            })
        }
    }

    switch ($script:SortUpdatesBy) {
        "Name"        { $AvailableUpdatesList = $AvailableUpdatesList | Sort-Object Name }
        "Type"        { $AvailableUpdatesList = $AvailableUpdatesList | Sort-Object Type, Name }
        "Category"    { $AvailableUpdatesList = $AvailableUpdatesList | Sort-Object Category, Name }
        "ReleaseDate" { $AvailableUpdatesList = $AvailableUpdatesList | Sort-Object @{ Expression = { Get-Date $_.ReleaseDate }; Descending = $true }, Name }
        "Severity"    {
            $AvailableUpdatesList = $AvailableUpdatesList | Sort-Object @{
                Expression = {
                    if ($_.Severity -match "Urgent") { 1 }
                    elseif ($_.Severity -eq "Recommended") { 2 }
                    elseif ($_.Severity -eq "Optional") { 3 }
                    else { 4 }
                }
            }, Name
        }
    }

    return $AvailableUpdatesList
}

function Invoke-ParsedCommandLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine
    )

    $CommandLine = $CommandLine.Trim()

    if ($CommandLine -match '^\s*"(?<exe>[^"]+)"\s*(?<args>.*)$') {
        $Executable = $Matches.exe
        $Arguments = $Matches.args
    }
    elseif ($CommandLine -match '^\s*(?<exe>\S+)\s*(?<args>.*)$') {
        $Executable = $Matches.exe
        $Arguments = $Matches.args
    }
    else {
        throw [System.ArgumentException]::new("Unable to parse the executable from command line '$CommandLine'.")
    }

    $StartArgs = @{ FilePath = $Executable; Wait = $true; NoNewWindow = $true; PassThru = $true; ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($Arguments)) { $StartArgs.ArgumentList = $Arguments }
    $Process = Start-Process @StartArgs
    return $Process.ExitCode
}

function Get-DotNet10VersionForDCU572 {
    [CmdletBinding()]
    param ()

    # Deployment minimum: .NET Desktop Runtime 10.0.12; Dell's minimum is 10.0.8. Microsoft's release metadata gives
    # the latest servicing release, so an old patch release is never pinned.
    $MinSupportedVersion = [version]"10.0.12"
    $DownloadURL = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json"
    $DestinationPath = "$env:TEMP\DotNet10Releases.json"

    Invoke-Download -URL $DownloadURL -Path $DestinationPath -Attempts 3 -SkipSleep -Overwrite -Quiet -ErrorAction Stop | Out-Null

    try {
        $ReleasesJSON = Get-Content $DestinationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    finally {
        Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
    }

    $CandidateRelease = $ReleasesJSON.releases |
        Where-Object {
            try {
                $v = [version]$_."release-version"
                $v.Major -eq 10 -and $v -ge $MinSupportedVersion
            }
            catch { $false }
        } |
        Sort-Object { [version]$_."release-version" } -Descending |
        Select-Object -First 1

    if (-not $CandidateRelease) {
        throw [System.Exception]::new("Could not find a .NET Desktop Runtime 10 release at or above $MinSupportedVersion.")
    }

    $DesktopRuntime = $CandidateRelease.windowsdesktop.files |
        Where-Object {
            ($_.rid -eq "win-x64" -and $_.url -match '\.exe($|\?)') -or
            ($_.name -match '(?i)windowsdesktop.*x64.*\.exe$') -or
            ($_.url -match '(?i)windowsdesktop.*x64.*\.exe($|\?)')
        } |
        Select-Object -First 1

    if (-not $DesktopRuntime) {
        throw [System.Exception]::new("Could not find the Windows x64 .NET Desktop Runtime installer for version $($CandidateRelease.'release-version').")
    }

    return [PSCustomObject]@{
        Version     = $CandidateRelease."release-version"
        DownloadURL = $DesktopRuntime.url
        Hash        = $DesktopRuntime.hash
        MinVersion  = $MinSupportedVersion
    }
}

function Get-InstalledDCUInfo {
    [CmdletBinding()]
    param ()

    $PossiblePaths = @(
        "$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
        "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
    )

    $DCUExe = Get-Item -Path $PossiblePaths -ErrorAction SilentlyContinue | Select-Object -First 1

    $Version = $null
    if ($DCUExe) {
        try { $Version = [version]$DCUExe.VersionInfo.ProductVersion }
        catch {
            try { $Version = [version]$DCUExe.VersionInfo.FileVersion } catch { $Version = $null }
        }
    }

    $UninstallEntry = $null
    foreach ($Root in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )) {
        $Match = Get-ItemProperty -Path $Root -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '^Dell Command \| Update' -or $_.DisplayName -match '^Dell Command Update' } |
            Sort-Object @{ Expression = { try { [version]$_.DisplayVersion } catch { [version]'0.0' } }; Descending = $true } |
            Select-Object -First 1

        if ($Match) {
            $UninstallEntry = $Match
            break
        }
    }

    if (-not $Version -and $UninstallEntry -and $UninstallEntry.DisplayVersion) {
        try { $Version = [version]$UninstallEntry.DisplayVersion } catch { $Version = $null }
    }

    if (-not $DCUExe -and -not $UninstallEntry) {
        return $null
    }

    return [PSCustomObject]@{
        Path                 = $DCUExe.FullName
        Version              = $Version
        DisplayName          = $UninstallEntry.DisplayName
        DisplayVersion       = $UninstallEntry.DisplayVersion
        UninstallString      = $UninstallEntry.UninstallString
        QuietUninstallString = $UninstallEntry.QuietUninstallString
    }
}

function Test-IsSystem {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]'544')
}

function Remove-FileQuietly {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return }
    try {
        Remove-Item -Path $Path -Force -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Warning] Failed to delete the file at '$Path'. Please delete this file manually."
        Write-Host -Object "[Warning] $($_.Exception.Message)"
    }
}

function Test-InstallerSignature {
    # $true when the file is validly signed and its signer subject matches $SubjectPattern.
    param([string]$Path, [string]$SubjectPattern, [string]$IssuerPattern)
    try {
        $Signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] Failed to check the file signature of '$Path'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        return $false
    }
    if ($Signature.Status -ne "Valid") {
        Write-Host -Object "[Error] The file signature of '$Path' is $($Signature.Status)."
        return $false
    }
    if ($IssuerPattern -and $Signature.SignerCertificate.IssuerName.Name -notmatch $IssuerPattern) {
        Write-Host -Object "[Error] The file signature of '$Path' has an unexpected issuer of '$($Signature.SignerCertificate.IssuerName.Name)'."
        return $false
    }
    if ($Signature.SignerCertificate.Subject -notmatch $SubjectPattern) {
        Write-Host -Object "[Error] The file signature of '$Path' has an unexpected subject of '$($Signature.SignerCertificate.Subject)'."
        return $false
    }
    return $true
}

function Select-ExpectedHash {
    # The strongest hash the catalog provides: @{ Algorithm; Hash } or $null.
    param([string]$Sha256, [string]$Sha1, [string]$Md5)
    foreach ($Candidate in @(@('SHA256', $Sha256), @('SHA1', $Sha1), @('MD5', $Md5))) {
        if ($Candidate[1] -and $Candidate[1] -ne '-' -and -not [string]::IsNullOrWhiteSpace($Candidate[1])) {
            return @{ Algorithm = $Candidate[0]; Hash = $Candidate[1] }
        }
    }
    return $null
}

# --------------------------------------------------------------------------- checks

try {
    $IsElevated = Test-IsElevated
}
catch {
    Write-Host -Object "[Error] Unable to determine if the account '$env:USERNAME' is running this script in an elevated session."
    Write-Host -Object "[Error] $($_.Exception.Message)"
    exit 1
}

if (-not $IsElevated) {
    Write-Host -Object "[Error] The user '$env:USERNAME' is not running this script in an elevated session. Please run this script as System."
    exit 1
}

if (-not (Test-IsSystem)) {
    Write-Host -Object "[Error] Please run this script as the SYSTEM account (in Fenrir: Run as = System)."
    exit 1
}

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
}
catch {
    Write-Host -Object "[Error] Failed to retrieve computer system information."
    Write-Host -Object "[Error] $($_.Exception.Message)"
    exit 1
}

if ($ComputerSystem.Manufacturer -notmatch "^Dell") {
    Write-Host -Object "[Error] This script is intended to be run on Dell systems only. The current system manufacturer is '$($ComputerSystem.Manufacturer)'."
    exit 1
}

if (-not (Test-Path -Path $DestinationFolderPath)) {
    try {
        New-Item -Path $DestinationFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host -Object "[Info] Created the folder '$DestinationFolderPath'.`n"
    }
    catch {
        Write-Host -Object "[Warning] Failed to create the directory at '$DestinationFolderPath': $($_.Exception.Message)"
        Write-Host -Object "[Info] Script will default to using the '$env:ProgramData\Dell\UpdateService' folder.`n"
        $DestinationFolderPath = "$env:ProgramData\Dell\UpdateService"

        if (-not (Test-Path -Path $DestinationFolderPath)) {
            try {
                New-Item -Path $DestinationFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host -Object "[Error] Failed to create the fallback directory at '$DestinationFolderPath'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
    }
}

try {
    $script:SupportedModels = Get-DellSupportedModels -DestinationFolder $DestinationFolderPath -ErrorAction Stop
}
catch {
    Write-Host -Object "[Error] Failed to retrieve the list of supported Dell models."
    Write-Host -Object "[Error] $($_.Exception.Message)"
    exit 1
}

$ComputerSKU = $ComputerSystem.SystemSKUNumber

if ($ComputerSKU -notin $script:SupportedModels.SKU) {
    Write-Host -Object "[Error] The computer's SKU of '$ComputerSKU' is not supported by Dell Command Update."
    exit 1
}

Write-Host -Object "[Info] All output files will be saved to the folder: '$DestinationFolderPath'`n"

# --------------------------------------------------------------------------- .NET runtime and Dell Command Update

$PrerequisiteRebootRequired = $false
$TargetDCUVersion = [version]"5.7.2"

$InstalledDCU = Get-InstalledDCUInfo
$script:DCUCLIPath = $InstalledDCU.Path
$InstalledDCUVersion = $InstalledDCU.Version
$NeedsDCUInstallOrUpgrade = $false

if (-not $InstalledDCU) {
    $NeedsDCUInstallOrUpgrade = $true
}
elseif (-not $InstalledDCUVersion) {
    Write-Host -Object "[Warning] Dell Command Update appears to be installed, but the installed version could not be determined. It will be treated as needing an upgrade to $TargetDCUVersion.`n"
    $NeedsDCUInstallOrUpgrade = $true
}
elseif ($InstalledDCUVersion -lt $TargetDCUVersion) {
    Write-Host -Object "[Info] Dell Command Update version $InstalledDCUVersion is installed; version $TargetDCUVersion is needed.`n"
    $NeedsDCUInstallOrUpgrade = $true
}
else {
    Write-Host -Object "[Info] Dell Command Update version $InstalledDCUVersion is already installed."
}

# Keep the runtime current even when DCU is already up to date, when installation is enabled.
if ($installDcuAndDotnet10IfNeeded) {
    $RequiredDotNetVersion = [version]"10.0.12"
    $DotNetPath = "$env:ProgramFiles\dotnet\shared\Microsoft.WindowsDesktop.App\"
    $IsDotNetInstalled = $false

    if (Test-Path -Path $DotNetPath) {
        foreach ($Folder in (Get-ChildItem -Path $DotNetPath -Directory -ErrorAction SilentlyContinue)) {
            if (-not (Get-ChildItem -Path $Folder.FullName -ErrorAction SilentlyContinue)) { continue }
            try { $ParsedVersion = [version]$Folder.Name } catch { continue }

            if ($ParsedVersion.Major -eq 10) {
                if ($ParsedVersion -ge $RequiredDotNetVersion) {
                    Write-Host -Object "[Info] Detected supported .NET Desktop Runtime version $ParsedVersion."
                    $IsDotNetInstalled = $true
                }
                else {
                    Write-Host -Object "[Warning] Detected .NET Desktop Runtime version $ParsedVersion, but version $RequiredDotNetVersion or later is required."
                }
            }
        }
    }

    if (-not $IsDotNetInstalled) {
        Write-Host -Object "[Info] Installing the latest .NET Desktop Runtime 10 (64-bit), version $RequiredDotNetVersion or later.`n"

        try {
            $LatestDotNetInfo = Get-DotNet10VersionForDCU572 -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to retrieve .NET Desktop Runtime 10 version information."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        $DotNetInstallerFilePath = "$DestinationFolderPath\DotNetDesktop64BitInstaller.exe"
        $DotNetInstallerLog = "$DestinationFolderPath\DotNetDesktop64BitInstallerLog.log"

        try {
            Write-Host -Object "[Info] Downloading the .NET Desktop Runtime $($LatestDotNetInfo.Version) installer."
            Invoke-Download -URL $LatestDotNetInfo.DownloadURL -Path $DotNetInstallerFilePath -UserAgent "Chrome" -Attempts 3 -SkipSleep -Overwrite -Quiet -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host -Object "[Error] Failed to download the .NET Desktop Runtime installer."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        $DownloadedDotNetHash = (Get-FileHash -Path $DotNetInstallerFilePath -Algorithm SHA512 -ErrorAction SilentlyContinue).Hash
        if (-not $DownloadedDotNetHash -or $DownloadedDotNetHash -ne $LatestDotNetInfo.Hash) {
            Write-Host -Object "[Error] The SHA512 hash of the downloaded .NET Desktop Runtime installer does not match the expected value."
            Write-Host -Object "[Error] Expected: $($LatestDotNetInfo.Hash)"
            Write-Host -Object "[Error] Actual:   $DownloadedDotNetHash"
            Remove-FileQuietly $DotNetInstallerFilePath
            exit 1
        }
        Write-Host -Object "[Info] Verified the SHA512 hash of the .NET Desktop Runtime installer."

        if (-not (Test-InstallerSignature -Path $DotNetInstallerFilePath -SubjectPattern "Microsoft Corporation" -IssuerPattern "Microsoft Corporation")) {
            Remove-FileQuietly $DotNetInstallerFilePath
            exit 1
        }
        Write-Host -Object "[Info] Verified the digital signature of the .NET Desktop Runtime installer."

        try {
            $DotNetInstallerProcess = Start-Process -FilePath $DotNetInstallerFilePath -ArgumentList "/install /quiet /norestart /log `"$DotNetInstallerLog`"" -Wait -NoNewWindow -PassThru -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to start the .NET Desktop Runtime installer."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        switch ($DotNetInstallerProcess.ExitCode) {
            0       { Write-Host -Object "[Info] Installed .NET Desktop Runtime $($LatestDotNetInfo.Version).`n" }
            { $_ -in 1641, 3010 } {
                Write-Host -Object "[Warning] .NET Desktop Runtime $($LatestDotNetInfo.Version) installed, but a reboot is required (exit code $($DotNetInstallerProcess.ExitCode))."
                $PrerequisiteRebootRequired = $true
            }
            default {
                Write-Host -Object "[Error] The .NET Desktop Runtime installer exited with code $($DotNetInstallerProcess.ExitCode). See '$DotNetInstallerLog'."
                exit 1
            }
        }

        Get-ChildItem "$DestinationFolderPath\DotNetDesktop64Bit*" -ErrorAction SilentlyContinue | ForEach-Object { Remove-FileQuietly $_.FullName }
    }
    else {
        Write-Host -Object "[Info] A supported .NET Desktop Runtime 10 is already installed.`n"
    }
}

if ($NeedsDCUInstallOrUpgrade -and -not $installDcuAndDotnet10IfNeeded) {
    Write-Host -Object "[Error] Dell Command Update is missing or older than $TargetDCUVersion. Run the script with 'Install or upgrade Dell Command Update and .NET 10 if needed' ticked."
    exit 1
}
elseif ($NeedsDCUInstallOrUpgrade) {
    $PrintedDCUDownloadURLWarning = $false
    $LatestDellCommandUpdate = $null

    try {
        $LatestDellCommandUpdate = Get-DellAvailableUpdates -SystemSKU $ComputerSKU -DestinationFolder $DestinationFolderPath -Method "CatalogDownload" -Latest -ErrorAction Stop |
            Where-Object { $_.Name -match "Command.+Windows Universal" } |
            Select-Object -First 1
    }
    catch {
        Write-Host -Object "[Warning] Failed to look up Dell Command Update for the SKU of '$ComputerSKU': $($_.Exception.Message)"
        Write-Host -Object "[Warning] The script will use the verified Dell download for version 5.7.2.`n"
        $PrintedDCUDownloadURLWarning = $true
    }

    $DellCommandUpdateDownloadURL = $LatestDellCommandUpdate.DownloadURL
    $ExpectedDCUSha256Hash = $LatestDellCommandUpdate.DownloadHashSha256
    $ExpectedDCUSha1Hash = $LatestDellCommandUpdate.DownloadHashSha1
    $ExpectedDCUMd5Hash = $LatestDellCommandUpdate.DownloadHashMD5
    $DellCommandUpdateVersion = $LatestDellCommandUpdate.VendorVersion

    # Pinned to the tested 5.7.2 so a future DCU release cannot invalidate the prerequisite logic.
    $CatalogDCUVersion = $null
    if ($DellCommandUpdateVersion) {
        try { $CatalogDCUVersion = [version]$DellCommandUpdateVersion } catch { $CatalogDCUVersion = $null }
    }

    if (-not $CatalogDCUVersion -or $CatalogDCUVersion -ne $TargetDCUVersion) {
        if ($DellCommandUpdateDownloadURL) {
            Write-Host -Object "[Warning] The model catalog offers Dell Command Update '$DellCommandUpdateVersion'; this script is pinned to the tested version $TargetDCUVersion and will use that instead.`n"
        }
        $DellCommandUpdateDownloadURL = $null
    }

    if ([string]::IsNullOrWhiteSpace($DellCommandUpdateDownloadURL)) {
        if (-not $PrintedDCUDownloadURLWarning) {
            Write-Host -Object "[Info] Using the verified Dell download for Dell Command Update 5.7.2.`n"
        }

        $DellCommandUpdateDownloadURL = "https://dl.dell.com/FOLDER15013620M/1/Dell-Command-Update-Windows-Universal-Application_M9H5F_WIN64_5.7.2_A00.EXE"
        $ExpectedDCUSha256Hash = "B405681CFE05BF61B4E129550D8D4134A1C42BB648F5C9D9FB980A1EDB918EE9"
        $ExpectedDCUSha1Hash = "EE529377C64718F361E38E4B47DD1E56D6A984CD"
        $ExpectedDCUMd5Hash = "384E59A3C0C63810D19D7B583FE642B3"
        $DellCommandUpdateVersion = "5.7.2"
    }

    $DCUInstallerFilePath = "$DestinationFolderPath\DellCommandUpdateInstaller.exe"
    $DCUInstallerLog = "$DestinationFolderPath\DellCommandUpdateInstallerLog.log"

    try {
        Write-Host -Object "[Info] Downloading the Dell Command Update $DellCommandUpdateVersion installer."
        Invoke-Download -URL $DellCommandUpdateDownloadURL -Path $DCUInstallerFilePath -UserAgent "Chrome" -Attempts 3 -SkipSleep -Overwrite -Quiet -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -Object "[Error] Failed to download Dell Command Update."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    $Expected = Select-ExpectedHash -Sha256 $ExpectedDCUSha256Hash -Sha1 $ExpectedDCUSha1Hash -Md5 $ExpectedDCUMd5Hash
    if (-not $Expected) {
        Write-Host -Object "[Error] No hash is available to verify the Dell Command Update installer. It will not be installed."
        Remove-FileQuietly $DCUInstallerFilePath
        exit 1
    }

    $DownloadedDCUHash = (Get-FileHash -Path $DCUInstallerFilePath -Algorithm $Expected.Algorithm -ErrorAction SilentlyContinue).Hash
    if ($DownloadedDCUHash -ne $Expected.Hash) {
        Write-Host -Object "[Error] The $($Expected.Algorithm) hash of the Dell Command Update installer does not match the expected value."
        Write-Host -Object "[Error] Expected: $($Expected.Hash)"
        Write-Host -Object "[Error] Actual:   $DownloadedDCUHash"
        Remove-FileQuietly $DCUInstallerFilePath
        exit 1
    }
    Write-Host -Object "[Info] Verified the $($Expected.Algorithm) hash of the Dell Command Update installer."

    if (-not (Test-InstallerSignature -Path $DCUInstallerFilePath -SubjectPattern "Dell Technologies Inc\." -IssuerPattern "DigiCert, Inc\.")) {
        Remove-FileQuietly $DCUInstallerFilePath
        exit 1
    }
    Write-Host -Object "[Info] Verified the digital signature of the Dell Command Update installer."

    if ($InstalledDCU -and $InstalledDCUVersion -and $InstalledDCUVersion -lt $TargetDCUVersion) {
        Write-Host -Object "[Info] Uninstalling Dell Command Update $InstalledDCUVersion before installing $TargetDCUVersion."

        $UninstallCommand = $InstalledDCU.QuietUninstallString
        if ([string]::IsNullOrWhiteSpace($UninstallCommand)) { $UninstallCommand = $InstalledDCU.UninstallString }

        if ([string]::IsNullOrWhiteSpace($UninstallCommand)) {
            Write-Host -Object "[Error] Could not find an uninstall command for the installed Dell Command Update in the registry."
            exit 1
        }

        if ($UninstallCommand -match '(?i)\bmsiexec(\.exe)?\b') {
            $UninstallCommand = $UninstallCommand -replace '(?i)\s/I(?=\s|{|")', ' /X'
            if ($UninstallCommand -notmatch '(?i)\s/X(?=\s|{|")') { $UninstallCommand += ' /X' }
            if ($UninstallCommand -notmatch '(?i)\s/qn(?=\s|$|")') { $UninstallCommand += ' /qn' }
            if ($UninstallCommand -notmatch '(?i)\s/norestart(?=\s|$|")') { $UninstallCommand += ' /norestart' }
        }
        elseif ($UninstallCommand -notmatch '(?i)(^| )/(quiet|qn|s)( |$|")') {
            $UninstallCommand = "$UninstallCommand /s"
        }

        Write-Host -Object "[Info] Uninstall command: $UninstallCommand"

        try {
            $UninstallExitCode = Invoke-ParsedCommandLine -CommandLine $UninstallCommand
        }
        catch {
            Write-Host -Object "[Error] Failed to start the uninstall of Dell Command Update $InstalledDCUVersion."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        if ($UninstallExitCode -notin @(0, 1641, 3010)) {
            Write-Host -Object "[Error] The uninstall of Dell Command Update $InstalledDCUVersion exited with code $UninstallExitCode."
            exit 1
        }

        if ($UninstallExitCode -in @(1641, 3010)) {
            Write-Host -Object "[Warning] Dell Command Update $InstalledDCUVersion was uninstalled, but a reboot is required (exit code $UninstallExitCode)."
            $PrerequisiteRebootRequired = $true
        }
        else {
            Write-Host -Object "[Info] Uninstalled Dell Command Update $InstalledDCUVersion.`n"
        }
        Start-Sleep -Seconds 5
    }

    try {
        Write-Host -Object "[Info] Installing Dell Command Update $DellCommandUpdateVersion."
        $DCUInstallerProcess = Start-Process -FilePath $DCUInstallerFilePath -ArgumentList "/s /l=`"$DCUInstallerLog`"" -Wait -NoNewWindow -PassThru -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] Failed to start the Dell Command Update installer."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    if ($DCUInstallerProcess.ExitCode -notin @(0, 2, 1641, 3010)) {
        Write-Host -Object "[Error] The Dell Command Update installer exited with code $($DCUInstallerProcess.ExitCode). See '$DCUInstallerLog'."
        exit 1
    }

    if ($DCUInstallerProcess.ExitCode -in @(2, 1641, 3010)) {
        Write-Host -Object "[Warning] Dell Command Update $DellCommandUpdateVersion installed, but a reboot is required (exit code $($DCUInstallerProcess.ExitCode))."
        $PrerequisiteRebootRequired = $true
    }
    else {
        Write-Host -Object "[Info] Installed Dell Command Update $DellCommandUpdateVersion.`n"
    }

    Get-ChildItem "$DestinationFolderPath\DellCommandUpdateInstaller*" -ErrorAction SilentlyContinue | ForEach-Object { Remove-FileQuietly $_.FullName }

    $InstalledDCU = Get-InstalledDCUInfo
    $script:DCUCLIPath = $InstalledDCU.Path
    $InstalledDCUVersion = $InstalledDCU.Version

    if (-not $script:DCUCLIPath) {
        Write-Host -Object "[Error] 'dcu-cli.exe' cannot be found after the install. Please check that Dell Command Update installed correctly."
        exit 1
    }

    if (-not $InstalledDCUVersion -or $InstalledDCUVersion -lt $TargetDCUVersion) {
        Write-Host -Object "[Error] Dell Command Update installed, but the detected version is '$InstalledDCUVersion'. Expected $TargetDCUVersion or later."
        exit 1
    }
}

# --------------------------------------------------------------------------- scan

$UpdatesList = New-Object System.Collections.Generic.List[PSObject]

try {
    Write-Host -Object "[Info] Scanning for available updates."
    Get-DellAvailableUpdates -Method "CLI" -DestinationFolder $DestinationFolderPath -ErrorAction Stop | ForEach-Object {
        if ($_ -and -not [string]::IsNullOrWhiteSpace([string]$_)) { $UpdatesList.Add($_) }
    }
}
catch {
    Write-Host -Object "[Error] Failed to scan for updates with dcu-cli.exe. The log file at '$DestinationFolderPath\DCUScan.log' may have more information."
    Write-Host -Object "[Error] $($_.Exception.Message)"
    exit 1
}

$InitialAvailableUpdatesCount = ($UpdatesList | Measure-Object).Count
Write-Host -Object "[Info] Found $InitialAvailableUpdatesCount available updates for this system."

if ($InitialAvailableUpdatesCount -gt 0) {
    Write-Host ""
    ($UpdatesList | Select-Object PackageID, Severity, Type, ReleaseDate, Version, Name | Format-Table -AutoSize | Out-String -Width 220).Trim() | Write-Host
}

# Record the fields now as well as at the end, so they are set even if the end of a long output is cut off.
Write-FenrirFields -Updates $UpdatesList

# --------------------------------------------------------------------------- install

$RebootRequired = [bool]$PrerequisiteRebootRequired
$SuccessfulUpdates = New-Object System.Collections.Generic.List[string]
$RebootRequiredUpdates = New-Object System.Collections.Generic.List[string]
$FailedUpdates = New-Object System.Collections.Generic.List[string]
$SkipUpdates = $false

if ($InitialAvailableUpdatesCount -gt 0 -and ($InstallAllUpdates -or $ValidatedPackageIDs.Count -gt 0 -or $InstallUpdatesByCategory -or $InstallUpdatesBySeverity -or $InstallUpdatesByType)) {
    Write-Host ""

    $UpdatesToInstall = @($UpdatesList)

    if ($ValidatedPackageIDs.Count -gt 0) {
        $ValidatedPackageIDs | Where-Object { $_ -notin $UpdatesToInstall.PackageID } | ForEach-Object {
            Write-Host -Object "[Warning] The package ID '$_' is not in the list of available updates. It will not be installed."
            $InvalidPackageIDs.Add($_)
        }
        $UpdatesToInstall = @($UpdatesToInstall | Where-Object { $_.PackageID -in $ValidatedPackageIDs })
    }
    else {
        if ($InstallUpdatesByType) { $UpdatesToInstall = @($UpdatesToInstall | Where-Object { $_.Type -eq $InstallUpdatesByType }) }
        if ($InstallUpdatesByCategory) { $UpdatesToInstall = @($UpdatesToInstall | Where-Object { $_.Category -eq $InstallUpdatesByCategory }) }
        if ($InstallUpdatesBySeverity) { $UpdatesToInstall = @($UpdatesToInstall | Where-Object { $_.Severity -match $InstallUpdatesBySeverity }) }
    }

    if ($UpdatesToInstall.Count -eq 0) {
        Write-Host -Object "[Error] No updates match the chosen criteria. No updates will be installed.`n"
        $ExitCode = 1
    }
    else {
        Write-Host -Object "[Info] The following updates will be installed: $(($UpdatesToInstall | Select-Object -ExpandProperty Name) -join ', ').`n"

        try {
            $UpdateCatalog = Get-DellAvailableUpdates -SystemSKU $ComputerSKU -DestinationFolder $DestinationFolderPath -Method "CatalogDownload" -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to retrieve the Dell update catalog for this device, which is needed to verify the downloads. No updates will be installed."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $SkipUpdates = $true
            $ExitCode = 1
        }

        if (-not $SkipUpdates) {
            $ValidSignaturesRegex = @("O=Dell Inc.?", "O=Dell Technologies Inc.?", "O=Intel Corporation", "O=Dell USA L.P.") -join "|"

            foreach ($Update in $UpdatesToInstall) {
                if ($ScriptClock.Elapsed.TotalSeconds -ge $StopStartingInstallsAfterSeconds) {
                    Write-Host -Object "[Warning] The script has run for $([int]$ScriptClock.Elapsed.TotalMinutes) minutes. '$($Update.Name)' and any remaining updates are left for the next run, so the time limit cannot stop an install part-way.`n"
                    $ExitCode = 1
                    break
                }

                $UpdateName = $Update.Name
                $PackageID = $Update.PackageID
                $CatalogEntry = $UpdateCatalog | Where-Object { $_.PackageID -eq $PackageID } | Select-Object -First 1
                $UpdatePath = "$DestinationFolderPath\$PackageID.exe"
                $LogPath = "$DestinationFolderPath\${PackageID}_InstallLog.log"
                $LogContent = $null

                Write-Host "[Info] Working on the '$UpdateName' update."

                try {
                    Invoke-Download -URL $Update.DownloadURL -Path $UpdatePath -UserAgent "Chrome" -Attempts 3 -Overwrite -Quiet -SkipSleep -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Host -Object "[Error] Failed to download '$UpdateName' from '$($Update.DownloadURL)'."
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }

                $Expected = Select-ExpectedHash -Sha256 $CatalogEntry.DownloadHashSha256 -Sha1 $CatalogEntry.DownloadHashSha1 -Md5 $CatalogEntry.DownloadHashMD5
                if (-not $Expected) {
                    Write-Host -Object "[Error] No hash is available in the catalog to verify '$UpdateName' (package $PackageID, SKU $ComputerSKU). It will not be installed.`n"
                    Remove-FileQuietly $UpdatePath
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }

                $DownloadedUpdateHash = (Get-FileHash -Path $UpdatePath -Algorithm $Expected.Algorithm -ErrorAction SilentlyContinue).Hash
                if ($DownloadedUpdateHash -ne $Expected.Hash) {
                    Write-Host -Object "[Error] The $($Expected.Algorithm) hash of '$UpdateName' does not match the expected value. It will not be installed."
                    Write-Host -Object "[Error] Expected: $($Expected.Hash)"
                    Write-Host -Object "[Error] Actual:   $DownloadedUpdateHash`n"
                    Remove-FileQuietly $UpdatePath
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }
                Write-Host -Object "[Info] Verified the update's $($Expected.Algorithm) hash."

                if (-not (Test-InstallerSignature -Path $UpdatePath -SubjectPattern $ValidSignaturesRegex)) {
                    Write-Host -Object "[Error] Expected a Dell or Intel signature. '$UpdateName' will not be installed."
                    Remove-FileQuietly $UpdatePath
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }
                Write-Host -Object "[Info] Verified the update's digital signature."

                $UpdateInstallArguments = "/s /l=`"$LogPath`""
                if ($Update.Type -match "BIOS" -and $BIOSPassword) {
                    Write-Host -Object "[Info] BIOS update: passing the BIOS password to the Dell package (not shown)."
                    $UpdateInstallArguments = "$UpdateInstallArguments /p=`"$BIOSPassword`""
                }

                Write-Host -Object "[Info] Installing the update."
                try {
                    Start-Process -FilePath $UpdatePath -ArgumentList $UpdateInstallArguments -Wait -NoNewWindow -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Host -Object "[Error] Failed to start the installation of '$UpdateName'."
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Remove-FileQuietly $UpdatePath
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }

                if (Test-Path -Path $LogPath) {
                    $LogContent = (Get-Content -Path $LogPath -ErrorAction SilentlyContinue | Where-Object { $_ } | Out-String).Trim()
                }

                if (-not $LogContent) {
                    Write-Host -Object "[Error] The log file for '$UpdateName' was not found or is empty at '$LogPath'. Cannot tell whether it succeeded."
                    Remove-FileQuietly $UpdatePath
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                    continue
                }

                $SuccessfulExitCodes = @("0", "2")

                if ($Update.Type -match "Firmware|BIOS") {
                    $UpdateExitCode = ([regex]::Matches($LogContent, "Exit Code = (?<ExitCode>\d+)") | Select-Object -Last 1).Groups[1].Value
                    $NeedsReboot = ([regex]::Matches($LogContent, "Reboot Required").Count -gt 0)

                    if ($UpdateExitCode -in $SuccessfulExitCodes) {
                        $Succeeded = $true
                    }
                    else {
                        $Succeeded = $false
                        if ($UpdateExitCode -eq "4") {
                            Write-Host -Object "[Error] The BIOS update '$UpdateName' failed: the BIOS password is missing, incorrect or was rejected. Check the BIOSPassword parameter or the bios_password field.`n"
                        }
                        else {
                            Write-Host -Object "[Error] The update failed to install. See '$LogPath'."
                            Write-Host -Object "[Error] Exit Code: $UpdateExitCode"
                            Write-Host -Object "[Error] Reboot Required: $NeedsReboot`n"
                        }
                    }
                }
                else {
                    $UpdateExitCode = ([regex]::Matches($LogContent, "Exit Code set to: (?<UpdateExitCode>\d+)") | Select-Object -Last 1).Groups[1].Value
                    $NameOfExitCode = ([regex]::Matches($LogContent, "Name of Exit Code: (?<NameOfExitCode>[^\n\r]*)") | Select-Object -Last 1).Groups[1].Value
                    $Result = ([regex]::Matches($LogContent, "Result: (?<Result>[^\n\r]*)") | Select-Object -Last 1).Groups[1].Value
                    $NeedsReboot = ($NameOfExitCode -match "REBOOT_REQUIRED" -or $Result -match "REBOOT")
                    $Succeeded = ($UpdateExitCode -in $SuccessfulExitCodes -and $NameOfExitCode -match "SUCCESS|REBOOT_REQUIRED" -and $Result -match "SUCCESS|REBOOT")

                    if (-not $Succeeded) {
                        Write-Host -Object "[Error] The update failed to install. See '$LogPath'."
                        Write-Host -Object "[Error] Exit Code: $UpdateExitCode"
                        Write-Host -Object "[Error] Name of Exit Code: $NameOfExitCode"
                        Write-Host -Object "[Error] Result: $Result`n"
                    }
                }

                if ($Succeeded) {
                    Write-Host -Object "[Info] Successfully installed the update.`n"
                    $SuccessfulUpdates.Add($PackageID)

                    if ($NeedsReboot) {
                        Write-Host -Object "[Info] '$UpdateName' needs a reboot to finish installing.`n"
                        $RebootRequired = $true
                        if (-not $SuspendBitLockerAndRebootIfNeeded) { $RebootRequiredUpdates.Add($PackageID) }
                    }

                    Remove-FileQuietly $LogPath
                }
                else {
                    $FailedUpdates.Add($PackageID)
                    $ExitCode = 1
                }

                Remove-FileQuietly $UpdatePath
            }
        }

        Write-Host -Object "[Info] Finished installing updates.`n"
    }

    $UpdatesList | ForEach-Object {
        if ($_.PackageID -in $RebootRequiredUpdates) { $_.Status = "Installed: Pending Reboot" }
        elseif ($_.PackageID -in $SuccessfulUpdates) { $_.Status = "Installed" }
        elseif ($_.PackageID -in $FailedUpdates) { $_.Status = "Failed to install" }
    }

    $AvailableAfter = ($UpdatesList | Where-Object { $_.Status -notmatch "^Installed" } | Measure-Object).Count
    $InstalledAfter = ($UpdatesList | Where-Object { $_.Status -match "^Installed" } | Measure-Object).Count
    $FailedAfter = ($UpdatesList | Where-Object { $_.Status -eq "Failed to install" } | Measure-Object).Count

    Write-Host -Object "[Info] $InstalledAfter update(s) installed. $FailedAfter update(s) failed. $AvailableAfter update(s) still available.`n"

    if ($InstalledAfter -gt 0) {
        Write-Host -Object "[Info] Installed:"
        ($UpdatesList | Where-Object { $_.PackageID -in $SuccessfulUpdates } | ForEach-Object { "- $($_.Name)" } | Out-String).Trim() | Write-Host
    }

    if ($FailedAfter -gt 0) {
        Write-Host -Object "`n[Error] Failed:"
        ($UpdatesList | Where-Object { $_.PackageID -in $FailedUpdates } | ForEach-Object { "- $($_.Name)" } | Out-String).Trim() | Write-Host
    }
}

if ($InvalidPackageIDs.Count -gt 0) {
    Write-Host -Object "`n[Warning] These package IDs were not valid or not available: $($InvalidPackageIDs -join ', ')"
}

# --------------------------------------------------------------------------- custom fields

Write-FenrirFields -Updates $UpdatesList

# --------------------------------------------------------------------------- reboot

if ($RebootRequired -and $SuspendBitLockerAndRebootIfNeeded) {
    Write-Host ""
    $BitLockerStatus = $null

    try {
        $BitLockerStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Warning] Failed to read the BitLocker status: $($_.Exception.Message)"
        Write-Host -Object "[Warning] Continuing without suspending BitLocker."
    }

    if ($BitLockerStatus -and $BitLockerStatus.VolumeStatus -eq "FullyEncrypted" -and $BitLockerStatus.ProtectionStatus -eq "On") {
        try {
            Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 -ErrorAction Stop | Out-Null
            Write-Host -Object "[Info] Suspended BitLocker on '$env:SystemDrive' for one reboot. It turns back on after the reboot.`n"
        }
        catch {
            Write-Host -Object "[Error] Failed to suspend BitLocker on '$env:SystemDrive': $($_.Exception.Message)`n"
            $ExitCode = 1
        }
    }
    elseif ($BitLockerStatus -and $BitLockerStatus.ProtectionStatus -eq "Off") {
        Write-Host -Object "[Info] BitLocker is already suspended.`n"
    }

    $RebootTime = (Get-Date).AddSeconds(60)
    Write-Host -Object "[Info] Rebooting at $($RebootTime.ToShortDateString()) $($RebootTime.ToShortTimeString())."

    try {
        Start-Process -FilePath "$env:WINDIR\System32\shutdown.exe" -ArgumentList "/r /t 60 /c `"Dell updates need a restart.`"" -NoNewWindow -Wait -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -Object "[Error] Failed to schedule the reboot: $($_.Exception.Message)"
        exit 1
    }
}

if ($RebootRequired -and -not $SuspendBitLockerAndRebootIfNeeded) {
    Write-Host -Object "`n[Warning] A reboot is needed to finish one or more installs, but 'Suspend BitLocker and reboot' was not ticked. Please reboot the device."
}

exit $ExitCode
