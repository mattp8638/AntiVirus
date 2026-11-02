<#
Target bootstrap script to run on the deployment machine (Windows PowerShell).
- Creates a virtual environment in `.venv` at package root
- Installs `backend/requirements.txt` and any service-specific `requirements.txt` under `backend/**`
- Does not assume internet restrictions; may take time on first run

Usage on target (from extracted package root):
    powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$venvPath = Join-Path (Get-Location) ".venv"
if (-Not (Test-Path $venvPath)) {
    Write-Host "Creating Python virtual environment at $venvPath"
    python -m venv $venvPath
} else {
    Write-Host "Virtual environment already exists at $venvPath"
}

$pythonExe = Join-Path $venvPath "Scripts\python.exe"
if (-Not (Test-Path $pythonExe)) {
    Write-Error "Python executable not found in venv. Ensure Python is installed and available as 'python'."
    exit 1
}

# Upgrade pip
& $pythonExe -m pip install --upgrade pip setuptools wheel

# Install top-level backend requirements
$rootReq = Join-Path (Join-Path (Get-Location) 'backend') 'requirements.txt'
if (Test-Path $rootReq) {
    Write-Host "Installing backend requirements: $rootReq"
    & $pythonExe -m pip install -r $rootReq
}

# Install any service-specific requirements under backend/**
$serviceReqs = Get-ChildItem -Path (Join-Path (Get-Location) 'backend') -Recurse -Filter 'requirements.txt' | Where-Object { $_.FullName -ne $rootReq }
foreach ($req in $serviceReqs) {
    Write-Host "Installing service requirements: $($req.FullName)"
    & $pythonExe -m pip install -r $req.FullName
}

Write-Host "Bootstrap complete. Start services with run-backend.bat or run backend\run_services.py using the .venv python."