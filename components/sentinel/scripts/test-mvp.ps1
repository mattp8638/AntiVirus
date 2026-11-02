param(
    [switch]$SkipFrontend,
    [switch]$SkipBackend
)

$ErrorActionPreference = "Stop"

Write-Host "Sentinel / Fenrir focused MVP validation" -ForegroundColor Cyan

if (-not $env:SENTINEL_SECRET_KEY) {
    $env:SENTINEL_SECRET_KEY = "dev-only-change-me-before-production"
    Write-Host "SENTINEL_SECRET_KEY was not set. Using a development-only value for tests." -ForegroundColor Yellow
}

if (-not $SkipBackend) {
    Write-Host ""
    Write-Host "[1/2] Installing backend development requirements and running pytest..." -ForegroundColor Cyan
    python -m pip install -r requirements-dev.txt
    pytest -q
}

if (-not $SkipFrontend) {
    Write-Host ""
    Write-Host "[2/2] Installing frontend dependencies and running Vite build..." -ForegroundColor Cyan
    npm install
    npm run build
}

Write-Host ""
Write-Host "Focused MVP validation completed." -ForegroundColor Green
Write-Host "Next manual checks: docs/MVP_TEST_CHECKLIST.md" -ForegroundColor Green
