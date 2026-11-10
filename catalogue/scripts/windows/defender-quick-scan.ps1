# name: Defender quick scan
# description: Runs a Microsoft Defender quick scan and shows what it found.
# category: Security
# platforms: windows
# timeout: 3600
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Start-MpScan -ScanType QuickScan
Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-2) } | Format-List
