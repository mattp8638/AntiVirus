# name: Microsoft Defender status
# description: Defender's protection state, signature age and recent detections.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-MpComputerStatus | Format-List AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge
Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 10 InitialDetectionTime, ThreatID, Resources | Format-List
