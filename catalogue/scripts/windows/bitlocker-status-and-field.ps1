# name: BitLocker status and field
# description: Encryption status of every drive, and records it in a bitlocker_on field if you created one.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
$vols | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod | Format-Table -AutoSize
$os = $vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' }
"FENRIR-FIELD bitlocker_on=$([bool]($os -and $os.ProtectionStatus -eq 'On'))"
