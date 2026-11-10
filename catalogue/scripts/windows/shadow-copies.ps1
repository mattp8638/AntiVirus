# name: Shadow copies
# description: Volume Shadow Copies (restore points for files) present on this device.
# category: Disk
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
vssadmin list shadows | Select-String 'Shadow Copy Volume|Creation Time|Original Volume' | ForEach-Object { $_.Line.Trim() }
