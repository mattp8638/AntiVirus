# name: Restore point now
# description: Creates a System Restore point before making changes.
# category: Maintenance
# platforms: windows
# timeout: 300
# param: Description | Description | string | Before changes (Fenrir) | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS
Get-ComputerRestorePoint | Select-Object -Last 3 | Format-Table SequenceNumber, CreationTime, Description
