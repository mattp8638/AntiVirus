# name: Pending reboot check
# description: Whether Windows is waiting for a restart, and why.
# category: Updates
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) { $reasons += 'File renames' }
if ($reasons) { "Restart pending: $($reasons -join ', ')" } else { 'No restart pending.' }
