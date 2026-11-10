# name: Remote access tools present
# description: Looks for common remote access tools (AnyDesk, TeamViewer, ScreenConnect and others) in services and installed programs.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$names = 'AnyDesk','TeamViewer','ScreenConnect','ConnectWise','Splashtop','LogMeIn','RustDesk','Atera','NinjaRMM','Kaseya','RemotePC','UltraVNC','TightVNC','RealVNC','Chrome Remote Desktop'
$pattern = ($names | ForEach-Object { [regex]::Escape($_) }) -join '|'
Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -match $pattern -or $_.PathName -match $pattern } | Select-Object Name, DisplayName, State, PathName | Format-Table -AutoSize | Out-String -Width 300
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $pattern } | Select-Object DisplayName, DisplayVersion, InstallLocation | Format-Table -AutoSize
