# name: Defender exclusions
# description: Folders, files, processes and extensions excluded from Microsoft Defender: attackers add these.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$p = Get-MpPreference
'Paths:'; $p.ExclusionPath; ''; 'Processes:'; $p.ExclusionProcess; ''; 'Extensions:'; $p.ExclusionExtension
