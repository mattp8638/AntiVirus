# name: Restart with a warning
# description: Warns signed-in users and restarts after a delay (minutes).
# category: Maintenance
# platforms: windows
# timeout: 300
# param: Minutes | Minutes before restart | number | 10 | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
shutdown.exe /r /t ([int]$Minutes * 60) /c "Your IT team will restart this computer in $Minutes minutes. Please save your work." /d p:4:1
"Restart scheduled in $Minutes minutes."
