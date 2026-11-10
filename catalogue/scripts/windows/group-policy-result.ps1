# name: Group Policy result
# description: Applied computer and user Group Policy objects (summary).
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
gpresult /r /scope computer | Out-String
