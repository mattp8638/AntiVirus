# name: Empty the Recycle Bin
# description: Empties the Recycle Bin on every drive (changes files).
# category: Maintenance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
'Recycle Bin emptied.'
