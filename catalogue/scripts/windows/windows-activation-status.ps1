# name: Windows activation status
# description: Whether Windows is activated and the licence channel.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" | Select-Object Name, LicenseStatus, @{n='Channel';e={$_.ProductKeyChannel}} | Format-List
