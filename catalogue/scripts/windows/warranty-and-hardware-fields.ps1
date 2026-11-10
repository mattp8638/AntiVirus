# name: Warranty and hardware fields
# description: Records the serial number and model into device custom fields named serial_number and model, if you created them.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$bios = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem
"Serial: $($bios.SerialNumber)  Model: $($cs.Manufacturer) $($cs.Model)"
"FENRIR-FIELD serial_number=$($bios.SerialNumber.Trim())"
"FENRIR-FIELD model=$(($cs.Manufacturer + ' ' + $cs.Model).Trim())"
