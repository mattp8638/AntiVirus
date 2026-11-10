# name: Battery report
# description: Battery design and full-charge capacity on laptops, to spot worn batteries.
# category: Diagnostics
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$b = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue
$d = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue
if (-not $b) { 'No battery.'; return }
$health = [math]::Round(100 * $b[0].FullChargedCapacity / $d[0].DesignedCapacity)
"Design capacity: $($d[0].DesignedCapacity) mWh  Full charge: $($b[0].FullChargedCapacity) mWh  Health: $health%"
"FENRIR-FIELD battery_health=$health"
