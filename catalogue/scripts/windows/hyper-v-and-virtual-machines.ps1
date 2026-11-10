# name: Hyper-V and virtual machines
# description: Virtual machines on this host and their state (Hyper-V hosts only).
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
if (Get-Command Get-VM -ErrorAction SilentlyContinue) { Get-VM | Select-Object Name, State, CPUUsage, @{n='MemoryGB';e={[math]::Round($_.MemoryAssigned/1GB,1)}}, Uptime | Format-Table -AutoSize } else { 'Hyper-V is not installed.' }
