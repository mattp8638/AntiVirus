# name: System summary
# description: Computer name, model, serial, OS build, uptime, memory and CPU in one view.
# category: Inventory
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
[pscustomobject]@{
  Computer = $env:COMPUTERNAME; Model = "$($cs.Manufacturer) $($cs.Model)"; Serial = $bios.SerialNumber
  OS = "$($os.Caption) $($os.Version)"; Uptime = ((Get-Date) - $os.LastBootUpTime).ToString('d\.hh\:mm')
  MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1); CPU = $cpu.Name.Trim(); Domain = $cs.Domain
} | Format-List
