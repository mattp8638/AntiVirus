# name: Outlook profile and OST sizes
# description: Size of Outlook data files for each user.
# category: Applications
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Outlook\*.ost','C:\Users\*\Documents\Outlook Files\*.pst' -ErrorAction SilentlyContinue |
  Select-Object FullName, @{n='SizeGB';e={[math]::Round($_.Length/1GB,2)}}, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
