# name: Browser extensions (Chrome and Edge)
# description: Extensions installed in Chrome and Edge for every user, by ID and name.
# category: Security
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
Get-ChildItem 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*\*\manifest.json','C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*\*\manifest.json' -ErrorAction SilentlyContinue | ForEach-Object {
  $m = Get-Content $_.FullName -Raw | ConvertFrom-Json
  [pscustomobject]@{ Browser = if ($_.FullName -match 'Edge') { 'Edge' } else { 'Chrome' }; Id = $_.Directory.Parent.Name; Name = $m.name; Version = $m.version }
} | Sort-Object Browser, Name -Unique | Format-Table -AutoSize | Out-String -Width 250
