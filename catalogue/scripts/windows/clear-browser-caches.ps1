# name: Clear browser caches
# description: Deletes Chrome, Edge and Firefox cache folders for every user (not passwords, cookies or history). Browsers should be closed.
# category: Maintenance
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$freed = 0
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
  $u = $_.FullName
  $paths = @("$u\AppData\Local\Google\Chrome\User Data\*\Cache", "$u\AppData\Local\Microsoft\Edge\User Data\*\Cache", "$u\AppData\Local\Mozilla\Firefox\Profiles\*\cache2")
  foreach ($p in $paths) { Get-Item $p -ErrorAction SilentlyContinue | ForEach-Object {
    $freed += (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Remove-Item "$($_.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue } }
}
"Freed about {0:N0} MB" -f ($freed/1MB)
