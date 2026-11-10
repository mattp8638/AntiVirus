# name: Largest folders on C:
# description: The 20 largest top-level folders under a path, to see what is filling a disk.
# category: Disk
# platforms: windows
# timeout: 1800
# param: Path | Folder | string | C:\ | optional
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
$root = if ($Path) { $Path } else { 'C:\' }
Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  $size = (Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
  [pscustomobject]@{ Folder = $_.FullName; SizeGB = [math]::Round($size/1GB, 2) }
} | Sort-Object SizeGB -Descending | Select-Object -First 20 | Format-Table -AutoSize
