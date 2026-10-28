$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\service\src\SystemProfileScript.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$names = @('disks', 'volumes', 'startup', 'printers', 'monitors', 'shares', 'auditPolicy')
$assignments = $ast.FindAll({ param($node)
  $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
  $node.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and
  $node.Left.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
  $node.Left.Expression.VariablePath.UserPath -eq 'profile' -and $names -contains $node.Left.Member.Value
}, $true)
if ($assignments.Count -ne $names.Count) { throw 'Not all profile collections were tested' }
# Execute the real assignments with a deterministic Section, avoiding any WMI,
# registry, encryption-key or Active Directory queries on the test runner.
function Section([scriptblock]$Block) {
  for ($i = 0; $i -lt $script:itemCount; $i++) { [ordered]@{ name = "Item $i" } }
}
foreach ($script:itemCount in @(0, 1, 2)) {
  $profile = [ordered]@{}
  foreach ($assignment in $assignments) { Invoke-Expression $assignment.Extent.Text }
  $roundTrip = ([ordered]@{ profile = $profile } | ConvertTo-Json -Depth 8 -Compress) | ConvertFrom-Json
  foreach ($name in $names) {
    if ($profile[$name] -isnot [array] -or $profile[$name].Count -ne $script:itemCount) { throw "$name lost its collection shape" }
    if ($roundTrip.profile.$name -isnot [array] -or $roundTrip.profile.$name.Count -ne $script:itemCount) { throw "$name changed shape in JSON" }
  }
}
Write-Host 'System profile collections retain arrays with zero, one and two items.'
