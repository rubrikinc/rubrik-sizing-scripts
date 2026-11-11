<#
.SYNOPSIS
  Dumps column-relevant facts from a sizing PowerShell script as JSON, using the PowerShell parser.
.DESCRIPTION
  Facts: row constructors ([PSCustomObject]@{} / [ordered]@{}), member additions (.Add("k"),
  ["k"]=, Add-Member), helper functions that add fixed members, and Export-Csv sites.
  Consumed by build_columns.py. Does not execute the script.
#>
param([Parameter(Mandatory)][string]$Path)
$AstNs = 'System.Management.Automation.Language'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors) { $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; exit 1 }

function Get-Fn($n) {
  $p = $n.Parent
  while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
  if ($p) { $p.Name } else { '' }
}
function Get-Text($e) {
  if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $e.Value }
  return $e.Extent.Text
}
function Test-Dynamic($text) { return $text -match '\$' }
# Extents ("start-end" offsets) of the if/switch/try/loop statements enclosing $node.
# Whether a column is conditional is decided later, relative to its row constructor.
function Get-Ctx($node) {
  $out = @()
  $p = $node.Parent
  while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) {
    if ($p -is [System.Management.Automation.Language.IfStatementAst] -or
        $p -is [System.Management.Automation.Language.SwitchStatementAst] -or
        $p -is [System.Management.Automation.Language.TryStatementAst] -or
        $p -is [System.Management.Automation.Language.ForEachStatementAst] -or
        $p -is [System.Management.Automation.Language.ForStatementAst] -or
        $p -is [System.Management.Automation.Language.WhileStatementAst]) {
      $out += "$($p.Extent.StartOffset)-$($p.Extent.EndOffset)"
    }
    $p = $p.Parent
  }
  return ,$out
}

$facts = New-Object System.Collections.ArrayList

# Row constructors: any [PSCustomObject]@{...} or [ordered]@{...}
$converts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ConvertExpressionAst] -and $n.Child -is [System.Management.Automation.Language.HashtableAst] }, $true)
foreach ($c in $converts) {
  $how = $c.Type.TypeName.Name
  if ($how -notmatch '(?i)^(PSCustomObject|ordered)$') { continue }
  $var = ''
  $p = $c.Parent
  if ($p -is [System.Management.Automation.Language.CommandExpressionAst] -and $p.Parent -is [System.Management.Automation.Language.AssignmentStatementAst]) { $var = $p.Parent.Left.Extent.Text }
  $keys = @($c.Child.KeyValuePairs | ForEach-Object { Get-Text $_.Item1 })
  [void]$facts.Add([pscustomobject]@{ kind = 'obj'; var = $var; fn = (Get-Fn $c); line = $c.Extent.StartLineNumber; how = $how; keys = $keys; ctx = (Get-Ctx $c) })
}

# Member additions
$invokes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
foreach ($i in $invokes) {
  if ($i.Member.Extent.Text -ne 'Add' -or $i.Arguments.Count -lt 2) { continue }
  if (-not ($i.Expression -is [System.Management.Automation.Language.VariableExpressionAst])) { continue }
  $k = Get-Text $i.Arguments[0]
  [void]$facts.Add([pscustomobject]@{ kind = 'add'; target = $i.Expression.Extent.Text; name = $k; dynamic = (Test-Dynamic $k); line = $i.Extent.StartLineNumber; fn = (Get-Fn $i); ctx = (Get-Ctx $i) })
}
$idx = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.IndexExpressionAst] }, $true)
foreach ($a in $idx) {
  $l = $a.Left
  if (-not ($l.Target -is [System.Management.Automation.Language.VariableExpressionAst])) { continue }
  $k = Get-Text $l.Index
  [void]$facts.Add([pscustomobject]@{ kind = 'index'; target = $l.Target.Extent.Text; name = $k; dynamic = (Test-Dynamic $k); line = $a.Extent.StartLineNumber; fn = (Get-Fn $a); ctx = (Get-Ctx $a) })
}

# Commands
$cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($c in $cmds) {
  $name = $c.GetCommandName()
  if (-not $name) { continue }
  $els = $c.CommandElements
  function Get-Param($pat) {
    for ($i = 1; $i -lt $els.Count; $i++) {
      $e = $els[$i]
      if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -match $pat) {
        if ($e.Argument) { return $e.Argument }
        if ($i + 1 -lt $els.Count) { return $els[$i + 1] }
      }
    }
    return $null
  }
  if ($name -eq 'Add-Member') {
    $n = Get-Param '^(?i)(Name|NotePropertyName)$'
    $t = Get-Param '^(?i)InputObject$'
    $target = $null
    if ($t) { $target = $t.Extent.Text }
    else {
      $pl = $c.Parent
      if ($pl -is [System.Management.Automation.Language.PipelineAst] -and $pl.PipelineElements.Count -gt 1 -and $pl.PipelineElements[1] -eq $c) { $target = $pl.PipelineElements[0].Extent.Text }
    }
    $nm = if ($n) { Get-Text $n } else { $null }
    [void]$facts.Add([pscustomobject]@{ kind = 'addmember'; target = $target; name = $nm; dynamic = ($nm -and (Test-Dynamic $nm)); line = $c.Extent.StartLineNumber; fn = (Get-Fn $c); ctx = (Get-Ctx $c) })
  }
  elseif ($name -match '^(?i)Export-Csv$') {
    $pl = $c.Parent; $src = $null
    if ($pl -is [System.Management.Automation.Language.PipelineAst] -and $pl.PipelineElements[0] -ne $c) { $src = $pl.PipelineElements[0].Extent.Text }
    $p = Get-Param '^(?i)Path$'
    [void]$facts.Add([pscustomobject]@{ kind = 'export'; source = $src; path = $(if ($p) { $p.Extent.Text }); line = $c.Extent.StartLineNumber; fn = (Get-Fn $c) })
  }
  elseif ($name -match '^(?i)(Add-BackupColumnsToRow)$') {
    $r = Get-Param '^(?i)Row$'
    [void]$facts.Add([pscustomobject]@{ kind = 'helper'; helper = $name; target = $(if ($r) { $r.Extent.Text }); line = $c.Extent.StartLineNumber; fn = (Get-Fn $c); ctx = (Get-Ctx $c) })
  }
}
$facts | ConvertTo-Json -Depth 6 -Compress
