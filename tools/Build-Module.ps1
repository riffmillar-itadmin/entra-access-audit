<#
.SYNOPSIS
    Builds the EntraAccessAudit module, the form the audit takes on the
    PowerShell Gallery.

.DESCRIPTION
    Copies the audit script, the example thresholds file and the licence into
    -OutputPath\EntraAccessAudit, and writes a manifest and a root module beside
    them.

    The root module has one command, Invoke-EntraAccessAudit, with the script's
    own parameters and help, generated from the script, so the two can't drift.
    It runs the script beside it and leaves the script's exit code in
    $LASTEXITCODE.

    The manifest takes its version from $EntraAccessAuditVersion in the script,
    the author from the copyright line in LICENSE, and the release notes from
    that version's row in the README changelog. A build stops if any of them is
    missing.

    The module doesn't require Microsoft.Graph.Authentication, because
    -FromSnapshot needs no Graph module. The script loads it when it signs in,
    and says how to install it if it is missing.

    The script runs from the repository exactly as before; the module is only
    another way to install it.

    To publish, give Publish-PSResource the manifest file, not the module
    folder. Given a folder, it reads the first .psd1 there by name, which is
    EntraAccessAudit.example.psd1, and stops with "No author was provided".

.PARAMETER OutputPath
    The folder to build in. The module goes in an EntraAccessAudit folder
    inside it, replacing an earlier build. Defaults to out under the repository,
    which git ignores.

.EXAMPLE
    .\tools\Build-Module.ps1
    Publish-PSResource -Path .\out\EntraAccessAudit\EntraAccessAudit.psd1 -Repository PSGallery -ApiKey $key
    Build, then publish to the PowerShell Gallery.

.NOTES
    Part of entra-access-audit. Windows PowerShell 5.1 or PowerShell 7, on any
    operating system.
#>

[CmdletBinding()]
param(
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleName = 'EntraAccessAudit'
# The Gallery knows the module by this GUID. Never change it.
$ModuleGuid = '052b493b-9421-4baa-8e90-17b36c9b2226'
$ProjectUri = 'https://github.com/riffmillar-itadmin/entra-access-audit'

# The scripts the module runs, and anything the generated command needs on top
# of the script's own attributes.
$Commands = [ordered]@{
    'Invoke-EntraAccessAudit' = ''
}

function Get-ModuleVersion {
    # $EntraAccessAuditVersion, read from the script's text rather than run.
    param([string]$ScriptPath)
    $m = [regex]::Match([IO.File]::ReadAllText($ScriptPath), "(?m)^\`$EntraAccessAuditVersion = '(\d+\.\d+\.\d+)'")
    if (-not $m.Success) { throw "Can't find `$EntraAccessAuditVersion in $ScriptPath." }
    $m.Groups[1].Value
}

function Get-CopyrightHolder {
    # The name on LICENSE's copyright line, such as 'Copyright 2026 A. Name'.
    param([string]$LicensePath)
    $m = [regex]::Match([IO.File]::ReadAllText($LicensePath), '(?m)^\s*Copyright (\d{4}) (\S.*?)\s*$')
    if (-not $m.Success) { throw "Can't find a copyright line in $LicensePath." }
    [pscustomobject]@{ Year = $m.Groups[1].Value; Name = $m.Groups[2].Value }
}

function Get-ReleaseNote {
    # This version's row of the README changelog, as plain text.
    param([string]$ReadmePath, [string]$Version)
    $pattern = '^\| ' + [regex]::Escape($Version) + ' \| \d{4}-\d{2}-\d{2} \| (.+) \|\s*$'
    foreach ($line in [IO.File]::ReadAllLines($ReadmePath)) {
        $m = [regex]::Match($line, $pattern)
        if ($m.Success) { return ($m.Groups[1].Value -replace '`', '' -replace '\[([^\]]+)\]\([^)]+\)', '$1') }
    }
    throw "The README changelog has no row for $Version."
}

function ConvertTo-ModuleFunction {
    # A function that runs one script, with that script's help, attributes and
    # parameters. Script names in the help become command names.
    param([string]$ScriptPath, [string]$Name, [string]$ExtraAttribute)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) { throw "$ScriptPath doesn't parse: $($errors[0].Message)" }
    $help = @($tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.StartsWith('<#') })
    if ($help.Count -eq 0) { throw "$ScriptPath has no comment-based help." }
    $helpText = $help[0].Text
    $names = ($Commands.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $helpText = $helpText -replace "pwsh -File \./($names)\.ps1", '$1'
    $helpText = $helpText -replace "(?:\.[\\/])?\b($names)\.ps1", '$1'
    $block = $ast.ParamBlock
    if (-not $block) { throw "$ScriptPath has no param block." }
    $text = $ast.Extent.Text
    $start = $block.Extent.StartOffset
    foreach ($a in @($block.Attributes)) { $start = [math]::Min($start, $a.Extent.StartOffset) }
    $paramText = $text.Substring($start - $ast.Extent.StartOffset, $block.Extent.EndOffset - $start)
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("function $Name {")
    $lines.Add($helpText)
    if ($ExtraAttribute) { $lines.Add($ExtraAttribute) }
    $lines.Add($paramText)
    $lines.Add('')
    $lines.Add("    & (Join-Path `$PSScriptRoot '$Name.ps1') @PSBoundParameters")
    $lines.Add('}')
    $lines -join "`n"
}

function Get-ModuleFile {
    # The repository files that go in the module, as Source and the path in it.
    param([string]$Root)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in @($Commands.Keys | ForEach-Object { "$_.ps1" }) + 'EntraAccessAudit.example.psd1', 'LICENSE') {
        $files.Add([pscustomobject]@{ Source = Join-Path $Root $name; Target = $name })
    }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f.Source -PathType Leaf)) { throw "Can't find $($f.Source)." }
    }
    $files.ToArray()
}

# Dot-sourced (as the tests do): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

$root = Split-Path $PSScriptRoot -Parent
if (-not $OutputPath) { $OutputPath = Join-Path $root 'out' }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$moduleRoot = Join-Path $OutputPath $ModuleName

$version = Get-ModuleVersion (Join-Path $root 'Invoke-EntraAccessAudit.ps1')
$holder = Get-CopyrightHolder (Join-Path $root 'LICENSE')
$notes = Get-ReleaseNote -ReadmePath (Join-Path $root 'README.md') -Version $version
$files = @(Get-ModuleFile $root)

# An earlier build is replaced, but only a folder that holds this module, so a
# wrong -OutputPath can't remove anything else.
if (Test-Path -LiteralPath $moduleRoot) {
    if (-not (Test-Path -LiteralPath (Join-Path $moduleRoot "$ModuleName.psd1"))) {
        throw "$moduleRoot exists and doesn't hold an earlier build of $ModuleName, so it isn't replaced."
    }
    Remove-Item -LiteralPath $moduleRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $moduleRoot -Force
foreach ($f in $files) { Copy-Item -LiteralPath $f.Source -Destination (Join-Path $moduleRoot $f.Target) }

# With a BOM, so Windows PowerShell 5.1 reads any non-ASCII text as UTF-8.
$utf8 = [Text.UTF8Encoding]::new($true)
$module = [Collections.Generic.List[string]]::new()
$module.Add("# $ModuleName $version, built by tools/Build-Module.ps1 from the script")
$module.Add('# beside this file. The command runs the script; change the script, not this.')
$module.Add('')
foreach ($name in $Commands.Keys) {
    $module.Add((ConvertTo-ModuleFunction -ScriptPath (Join-Path $root "$name.ps1") -Name $name -ExtraAttribute $Commands[$name]))
    $module.Add('')
}
$module.Add("Export-ModuleMember -Function $(@($Commands.Keys) -join ', ')")
[IO.File]::WriteAllText((Join-Path $moduleRoot "$ModuleName.psm1"), (($module -join "`n") + "`n"), $utf8)

$manifest = @{
    Path                 = Join-Path $moduleRoot "$ModuleName.psd1"
    RootModule           = "$ModuleName.psm1"
    ModuleVersion        = $version
    Guid                 = $ModuleGuid
    Author               = $holder.Name
    CompanyName          = $holder.Name
    Copyright            = "Copyright $($holder.Year) $($holder.Name). Apache License 2.0."
    Description          = 'A read-only audit of who can get into a Microsoft Entra ID tenant and how: privileged roles and PIM, stale and guest accounts, MFA coverage, app credentials and permissions, service accounts, Conditional Access gaps and tenant-wide settings. Reads Microsoft Graph with GET requests and .Read. scopes only, and writes HTML, CSV and JSON reports. Signing in needs Microsoft.Graph.Authentication; evaluating a saved snapshot needs nothing else.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @($Commands.Keys)
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    Tags                 = @('Entra', 'EntraID', 'AzureAD', 'MicrosoftGraph', 'Security', 'Audit', 'IAM', 'ConditionalAccess', 'PIM', 'MFA', 'PSEdition_Desktop', 'PSEdition_Core')
    ProjectUri           = $ProjectUri
    LicenseUri           = "$ProjectUri/blob/main/LICENSE"
    ReleaseNotes         = "$version`: $notes Changelog: $ProjectUri#changelog"
}
New-ModuleManifest @manifest
# New-ModuleManifest writes UTF-16 on Windows PowerShell 5.1, and leaves
# trailing spaces; keep one encoding and no trailing spaces.
$text = [IO.File]::ReadAllText($manifest.Path) -replace '[ \t]+(\r?\n)', '$1'
# PowerShell 7 comments out an empty export list, which then means everything.
# State each one, so the module exports its function and nothing more.
foreach ($key in 'CmdletsToExport', 'VariablesToExport', 'AliasesToExport') {
    $text = $text -replace "(?m)^#?[ \t]*$key = [^\r\n]*", "$key = @()"
}
[IO.File]::WriteAllText($manifest.Path, $text, $utf8)

Write-Host "Built $ModuleName $version in $moduleRoot" -ForegroundColor Cyan
Write-Host "To publish: Publish-PSResource -Path '$($manifest.Path)' -Repository PSGallery -ApiKey <key>"
Get-Item -LiteralPath $moduleRoot
