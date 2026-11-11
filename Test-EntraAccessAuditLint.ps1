<#
.SYNOPSIS
    Lints the repository with PSScriptAnalyzer, exactly as CI does, and ends
    with a summary table.

.DESCRIPTION
    Runs PSScriptAnalyzer over every script in the repository with
    PSScriptAnalyzerSettings.psd1. Errors, warnings and parse errors fail (exit
    1); Information findings are reported but do not. Finding no PowerShell
    files to lint fails too, since that would be a silent pass.

    -BothEditions lints under Windows PowerShell 5.1 and PowerShell 7, each in
    its own process. An edition that can't be found fails the run.

    Pinned to the analyzer version the settings were tuned against, because a
    newer analyzer can add rules and fail the build with no code change. Installs
    that version for the current user if it is missing: from the PowerShell
    Gallery, then from the analyzer's GitHub release (checked against a pinned
    SHA-256), then from -PackagePath, whichever works first.

    Inside GitHub Actions each finding becomes an annotation on its file and
    line; anywhere else it prints file:line [rule] message. Either way the run
    ends with a table of the edition, files linted, findings and result.

.PARAMETER BothEditions
    Lint under powershell.exe (5.1) and pwsh (7), with one table for both. Use
    it before every commit.

.PARAMETER PackagePath
    A folder holding PSScriptAnalyzer.1.25.0.nupkg, used if the analyzer is
    missing and can't be downloaded.

.PARAMETER ResultPath
    Where a run writes its counts as JSON. -BothEditions sets this for each
    edition so the summary table can show them; you never need to.

.EXAMPLE
    .\Test-EntraAccessAuditLint.ps1 -BothEditions
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-EntraAccessAuditLint.ps1   # Windows PowerShell 5.1 only
#>

[CmdletBinding()]
param(
    [switch]$BothEditions,
    [string]$PackagePath,
    [string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '1.25.0'

function Write-SummaryTable {
    param($Rows)
    Write-Host "`n==== lint summary ====" -ForegroundColor Cyan
    $Rows | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Write-Host
}

if ($BothEditions) {
    $rows = foreach ($exe in 'powershell.exe', 'pwsh') {
        Write-Host "`n==== $exe ====" -ForegroundColor Cyan
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            Write-Host "$exe not found, so this edition was not linted." -ForegroundColor Red
            [pscustomobject][ordered]@{ Edition = $exe; Version = '-'; Analyzer = '-'; Files = '-'; Findings = '-'; Blocking = '-'; Result = 'MISSING' }
            continue
        }
        $out = Join-Path ([IO.Path]::GetTempPath()) ("eaa-lint-{0}.json" -f [guid]::NewGuid().ToString('N'))
        $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-ResultPath', $out)
        if ($PackagePath) { $childArgs += '-PackagePath', $PackagePath }
        & $exe @childArgs | Out-Host
        $code = $LASTEXITCODE
        $r = $null
        if (Test-Path -LiteralPath $out) {
            try { $r = [IO.File]::ReadAllText($out) | ConvertFrom-Json }
            catch { Write-Host "Couldn't read the $exe result file: $($_.Exception.Message)" -ForegroundColor Red }
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
        [pscustomobject][ordered]@{
            Edition  = $exe
            Version  = $(if ($r) { $r.Version } else { '-' })
            Analyzer = $(if ($r) { $r.Analyzer } else { '-' })
            Files    = $(if ($r) { $r.Files } else { '-' })
            Findings = $(if ($r) { $r.Findings } else { '-' })
            Blocking = $(if ($r) { $r.Blocking } else { '-' })
            Result   = $(if ($code -eq 0 -and $r) { 'PASS' } elseif ($r) { "FAIL (exit $code)" } else { "FAIL (exit $code, no counts written)" })
        }
    }
    Write-SummaryTable $rows
    if (@($rows | Where-Object Result -ne 'PASS').Count -gt 0) { exit 1 }
    exit 0
}

if (-not (Get-Module -ListAvailable PSScriptAnalyzer | Where-Object Version -eq $version)) {
    . (Join-Path $PSScriptRoot 'tools/Install-PinnedModule.ps1')
    Install-PinnedModule -Name PSScriptAnalyzer -Version $version -PackagePath $PackagePath
}
Import-Module PSScriptAnalyzer -RequiredVersion $version

$settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
$findings = @(Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -Settings $settings)
# Filtered by extension rather than -Include, which Windows PowerShell 5.1
# ignores with -LiteralPath and so counted every file.
$files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
$inActions = $env:GITHUB_ACTIONS -eq 'true'

Push-Location $PSScriptRoot
try {
    foreach ($f in $findings) {
        # repo-relative with forward slashes, so GitHub links the annotation to the file
        $file = (Resolve-Path -Relative $f.ScriptPath) -replace '^\.[\\/]', '' -replace '\\', '/'
        if ($inActions) {
            $level = if ("$($f.Severity)" -eq 'Information') { 'notice' } else { 'error' }
            Write-Output "::$level file=$file,line=$($f.Line)::[$($f.RuleName)] $($f.Message)"
        } else {
            Write-Output "$($file):$($f.Line) [$($f.Severity)] [$($f.RuleName)] $($f.Message)"
        }
    }
} finally { Pop-Location }

$blocking = @($findings | Where-Object { "$($_.Severity)" -in 'Error', 'Warning', 'ParseError' })
$failed = [int]($blocking.Count -gt 0 -or $files.Count -eq 0)
$row = [pscustomobject][ordered]@{
    Edition  = "$($PSVersionTable.PSEdition)"
    Version  = "$($PSVersionTable.PSVersion)"
    Analyzer = $version
    Files    = $files.Count
    Findings = $findings.Count
    Blocking = $blocking.Count
    Result   = $(if ($files.Count -eq 0) { 'FAIL (no files linted)' } elseif ($failed) { 'FAIL' } else { 'PASS' })
}
if ($ResultPath) {
    [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
} else {
    Write-SummaryTable @($row)
}
exit $failed
