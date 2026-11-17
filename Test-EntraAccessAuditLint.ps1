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
    ends with a summary block that is easy to find and copy: a coloured banner
    with the pass, fail and skip counts (one per edition linted), the target,
    run time and PowerShell version, a table of files, findings and result per
    edition, and a RESULT bar. A run that stops with an error still prints the
    summary, counted as a failure.

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
$target = "Every .ps1, .psm1 and .psd1 in the repository, with PSScriptAnalyzer $version and PSScriptAnalyzerSettings.psd1"
. (Join-Path $PSScriptRoot 'tools/Write-TestSummary.ps1')

function Get-LintRow {
    # One row of the summary table. Counts that weren't produced show as '-'.
    param([string]$Edition, $Counts, [string]$Result, [string]$Notes)
    $row = [ordered]@{ Suite = 'Lint'; Edition = $Edition }
    foreach ($name in 'Version', 'Analyzer', 'Files', 'Findings', 'Blocking') {
        $row[$name] = if ($Counts) { $Counts.$name } else { '-' }
    }
    $row.Result = $Result
    $row.Notes = $Notes
    [pscustomobject]$row
}

function Write-Summary {
    # Each edition linted is one pass or one failure.
    param($Rows, [string]$Title = 'Test-EntraAccessAuditLint.ps1')
    $pass = @($Rows | Where-Object { $_.Result -eq 'PASS' }).Count
    $fail = @($Rows).Count - $pass
    Write-TestSummary -Title $Title -Target $target -Rows $Rows -Pass $pass -Fail $fail -Skip 0
}

if ($BothEditions) {
    $rows = foreach ($exe in 'powershell.exe', 'pwsh') {
        Write-Host "`n==== $exe ====" -ForegroundColor Cyan
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            Write-Host "$exe not found, so this edition was not linted." -ForegroundColor Red
            Get-LintRow -Edition $exe -Result 'MISSING' -Notes 'Edition not installed'
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
        $result = if ($code -eq 0 -and $r) { 'PASS' } elseif ($r) { "FAIL (exit $code)" } else { "FAIL (exit $code, no counts written)" }
        Get-LintRow -Edition $exe -Counts $r -Result $result -Notes $(if ($r) { $r.Notes } else { 'The run stopped before writing its counts.' })
    }
    Write-Summary @($rows) 'Test-EntraAccessAuditLint.ps1 -BothEditions'
    if (@($rows | Where-Object Result -ne 'PASS').Count -gt 0) { exit 1 }
    exit 0
}

try {
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
} catch {
    # A run that stops still reports, as a failure, with the reason.
    Write-Host "The lint run stopped: $($_.Exception.Message)" -ForegroundColor Red
    $row = Get-LintRow -Edition "$($PSVersionTable.PSEdition)" -Result 'FAIL (error)' -Notes "The run stopped: $($_.Exception.Message)"
    $row.Version = "$($PSVersionTable.PSVersion)"
    if ($ResultPath) { [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false)) }
    else { Write-Summary @($row) }
    exit 1
}

$blocking = @($findings | Where-Object { "$($_.Severity)" -in 'Error', 'Warning', 'ParseError' })
$failed = [int]($blocking.Count -gt 0 -or $files.Count -eq 0)
$counts = [pscustomobject]@{
    Version  = "$($PSVersionTable.PSVersion)"
    Analyzer = $version
    Files    = $files.Count
    Findings = $findings.Count
    Blocking = $blocking.Count
}
$notes = if ($files.Count -eq 0) { 'No PowerShell files found to lint.' }
    elseif ($blocking.Count -gt 0) { "Blocking: $(@($blocking | ForEach-Object { $_.RuleName } | Sort-Object -Unique) -join ', ')" }
    elseif ($findings.Count -gt 0) { 'Information findings only; they do not fail the run.' }
    else { '' }
$row = Get-LintRow -Edition "$($PSVersionTable.PSEdition)" -Counts $counts -Result $(if ($files.Count -eq 0) { 'FAIL (no files linted)' } elseif ($failed) { 'FAIL' } else { 'PASS' }) -Notes $notes
if ($ResultPath) {
    [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
} else {
    Write-Summary @($row)
}
exit $failed
