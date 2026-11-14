<#
.SYNOPSIS
    Runs the Pester suite, exactly as CI does, and ends with a summary table.

.DESCRIPTION
    Runs tests\*.Tests.ps1 with Pester, pinned to the version the suite was
    written against. Installs that version for the current user if it is
    missing: from the PowerShell Gallery, then from nuget.org (checked against a
    pinned SHA-256), then from -PackagePath, whichever works first.

    The suite needs no tenant, no network and no Graph module: every check runs
    against the fictional Westmark tenant in tests\fixtures, and the collector
    runs against a fake Microsoft Graph.

    -BothEditions runs the suite under Windows PowerShell 5.1 and PowerShell 7,
    each in its own process. A pass on one says nothing about the other, so an
    edition that can't be found fails the run rather than reporting half a
    result.

    Ends with a summary block that is easy to find and copy: a coloured banner
    with the pass, fail and skip counts, the target, run time and PowerShell
    version, a table of each edition's counts, and a RESULT bar. A run that
    stops with an error still prints the summary, counted as a failure. Exit
    code 0 only when every test passed and none was skipped or left unrun: a
    test that can't apply must say so, not pass.

.PARAMETER BothEditions
    Run the suite under powershell.exe (5.1) and pwsh (7). Use it before every
    commit.

.PARAMETER PackagePath
    A folder holding Pester.6.2.0.nupkg, used if Pester is missing and can't be
    downloaded.

.PARAMETER ResultPath
    Where a run writes its counts as JSON. -BothEditions sets this for each
    edition so the summary table can show them; you never need to.

.EXAMPLE
    .\Test-EntraAccessAudit.ps1 -BothEditions
    pwsh -File ./Test-EntraAccessAudit.ps1          # one edition, any OS
    .\Test-EntraAccessAudit.ps1 -PackagePath D:\packages   # no internet access
#>

[CmdletBinding()]
param(
    [switch]$BothEditions,
    [string]$PackagePath,
    [string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '6.2.0'
$fixtures = 'westmark.snapshot.json + westmark.psd1 (fictional tenant); fake Graph'
$target = "tests\*.Tests.ps1 with Pester $version on the fictional Westmark tenant and a fake Microsoft Graph"
. (Join-Path $PSScriptRoot 'tools/Write-TestSummary.ps1')

function Get-ResultRow {
    # One row of the summary table. Counts that weren't produced show as '-'.
    param([string]$Edition, $Counts, [string]$Result, [string]$Notes)
    $row = [ordered]@{ Suite = 'Pester'; Edition = $Edition }
    foreach ($name in 'Version', 'Fixtures', 'Passed', 'Failed', 'Skipped', 'NotRun') {
        $row[$name] = if ($Counts) { $Counts.$name } else { '-' }
    }
    $row.Result = $Result
    $row.Notes = $Notes
    [pscustomobject]$row
}

function Write-Summary {
    # Adds up the rows and prints the summary block. A row that didn't pass
    # with no failed test behind it (a missing edition, a run that stopped, a
    # skipped or unrun test, a file that didn't load) counts as one failure,
    # so the banner can never be green when the run failed.
    param($Rows)
    # Counts that weren't produced are '-', which count as 0.
    $num = { param($Value) if ($Value -is [ValueType]) { [int]$Value } else { 0 } }
    $pass = 0; $fail = 0; $skip = 0
    foreach ($row in @($Rows)) {
        $pass += & $num $row.Passed
        $skip += & $num $row.Skipped
        $failedTests = & $num $row.Failed
        $fail += $failedTests
        if ($row.Result -ne 'PASS' -and $failedTests -eq 0) { $fail++ }
    }
    Write-TestSummary -Title 'Test-EntraAccessAudit' -Target $target -Rows $Rows -Pass $pass -Fail $fail -Skip $skip
}

if ($BothEditions) {
    $rows = foreach ($exe in 'powershell.exe', 'pwsh') {
        Write-Host "`n==== $exe ====" -ForegroundColor Cyan
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            Write-Host "$exe not found, so this edition was not tested." -ForegroundColor Red
            Get-ResultRow -Edition $exe -Result 'MISSING' -Notes 'Edition not installed'
            continue
        }
        $out = Join-Path ([IO.Path]::GetTempPath()) ("eaa-result-{0}.json" -f [guid]::NewGuid().ToString('N'))
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
        Get-ResultRow -Edition $exe -Counts $r -Result $result -Notes $(if ($r) { $r.Notes } else { 'The run stopped before writing its counts.' })
    }
    Write-Summary @($rows)
    if (@($rows | Where-Object Result -ne 'PASS').Count -gt 0) { exit 1 }
    exit 0
}

try {
    if ($PackagePath) { $PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path }
    if (-not (Get-Module -ListAvailable Pester | Where-Object { "$($_.Version)" -eq $version })) {
        . (Join-Path $PSScriptRoot 'tools/Install-PinnedModule.ps1')
        Install-PinnedModule -Name Pester -Version $version -PackagePath $PackagePath `
            -GalleryParameters @{ SkipPublisherCheck = $true; AllowClobber = $true }
    }
    Import-Module Pester -RequiredVersion $version

    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $PSScriptRoot 'tests'
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Normal'
    $result = Invoke-Pester -Configuration $config
} catch {
    # A run that stops still reports, as a failure, with the reason.
    Write-Host "The test run stopped: $($_.Exception.Message)" -ForegroundColor Red
    $row = Get-ResultRow -Edition "$($PSVersionTable.PSEdition)" -Result 'FAIL (error)' -Notes "The run stopped: $($_.Exception.Message)"
    $row.Version = "$($PSVersionTable.PSVersion)"
    if ($ResultPath) { [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false)) }
    else { Write-Summary @($row) }
    exit 1
}

$notes = [Collections.Generic.List[string]]::new()
if ($result.FailedCount -gt 0) { $notes.Add("Failed: $(@($result.Failed | ForEach-Object { $_.ExpandedPath }) -join '; ')") }
if ($result.SkippedCount -gt 0) { $notes.Add('A skipped test fails the run.') }
if ($result.NotRunCount -gt 0) { $notes.Add('A test that did not run fails the run.') }
if ($result.PassedCount -eq 0) { $notes.Add('No test passed.') }
if (@($result.Containers | Where-Object { $_.Result -eq 'Failed' -and $_.FailedCount -eq 0 }).Count -gt 0) { $notes.Add('A test file failed to load.') }
$failed = [int]($notes.Count -gt 0)
if ($notes.Count -eq 0) { $notes.Add('All tests passed.') }

$counts = [pscustomobject]@{
    Version  = "$($PSVersionTable.PSVersion)"
    Fixtures = $fixtures
    Passed   = $result.PassedCount
    Failed   = $result.FailedCount
    Skipped  = $result.SkippedCount
    NotRun   = $result.NotRunCount
}
$row = Get-ResultRow -Edition "$($PSVersionTable.PSEdition)" -Counts $counts -Result $(if ($failed) { 'FAIL' } else { 'PASS' }) -Notes ($notes -join ' ')
if ($ResultPath) {
    [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
} else {
    Write-Summary @($row)
}
exit $failed
