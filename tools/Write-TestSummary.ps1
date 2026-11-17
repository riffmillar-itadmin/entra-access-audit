<#
.SYNOPSIS
    Prints the summary block that ends every test and lint run.

.DESCRIPTION
    Dot-sourced by Test-EntraAccessAudit.ps1 and Test-EntraAccessAuditLint.ps1,
    in the same layout as the JobSweep and endpoint scan suites. After two blank
    lines, Write-TestSummary prints a full-width '#' banner with the script name,
    the status and the pass, fail and skip counts; the target, run time and
    PowerShell version; the table; and a RESULT bar that matches the banner.

    The '##' lines are green when everything passed, dark yellow when
    something was skipped, and red when anything failed. Every line is plain
    text, so the whole block copies cleanly out of a console or a CI log. A
    table column that is empty in every row, such as Notes on a clean run, is
    left out.
#>

function Get-TestStatus {
    # PASS, PASS WITH SKIPS or FAIL from the counts. Any failure wins.
    param([int]$Fail, [int]$Skip)
    if ($Fail -gt 0) { return 'FAIL' }
    if ($Skip -gt 0) { return 'PASS WITH SKIPS' }
    return 'PASS'
}

function Write-TestSummary {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
        [int]$Pass,
        [int]$Fail,
        [int]$Skip
    )
    $status = Get-TestStatus -Fail $Fail -Skip $Skip
    $colour = switch ($status) { 'FAIL' { 'Red' } 'PASS WITH SKIPS' { 'DarkYellow' } default { 'Green' } }
    $width = 100
    try { $width = [Math]::Max(60, [Math]::Min(160, $Host.UI.RawUI.WindowSize.Width - 1)) }
    catch { Write-Verbose "Console width unknown, so the banner is $width wide." }
    $bar = '#' * $width
    $counts = "Pass $Pass  Fail $Fail  Skip $Skip"

    $table = ''
    $rowList = @($Rows | Where-Object { $null -ne $_ })
    if ($rowList.Count -gt 0) {
        $columns = @($rowList[0].PSObject.Properties.Name | Where-Object {
                $name = $_
                @($rowList | Where-Object { "$($_.$name)" -ne '' }).Count -gt 0
            })
        # A wide line so the notes column isn't cut to the window.
        $table = ($rowList | Select-Object -Property $columns | Format-Table -AutoSize -Wrap | Out-String -Width 400).Trim()
    }

    $lines = @('', '', $bar, "##  $Title  |  $status  |  $counts", $bar)
    $lines += "Target:  $Target"
    $lines += "Run:     $((Get-Date).ToString('yyyy-MM-dd HH:mm'))"
    $lines += "PS:      $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    if ($table) { $lines += ''; $lines += $table }
    $lines += @('', $bar, "##  RESULT: $status  ($counts)", $bar)
    foreach ($line in $lines) {
        if ($line -like '##*') { Write-Host $line -ForegroundColor $colour } else { Write-Host $line }
    }
}
