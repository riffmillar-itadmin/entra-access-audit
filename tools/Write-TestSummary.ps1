<#
.SYNOPSIS
    Prints the summary block that ends every test and lint run.

.DESCRIPTION
    Dot-sourced by Test-EntraAccessAudit.ps1 and Test-EntraAccessAuditLint.ps1.
    Write-TestSummary prints two blank lines, then a full-width '#' banner
    with the script name, the status and the pass, fail and skip counts. The
    target, run time and PowerShell version follow, then the table, then a
    RESULT bar in the same colour as the banner.

    The banner is green when everything passed, dark yellow when something was
    skipped, and red when anything failed. Every line is plain text, so the
    whole block copies cleanly out of a console or a CI log.
#>

function Write-TestSummary {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
        [int]$Pass,
        [int]$Fail,
        [int]$Skip
    )
    $width = 78
    $rule = '#' * $width
    $colour = if ($Fail) { 'Red' } elseif ($Skip) { 'DarkYellow' } else { 'DarkGreen' }
    $status = if ($Fail) { "FAILED ($Fail failing)" } elseif ($Skip) { "PASSED WITH SKIPS ($Skip skipped)" } else { 'ALL PASSED' }
    $counts = "Pass $Pass   Fail $Fail   Skip $Skip"
    $bar = @{ ForegroundColor = 'White'; BackgroundColor = $colour }

    Write-Host ''
    Write-Host ''
    Write-Host $rule @bar
    Write-Host ('##  SUMMARY: {0}' -f $Title).PadRight($width) @bar
    Write-Host ('##  {0}  |  {1}' -f $status, $counts).PadRight($width) @bar
    Write-Host $rule @bar
    Write-Host "Target:  $Target"
    Write-Host "Run:     $((Get-Date).ToString('yyyy-MM-dd HH:mm'))   PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    Write-Host ''
    # A wide line so the notes column isn't cut to the window.
    Write-Host (@($Rows) | Format-Table -AutoSize -Wrap | Out-String -Width 300).Trim()
    Write-Host ''
    Write-Host ('##  RESULT: {0}  |  {1}' -f $status, $counts).PadRight($width) @bar
    Write-Host $rule @bar
    Write-Host ''
}
