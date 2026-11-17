# Pester tests for the summary block the test and lint scripts end with: the
# banner and RESULT bar text, the status from the counts, and the table.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'tools/Write-TestSummary.ps1')

    function Get-SummaryLine {
        # The lines Write-TestSummary prints, from the information stream.
        param($Rows, [int]$Pass, [int]$Fail, [int]$Skip)
        @(Write-TestSummary -Title 'Test-Example.ps1 -BothEditions' -Target 'the example' -Rows $Rows -Pass $Pass -Fail $Fail -Skip $Skip 6>&1 |
                ForEach-Object { "$_" })
    }
}

Describe 'Write-TestSummary' {
    It 'gives <Expected> for fail <Fail> and skip <Skip>' -ForEach @(
        @{ Fail = 0; Skip = 0; Expected = 'PASS' }
        @{ Fail = 0; Skip = 2; Expected = 'PASS WITH SKIPS' }
        @{ Fail = 1; Skip = 2; Expected = 'FAIL' }
    ) {
        Get-TestStatus -Fail $Fail -Skip $Skip | Should -Be $Expected
    }

    It 'prints the banner, target, run, PowerShell version and RESULT bar' {
        $lines = Get-SummaryLine -Rows @([pscustomobject]@{ Edition = 'pwsh'; Result = 'PASS' }) -Pass 3 -Fail 0 -Skip 1
        $lines[0] | Should -Be ''
        $lines[1] | Should -Be ''
        $lines[2] | Should -Match '^#{60,}$'
        $lines[3] | Should -Be '##  Test-Example.ps1 -BothEditions  |  PASS WITH SKIPS  |  Pass 3  Fail 0  Skip 1'
        $lines[4] | Should -Be $lines[2]
        $lines[5] | Should -Be 'Target:  the example'
        $lines[6] | Should -Match '^Run:     \d{4}-\d{2}-\d{2} \d{2}:\d{2}$'
        $lines[7] | Should -Be "PS:      $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
        $lines[-2] | Should -Be '##  RESULT: PASS WITH SKIPS  (Pass 3  Fail 0  Skip 1)'
        $lines[-1] | Should -Be $lines[2]
    }

    It 'leaves out a column that is empty in every row, and keeps it when a row has a value' {
        $clean = @([pscustomobject]@{ Edition = 'pwsh'; Result = 'PASS'; Notes = '' }, [pscustomobject]@{ Edition = 'powershell.exe'; Result = 'PASS'; Notes = '' })
        ((Get-SummaryLine -Rows $clean -Pass 2) -join "`n") | Should -Not -Match 'Notes'
        $clean[1].Result = 'MISSING'; $clean[1].Notes = 'Edition not installed'
        $text = (Get-SummaryLine -Rows $clean -Pass 1 -Fail 1) -join "`n"
        $text | Should -Match 'Notes'
        $text | Should -Match 'Edition not installed'
        $text | Should -Match '##  RESULT: FAIL  \(Pass 1  Fail 1  Skip 0\)'
    }

    It 'prints no table when there are no rows' {
        $lines = Get-SummaryLine -Rows @() -Fail 1
        $lines[8] | Should -Be ''
        $lines[9] | Should -Match '^#{60,}$'
    }
}
