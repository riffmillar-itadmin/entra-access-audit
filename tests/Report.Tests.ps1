# Pester tests for the reports, the exit code, the thresholds file and the
# script run end to end on the Westmark fixture.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-EntraAccessAudit.ps1'
    . $ScriptPath
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json'
    $script:ProfileFixture = Join-Path $PSScriptRoot 'fixtures/westmark.psd1'
    $script:Westmark = Get-AuditProfile -Path $ProfileFixture
    # The edition running the tests, to run the script in a child process.
    $script:Exe = (Get-Process -Id $PID).Path
}

Describe 'Write-AuditReport' {
    BeforeAll {
        $script:Snapshot = Read-Snapshot -Path $FixturePath
        $script:Results = @(Invoke-AuditCheck -Snapshot $Snapshot -AuditProfile $Westmark)
        $script:Out = Join-Path $TestDrive 'reports'
        $script:Files = @(Write-AuditReport -Results $Results -Snapshot $Snapshot -AuditProfile $Westmark -Path $Out -WarningVariable script:ReportWarnings -WarningAction SilentlyContinue)
    }

    It 'writes the reports without a warning' {
        # Regression: PowerShell 7.7 warned that -NoTypeInformation is obsolete.
        @($ReportWarnings) | Should -HaveCount 0
    }

    It 'writes the HTML, CSV and JSON reports, named by collection time' {
        @($Files | ForEach-Object { Split-Path $_ -Leaf }) | Should -Be @(
            'entra-access-audit-20261101T120000Z.html', 'entra-access-audit-20261101T120000Z.csv', 'entra-access-audit-20261101T120000Z.json')
        foreach ($f in $Files) { Test-Path -LiteralPath $f | Should -BeTrue }
    }

    It 'writes one CSV row per finding, and one for each check without findings' {
        $rows = @(Import-Csv -LiteralPath $Files[1])
        $expected = 0
        foreach ($r in $Results) { $expected += [math]::Max(1, @($r.Findings).Count) }
        $rows.Count | Should -Be $expected
        @($rows | Where-Object CheckId -eq 'STALE-01').Subject | Should -Be 'jo.park@westmark.example'
        @($rows | Where-Object CheckId -eq 'CA-02').Subject | Should -Be ''
    }

    It 'writes JSON with the counts, dataset status and every result' {
        $text = [IO.File]::ReadAllText($Files[2])
        # Checked in the text: PowerShell 7's ConvertFrom-Json would turn it into a DateTime.
        $text | Should -Match '"CollectedAt":\s*"2026-11-01T12:00:00Z"'
        $json = $text | ConvertFrom-Json
        $json.Version | Should -Be $EntraAccessAuditVersion
        $json.Counts.Fail | Should -Be @($Results | Where-Object Status -eq 'Fail').Count
        $json.Datasets.Users.Status | Should -Be 'Collected'
        @($json.Results).Count | Should -Be $AuditChecks.Count
        @($json.Thresholds.BreakGlassAccounts) | Should -Be @('bg.one@westmark.example', 'bg.two@westmark.example')
    }

    It 'writes an HTML page with every check and no script or external file' {
        $html = [IO.File]::ReadAllText($Files[0])
        foreach ($c in $AuditChecks) { $html | Should -Match ([regex]::Escape("<b>$($c.Id)</b>")) }
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '(src|href)="https?:'
        $html | Should -Match 'prefers-color-scheme: dark'
    }

    It 'escapes names in the HTML' {
        $s = Read-Snapshot -Path $FixturePath
        @($s.Datasets.Applications.Items | Where-Object displayName -eq 'Westmark Payroll Connector')[0].displayName = '<img src=x onerror=alert(1)>'
        $r = @(Invoke-AuditCheck -Snapshot $s -AuditProfile $Westmark)
        $html = ConvertTo-AuditHtml -Results $r -Snapshot $s -AuditProfile $Westmark
        $html | Should -Not -Match '<img'
        $html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
    }
}

Describe 'Get-AuditExitCode' {
    BeforeAll {
        function Get-Code {
            param($Snapshot)
            Get-AuditExitCode -Results @(Invoke-AuditCheck -Snapshot $Snapshot -AuditProfile $Westmark) -Snapshot $Snapshot
        }
    }

    It 'is 1 when a check fails' {
        Get-Code (Read-Snapshot -Path $FixturePath) | Should -Be 1
    }

    It 'is 2 when a dataset was denied, even though licensing gaps are not' {
        $s = Read-Snapshot -Path $FixturePath
        $s.Datasets.RoleEligibility.Status = 'NotLicensed'
        Get-Code $s | Should -Be 1
        $s.Datasets.ConditionalAccess.Status = 'Denied'
        Get-Code $s | Should -Be 2
    }

    It 'is 2 when a check errors' {
        $s = Read-Snapshot -Path $FixturePath
        $s.Datasets.Applications.Items[0].passwordCredentials[0].endDateTime = 'not a date'
        Get-Code $s | Should -Be 2
    }

    It 'is 0 with nothing failed' {
        $results = @([pscustomobject]@{ Status = 'Pass' }, [pscustomobject]@{ Status = 'Warn' }, [pscustomobject]@{ Status = 'Skipped' })
        Get-AuditExitCode -Results $results -Snapshot (Read-Snapshot -Path $FixturePath) | Should -Be 0
    }
}

Describe 'Get-AuditProfile' {
    It 'matches the defaults with no file, and with the example file' {
        $defaults = Get-AuditProfile
        $example = Get-AuditProfile -Path (Join-Path $Root 'EntraAccessAudit.example.psd1')
        foreach ($k in $defaults.Keys) { @($example[$k]) | Should -Be @($defaults[$k]) -Because $k }
        @($example.Keys) | Should -Be @($defaults.Keys)
    }

    It 'stops on a setting it does not know' {
        $f = Join-Path $TestDrive 'typo.psd1'
        Set-Content -LiteralPath $f -Value "@{ StaleDay = 30 }"
        { Get-AuditProfile -Path $f } | Should -Throw "*unknown setting 'StaleDay'*"
    }

    It 'stops on a number that is not a whole number' {
        $f = Join-Path $TestDrive 'bad.psd1'
        Set-Content -LiteralPath $f -Value "@{ StaleDays = 'ninety' }"
        { Get-AuditProfile -Path $f } | Should -Throw '*whole number*'
    }

    It 'stops when MinGlobalAdmins is above MaxGlobalAdmins' {
        $f = Join-Path $TestDrive 'minmax.psd1'
        Set-Content -LiteralPath $f -Value "@{ MinGlobalAdmins = 5; MaxGlobalAdmins = 3 }"
        { Get-AuditProfile -Path $f } | Should -Throw '*MinGlobalAdmins*'
    }

    It 'keeps a one-item list as a list' {
        , $Westmark.BreakGlassAccounts | Should -BeOfType [object[]]
        $f = Join-Path $TestDrive 'one.psd1'
        Set-Content -LiteralPath $f -Value "@{ AcceptedApps = 'Westmark Backup' }"
        $p = Get-AuditProfile -Path $f
        , $p.AcceptedApps | Should -BeOfType [object[]]
        $p.AcceptedApps.Count | Should -Be 1
    }
}

Describe 'Read-Snapshot' {
    It 'refuses a snapshot from another schema version' {
        $f = Join-Path $TestDrive 'old.json'
        Set-Content -LiteralPath $f -Value '{"SchemaVersion":0,"Datasets":{}}'
        { Read-Snapshot -Path $f } | Should -Throw '*schema version*'
    }

    It 'refuses a file that does not exist' {
        { Read-Snapshot -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
    }
}

Describe 'The script, run on the Westmark fixture' {
    It 'writes the reports and exits 1 for the fixture''s failures' {
        $out = Join-Path $TestDrive 'run'
        $log = & $Exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -FromSnapshot $FixturePath -ProfilePath $ProfileFixture -OutputPath $out *>&1
        $LASTEXITCODE | Should -Be 1 -Because ($log -join "`n")
        @(Get-ChildItem -LiteralPath $out -File).Count | Should -Be 3
        ($log -join "`n") | Should -Match 'Fail 15  Warn 12  Pass 2  Skipped 0  Error 0'
    }

    It 'exits 2 when it cannot start' {
        $null = & $Exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -FromSnapshot (Join-Path $TestDrive 'missing.json') -OutputPath (Join-Path $TestDrive 'none') *>&1
        $LASTEXITCODE | Should -Be 2
    }
}
