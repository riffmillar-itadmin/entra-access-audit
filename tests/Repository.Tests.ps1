# Pester tests that keep the documentation in step with the code: the README's
# check table, the version notes and the changelog, and the files that must
# never be tracked.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-EntraAccessAudit.ps1'
    . $ScriptPath
    $script:Readme = [IO.File]::ReadAllLines((Join-Path $Root 'README.md'))
}

Describe 'README check table' {
    BeforeAll {
        # | ROLE-01 | Privileged roles | High | Title | Reports |
        $script:Rows = @(foreach ($line in $Readme) {
                $m = [regex]::Match($line, '^\| ([A-Z]+-\d{2}) \| ([^|]+) \| (High|Medium|Low) \| ([^|]+) \|')
                if ($m.Success) {
                    [pscustomobject]@{ Id = $m.Groups[1].Value; Area = $m.Groups[2].Value.Trim(); Severity = $m.Groups[3].Value; Title = $m.Groups[4].Value.Trim() }
                }
            })
    }

    It 'has one row per check, in the same order' {
        @($Rows | ForEach-Object Id) | Should -Be @($AuditChecks | ForEach-Object Id)
    }

    It 'gives each check its area, severity and title' {
        foreach ($c in $AuditChecks) {
            $row = @($Rows | Where-Object Id -eq $c.Id)[0]
            $row.Area | Should -Be $c.Area -Because $c.Id
            $row.Severity | Should -Be $c.Severity -Because $c.Id
            $row.Title | Should -Be $c.Title -Because $c.Id
        }
    }

    It 'gives the number of checks in the changelog' {
        ($Readme -join "`n") | Should -Match "with $($AuditChecks.Count) checks"
    }
}

Describe 'Thresholds table' {
    It 'names every setting the script knows' {
        $text = $Readme -join "`n"
        foreach ($k in $DefaultAuditProfile.Keys) { $text | Should -Match ([regex]::Escape("``$k``")) -Because $k }
    }
}

Describe 'Versions' {
    BeforeAll {
        $script:Notes = @([regex]::Matches([IO.File]::ReadAllText($ScriptPath), '(?m)^\s{4}(\d+\.\d+\.\d+)\s+\d{4}-\d{2}-\d{2}\s') | ForEach-Object { $_.Groups[1].Value })
        $script:Changelog = @($Readme | ForEach-Object { [regex]::Match($_, '^\| (\d+\.\d+\.\d+) \| \d{4}-\d{2}-\d{2} \|') } | Where-Object Success | ForEach-Object { $_.Groups[1].Value })
    }

    It 'ends the version notes with $EntraAccessAuditVersion' {
        $Notes.Count | Should -BeGreaterThan 0
        $Notes[-1] | Should -Be $EntraAccessAuditVersion
    }

    It 'starts the README changelog with $EntraAccessAuditVersion' {
        $Changelog.Count | Should -BeGreaterThan 0
        $Changelog[0] | Should -Be $EntraAccessAuditVersion
    }

    It 'lists the same releases in the version notes and the changelog' {
        @($Notes | Sort-Object { [version]$_ }) | Should -Be @($Changelog | Sort-Object { [version]$_ })
    }

    It 'gives the fixture the current snapshot schema' {
        (Read-Snapshot -Path (Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json')).SchemaVersion | Should -Be $SnapshotSchemaVersion
    }
}

Describe 'Files' {
    It 'keeps every script and data file in ASCII, so 5.1 reads them the same way' {
        # Filtered by extension: Windows PowerShell 5.1 ignores -Include with -LiteralPath.
        $files = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object {
                $_.Extension -in '.ps1', '.psd1', '.json' -and $_.FullName -notmatch '[\\/]\.git[\\/]' })
        # Every script, data file and fixture, so a broken filter can't pass vacuously.
        $expected = 0
        foreach ($filter in '*.ps1', '*.psd1', '*.json') { $expected += @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $filter).Count }
        $files.Count | Should -Be $expected
        $files.Count | Should -BeGreaterThan 10
        foreach ($f in $files) {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because $f.Name
        }
    }

    It 'ignores local profiles, reports and real snapshots, but not the fixtures' {
        $ignore = [IO.File]::ReadAllText((Join-Path $Root '.gitignore'))
        foreach ($pattern in 'EntraAccessAudit.local*.psd1', '*.local*.md', 'Reports/', 'entra-access-audit-*', '*.snapshot.json', '!tests/fixtures/*.snapshot.json') {
            $ignore | Should -Match ([regex]::Escape($pattern)) -Because $pattern
        }
    }

    It 'uses only fictional IDs in the fixture, apart from Microsoft''s well-known ones' {
        $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json'))
        $known = @($PrivilegedRoles.Keys) + @($GraphAppId, 'f2ef992c-3afb-46b9-b7cf-a126ee74c451', '00000000-0000-0000-0000-000000000004')
        $guids = @([regex]::Matches($text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object Value | Sort-Object -Unique)
        $guids.Count | Should -BeGreaterThan 0
        foreach ($g in $guids) {
            ($g -like '00000000-0000-4000-8000-*' -or $known -contains $g) | Should -BeTrue -Because $g
        }
        @([regex]::Matches($text, '[\w.#-]@([\w-]+(?:\.[\w-]+)+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique) | Should -Be @('westmark.example')
    }
}
