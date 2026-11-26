# Pester tests for tools/Build-Module.ps1 and the EntraAccessAudit module it
# builds for the PowerShell Gallery. The module is built in TestDrive and
# imported into this session, so it is tested under whichever edition runs the
# suite.
#
# Run through ..\Test-EntraAccessAudit.ps1, which pins the Pester version and
# can run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Builder = Join-Path $Root 'tools/Build-Module.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json'
    $script:ProfileFixture = Join-Path $PSScriptRoot 'fixtures/westmark.psd1'
    . (Join-Path $Root 'Invoke-EntraAccessAudit.ps1')
    $script:Built = @(& $Builder -OutputPath (Join-Path $TestDrive 'out') 6>$null)[-1].FullName
    $script:Manifest = Join-Path $Built 'EntraAccessAudit.psd1'
    $script:Data = Import-PowerShellDataFile -LiteralPath $Manifest
    Import-Module $Manifest -Force
}

AfterAll {
    Remove-Module EntraAccessAudit -Force -ErrorAction SilentlyContinue
}

Describe 'Module manifest' {
    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $Manifest -ErrorAction Stop } | Should -Not -Throw
    }

    It 'takes its version from $EntraAccessAuditVersion' {
        $Data.ModuleVersion | Should -Be $EntraAccessAuditVersion
    }

    It 'keeps the GUID the Gallery knows the module by' {
        $Data.GUID | Should -Be '052b493b-9421-4baa-8e90-17b36c9b2226'
    }

    It 'takes the author from the copyright line in LICENSE' {
        $m = [regex]::Match([IO.File]::ReadAllText((Join-Path $Root 'LICENSE')), '(?m)^\s*Copyright \d{4} (\S.*?)\s*$')
        $m.Success | Should -BeTrue
        $Data.Author | Should -Be $m.Groups[1].Value
    }

    It 'runs on Windows PowerShell 5.1 and PowerShell 7' {
        $Data.PowerShellVersion | Should -Be '5.1'
        @($Data.CompatiblePSEditions | Sort-Object) | Should -Be @('Core', 'Desktop')
    }

    It 'exports Invoke-EntraAccessAudit and nothing else' {
        @($Data.FunctionsToExport) | Should -Be @('Invoke-EntraAccessAudit')
        @($Data.CmdletsToExport).Count | Should -Be 0
        @($Data.VariablesToExport).Count | Should -Be 0
        @($Data.AliasesToExport).Count | Should -Be 0
        @((Get-Module EntraAccessAudit).ExportedFunctions.Keys) | Should -Be @('Invoke-EntraAccessAudit')
    }

    It 'requires no other module, since a snapshot needs none' {
        $Data.ContainsKey('RequiredModules') | Should -BeFalse
    }

    It 'carries this version''s changelog entry and the project links' {
        $psData = $Data.PrivateData.PSData
        $psData.ReleaseNotes | Should -BeLike "$EntraAccessAuditVersion`: *"
        $psData.ReleaseNotes | Should -Not -Match '\]\('
        $psData.ProjectUri | Should -Be 'https://github.com/riffmillar-itadmin/entra-access-audit'
        $psData.LicenseUri | Should -BeLike 'https://github.com/riffmillar-itadmin/entra-access-audit/*'
        @($psData.Tags) | Should -Contain 'Entra'
        @($psData.Tags | Where-Object { $_ -match '\s' }).Count | Should -Be 0
    }
}

Describe 'Module contents' {
    It 'holds the script, the example thresholds file and the licence' {
        foreach ($name in 'Invoke-EntraAccessAudit.ps1', 'EntraAccessAudit.example.psd1', 'LICENSE', 'EntraAccessAudit.psm1', 'EntraAccessAudit.psd1') {
            Test-Path -LiteralPath (Join-Path $Built $name) | Should -BeTrue -Because $name
        }
        @(Get-ChildItem -LiteralPath $Built -Recurse -File).Count | Should -Be 5
    }

    It 'never holds a local profile, a report or a snapshot' {
        @(Get-ChildItem -LiteralPath $Built -Recurse -File | Where-Object {
                $_.Name -like 'EntraAccessAudit.local*' -or $_.Name -like 'entra-access-audit-*' -or $_.Name -like '*.snapshot.json' }).Count | Should -Be 0
    }

    It 'copies the script byte for byte' {
        $a = [IO.File]::ReadAllBytes((Join-Path $Root 'Invoke-EntraAccessAudit.ps1'))
        $b = [IO.File]::ReadAllBytes((Join-Path $Built 'Invoke-EntraAccessAudit.ps1'))
        [Convert]::ToBase64String($b) | Should -Be ([Convert]::ToBase64String($a))
    }
}

Describe 'Module command' {
    It 'has the same parameters as the script' {
        $script = Get-Command (Join-Path $Root 'Invoke-EntraAccessAudit.ps1')
        $command = Get-Command Invoke-EntraAccessAudit -Module EntraAccessAudit
        @($command.Parameters.Keys | Sort-Object) | Should -Be @($script.Parameters.Keys | Sort-Object)
        foreach ($p in $script.Parameters.Values) {
            $command.Parameters[$p.Name].ParameterType | Should -Be $p.ParameterType -Because $p.Name
        }
    }

    It 'has the script''s help, naming the command instead of the script file' {
        $help = Get-Help Invoke-EntraAccessAudit -Full
        "$($help.Synopsis)".Trim() | Should -BeLike 'Audits who can get into a Microsoft Entra ID tenant*'
        $text = $help | Out-String -Width 200
        $text | Should -Not -Match 'Invoke-EntraAccessAudit\.ps1'
        @($help.Examples.Example).Count | Should -BeGreaterThan 0
        @($help.Parameters.Parameter | ForEach-Object Name) | Should -Contain 'FromSnapshot'
    }
}

Describe 'Running the module' {
    BeforeEach {
        $script:Work = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $Work
        Push-Location -LiteralPath $Work
    }

    AfterEach {
        Pop-Location
    }

    It 'audits a snapshot into .\Reports in the current folder and sets $LASTEXITCODE' {
        $null = Invoke-EntraAccessAudit -FromSnapshot $FixturePath -ProfilePath $ProfileFixture 6>$null
        # The Westmark fixture has failures, so 1.
        $LASTEXITCODE | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $Work 'Reports') -Filter 'entra-access-audit-*').Count | Should -Be 3
        Test-Path -LiteralPath (Join-Path $Built 'Reports') | Should -BeFalse -Because 'nothing is written in the module folder'
    }

    It 'passes -PassThru through, one result per check' {
        $results = @(Invoke-EntraAccessAudit -FromSnapshot $FixturePath -ProfilePath $ProfileFixture -OutputPath (Join-Path $Work 'out') -PassThru 6>$null)
        $results.Count | Should -Be $AuditChecks.Count
        @($results | Where-Object Status -eq 'Fail').Count | Should -BeGreaterThan 0
    }

    It 'exits 2 through the module when it cannot start' {
        $null = Invoke-EntraAccessAudit -FromSnapshot (Join-Path $Work 'missing.json') -OutputPath (Join-Path $Work 'out') 6>$null
        $LASTEXITCODE | Should -Be 2
    }
}

Describe 'Building the module' {
    It 'replaces an earlier build' {
        $out = Join-Path $TestDrive 'again'
        $first = @(& $Builder -OutputPath $out 6>$null)[-1].FullName
        Set-Content -LiteralPath (Join-Path $first 'stale.txt') -Value 'x'
        $second = @(& $Builder -OutputPath $out 6>$null)[-1].FullName
        $second | Should -Be $first
        Test-Path -LiteralPath (Join-Path $second 'stale.txt') | Should -BeFalse
    }

    It 'refuses to replace a folder that is not an earlier build' {
        $out = Join-Path $TestDrive 'other'
        $null = New-Item -ItemType Directory -Path (Join-Path $out 'EntraAccessAudit')
        Set-Content -LiteralPath (Join-Path $out 'EntraAccessAudit/keep.txt') -Value 'x'
        { & $Builder -OutputPath $out 6>$null } | Should -Throw "*doesn't hold an earlier build*"
        Test-Path -LiteralPath (Join-Path $out 'EntraAccessAudit/keep.txt') | Should -BeTrue
    }

    It 'stops when the changelog has no row for the version' {
        . $Builder
        $readme = Join-Path $TestDrive 'README.md'
        Set-Content -LiteralPath $readme -Value '| 0.1.0 | 2026-11-10 | First. |'
        { Get-ReleaseNote -ReadmePath $readme -Version '9.9.9' } | Should -Throw '*no row for 9.9.9*'
        Get-ReleaseNote -ReadmePath $readme -Version '0.1.0' | Should -Be 'First.'
    }

    It 'stops when LICENSE has no copyright line' {
        . $Builder
        $license = Join-Path $TestDrive 'LICENSE'
        Set-Content -LiteralPath $license -Value 'No line here.'
        { Get-CopyrightHolder $license } | Should -Throw '*copyright line*'
    }

    It 'documents publishing by the manifest file, not the folder' {
        $manifestPath = [regex]::Escape('out\EntraAccessAudit\EntraAccessAudit.psd1')
        foreach ($doc in 'tools/Build-Module.ps1', 'README.md') {
            $text = [IO.File]::ReadAllText((Join-Path $Root $doc))
            $text | Should -Match "Publish-PSResource -Path \.\\$manifestPath " -Because $doc
            $text | Should -Not -Match '(?m)^\s*Publish-Module ' -Because "$doc shouldn't offer Publish-Module, which fails to pack with a newer .NET SDK"
        }
    }

    It 'documents installing from the Gallery by the module''s name, as released' {
        $text = [IO.File]::ReadAllText((Join-Path $Root 'README.md'))
        $text | Should -Match "(?m)^Install-Module $($Data.RootModule -replace '\.psm1$') -Scope CurrentUser\s*$"
        $text | Should -Match '(?m)^Invoke-EntraAccessAudit\s*$'
        $text | Should -Not -Match '(?i)from 1\.0\.0 (the audit|it) is'
    }

    It 'keeps the built module out of git' {
        [IO.File]::ReadAllLines((Join-Path $Root '.gitignore')) | Should -Contain 'out/'
    }
}
