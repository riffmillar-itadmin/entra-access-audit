# Pester tests for the Power BI project in powerbi\. Power BI Desktop is what
# opens it, so these check what can be checked without it: the files parse,
# every field a visual or filter uses exists in the model, the model reads the
# fields the audit writes to its JSON report, and nothing local is in the files.
#
# Run through ..\Test-EntraAccessAudit.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeDiscovery {
    $discoveryRoot = Split-Path $PSScriptRoot -Parent
    # Desktop leaves its own settings in .pbi\localSettings.json; git ignores them.
    $script:JsonFiles = @(Get-ChildItem -LiteralPath (Join-Path $discoveryRoot 'powerbi') -Recurse -File -Force |
        Where-Object { $_.Extension -in '.json', '.pbir', '.pbism', '.pbip', '.platform' -and $_.Name -ne 'localSettings.json' } |
        ForEach-Object {
            $name = $_.FullName.Substring($discoveryRoot.Length + 1)
            $doc = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            # Desktop writes .pbip, .pbir, .pbism and its layout and editor
            # settings without a $schema. Report definition files always have one.
            $needsSchema = [bool]$doc.PSObject.Properties['$schema'] -or $name -match '[\\/]definition[\\/]'
            @{ Path = $_.FullName; Name = $name; NeedsSchema = $needsSchema }
        })
    $script:SchemaFiles = @($JsonFiles | Where-Object { $_.NeedsSchema })
}

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Project = Join-Path $Root 'powerbi'
    $script:Model = Join-Path $Project 'EntraAccessAudit.SemanticModel/definition'
    $script:Report = Join-Path $Project 'EntraAccessAudit.Report/definition'
    . (Join-Path $Root 'Invoke-EntraAccessAudit.ps1')

    function ConvertFrom-TmdlName {
        # 'Fail checks' -> Fail checks; 'it''s' -> it's
        param([string]$Name)
        $Name = $Name.Trim()
        if ($Name.StartsWith("'")) { return $Name.Substring(1, $Name.Length - 2).Replace("''", "'") }
        $Name
    }

    function Get-ModelTable {
        # Each table file: its name, column names and measure names.
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $Model 'tables') -Filter '*.tmdl') {
            $lines = [IO.File]::ReadAllLines($file.FullName)
            $name = ConvertFrom-TmdlName (@($lines | Where-Object { $_ -match '^table ' })[0] -replace '^table ', '')
            [pscustomobject]@{
                Name     = $name
                File     = $file.FullName
                Text     = [IO.File]::ReadAllText($file.FullName)
                Columns  = @($lines | Where-Object { $_ -match '^\tcolumn ' } | ForEach-Object { ConvertFrom-TmdlName ($_ -replace '^\tcolumn ', '') })
                Measures = @($lines | Where-Object { $_ -match '^\tmeasure ' } | ForEach-Object { ConvertFrom-TmdlName (($_ -replace '^\tmeasure ', '') -replace '\s*=.*$', '') })
            }
        }
    }

    function Get-FieldReference {
        # Every Column and Measure reference in a report JSON object, as
        # Kind / Entity / Property. Filters name their table through an alias in
        # From, so the aliases are carried down.
        param($Node, [hashtable]$Alias = @{})
        if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }
        if ($Node -is [Collections.IEnumerable]) {
            foreach ($item in $Node) { Get-FieldReference $item $Alias }
            return
        }
        $props = @($Node.PSObject.Properties | ForEach-Object { $_.Name })
        if ($props -contains 'From' -and $props -contains 'Where') {
            $Alias = $Alias.Clone()
            foreach ($f in @($Node.From)) { $Alias[$f.Name] = $f.Entity }
        }
        foreach ($kind in 'Column', 'Measure') {
            if ($props -contains $kind) {
                $ref = $Node.$kind.Expression.SourceRef
                $entity = if ($ref.PSObject.Properties['Entity']) { $ref.Entity } else { $Alias[$ref.Source] }
                [pscustomobject]@{ Kind = $kind; Entity = $entity; Property = $Node.$kind.Property }
            }
        }
        foreach ($p in $Node.PSObject.Properties) { Get-FieldReference $p.Value $Alias }
    }

    function Get-CommittedProjectFile {
        # The project files git would commit: tracked, or new and not ignored.
        # Desktop keeps a data cache and local settings beside them, which a
        # plain folder listing would include. Without git, such as in a copy of
        # the repository with no .git folder, it lists the folder itself and
        # leaves out what the .gitignore patterns match, so these tests still
        # run there rather than skip.
        param([string] $Path, [switch] $NoGit)
        if (-not $NoGit -and (Get-Command git -ErrorAction SilentlyContinue) -and
            (Test-Path -LiteralPath (Join-Path $Path '.git'))) {
            $listed = @(& git -C $Path ls-files --cached --others --exclude-standard -- powerbi 2>$null)
            if ($LASTEXITCODE -eq 0) {
                return @($listed | ForEach-Object { Join-Path $Path $_ } | Where-Object { Test-Path -LiteralPath $_ })
            }
            Write-Verbose "git could not list $Path, so the .gitignore patterns are applied instead."
        }
        $patterns = @([IO.File]::ReadAllLines((Join-Path $Path '.gitignore')) |
                ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^[#!]' })
        @(Get-ChildItem -LiteralPath (Join-Path $Path 'powerbi') -Recurse -File -Force | Where-Object {
                $rel = $_.FullName.Substring($Path.Length + 1).Replace('\', '/')
                $ignored = $false
                foreach ($p in $patterns) {
                    if ($p.EndsWith('/')) { $p += '*' }
                    if ($p.Contains('/')) {
                        $p = $p.TrimStart('/')
                        if ($p.StartsWith('**/')) {
                            # '**/' matches any number of folders, or none.
                            $p = $p.Substring(3)
                            if ($rel -like $p -or $rel -like "*/$p") { $ignored = $true }
                        } elseif ($rel -like $p) { $ignored = $true }
                    } elseif ($_.Name -like $p) { $ignored = $true }
                }
                -not $ignored
            } | ForEach-Object FullName)
    }

    function Read-JsonFile {
        param([string]$Path)
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }

    function Get-ExpandedField {
        # The field names one Table.ExpandRecordColumn call in a query reads.
        param([string]$Text, [string]$Column)
        $m = [regex]::Match($Text, "Table\.ExpandRecordColumn\(\w+, ""$Column"", \{([^}]*)\}\)")
        if (-not $m.Success) { return $null }
        @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
    }

    # A real JSON report from the Westmark fixture, for the field checks.
    $snapshot = Read-Snapshot -Path (Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json')
    $auditProfile = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1')
    $results = @(Invoke-AuditCheck -Snapshot $snapshot -AuditProfile $auditProfile)
    $files = @(Write-AuditReport -Results $results -Snapshot $snapshot -AuditProfile $auditProfile -Path (Join-Path $TestDrive 'pbi'))
    $script:ReportJson = [IO.File]::ReadAllText(($files | Where-Object { $_ -like '*.json' })) | ConvertFrom-Json
    $script:ReportName = Split-Path ($files | Where-Object { $_ -like '*.json' }) -Leaf
}

Describe 'Power BI project files' {
    It '<Name> is JSON' -ForEach $JsonFiles {
        { Read-JsonFile $Path } | Should -Not -Throw
    }

    It '<Name> names a Fabric schema' -ForEach $SchemaFiles {
        (Read-JsonFile $Path).'$schema' | Should -Match '^https://developer\.microsoft\.com/json-schemas/fabric/'
    }

    It 'lists every model table it has a file for' {
        # Not $model: names aren't case-sensitive, and $Model is the folder.
        $modelText = [IO.File]::ReadAllText((Join-Path $Model 'model.tmdl'))
        $listed = @([regex]::Matches($modelText, '(?m)^ref table (.+)$') | ForEach-Object { ConvertFrom-TmdlName $_.Groups[1].Value })
        @(Get-ModelTable | ForEach-Object Name | Sort-Object) | Should -Be @($listed | Sort-Object)
    }

    It 'relates columns that exist' {
        $tables = @(Get-ModelTable)
        $text = [IO.File]::ReadAllText((Join-Path $Model 'relationships.tmdl'))
        $ends = @([regex]::Matches($text, '(?m)^\t(?:fromColumn|toColumn): (\w+)\.(.+)$'))
        $ends.Count | Should -Be 6
        foreach ($e in $ends) {
            $t = $tables | Where-Object Name -eq $e.Groups[1].Value
            $t | Should -Not -BeNullOrEmpty -Because $e.Value
            $t.Columns | Should -Contain (ConvertFrom-TmdlName $e.Groups[2].Value) -Because $e.Value
        }
    }

    It 'opens the report on the semantic model in the project, by relative path' {
        $pbir = Read-JsonFile (Join-Path $Project 'EntraAccessAudit.Report/definition.pbir')
        $pbir.datasetReference.byPath.path | Should -Be '../EntraAccessAudit.SemanticModel'
        Test-Path -LiteralPath (Join-Path $Project 'EntraAccessAudit.SemanticModel/definition.pbism') | Should -BeTrue
    }

    It 'orders pages that exist, and names each page and visual after its folder' {
        $pages = Read-JsonFile (Join-Path $Report 'pages/pages.json')
        $folders = @(Get-ChildItem -LiteralPath (Join-Path $Report 'pages') -Directory | ForEach-Object Name)
        @($pages.pageOrder | Sort-Object) | Should -Be @($folders | Sort-Object)
        foreach ($folder in $folders) {
            (Read-JsonFile (Join-Path $Report "pages/$folder/page.json")).name | Should -Be $folder
            foreach ($v in @(Get-ChildItem -LiteralPath (Join-Path $Report "pages/$folder/visuals") -Directory)) {
                (Read-JsonFile (Join-Path $v.FullName 'visual.json')).name | Should -Be $v.Name
            }
        }
    }
}

Describe 'Power BI readability' {
    BeforeAll {
        $script:Visuals = @(Get-ChildItem -LiteralPath (Join-Path $Report 'pages') -Recurse -Filter 'visual.json' |
            ForEach-Object { Read-JsonFile $_.FullName })
    }

    It 'sets grid text to at least 11pt in every table and matrix' {
        $grids = @($Visuals | Where-Object { $_.visual.visualType -in 'tableEx', 'pivotTable' })
        $grids.Count | Should -BeGreaterThan 0
        foreach ($v in $grids) {
            foreach ($card in 'values', 'columnHeaders') {
                $size = $v.visual.objects.$card[0].properties.fontSize.expr.Literal.Value
                $size | Should -Not -BeNullOrEmpty -Because "$($v.name) $card"
                [double]($size -replace 'D$', '') | Should -BeGreaterOrEqual 11 -Because "$($v.name) $card"
            }
        }
    }

    It 'draws every line chart with lines thicker than the default' {
        $lines = @($Visuals | Where-Object { $_.visual.visualType -eq 'lineChart' })
        $lines.Count | Should -BeGreaterThan 0
        foreach ($v in $lines) {
            $width = $v.visual.objects.lineStyles[0].properties.strokeWidth.expr.Literal.Value
            $width | Should -Not -BeNullOrEmpty -Because $v.name
            [int]($width -replace 'L$', '') | Should -BeGreaterOrEqual 3 -Because $v.name
        }
    }
}

Describe 'Power BI fields' {
    BeforeAll {
        $script:Tables = @(Get-ModelTable)
        $script:Refs = @(Get-ChildItem -LiteralPath $Report -Recurse -Filter '*.json' |
            ForEach-Object { Get-FieldReference (Read-JsonFile $_.FullName) })
        $script:Expressions = [IO.File]::ReadAllText((Join-Path $Model 'expressions.tmdl'))
    }

    It 'finds the fields the report uses' {
        # A silent pass if the walk found nothing.
        @($Refs | Where-Object Kind -eq 'Column').Count | Should -BeGreaterThan 20
        @($Refs | Where-Object Kind -eq 'Measure').Count | Should -BeGreaterThan 10
    }

    It 'uses only columns and measures the model has' {
        $missing = @(foreach ($r in $Refs) {
                $t = $Tables | Where-Object Name -eq $r.Entity
                $names = if ($null -eq $t) { @() } elseif ($r.Kind -eq 'Column') { $t.Columns } else { $t.Measures }
                if ($names -notcontains $r.Property) { "$($r.Kind) $($r.Entity)[$($r.Property)]" }
            })
        $missing | Should -BeNullOrEmpty
    }

    It 'picks out the audit''s JSON report by its name and Tool field' {
        $ReportName | Should -BeLike 'entra-access-audit-*.json'
        $Expressions | Should -Match ([regex]::Escape('Text.StartsWith(Text.Lower([Name]), "entra-access-audit-")'))
        $Expressions | Should -Match ([regex]::Escape("""Tool"", null) = ""$($ReportJson.Tool)"""))
    }

    It 'reads top-level fields the JSON report has' {
        $top = @($ReportJson.PSObject.Properties.Name)
        $all = ($Expressions + ($Tables | ForEach-Object Text)) -join "`n"
        $read = @([regex]::Matches($all, '(?:Record\.FieldOrDefault\((?:d|\[Doc\]), "(\w+)"|\[Doc\]\[(\w+)\])') |
            ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } } | Sort-Object -Unique)
        $read.Count | Should -BeGreaterThan 5
        foreach ($f in $read) { $top | Should -Contain $f -Because "the model reads $f" }
        foreach ($f in 'TenantId', 'CollectedAt', 'Counts', 'Datasets', 'Results', 'Version') { $read | Should -Contain $f }
    }

    It 'reads every field of a result, and of a finding' {
        $resultsText = ($Tables | Where-Object Name -eq 'Results').Text
        Get-ExpandedField $resultsText 'Rows' | Should -Be @($ReportJson.Results[0].PSObject.Properties.Name)
        $withFinding = @($ReportJson.Results | Where-Object { @($_.Findings).Count -gt 0 })[0]
        $findingsText = ($Tables | Where-Object Name -eq 'Findings').Text
        Get-ExpandedField $findingsText 'Findings' | Should -Be @($withFinding.Findings[0].PSObject.Properties.Name)
    }

    It 'reads every field of a dataset''s status' {
        $datasetsText = ($Tables | Where-Object Name -eq 'Datasets').Text
        Get-ExpandedField $datasetsText 'Value' | Should -Be @($ReportJson.Datasets.Users.PSObject.Properties.Name)
    }

    It 'reads every count the report gives' {
        $runsText = ($Tables | Where-Object Name -eq 'Runs').Text
        foreach ($s in $ReportJson.Counts.PSObject.Properties.Name) { $runsText | Should -Match "Record\.FieldOrDefault\(c, ""$s"", 0\)" }
    }

    It 'counts and codes every result a check can have' {
        $resultsText = ($Tables | Where-Object Name -eq 'Results').Text
        foreach ($s in 'Fail', 'Warn', 'Pass', 'Skipped', 'Error') {
            ($Tables | Where-Object Name -eq 'Results').Measures | Should -Contain "$s checks"
            $resultsText | Should -Match """$s"", ""[A-Z]"""
            $resultsText | Should -Match "\[Status\] = ""$s"" then \d"
        }
    }

    It 'ranks every severity a check can have' {
        $resultsText = ($Tables | Where-Object Name -eq 'Results').Text
        foreach ($sev in @($AuditChecks | ForEach-Object Severity | Sort-Object -Unique)) {
            $resultsText | Should -Match "\[Severity\] = ""$sev"" then \d"
        }
    }
}

Describe 'Power BI privacy' {
    It 'holds no local paths, accounts or email addresses' {
        $files = Get-CommittedProjectFile -Path $Root
        $files.Count | Should -BeGreaterThan 30
        $hits = @(Select-String -LiteralPath $files -Pattern @(
                '[A-Za-z]:\\', '\\Users\\', '/Users/', '/home/', '[\w.+-]+@[\w-]+\.[\w.]+') |
                ForEach-Object { "$($_.Path):$($_.LineNumber)" })
        $hits | Should -BeNullOrEmpty
    }

    It 'ships the example share as the report folder, not a real one' {
        $expr = [IO.File]::ReadAllText((Join-Path $Model 'expressions.tmdl'))
        $expr | Should -Match 'expression ReportFolder = "\\\\fileserver\\entra-audit" meta'
    }

    It 'loads empty with the example share, so Desktop can export the template' {
        # Regression: Desktop refreshes before it exports, and the example
        # share doesn't exist, so the export stopped on IO error 53.
        $expr = [IO.File]::ReadAllText((Join-Path $Model 'expressions.tmdl'))
        $expr | Should -Match 'Example = "\\\\fileserver\\entra-audit",'
        $expr | Should -Match 'else if ReportFolder = Example then #table\(type table \[Name = text, Content = binary\], \{\}\)'
        $expr | Should -Match 'Checked = if Table\.IsEmpty\(Audit\) and ReportFolder <> Example'
        # With no runs, Table.FromRecords needs the column names to keep the
        # table's shape for the steps after it.
        $runs = [IO.File]::ReadAllText((Join-Path $Model 'tables/Runs.tmdl'))
        $runs | Should -Match 'Table\.FromRecords\(Rows\[R\], \{"RunKey", "TenantId", "CollectedUtc", "ToolVersion", "Checks",\s+"Fail", "Warn", "Pass", "Skipped", "Error", "NotCollected", "ReportFile"\}\)'
    }

    It 'commits no Power BI cache, local settings or saved report' {
        $files = Get-CommittedProjectFile -Path $Root
        @($files | Where-Object { (Split-Path $_ -Leaf) -in 'cache.abf', 'localSettings.json' -or [IO.Path]::GetExtension($_) -in '.pbix', '.pbit' }) |
            Should -BeNullOrEmpty
    }

    It 'lists the same files without git, by the .gitignore patterns' {
        # Regression: in a copy with no .git folder both tests above skipped,
        # and a skipped test fails the run.
        $copy = Join-Path $TestDrive 'nogit'
        $null = New-Item -ItemType Directory -Path $copy
        Copy-Item -LiteralPath (Join-Path $Root 'powerbi') -Destination $copy -Recurse
        Copy-Item -LiteralPath (Join-Path $Root '.gitignore') -Destination $copy
        $copy = (Get-Item -LiteralPath $copy).FullName
        $pbi = Join-Path $copy 'powerbi/EntraAccessAudit.SemanticModel/.pbi'
        $null = New-Item -ItemType Directory -Path $pbi -Force
        foreach ($f in (Join-Path $pbi 'localSettings.json'), (Join-Path $pbi 'cache.abf'),
            (Join-Path $copy 'powerbi/EntraAccessAudit.pbit'), (Join-Path $copy 'powerbi/EntraAccessAudit.pbix')) {
            Set-Content -LiteralPath $f -Value 'Desktop data'
        }
        $files = @(Get-CommittedProjectFile -Path $copy -NoGit)
        $leaves = @($files | ForEach-Object { Split-Path $_ -Leaf })
        foreach ($leaf in 'localSettings.json', 'cache.abf', 'EntraAccessAudit.pbit', 'EntraAccessAudit.pbix') {
            $leaves | Should -Not -Contain $leaf
        }
        $leaves | Should -Contain 'EntraAccessAudit.pbip'
        $files.Count | Should -Be @(Get-ChildItem -LiteralPath (Join-Path $Root 'powerbi') -Recurse -File -Force |
                Where-Object { $_.FullName -notmatch '[\\/]\.pbi[\\/]' -and $_.Extension -notin '.pbix', '.pbit' }).Count
    }

    It 'keeps them out of git' {
        $ignore = [IO.File]::ReadAllLines((Join-Path $Root '.gitignore'))
        foreach ($p in '**/.pbi/localSettings.json', '**/.pbi/cache.abf', '*.pbix', '*.pbit') {
            $ignore | Should -Contain $p
        }
    }
}
