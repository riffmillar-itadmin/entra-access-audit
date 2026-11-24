# Pester tests for every check, run against the fictional Westmark tenant in
# fixtures/westmark.snapshot.json. Each check gets a Fail or Warn case (the
# fixture as it is), a Pass case (the fixture changed to fix the gap), and a
# Skipped case (the data it needs marked as not collected).
#
# Run through ..\Test-EntraAccessAudit.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'Invoke-EntraAccessAudit.ps1')
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/westmark.snapshot.json'
    $script:Westmark = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1')

    function Get-Fixture { Read-Snapshot -Path $FixturePath }

    function Get-Result {
        # Runs every check and returns the results by check ID.
        param($Snapshot, $AuditProfile = $Westmark)
        $byId = @{}
        foreach ($r in @(Invoke-AuditCheck -Snapshot $Snapshot -AuditProfile $AuditProfile)) { $byId[$r.Id] = $r }
        return $byId
    }

    function Get-Subject {
        param($Result)
        @($Result.Findings | ForEach-Object Subject | Sort-Object)
    }

    function Get-FixtureItem {
        # One fixture item by a property value, to change it in place.
        param($Snapshot, [string]$Dataset, [string]$Property, [string]$Value)
        $found = @($Snapshot.Datasets.$Dataset.Items | Where-Object { "$($_.$Property)" -eq $Value })
        if ($found.Count -ne 1) { throw "Expected one $Dataset item with $Property = $Value, found $($found.Count)." }
        return $found[0]
    }

    function Remove-FixtureItem {
        # Drops items from a dataset by a property value.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes a test copy of the fixture in memory only.')]
        param($Snapshot, [string]$Dataset, [string]$Property, [string[]]$Value)
        $Snapshot.Datasets.$Dataset.Items = @($Snapshot.Datasets.$Dataset.Items | Where-Object { $Value -notcontains "$($_.$Property)" })
    }

    function Set-NotCollected {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes a test copy of the fixture in memory only.')]
        param($Snapshot, [string]$Dataset, [string]$Status = 'NotLicensed')
        $Snapshot.Datasets.$Dataset.Status = $Status
        $Snapshot.Datasets.$Dataset.Reason = 'Needs Microsoft Entra ID P1.'
        $Snapshot.Datasets.$Dataset.Items = @()
    }

    function Get-UserId {
        param($Snapshot, [string]$Upn)
        (Get-FixtureItem $Snapshot 'Users' 'userPrincipalName' $Upn).id
    }
}

Describe 'The Westmark fixture as it is' {
    BeforeAll { $script:Fixture = Get-Result (Get-Fixture) }

    It 'gives every check a result' {
        $Fixture.Count | Should -Be $AuditChecks.Count
        @($Fixture.Values | Where-Object Status -in 'Skipped', 'Error').Count | Should -Be 0
    }

    It 'gives each check the expected result' {
        $expected = [ordered]@{
            'ROLE-01' = 'Pass'; 'ROLE-02' = 'Fail'; 'ROLE-03' = 'Fail'; 'ROLE-04' = 'Fail'; 'ROLE-05' = 'Fail'; 'ROLE-06' = 'Warn'
            'ROLE-07' = 'Fail'; 'ROLE-08' = 'Warn'; 'ROLE-09' = 'Fail'; 'ROLE-10' = 'Warn'; 'ROLE-11' = 'Fail'; 'ROLE-12' = 'Warn'; 'ROLE-13' = 'Pass'
            'STALE-01' = 'Fail'; 'STALE-02' = 'Fail'; 'STALE-03' = 'Fail'; 'STALE-04' = 'Warn'
            'MFA-01' = 'Fail'; 'MFA-02' = 'Warn'; 'MFA-03' = 'Fail'
            'APP-01' = 'Warn'; 'APP-02' = 'Warn'; 'APP-03' = 'Warn'; 'APP-04' = 'Fail'; 'APP-05' = 'Warn'; 'APP-06' = 'Fail'; 'APP-07' = 'Warn'
            'SVC-01' = 'Warn'; 'SVC-02' = 'Fail'; 'SVC-03' = 'Fail'; 'SVC-04' = 'Warn'; 'SVC-05' = 'Fail'
            'CA-01' = 'Fail'; 'CA-02' = 'Pass'; 'CA-03' = 'Fail'; 'CA-04' = 'Warn'; 'CA-05' = 'Warn'
            'TEN-01' = 'Fail'; 'TEN-02' = 'Warn'; 'TEN-03' = 'Warn'; 'TEN-04' = 'Warn'; 'TEN-05' = 'Pass'; 'TEN-06' = 'Warn'; 'TEN-07' = 'Warn'
        }
        @($expected.Keys | Sort-Object) | Should -Be @($AuditChecks | ForEach-Object Id | Sort-Object)
        foreach ($id in $expected.Keys) { $Fixture[$id].Status | Should -Be $expected[$id] -Because $id }
    }

    It 'never passes a check with findings, or fails one without' {
        foreach ($r in $Fixture.Values) {
            if ($r.Status -in 'Fail', 'Warn') { @($r.Findings).Count | Should -BeGreaterThan 0 -Because $r.Id }
        }
    }
}

Describe 'Privileged roles' {
    It 'ROLE-01 passes within the limits and counts eligible holders' {
        $r = (Get-Result (Get-Fixture))['ROLE-01']
        $r.Status | Should -Be 'Pass'
        Get-Subject $r | Should -Be @('admin.lee@westmark.example', 'bg.one@westmark.example', 'bg.two@westmark.example', 'sam.ortiz@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'sam.ortiz@westmark.example')[0].Detail | Should -Be 'Eligible'
    }

    It 'ROLE-01 fails above MaxGlobalAdmins' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.MaxGlobalAdmins = 3
        (Get-Result (Get-Fixture) $p)['ROLE-01'].Status | Should -Be 'Fail'
    }

    It 'ROLE-01 warns below MinGlobalAdmins' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-02', 'ra-03'
        Remove-FixtureItem $s 'RoleEligibility' 'id' 'ra-09'
        $r = (Get-Result $s)['ROLE-01']
        $r.Status | Should -Be 'Warn'
        $r.Summary | Should -Match '^1 account'
    }

    It 'ROLE-01 says when PIM-eligible holders could not be counted' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleEligibility'
        $r = (Get-Result $s)['ROLE-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match "eligible assignments weren't counted \(RoleEligibility: NotLicensed\)"
    }

    It 'ROLE-02 fails on a standing Global Administrator, leaving out break-glass' {
        $r = (Get-Result (Get-Fixture))['ROLE-02']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('admin.lee@westmark.example')
    }

    It 'ROLE-02 passes when the assignment is PIM-activated' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignmentSchedules' 'id' 'rs-01').assignmentType = 'Activated'
        (Get-Result $s)['ROLE-02'].Status | Should -Be 'Pass'
    }

    It 'ROLE-02 passes when the assignment has an end date' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignmentSchedules' 'id' 'rs-01').scheduleInfo.expiration.type = 'afterDateTime'
        (Get-Result $s)['ROLE-02'].Status | Should -Be 'Pass'
    }

    It 'ROLE-02 counts every active assignment as standing without PIM, and says so' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignmentSchedules' 'id' 'rs-01').assignmentType = 'Activated'
        Set-NotCollected $s 'RoleAssignmentSchedules'
        $r = (Get-Result $s)['ROLE-02']
        $r.Status | Should -Be 'Fail'
        $r.Summary | Should -Match 'every active assignment counts as standing'
    }

    It 'ROLE-03 fails on a guest in a privileged role, and passes without one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['ROLE-03']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('vendor.ops_partner.example#EXT#@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Security Administrator'
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-05'
        (Get-Result $s)['ROLE-03'].Status | Should -Be 'Pass'
    }

    It 'ROLE-03 ignores a guest in a role that is not privileged' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignments' 'id' 'ra-05').roleDefinitionId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
        (Get-Result $s)['ROLE-03'].Status | Should -Be 'Pass'
    }

    It 'ROLE-03 treats a custom role that Graph marks privileged as privileged' {
        $s = Get-Fixture
        $s.Datasets.RoleDefinitions.Items += [pscustomobject]@{ id = 'custom-01'; displayName = 'Westmark Tier 0'; isBuiltIn = $false; isPrivileged = $true }
        (Get-FixtureItem $s 'RoleAssignments' 'id' 'ra-05').roleDefinitionId = 'custom-01'
        $r = (Get-Result $s)['ROLE-03']
        $r.Status | Should -Be 'Fail'
        $r.Findings[0].Detail | Should -Be 'Westmark Tier 0'
    }

    It 'ROLE-03 is skipped without the user list' {
        $s = Get-Fixture; Set-NotCollected $s 'Users' 'Denied'
        $r = (Get-Result $s)['ROLE-03']
        $r.Status | Should -Be 'Skipped'
        $r.Summary | Should -Match 'Users was not collected \(Denied\)'
    }

    It 'ROLE-04 fails on a synced account in a privileged role, and passes when it is cloud-only' {
        $s = Get-Fixture
        $r = (Get-Result $s)['ROLE-04']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example')
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'dana.kim@westmark.example').onPremisesSyncEnabled = $null
        (Get-Result $s)['ROLE-04'].Status | Should -Be 'Pass'
    }

    It 'ROLE-05 fails on privileged accounts without a phishing-resistant method' {
        $r = (Get-Result (Get-Fixture))['ROLE-05']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example', 'jo.park@westmark.example', 'riley.ng@westmark.example', 'sam.ortiz@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'riley.ng@westmark.example')[0].Detail | Should -Match '^Helpdesk Administrator via Helpdesk Tier 2\.'
    }

    It 'ROLE-05 passes when each privileged account has a passkey or security key' {
        $s = Get-Fixture
        foreach ($upn in 'dana.kim@westmark.example', 'riley.ng@westmark.example', 'sam.ortiz@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example') {
            (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).methodsRegistered = @('passKeyDeviceBoundAuthenticator')
        }
        (Get-FixtureItem $s 'RoleGroupMembers' 'groupId' '00000000-0000-4000-8000-000000000101').members = @(
            (Get-FixtureItem $s 'RoleGroupMembers' 'groupId' '00000000-0000-4000-8000-000000000101').members | Where-Object id -ne '00000000-0000-4000-8000-000000000007')
        (Get-Result $s)['ROLE-05'].Status | Should -Be 'Pass'
    }

    It 'ROLE-05 warns, naming them, when the only gaps are privileged accounts with no registration record' {
        # Regression: accounts with no record were left out, and the check passed.
        $s = Get-Fixture
        foreach ($upn in 'riley.ng@westmark.example', 'sam.ortiz@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example') {
            (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).methodsRegistered = @('passKeyDeviceBoundAuthenticator')
        }
        Remove-FixtureItem $s 'Registration' 'userPrincipalName' 'dana.kim@westmark.example', 'jo.park@westmark.example'
        $r = (Get-Result $s)['ROLE-05']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example', 'jo.park@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'dana.kim@westmark.example')[0].Detail | Should -Be 'Exchange Administrator. No registration record'
    }

    It 'ROLE-05 is skipped without the registration report' {
        $s = Get-Fixture; Set-NotCollected $s 'Registration'
        (Get-Result $s)['ROLE-05'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-06 warns on roles held by a group and an app, and passes without them' {
        $s = Get-Fixture
        $r = (Get-Result $s)['ROLE-06']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Helpdesk Tier 2', 'Westmark Provisioning')
        @($r.Findings | Where-Object Subject -eq 'Helpdesk Tier 2')[0].Detail | Should -Match 'group of 2 member\(s\); each member is checked'
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-06', 'ra-07'
        (Get-Result $s)['ROLE-06'].Status | Should -Be 'Pass'
    }

    It 'ROLE-06 lists a principal it cannot identify as Unknown when the roles were read without expansion' {
        $s = Get-Fixture
        foreach ($a in $s.Datasets.RoleAssignments.Items) { $a.PSObject.Properties.Remove('principal') }
        $r = (Get-Result $s)['ROLE-06']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | ForEach-Object Detail) | Should -Match 'Unknown'
        # Users are still matched from the user list.
        (Get-Result $s)['ROLE-03'].Status | Should -Be 'Fail'
    }

    It 'checks members of a role group as role holders, and names the group' {
        $r = Get-Result (Get-Fixture)
        @($r['MFA-03'].Findings | Where-Object Subject -eq 'jo.park@westmark.example')[0].Detail | Should -Be 'Helpdesk Administrator via Helpdesk Tier 2'
    }

    It 'counts a Global Administrator held through a group once per member' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignments' 'id' 'ra-06').roleDefinitionId = $GlobalAdminRoleId
        $r = (Get-Result $s)['ROLE-01']
        Get-Subject $r | Should -Be @('admin.lee@westmark.example', 'bg.one@westmark.example', 'bg.two@westmark.example', 'jo.park@westmark.example', 'riley.ng@westmark.example', 'sam.ortiz@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'jo.park@westmark.example')[0].Detail | Should -Be 'Active via Helpdesk Tier 2'
        $r.Status | Should -Be 'Fail'
        $r2 = (Get-Result $s)['ROLE-02']
        Get-Subject $r2 | Should -Be @('admin.lee@westmark.example', 'jo.park@westmark.example', 'riley.ng@westmark.example')
        @($r2.Findings | Where-Object Subject -eq 'jo.park@westmark.example')[0].Detail | Should -Be 'User, permanently active via Helpdesk Tier 2'
    }

    It 'counts a role group as one holder, and says so, when its members were not read' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleAssignments' 'id' 'ra-06').roleDefinitionId = $GlobalAdminRoleId
        Set-NotCollected $s 'RoleGroupMembers' 'Denied'
        $r = Get-Result $s
        Get-Subject $r['ROLE-01'] | Should -Contain 'Helpdesk Tier 2'
        $r['ROLE-01'].Summary | Should -Match "1 group\(s\) hold the role and their members weren't read \(RoleGroupMembers: Denied\)"
        @($r['ROLE-06'].Findings | Where-Object Subject -eq 'Helpdesk Tier 2')[0].Detail | Should -Match "members weren't read \(RoleGroupMembers: Denied\)"
        Get-Subject $r['MFA-03'] | Should -Not -Contain 'jo.park@westmark.example'
    }

    It 'reads a schema 1 snapshot, which has no group members, and says the members were not read' {
        $s = Get-Fixture
        $s.SchemaVersion = 1
        $s.Datasets.PSObject.Properties.Remove('RoleGroupMembers')
        $r = (Get-Result $s)['ROLE-06']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | Where-Object Subject -eq 'Helpdesk Tier 2')[0].Detail | Should -Match 'RoleGroupMembers: NotCollected'
    }

    It 'every privileged-role check is skipped without role assignments' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Error'
        $r = Get-Result $s
        foreach ($id in 'ROLE-01', 'ROLE-02', 'ROLE-03', 'ROLE-04', 'ROLE-05', 'ROLE-06', 'MFA-03') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
    }
    It 'ROLE-07 fails on other privileged roles held permanently, leaving out Global Administrator, apps and time-bound assignments' {
        $r = (Get-Result (Get-Fixture))['ROLE-07']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('jo.park@westmark.example', 'riley.ng@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'jo.park@westmark.example')[0].Detail | Should -Be 'Helpdesk Administrator via Helpdesk Tier 2; permanently active'
        # Dana Kim's Exchange Administrator has an end date; Avery Lee's Global Administrator is ROLE-02's.
        Get-Subject $r | Should -Not -Contain 'dana.kim@westmark.example'
        Get-Subject $r | Should -Not -Contain 'admin.lee@westmark.example'
    }

    It 'ROLE-07 passes once those assignments end, and says when PIM schedules were not read' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-05', 'ra-06'
        $r = (Get-Result $s)['ROLE-07']
        $r.Status | Should -Be 'Pass'
        Set-NotCollected $s 'RoleAssignmentSchedules'
        $r = (Get-Result $s)['ROLE-07']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example')
        $r.Summary | Should -Match 'every active assignment counts as permanent'
    }

    It 'ROLE-07 is skipped without role assignments' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Denied'
        (Get-Result $s)['ROLE-07'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-08 warns on an eligible assignment with no end date, and passes once it has one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['ROLE-08']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('sam.ortiz@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Global Administrator; eligible with no end date'
        (Get-FixtureItem $s 'RoleEligibility' 'id' 'ra-09').scheduleInfo.expiration.type = 'afterDateTime'
        $r = (Get-Result $s)['ROLE-08']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^Every eligible privileged assignment has an end date'
    }

    It 'ROLE-08 says when an eligible assignment had no schedule to read, rather than passing it silently' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'RoleEligibility' 'id' 'ra-09').PSObject.Properties.Remove('scheduleInfo')
        $r = (Get-Result $s)['ROLE-08']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match "1 eligible assignment\(s\) had no schedule to read, so their end dates weren't checked"
    }

    It 'ROLE-08 is skipped without PIM eligibility' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleEligibility'
        (Get-Result $s)['ROLE-08'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-09 fails on a role an account added to itself, leaving out PIM activations, PIM''s own completions and failed attempts' {
        $s = Get-Fixture
        $r = (Get-Result $s)['ROLE-09']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('vendor.ops_partner.example#EXT#@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Add member to role: Security Administrator, 2026-10-24'
        $r.Summary | Should -Match 'since 2026-10-20'
    }

    It 'ROLE-09 counts an eligible assignment made through PIM to oneself' {
        $s = Get-Fixture
        $e = Get-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-03'
        $e.activityDisplayName = 'Add eligible member to role in PIM requested (permanent)'
        Get-Subject (Get-Result $s)['ROLE-09'] | Should -Contain 'sam.ortiz@westmark.example'
    }

    It 'ROLE-09 passes when someone else made each change, and says how far back the log goes' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-02'
        $r = (Get-Result $s)['ROLE-09']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^None of the 1 role addition\(s\) in the audit log since 2026-10-20'
    }

    It 'ROLE-09 says when the audit log holds no role changes' {
        $s = Get-Fixture; $s.Datasets.RoleAuditEvents.Items = @()
        $r = (Get-Result $s)['ROLE-09']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^The audit log holds no role changes to check'
    }

    It 'ROLE-09 counts a self-grant made outside PIM once, though PIM logs it a second time' {
        $s = Get-Fixture
        $copy = (Get-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-02' | ConvertTo-Json -Depth 5 | ConvertFrom-Json)
        $copy.id = 'ae-02-pim'
        $copy.activityDisplayName = 'Add member to role outside of PIM (permanent)'
        $s.Datasets.RoleAuditEvents.Items = @($s.Datasets.RoleAuditEvents.Items) + $copy
        $r = (Get-Result $s)['ROLE-09']
        $r.Findings.Count | Should -Be 1
        $r.Findings[0].Detail | Should -Be 'Add member to role: Security Administrator, 2026-10-24'
    }

    It 'ROLE-09 is skipped without the audit log' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAuditEvents' 'Denied'
        (Get-Result $s)['ROLE-09'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-10 warns on weak activation rules for a role with eligible accounts' {
        $r = (Get-Result (Get-Fixture))['ROLE-10']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Global Administrator')
        $r.Findings[0].Detail | Should -Be 'activation needs no MFA; activation lasts up to 10 hours; activation needs no approval; 1 eligible account(s)'
    }

    It 'ROLE-10 passes once activation needs MFA and approval and lasts no more than MaxActivationHours' {
        $s = Get-Fixture
        $policy = Get-FixtureItem $s 'RolePolicies' 'roleDefinitionId' '62e90394-69f5-4237-9190-012177145e10'
        @($policy.rules | Where-Object id -eq 'Enablement_EndUser_Assignment')[0].enabledRules = @('MultiFactorAuthentication', 'Justification')
        @($policy.rules | Where-Object id -eq 'Approval_EndUser_Assignment')[0].setting.isApprovalRequired = $true
        @($policy.rules | Where-Object id -eq 'Expiration_EndUser_Assignment')[0].maximumDuration = 'PT8H'
        (Get-Result $s)['ROLE-10'].Status | Should -Be 'Pass'
    }

    It 'ROLE-10 accepts an authentication context in place of MFA, and honours MaxActivationHours' {
        $s = Get-Fixture
        $policy = Get-FixtureItem $s 'RolePolicies' 'roleDefinitionId' '62e90394-69f5-4237-9190-012177145e10'
        @($policy.rules | Where-Object id -eq 'AuthenticationContext_EndUser_Assignment')[0].isEnabled = $true
        @($policy.rules | Where-Object id -eq 'Approval_EndUser_Assignment')[0].setting.isApprovalRequired = $true
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.MaxActivationHours = 12
        (Get-Result $s $p)['ROLE-10'].Status | Should -Be 'Pass'
    }

    It 'ROLE-10 names a role whose policy was not read, and passes when no one is eligible' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'RolePolicies' 'roleDefinitionId' '62e90394-69f5-4237-9190-012177145e10'
        $r = (Get-Result $s)['ROLE-10']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match "No PIM policy was read for Global Administrator, so it wasn't checked"
        Remove-FixtureItem $s 'RoleEligibility' 'id' 'ra-09'
        (Get-Result $s)['ROLE-10'].Summary | Should -Match '^No account is eligible for a privileged role'
    }

    It 'ROLE-10 is skipped without the PIM policies' {
        $s = Get-Fixture; Set-NotCollected $s 'RolePolicies'
        (Get-Result $s)['ROLE-10'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-11 fails on an owner of a group that holds a privileged role, leaving out Global Administrators' {
        $r = (Get-Result (Get-Fixture))['ROLE-11']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Owns Helpdesk Tier 2, which holds Helpdesk Administrator (Active)'
        $r.Summary | Should -Match '1 owner\(s\) who are Global or Privileged Role Administrators'
    }

    It 'ROLE-11 passes when only admins own the group, and when no group holds a role' {
        $s = Get-Fixture
        $g = Get-FixtureItem $s 'RoleGroupOwners' 'groupId' '00000000-0000-4000-8000-000000000101'
        $g.owners = @($g.owners | Where-Object id -ne '00000000-0000-4000-8000-000000000005')
        (Get-Result $s)['ROLE-11'].Status | Should -Be 'Pass'
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-06'
        (Get-Result $s)['ROLE-11'].Summary | Should -Be 'No group holds a privileged role.'
    }

    It 'ROLE-11 is skipped when the group owners could not be read' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleGroupOwners' 'Denied'
        (Get-Result $s)['ROLE-11'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-12 warns on a privileged role assigned outside PIM, leaving out break-glass accounts' {
        $r = (Get-Result (Get-Fixture))['ROLE-12']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Exchange Administrator by admin.lee@westmark.example, 2026-10-21'
        $r.Summary | Should -Match '1 assignment\(s\) to break-glass accounts weren''t counted'
    }

    It 'ROLE-12 leaves out roles that are not privileged and failed attempts' {
        $s = Get-Fixture
        $e = Get-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-06'
        $e.targetResources[0].id = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'
        $e.targetResources[0].displayName = 'Directory Readers'
        (Get-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-07').result = 'failure'
        $r = (Get-Result $s)['ROLE-12']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 assignment\(s\) of roles that aren''t privileged'
        $r.Summary | Should -Not -Match 'break-glass'
    }

    It 'ROLE-12 passes when every privileged role went through PIM' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'RoleAuditEvents' 'id' 'ae-06', 'ae-07'
        $r = (Get-Result $s)['ROLE-12']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^No privileged role was assigned outside PIM'
    }

    It 'ROLE-12 is skipped without PIM, where every assignment is made outside it' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignmentSchedules'
        (Get-Result $s)['ROLE-12'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-12 is skipped without the audit log' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAuditEvents' 'Denied'
        (Get-Result $s)['ROLE-12'].Status | Should -Be 'Skipped'
    }

    It 'ROLE-07 to ROLE-11 and SVC-05 are skipped on a snapshot from before schema 4, not passed' {
        $s = Get-Fixture
        $s.SchemaVersion = 3
        foreach ($name in 'RoleAuditEvents', 'RolePolicies', 'RoleGroupOwners', 'AppOwners') { $s.Datasets.PSObject.Properties.Remove($name) }
        $r = Get-Result $s
        foreach ($id in 'ROLE-09', 'ROLE-10', 'ROLE-11', 'ROLE-12', 'SVC-05') {
            $r[$id].Status | Should -Be 'Skipped' -Because $id
            $r[$id].Summary | Should -Match 'was not collected \(NotCollected\): The snapshot has schema 3, from before' -Because $id
        }
        # ROLE-07 and ROLE-08 read data every schema has.
        $r['ROLE-07'].Status | Should -Be 'Fail'
        $r['ROLE-08'].Status | Should -Be 'Warn'
    }

    It 'ROLE-13 passes when privileged members are the tenant''s own, leaving guests to ROLE-03' {
        $r = Get-Result (Get-Fixture)
        $r['ROLE-13'].Status | Should -Be 'Pass'
        # A guest holds a privileged role in the fixture; ROLE-03 reports it.
        $r['ROLE-03'].Status | Should -Be 'Fail'
    }

    It 'ROLE-13 fails on a privileged role held by a personal Microsoft account' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'admin.lee@westmark.example').identities = @(
            [pscustomobject]@{ signInType = 'federated'; issuer = 'MicrosoftAccount'; issuerAssignedId = $null })
        $r = (Get-Result $s)['ROLE-13']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('admin.lee@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Global Administrator. Signs in with a personal Microsoft account.'
    }

    It 'ROLE-13 names an account from another organization' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'dana.kim@westmark.example').identities = @(
            [pscustomobject]@{ signInType = 'federated'; issuer = 'ExternalAzureAD'; issuerAssignedId = $null })
        $r = (Get-Result $s)['ROLE-13']
        $r.Status | Should -Be 'Fail'
        $r.Findings[0].Detail | Should -Match 'Signs in with an account in another Microsoft Entra organization\.$'
    }

    It 'ROLE-13 falls back to #EXT# in the name on a snapshot without identities' {
        $s = Get-Fixture
        $u = Get-FixtureItem $s 'Users' 'userPrincipalName' 'admin.lee@westmark.example'
        $u.userPrincipalName = 'admin.lee_mail.example#EXT#@westmark.example'
        foreach ($user in $s.Datasets.Users.Items) { $user.PSObject.Properties.Remove('identities') }
        $r = (Get-Result $s)['ROLE-13']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('admin.lee_mail.example#EXT#@westmark.example')
        $r.Findings[0].Detail | Should -Match '#EXT# in its user principal name'
    }

    It 'ROLE-13 is skipped without the role assignments' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Denied'
        (Get-Result $s)['ROLE-13'].Status | Should -Be 'Skipped'
    }
}

Describe 'Stale accounts' {
    It 'STALE-01 fails on an enabled member with no recent sign-in, leaving out break-glass and disabled accounts' {
        $r = (Get-Result (Get-Fixture))['STALE-01']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('jo.park@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Last sign-in 2026-05-01'
    }

    It 'STALE-01 counts a recent non-interactive sign-in as activity' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'jo.park@westmark.example').signInActivity.lastNonInteractiveSignInDateTime = '2026-10-15T00:00:00Z'
        (Get-Result $s)['STALE-01'].Status | Should -Be 'Pass'
    }

    It 'STALE-01 follows StaleDays' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.StaleDays = 200
        (Get-Result (Get-Fixture) $p)['STALE-01'].Status | Should -Be 'Pass'
    }

    It 'STALE-01 reports break-glass accounts when none are named' {
        $r = (Get-Result (Get-Fixture) (Get-AuditProfile))['STALE-01']
        Get-Subject $r | Should -Be @('bg.one@westmark.example', 'jo.park@westmark.example')
    }

    It 'STALE-01 to STALE-03 are skipped without sign-in activity' {
        $s = Get-Fixture; Set-NotCollected $s 'SignIns'
        $r = Get-Result $s
        foreach ($id in 'STALE-01', 'STALE-02', 'STALE-03') {
            $r[$id].Status | Should -Be 'Skipped' -Because $id
            $r[$id].Summary | Should -Match 'SignIns was not collected \(NotLicensed\)'
        }
        $r['STALE-04'].Status | Should -Be 'Warn'
    }

    It 'STALE-02 fails on an old account never used, but not a new one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['STALE-02']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('old.unused@westmark.example')
        Remove-FixtureItem $s 'Users' 'userPrincipalName' 'old.unused@westmark.example'
        (Get-Result $s)['STALE-02'].Status | Should -Be 'Pass'
    }

    It 'STALE-03 fails on a stale guest and passes after it signs in' {
        $s = Get-Fixture
        $r = (Get-Result $s)['STALE-03']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('consultant_old.example#EXT#@westmark.example')
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'consultant_old.example#EXT#@westmark.example').signInActivity.lastSignInDateTime = '2026-10-01T00:00:00Z'
        (Get-FixtureItem $s 'Users' 'userPrincipalName' 'consultant_old.example#EXT#@westmark.example').signInActivity.lastSuccessfulSignInDateTime = '2026-10-01T00:00:00Z'
        (Get-Result $s)['STALE-03'].Status | Should -Be 'Pass'
    }

    It 'STALE-04 warns on an old pending invitation, not a recent one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['STALE-04']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('invitee_pending.example#EXT#@westmark.example')
        Remove-FixtureItem $s 'Users' 'userPrincipalName' 'invitee_pending.example#EXT#@westmark.example'
        (Get-Result $s)['STALE-04'].Status | Should -Be 'Pass'
    }

    It 'STALE-04 is skipped without the user list' {
        $s = Get-Fixture; Set-NotCollected $s 'Users' 'Error'
        (Get-Result $s)['STALE-04'].Status | Should -Be 'Skipped'
    }
}

Describe 'MFA coverage' {
    It 'MFA-01 fails on enabled members without MFA and notes members with no record' {
        $r = (Get-Result (Get-Fixture))['MFA-01']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('jo.park@westmark.example', 'old.unused@westmark.example')
        $r.Summary | Should -Match '1 enabled member\(s\) had no registration record'
    }

    It 'MFA-01 warns, naming them, when the only gaps are members with no registration record' {
        $s = Get-Fixture
        foreach ($upn in 'jo.park@westmark.example', 'old.unused@westmark.example') { (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).isMfaRegistered = $true }
        $r = (Get-Result $s)['MFA-01']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('new.hire@westmark.example')
        $r.Findings[0].Detail | Should -Be 'No registration record'
    }

    It 'MFA-01 passes when every member has registered' {
        $s = Get-Fixture
        foreach ($upn in 'jo.park@westmark.example', 'old.unused@westmark.example') { (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).isMfaRegistered = $true }
        $s.Datasets.Registration.Items = @($s.Datasets.Registration.Items) + [pscustomobject]@{
            id = (Get-UserId $s 'new.hire@westmark.example'); userPrincipalName = 'new.hire@westmark.example'; isMfaRegistered = $true; methodsRegistered = @('microsoftAuthenticatorPush') }
        (Get-Result $s)['MFA-01'].Status | Should -Be 'Pass'
    }

    It 'treats an empty registration report as not collected, so ROLE-05 and MFA-01 to MFA-03 are skipped, not passed' {
        # Regression: a new tenant's report was empty and these four passed.
        $s = Get-Fixture
        $s.Datasets.Registration.Items = @()
        $r = Get-Result $s
        foreach ($id in 'ROLE-05', 'MFA-01', 'MFA-02', 'MFA-03') {
            $r[$id].Status | Should -Be 'Skipped' -Because $id
            $r[$id].Summary | Should -Match 'Registration was not collected \(Empty\): The MFA registration report has no records' -Because $id
        }
    }

    It 'MFA-01 to MFA-03 are skipped without the registration report' {
        $s = Get-Fixture; Set-NotCollected $s 'Registration'
        $r = Get-Result $s
        foreach ($id in 'MFA-01', 'MFA-02', 'MFA-03') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
    }

    It 'MFA-02 warns on an account with only a phone and email, and passes once it adds the app' {
        $s = Get-Fixture
        $r = (Get-Result $s)['MFA-02']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('dana.kim@westmark.example')
        (Get-FixtureItem $s 'Registration' 'userPrincipalName' 'dana.kim@westmark.example').methodsRegistered = @('mobilePhone', 'microsoftAuthenticatorPush')
        (Get-Result $s)['MFA-02'].Status | Should -Be 'Pass'
    }

    It 'MFA-02 does not report an account with no methods at all (MFA-01 does)' {
        $r = (Get-Result (Get-Fixture))['MFA-02']
        Get-Subject $r | Should -Not -Contain 'jo.park@westmark.example'
    }

    It 'MFA-03 fails on a privileged account without MFA, and passes once it registers' {
        $s = Get-Fixture
        $r = (Get-Result $s)['MFA-03']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('jo.park@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example')
        (Get-FixtureItem $s 'Registration' 'userPrincipalName' 'vendor.ops_partner.example#EXT#@westmark.example').isMfaRegistered = $true
        (Get-FixtureItem $s 'Registration' 'userPrincipalName' 'jo.park@westmark.example').isMfaRegistered = $true
        (Get-Result $s)['MFA-03'].Status | Should -Be 'Pass'
    }

    It 'MFA-03 warns when the only gap is a privileged account with no registration record' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Registration' 'userPrincipalName' 'jo.park@westmark.example').isMfaRegistered = $true
        Remove-FixtureItem $s 'Registration' 'userPrincipalName' 'vendor.ops_partner.example#EXT#@westmark.example'
        $r = (Get-Result $s)['MFA-03']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('vendor.ops_partner.example#EXT#@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Security Administrator. No registration record'
    }
}

Describe 'Apps' {
    It 'APP-01 warns on an expired secret, and passes once it is removed' {
        $s = Get-Fixture
        $r = (Get-Result $s)['APP-01']
        $r.Status | Should -Be 'Warn'
        $r.Findings[0].Subject | Should -Be 'Westmark HR Sync'
        $r.Findings[0].Detail | Should -Be "Secret 'hr-sync-2025' expired 2026-09-01"
        (Get-FixtureItem $s 'Applications' 'displayName' 'Westmark HR Sync').passwordCredentials = @()
        (Get-Result $s)['APP-01'].Status | Should -Be 'Pass'
    }

    It 'APP-02 warns on a certificate expiring within CredentialExpiryDays' {
        $r = (Get-Result (Get-Fixture))['APP-02']
        $r.Status | Should -Be 'Warn'
        $r.Findings[0].Detail | Should -Be "Certificate 'CN=hr-sync' expires 2026-11-20"
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.CredentialExpiryDays = 10
        (Get-Result (Get-Fixture) $p)['APP-02'].Status | Should -Be 'Pass'
    }

    It 'APP-03 warns on a secret valid for more than MaxSecretLifetimeDays, and not on a 364-day one' {
        $r = (Get-Result (Get-Fixture))['APP-03']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Westmark Payroll Connector')
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.MaxSecretLifetimeDays = 1100
        (Get-Result (Get-Fixture) $p)['APP-03'].Status | Should -Be 'Pass'
    }

    It 'APP-04 fails on high-risk Graph permissions and ignores read-only ones' {
        $r = (Get-Result (Get-Fixture))['APP-04']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('Westmark Backup', 'Westmark HR Sync')
        @($r.Findings | ForEach-Object Detail) -join ';' | Should -Not -Match 'User\.Read\.All'
    }

    It 'APP-04 counts, but does not list, apps named in AcceptedApps' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.AcceptedApps = @('westmark backup', 'Westmark HR Sync')
        $r = (Get-Result (Get-Fixture) $p)['APP-04']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '2 grant\(s\) to apps listed in AcceptedApps'
    }

    It 'APP-04 is skipped when the grants could not be read' {
        $s = Get-Fixture; Set-NotCollected $s 'GraphPermissionGrants' 'Denied'
        (Get-Result $s)['APP-04'].Status | Should -Be 'Skipped'
    }

    It 'APP-05 warns on an app with no owner, and passes once it has one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['APP-05']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Westmark Payroll Connector')
        (Get-FixtureItem $s 'Applications' 'displayName' 'Westmark Payroll Connector').owners = @([pscustomobject]@{ id = '00000000-0000-4000-8000-000000000014' })
        (Get-Result $s)['APP-05'].Status | Should -Be 'Pass'
    }

    It 'APP-06 fails on tenant-wide consent to high-risk Graph permissions, ignoring other APIs and low-risk scopes' {
        $s = Get-Fixture
        $r = (Get-Result $s)['APP-06']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('Westmark Mail Assistant')
        $r.Findings[0].Detail | Should -Be 'Mail.ReadWrite, Mail.Send, consented for every user'
        Remove-FixtureItem $s 'DelegatedPermissionGrants' 'id' 'pg-01'
        (Get-Result $s)['APP-06'].Status | Should -Be 'Pass'
    }

    It 'APP-06 counts, but does not list, apps named in AcceptedApps' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.AcceptedApps = @('westmark mail assistant')
        $r = (Get-Result (Get-Fixture) $p)['APP-06']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 grant\(s\) to apps listed in AcceptedApps'
    }

    It 'APP-06 names the app by its ID when the service principal is unknown' {
        $s = Get-Fixture
        Remove-FixtureItem $s 'ServicePrincipals' 'id' '00000000-0000-4000-8000-000000000602'
        Get-Subject (Get-Result $s)['APP-06'] | Should -Be @('00000000-0000-4000-8000-000000000602')
    }

    It 'APP-07 warns on user consent to high-risk Graph permissions, one finding per app' {
        $s = Get-Fixture
        $r = (Get-Result $s)['APP-07']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Pocket Files Sync')
        $r.Findings[0].Detail | Should -Be 'Files.ReadWrite.All, consented by 2 user(s): jo.park@westmark.example, riley.ng@westmark.example'
        Remove-FixtureItem $s 'DelegatedPermissionGrants' 'id' 'pg-03', 'pg-04'
        (Get-Result $s)['APP-07'].Status | Should -Be 'Pass'
    }

    It 'APP-06 and APP-07 are skipped without the grants or the service principals' {
        foreach ($ds in 'DelegatedPermissionGrants', 'ServicePrincipals') {
            $s = Get-Fixture; Set-NotCollected $s $ds 'Denied'
            $r = Get-Result $s
            foreach ($id in 'APP-06', 'APP-07') { $r[$id].Status | Should -Be 'Skipped' -Because "$id without $ds" }
        }
    }

    It 'APP-01 to APP-03 and APP-05 are skipped without app registrations' {
        $s = Get-Fixture; Set-NotCollected $s 'Applications' 'Error'
        $r = Get-Result $s
        foreach ($id in 'APP-01', 'APP-02', 'APP-03', 'APP-05') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
        $r['APP-04'].Status | Should -Be 'Fail'
    }
}

Describe 'Service accounts' {
    It 'SVC-01 warns on a secret added to an enterprise app, leaving out SAML signing, managed identity and expired certificates' {
        $s = Get-Fixture
        $r = (Get-Result $s)['SVC-01']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Westmark Mail Assistant')
        $r.Findings[0].Detail | Should -Be "Secret 'sync', valid to 2028-08-01"
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Mail Assistant').passwordCredentials = @()
        (Get-Result $s)['SVC-01'].Status | Should -Be 'Pass'
    }

    It 'SVC-01 reports a Verify certificate that is not paired with a signing key' {
        $s = Get-Fixture
        $sp = Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Intranet'
        $sp.keyCredentials = @($sp.keyCredentials | Where-Object usage -eq 'Verify')
        Get-Subject (Get-Result $s)['SVC-01'] | Should -Contain 'Westmark Intranet'
    }

    It 'SVC-01 counts, but does not list, apps named in AcceptedApps' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.AcceptedApps = @('00000000-0000-4000-8000-000000000702')
        $r = (Get-Result (Get-Fixture) $p)['SVC-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 credential\(s\) on apps listed in AcceptedApps'
    }

    It 'SVC-01, SVC-03 and SVC-04 are skipped on a snapshot from before service principal details, not passed' {
        # Older snapshots have service principals without credentials, owner or state.
        $s = Get-Fixture
        $s.SchemaVersion = 2
        $r = Get-Result $s
        foreach ($id in 'SVC-01', 'SVC-03', 'SVC-04') {
            $r[$id].Status | Should -Be 'Skipped' -Because $id
            $r[$id].Summary | Should -Match 'ServicePrincipalDetails was not collected \(NotCollected\): The snapshot has schema 2' -Because $id
        }
        $r['SVC-02'].Status | Should -Be 'Fail'
    }

    It 'SVC-01, SVC-03 and SVC-04 are skipped when the service principals could not be read' {
        $s = Get-Fixture; Set-NotCollected $s 'ServicePrincipals' 'Denied'
        $r = Get-Result $s
        foreach ($id in 'SVC-01', 'SVC-03', 'SVC-04') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
    }

    It 'SVC-02 fails on an app in a privileged role, including through a group, and passes without one' {
        $s = Get-Fixture
        $r = (Get-Result $s)['SVC-02']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('Westmark Provisioning')
        $r.Findings[0].Detail | Should -Be 'User Administrator (Active)'
        (Get-FixtureItem $s 'RoleGroupMembers' 'groupId' '00000000-0000-4000-8000-000000000101').members += [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.servicePrincipal'; id = '00000000-0000-4000-8000-000000000606'; displayName = 'Westmark HR Sync' }
        $r = (Get-Result $s)['SVC-02']
        @($r.Findings | Where-Object Subject -eq 'Westmark HR Sync')[0].Detail | Should -Be 'Helpdesk Administrator via Helpdesk Tier 2 (Active)'
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-07'
        (Get-FixtureItem $s 'RoleGroupMembers' 'groupId' '00000000-0000-4000-8000-000000000101').members = @(
            (Get-FixtureItem $s 'RoleGroupMembers' 'groupId' '00000000-0000-4000-8000-000000000101').members | Where-Object id -ne '00000000-0000-4000-8000-000000000606')
        (Get-Result $s)['SVC-02'].Status | Should -Be 'Pass'
    }

    It 'SVC-02 counts, but does not list, apps named in AcceptedApps, and is skipped without role assignments' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.AcceptedApps = @('Westmark Provisioning')
        $r = (Get-Result (Get-Fixture) $p)['SVC-02']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 app\(s\) listed in AcceptedApps'
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Error'
        (Get-Result $s)['SVC-02'].Status | Should -Be 'Skipped'
    }

    It 'SVC-03 fails on an app from another organization with a high-risk permission, and passes once it is this tenant''s or Microsoft''s' {
        $s = Get-Fixture
        $r = (Get-Result $s)['SVC-03']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('Westmark Backup')
        $r.Findings[0].Detail | Should -Be 'Files.ReadWrite.All (application); published by tenant 00000000-0000-4000-8000-000000000888'
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Backup').appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        (Get-Result $s)['SVC-03'].Status | Should -Be 'Pass'
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Backup').appOwnerOrganizationId = '00000000-0000-4000-8000-000000000999'
        (Get-Result $s)['SVC-03'].Status | Should -Be 'Pass'
    }

    It 'SVC-03 counts tenant-wide delegated consent, but not one user''s' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Mail Assistant').appOwnerOrganizationId = '00000000-0000-4000-8000-000000000888'
        $r = (Get-Result $s)['SVC-03']
        Get-Subject $r | Should -Be @('Westmark Backup', 'Westmark Mail Assistant')
        @($r.Findings | Where-Object Subject -eq 'Westmark Mail Assistant')[0].Detail | Should -Match '^Mail\.ReadWrite \(delegated, every user\), Mail\.Send \(delegated, every user\);'
        # Pocket Files Sync is from another organization too, but only two users consented.
        Get-Subject $r | Should -Not -Contain 'Pocket Files Sync'
    }

    It 'SVC-03 is skipped when the snapshot has no tenant ID' {
        $s = Get-Fixture; $s.TenantId = ''
        $r = (Get-Result $s)['SVC-03']
        $r.Status | Should -Be 'Skipped'
        $r.Summary | Should -Match "doesn't record the tenant's ID"
    }

    It 'SVC-04 warns on a disabled app that still holds a permission, and passes once it holds none' {
        $s = Get-Fixture
        $r = (Get-Result $s)['SVC-04']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Old Reporting Connector')
        $r.Findings[0].Detail | Should -Be 'Disabled, still holds: Reports.Read.All (application)'
        Remove-FixtureItem $s 'GraphPermissionGrants' 'principalDisplayName' 'Old Reporting Connector'
        (Get-Result $s)['SVC-04'].Status | Should -Be 'Pass'
    }

    It 'SVC-04 counts a role and a delegated grant held by a disabled app' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Provisioning').accountEnabled = $false
        (Get-FixtureItem $s 'ServicePrincipals' 'displayName' 'Westmark Intranet').accountEnabled = $false
        $r = (Get-Result $s)['SVC-04']
        @($r.Findings | Where-Object Subject -eq 'Westmark Provisioning')[0].Detail | Should -Be 'Disabled, still holds: User Administrator'
        @($r.Findings | Where-Object Subject -eq 'Westmark Intranet')[0].Detail | Should -Match 'delegated: openid profile User\.Read'
    }
    It 'SVC-05 fails on an owner who could add a secret to an app with high-risk access, leaving out app admins' {
        $r = (Get-Result (Get-Fixture))['SVC-05']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('new.hire@westmark.example')
        $r.Findings[0].Detail | Should -Be 'Owns the enterprise app Westmark HR Sync, which holds User.ReadWrite.All'
        # Avery Lee owns the HR Sync app registration but is a Global Administrator.
        $r.Summary | Should -Match '1 owner\(s\) who already hold an admin role over apps'
    }

    It 'SVC-05 counts app registration owners and apps in privileged roles' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Applications' 'displayName' 'Westmark HR Sync').owners = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = '00000000-0000-4000-8000-000000000014' })
        (Get-FixtureItem $s 'AppOwners' 'displayName' 'Westmark Provisioning').owners = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = '00000000-0000-4000-8000-000000000007'; displayName = 'Jo Park'; userPrincipalName = 'jo.park@westmark.example' })
        $r = (Get-Result $s)['SVC-05']
        Get-Subject $r | Should -Be @('jo.park@westmark.example', 'new.hire@westmark.example', 'riley.ng@westmark.example')
        @($r.Findings | Where-Object Subject -eq 'riley.ng@westmark.example')[0].Detail | Should -Be 'Owns the app registration Westmark HR Sync, which holds User.ReadWrite.All'
        @($r.Findings | Where-Object Subject -eq 'jo.park@westmark.example')[0].Detail | Should -Be 'Owns the enterprise app Westmark Provisioning, which holds User Administrator'
    }

    It 'SVC-05 passes when no one else owns those apps, and counts AcceptedApps' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'AppOwners' 'displayName' 'Westmark HR Sync').owners = @()
        (Get-Result $s)['SVC-05'].Status | Should -Be 'Pass'
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.AcceptedApps = @('Westmark HR Sync')
        $r = (Get-Result (Get-Fixture) $p)['SVC-05']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 app\(s\) listed in AcceptedApps'
    }

    It 'SVC-05 is skipped when the app owners could not be read' {
        $s = Get-Fixture; Set-NotCollected $s 'AppOwners' 'NotCollected'
        (Get-Result $s)['SVC-05'].Status | Should -Be 'Skipped'
    }
}

Describe 'Conditional Access' {
    It 'CA-01 fails when the all-users MFA policy covers only some apps, and passes when it covers all' {
        $s = Get-Fixture
        (Get-Result $s)['CA-01'].Status | Should -Be 'Fail'
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365').conditions.applications.includeApplications = @('All')
        $r = (Get-Result $s)['CA-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'Require MFA for Office 365'
    }

    It 'CA-01 accepts an authentication strength in place of MFA' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.applications.includeApplications = @('All')
        $p.grantControls.builtInControls = @()
        $p.grantControls.authenticationStrength = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA' }
        (Get-Result $s)['CA-01'].Status | Should -Be 'Pass'
    }

    It 'CA-01 does not count a disabled policy' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.applications.includeApplications = @('All')
        $p.state = 'disabled'
        (Get-Result $s)['CA-01'].Status | Should -Be 'Fail'
    }

    It 'CA-01 to CA-03 pass with security defaults on, even without Conditional Access' {
        $s = Get-Fixture
        $s.Datasets.SecurityDefaults.Items[0].isEnabled = $true
        Set-NotCollected $s 'ConditionalAccess'
        $r = Get-Result $s
        foreach ($id in 'CA-01', 'CA-02', 'CA-03') {
            $r[$id].Status | Should -Be 'Pass' -Because $id
            $r[$id].Summary | Should -Match '^Security defaults are on'
        }
        $r['CA-04'].Status | Should -Be 'Skipped'
        $r['CA-05'].Status | Should -Be 'Skipped'
    }

    It 'CA-01 to CA-03 fail with security defaults off and no Conditional Access licence' {
        $s = Get-Fixture; Set-NotCollected $s 'ConditionalAccess' 'NotLicensed'
        $r = Get-Result $s
        foreach ($id in 'CA-01', 'CA-02', 'CA-03') {
            $r[$id].Status | Should -Be 'Fail' -Because $id
            $r[$id].Summary | Should -Match 'no Conditional Access licence'
        }
    }

    It 'CA-01 to CA-03 are skipped when neither Conditional Access nor security defaults could be read' {
        $s = Get-Fixture; Set-NotCollected $s 'ConditionalAccess' 'Denied'; Set-NotCollected $s 'SecurityDefaults' 'Denied'
        $r = Get-Result $s
        foreach ($id in 'CA-01', 'CA-02', 'CA-03') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
    }

    It 'CA-02 fails when the admin policy is off' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for admins').state = 'disabled'
        (Get-Result $s)['CA-02'].Status | Should -Be 'Fail'
    }

    It 'CA-03 fails while the block is report-only, and passes once it is on' {
        $s = Get-Fixture
        (Get-Result $s)['CA-03'].Status | Should -Be 'Fail'
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Block legacy authentication').state = 'enabled'
        (Get-Result $s)['CA-03'].Status | Should -Be 'Pass'
    }

    It 'CA-03 needs both legacy client types blocked' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Block legacy authentication'
        $p.state = 'enabled'
        $p.conditions.clientAppTypes = @('exchangeActiveSync')
        (Get-Result $s)['CA-03'].Status | Should -Be 'Fail'
    }

    It 'CA-04 warns on a report-only policy, and passes once it is on' {
        $s = Get-Fixture
        $r = (Get-Result $s)['CA-04']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Block legacy authentication')
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Block legacy authentication').state = 'enabled'
        (Get-Result $s)['CA-04'].Status | Should -Be 'Pass'
    }

    It 'CA-05 warns on exclusions beyond break-glass, naming the accounts' {
        $r = (Get-Result (Get-Fixture))['CA-05']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | ForEach-Object Detail) | Should -Be @(
            "Excludes 1 account(s) that aren't break-glass: jo.park@westmark.example"
            ("Excludes group 'Travel Exemptions'; 1 member(s) that aren't break-glass bypass it: sam.ortiz@westmark.example; " +
                "it isn't role-assignable, so Groups, User and Intune Administrators can add anyone to it; " +
                'its 1 owner(s) can add anyone to it: dana.kim@westmark.example')
        )
    }

    It 'CA-05 expects a role-assignable, ownerless group holding only break-glass accounts' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne (Get-UserId $s 'jo.park@westmark.example') })
        $g = $s.Datasets.CaGroups.Items[0]
        $g.isAssignableToRole = $true
        $g.owners = @()
        $g.members = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = (Get-UserId $s 'bg.one@westmark.example'); userPrincipalName = 'bg.one@westmark.example' })
        $r = (Get-Result $s)['CA-05']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '1 exclusion\(s\) of a role-assignable, ownerless group holding only break-glass accounts are expected'
    }

    It 'CA-05 flags an excluded group that no longer exists' {
        $s = Get-Fixture
        $g = $s.Datasets.CaGroups.Items[0]
        $g.found = $false; $g.members = @(); $g.owners = @()
        $r = (Get-Result $s)['CA-05']
        @($r.Findings | ForEach-Object Detail) | Should -Contain 'Excludes group 00000000-0000-4000-8000-000000000103, which no longer exists. Remove it from the policy.'
    }

    It 'CA-05 still warns on an excluded group when its members weren''t collected' {
        $s = Get-Fixture
        $s.SchemaVersion = 5
        $s.Datasets.PSObject.Properties.Remove('CaGroups')
        $r = (Get-Result $s)['CA-05']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | ForEach-Object Detail) | Should -Contain "Excludes 1 group(s) whose members weren't collected; they bypass the policy"
    }

    It 'CA-05 passes when only break-glass accounts are excluded' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne (Get-UserId $s 'jo.park@westmark.example') })
        $p.conditions.users.excludeGroups = @()
        (Get-Result $s)['CA-05'].Status | Should -Be 'Pass'
    }

    It 'CA-05 says there is nothing to exclude from when no policy is enabled' {
        $s = Get-Fixture
        foreach ($p in $s.Datasets.ConditionalAccess.Items) { $p.state = 'disabled' }
        $r = (Get-Result $s)['CA-05']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Be 'No policy is enabled, so none has exclusions.'
    }

    It 'CA-05 reports the break-glass exclusions too when none are named' {
        $r = (Get-Result (Get-Fixture) (Get-AuditProfile))['CA-05']
        @($r.Findings).Count | Should -Be 3
    }
}

Describe 'Tenant settings' {
    BeforeAll {
        function Get-Policy {
            param($Snapshot, [string]$Dataset)
            $Snapshot.Datasets.$Dataset.Items[0]
        }

        function Set-BreakGlassTested {
            # Gives both break-glass accounts a recent test sign-in.
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes a test copy of the fixture in memory only.')]
            param($Snapshot)
            foreach ($upn in 'bg.one@westmark.example', 'bg.two@westmark.example') {
                $u = Get-FixtureItem $Snapshot 'Users' 'userPrincipalName' $upn
                $u | Add-Member -NotePropertyName signInActivity -NotePropertyValue ([pscustomobject]@{ lastSignInDateTime = '2026-10-15T09:00:00Z' }) -Force
            }
        }
    }

    It 'TEN-01 fails when users can consent to any app' {
        $r = (Get-Result (Get-Fixture))['TEN-01']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('User consent')
    }

    It 'TEN-01 fails when users can consent to apps Microsoft flags as risky' {
        $s = Get-Fixture
        $p = Get-Policy $s 'AuthorizationPolicy'
        $p.defaultUserRolePermissions.permissionGrantPoliciesAssigned = @($LowConsentPolicy)
        $p.allowUserConsentForRiskyApps = $true
        $r = (Get-Result $s)['TEN-01']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('Risky apps')
    }

    It 'TEN-01 warns on a custom consent policy' {
        $s = Get-Fixture
        (Get-Policy $s 'AuthorizationPolicy').defaultUserRolePermissions.permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.westmark-sales-apps')
        $r = (Get-Result $s)['TEN-01']
        $r.Status | Should -Be 'Warn'
        $r.Findings[0].Detail | Should -Be 'Custom consent policy: westmark-sales-apps'
    }

    It 'TEN-01 passes on Microsoft''s managed consent policies, which are not custom' {
        # Regression: 0.5.1 warned that the recommended and mail client
        # policies, the default in a new tenant, were custom.
        $s = Get-Fixture
        (Get-Policy $s 'AuthorizationPolicy').defaultUserRolePermissions.permissionGrantPoliciesAssigned = @($RecommendedConsentPolicy, $MailAppsConsentPolicy)
        $r = (Get-Result $s)['TEN-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^Microsoft manages user consent'
        $r.Summary | Should -Match 'popular mail apps'
        @($r.Findings).Count | Should -Be 0
    }

    It 'TEN-01 passes with consent for verified publishers only, or none' {
        $s = Get-Fixture
        $p = Get-Policy $s 'AuthorizationPolicy'
        $p.defaultUserRolePermissions.permissionGrantPoliciesAssigned = @($LowConsentPolicy, 'ManageChatResourceSpecificConsent')
        $r = (Get-Result $s)['TEN-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'verified publishers'
        $p.defaultUserRolePermissions.permissionGrantPoliciesAssigned = @()
        $r = (Get-Result $s)['TEN-01']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^Users cannot consent'
    }

    It 'TEN-01 is an error, not a pass, when the policy dataset holds nothing' {
        $s = Get-Fixture; $s.Datasets.AuthorizationPolicy.Items = @()
        $r = Get-Result $s
        foreach ($id in 'TEN-01', 'TEN-02', 'TEN-03') {
            $r[$id].Status | Should -Be 'Error' -Because $id
            $r[$id].Summary | Should -Match 'holds 0 policies' -Because $id
        }
    }

    It 'TEN-02 warns when users can register apps, and on tenant creation too' {
        $s = Get-Fixture
        $r = (Get-Result $s)['TEN-02']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('App registrations')
        (Get-Policy $s 'AuthorizationPolicy').defaultUserRolePermissions.allowedToCreateTenants = $true
        Get-Subject (Get-Result $s)['TEN-02'] | Should -Be @('App registrations', 'Tenant creation')
    }

    It 'TEN-02 passes when both are off' {
        $s = Get-Fixture
        (Get-Policy $s 'AuthorizationPolicy').defaultUserRolePermissions.allowedToCreateApps = $false
        (Get-Result $s)['TEN-02'].Status | Should -Be 'Pass'
    }

    It 'TEN-03 warns when anyone can invite guests, and on member-level guests and self-service sign-up' {
        $s = Get-Fixture
        $r = (Get-Result $s)['TEN-03']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Guest invitations')
        $p = Get-Policy $s 'AuthorizationPolicy'
        $p.guestUserRoleId = $MemberGuestRoleId
        $p.allowEmailVerifiedUsersToJoinOrganization = $true
        $r = (Get-Result $s)['TEN-03']
        Get-Subject $r | Should -Be @('Guest access', 'Guest invitations', 'Self-service sign-up')
        $r.Summary | Should -Match 'Guests have the same access as members'
    }

    It 'TEN-03 passes with limited guests and invitations kept to admins' {
        $s = Get-Fixture
        (Get-Policy $s 'AuthorizationPolicy').allowInvitesFrom = 'adminsAndGuestInviters'
        $r = (Get-Result $s)['TEN-03']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Be 'Guests have limited access (the default), and invitations are limited to adminsAndGuestInviters.'
    }

    It 'TEN-01 to TEN-03 are skipped without the authorization policy' {
        $s = Get-Fixture; Set-NotCollected $s 'AuthorizationPolicy' 'Denied'
        $r = Get-Result $s
        foreach ($id in 'TEN-01', 'TEN-02', 'TEN-03') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
    }

    It 'TEN-04 warns on text message and voice call' {
        $s = Get-Fixture
        $r = (Get-Result $s)['TEN-04']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Text message (SMS)')
        @((Get-Policy $s 'AuthMethodsPolicy').methods | Where-Object id -eq 'Voice')[0].state = 'enabled'
        Get-Subject (Get-Result $s)['TEN-04'] | Should -Be @('Text message (SMS)', 'Voice call')
    }

    It 'TEN-04 passes with both off, and says when the legacy settings still apply' {
        $s = Get-Fixture
        $p = Get-Policy $s 'AuthMethodsPolicy'
        @($p.methods | Where-Object id -eq 'Sms')[0].state = 'disabled'
        $r = (Get-Result $s)['TEN-04']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Not -Match 'legacy'
        $p.policyMigrationState = 'migrationInProgress'
        (Get-Result $s)['TEN-04'].Summary | Should -Match 'legacy MFA and SSPR settings still apply too \(migration state: migrationInProgress\)'
    }

    It 'TEN-04 is skipped without the authentication methods policy' {
        $s = Get-Fixture; Set-NotCollected $s 'AuthMethodsPolicy' 'Denied'
        (Get-Result $s)['TEN-04'].Status | Should -Be 'Skipped'
    }

    It 'TEN-05 passes on Microsoft''s defaults' {
        $r = (Get-Result (Get-Fixture))['TEN-05']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'Microsoft''s defaults'
    }

    It 'TEN-05 warns when B2B direct connect or automatic redemption is open to every organization' {
        $s = Get-Fixture
        $p = Get-Policy $s 'CrossTenantAccess'
        $p.isServiceDefault = $false
        $p.b2bDirectConnectInbound.usersAndGroups.accessType = 'allowed'
        $p.automaticUserConsentSettings.outboundAllowed = $true
        $r = (Get-Result $s)['TEN-05']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Automatic redemption (outbound)', 'B2B direct connect (inbound)')
        @($r.Findings | Where-Object Subject -eq 'B2B direct connect (inbound)')[0].Detail | Should -Match 'Allowed for all users'
    }

    It 'TEN-05 is skipped without the cross-tenant settings' {
        $s = Get-Fixture; Set-NotCollected $s 'CrossTenantAccess' 'Denied'
        (Get-Result $s)['TEN-05'].Status | Should -Be 'Skipped'
    }

    It 'TEN-06 passes when both break-glass accounts are ready' {
        $s = Get-Fixture; Set-BreakGlassTested $s
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^All 2 break-glass accounts .* outside every enforced Conditional Access policy and signed in within 90 days\.$'
    }

    It 'TEN-06 warns on a break-glass account never tested, or not in 90 days' {
        $r = (Get-Result (Get-Fixture))['TEN-06']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | ForEach-Object { "$($_.Subject): $($_.Detail)" }) | Should -Be @(
            'bg.one@westmark.example: Last signed in 2026-01-15. Test it at least every 90 days.'
            'bg.two@westmark.example: No sign-in recorded, so it has never been tested. Test it at least every 90 days. Sign-in activity can take a few hours to appear.'
        )
    }

    It 'TEN-06 says the test sign-in was not checked without sign-in activity' {
        $s = Get-Fixture; Set-NotCollected $s 'SignIns'
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'Conditional Access policy\. Sign-in activity wasn''t collected, so the last test sign-in wasn''t checked\.$'
    }

    It 'TEN-06 fails on a break-glass account an enforced Conditional Access policy reaches' {
        $s = Get-Fixture; Set-BreakGlassTested $s
        $two = Get-UserId $s 'bg.two@westmark.example'
        foreach ($name in 'Require MFA for Office 365', 'Block legacy authentication') {
            $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' $name
            $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne $two })
        }
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Fail'
        # The report-only policy enforces nothing, so it isn't named.
        @($r.Findings | ForEach-Object { "$($_.Subject): $($_.Detail)" }) | Should -Be @(
            'bg.two@westmark.example: Enforced Conditional Access applies to it, so an outage of what a policy requires can lock it out. Exclude it from: Require MFA for Office 365.'
        )
    }

    It 'TEN-06 counts an exclusion through a group or a role, and a policy aimed elsewhere' {
        $s = Get-Fixture; Set-BreakGlassTested $s
        $two = Get-UserId $s 'bg.two@westmark.example'
        foreach ($p in $s.Datasets.ConditionalAccess.Items) { $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne $two }) }
        $s.Datasets.CaGroups.Items[0].members = @($s.Datasets.CaGroups.Items[0].members) + [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = $two; userPrincipalName = 'bg.two@westmark.example' }
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for admins').conditions.users.excludeRoles = @($GlobalAdminRoleId)
        (Get-Result $s)['TEN-06'].Status | Should -Be 'Pass'
        # A policy for one group bg.two isn't in doesn't reach it either.
        (Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for admins').conditions.users.excludeRoles = @()
        $admins = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for admins'
        $admins.conditions.users.includeRoles = @()
        $admins.conditions.users.includeGroups = @('00000000-0000-4000-8000-000000000103')
        $s.Datasets.CaGroups.Items[0].members = @($s.Datasets.CaGroups.Items[0].members | Where-Object { $_.id -ne $two })
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers) + $two
        (Get-Result $s)['TEN-06'].Status | Should -Be 'Pass'
    }

    It 'TEN-06 warns when a policy turns on a group whose members weren''t collected' {
        $s = Get-Fixture; Set-BreakGlassTested $s
        $s.SchemaVersion = 5
        $s.Datasets.PSObject.Properties.Remove('CaGroups')
        $two = Get-UserId $s 'bg.two@westmark.example'
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne $two })
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Warn'
        @($r.Findings | ForEach-Object { "$($_.Subject): $($_.Detail)" }) | Should -Be @(
            "bg.two@westmark.example: Couldn't tell whether these policies apply, because their groups' members weren't collected: Require MFA for Office 365."
        )
    }

    It 'TEN-06 warns when Conditional Access was denied, rather than passing' {
        $s = Get-Fixture; Set-BreakGlassTested $s; Set-NotCollected $s 'ConditionalAccess' 'Denied'
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('Conditional Access')
    }

    It 'TEN-06 fails on a break-glass account that is missing, disabled, synced or without Global Administrator' {
        $s = Get-Fixture
        $two = Get-FixtureItem $s 'Users' 'userPrincipalName' 'bg.two@westmark.example'
        $two.accountEnabled = $false
        $two.onPremisesSyncEnabled = $true
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-03'
        $bgProfile = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1')
        $bgProfile.BreakGlassAccounts = @('bg.one@westmark.example', 'bg.two@westmark.example', 'bg.three@westmark.example')
        Set-BreakGlassTested $s
        $r = (Get-Result $s $bgProfile)['TEN-06']
        $r.Status | Should -Be 'Fail'
        @($r.Findings | ForEach-Object { "$($_.Subject): $($_.Detail)" }) | Should -Be @(
            'bg.two@westmark.example: Disabled.'
            'bg.two@westmark.example: Synced from on-premises, so an outage there can lock it out.'
            'bg.two@westmark.example: Does not hold Global Administrator.'
            'bg.three@westmark.example: Not found in the tenant.'
        )
    }

    It 'TEN-06 fails on a break-glass account that is only eligible for Global Administrator' {
        $s = Get-Fixture
        $ra = Get-FixtureItem $s 'RoleAssignments' 'id' 'ra-03'
        Remove-FixtureItem $s 'RoleAssignments' 'id' 'ra-03'
        $s.Datasets.RoleEligibility.Items = @($s.Datasets.RoleEligibility.Items) + $ra
        $r = (Get-Result $s)['TEN-06']
        $r.Status | Should -Be 'Fail'
        $r.Findings[0].Detail | Should -Match '^Only eligible for Global Administrator'
    }

    It 'TEN-06 warns when no break-glass account, or only one, is listed' {
        $s = Get-Fixture
        $r = (Get-Result $s (Get-AuditProfile))['TEN-06']
        $r.Status | Should -Be 'Warn'
        $r.Summary | Should -Match '^No break-glass accounts are listed'
        $oneProfile = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1')
        $oneProfile.BreakGlassAccounts = @('bg.one@westmark.example')
        Set-BreakGlassTested $s
        $r = (Get-Result $s $oneProfile)['TEN-06']
        $r.Status | Should -Be 'Warn'
        $r.Findings[0].Detail | Should -Match '^The only break-glass account\.'
    }

    It 'TEN-06 is skipped without the role assignments' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Denied'
        (Get-Result $s)['TEN-06'].Status | Should -Be 'Skipped'
    }

    It 'TEN-01 to TEN-05 are skipped on a snapshot from before schema 5, not passed' {
        $s = Get-Fixture; Set-BreakGlassTested $s
        $s.SchemaVersion = 4
        foreach ($name in 'AuthorizationPolicy', 'AuthMethodsPolicy', 'CrossTenantAccess') { $s.Datasets.PSObject.Properties.Remove($name) }
        $r = Get-Result $s
        foreach ($id in 'TEN-01', 'TEN-02', 'TEN-03', 'TEN-04', 'TEN-05') {
            $r[$id].Status | Should -Be 'Skipped' -Because $id
            $r[$id].Summary | Should -Match 'was not collected \(NotCollected\): The snapshot has schema 4, from before' -Because $id
        }
        $r['TEN-06'].Status | Should -Be 'Pass'
    }

    It 'TEN-07 warns on a trial that is the only source of P2, naming the checks that need P2' {
        $r = (Get-Result (Get-Fixture))['TEN-07']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('AAD_PREMIUM_P2 (trial)')
        $r.Findings[0].Detail | Should -Match '^Carries Microsoft Entra ID P2\. The trial ends 2026-11-13, in 12 day\(s\)'
        $r.Findings[0].Detail | Should -Match 'Without it, these checks are Skipped: ROLE-08, ROLE-10, ROLE-12\.$'
    }

    It 'TEN-07 passes when a paid subscription carries P2 too' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'SPE_E3').servicePlans = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Be 'Microsoft Entra ID P1 and Microsoft Entra ID P2 come from a subscription that isn''t a trial ending within 30 days.'
    }

    It 'TEN-07 ignores a paid subscription''s renewal date, even within the window' {
        # The fixture's paid SPE_E3 next changes state 2026-11-15, 14 days
        # after collection; for a paid subscription that is its renewal.
        $s = Get-Fixture; Remove-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'AAD_PREMIUM_P2'
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^Microsoft Entra ID P1 comes from'
    }

    It 'TEN-07 lists a trial once, with the checks for P1 and P2, when it is the only source of both' {
        $s = Get-Fixture; Remove-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'SPE_E3'
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Warn'
        Get-Subject $r | Should -Be @('AAD_PREMIUM_P2 (trial)')
        $r.Findings[0].Detail | Should -Match '^Carries Microsoft Entra ID P1 and Microsoft Entra ID P2\.'
        $r.Findings[0].Detail | Should -Match 'Without them, these checks are Skipped: ROLE-05, ROLE-08, .*STALE-01, .*CA-05\.$'
    }

    It 'TEN-07 follows LicenceExpiryDays' {
        $p = Get-AuditProfile -Path (Join-Path $PSScriptRoot 'fixtures/westmark.psd1'); $p.LicenceExpiryDays = 10
        $r = (Get-Result (Get-Fixture) $p)['TEN-07']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'within 10 days'
    }

    It 'TEN-07 says when a trial has already ended' {
        $s = Get-Fixture
        (Get-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'AAD_PREMIUM_P2').nextLifecycleDateTime = '2026-10-30T00:00:00Z'
        (Get-Result $s)['TEN-07'].Findings[0].Detail | Should -Match 'The trial ended 2026-10-30,'
    }

    It 'TEN-07 fails on the only source of P1 when it is <State>' -ForEach @(
        @{ State = 'Warning'; Expected = 'Expired, and in its grace period until 2026-11-15; renew it before then\.' }
        @{ State = 'Suspended'; Expected = 'Suspended, so what it carries is already off\.' }
        @{ State = 'LockedOut'; Expected = 'LockedOut, so what it carries is already off\.' }
    ) {
        $s = Get-Fixture; Remove-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'AAD_PREMIUM_P2'
        (Get-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'SPE_E3').status = $State
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Fail'
        Get-Subject $r | Should -Be @('SPE_E3')
        $r.Findings[0].Detail | Should -Match $Expected
    }

    It 'TEN-07 leaves out deleted subscriptions and passes when nothing carries P1 or P2' {
        $s = Get-Fixture; Remove-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'AAD_PREMIUM_P2'
        (Get-FixtureItem $s 'Subscriptions' 'skuPartNumber' 'SPE_E3').status = 'Deleted'
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match '^No subscription carries Microsoft Entra ID P1 or P2'
    }

    It 'TEN-07 is skipped without the subscriptions, and on a snapshot from before schema 7' {
        $s = Get-Fixture; Set-NotCollected $s 'Subscriptions' 'Denied'
        (Get-Result $s)['TEN-07'].Status | Should -Be 'Skipped'
        $s = Get-Fixture; $s.SchemaVersion = 6; $s.Datasets.PSObject.Properties.Remove('Subscriptions')
        $r = (Get-Result $s)['TEN-07']
        $r.Status | Should -Be 'Skipped'
        $r.Summary | Should -Match 'The snapshot has schema 6, from before Subscriptions was collected'
    }
}

Describe 'Check runner' {
    It 'turns a check that throws into an Error, and carries on' {
        $s = Get-Fixture
        $s.Datasets.Applications.Items[0].passwordCredentials[0].endDateTime = 'not a date'
        $r = Get-Result $s
        $r['APP-01'].Status | Should -Be 'Error'
        $r['APP-01'].Summary | Should -Match '^The check failed'
        $r['APP-05'].Status | Should -Be 'Warn'
    }

    It 'treats a dataset missing from the snapshot as not collected' {
        $s = Get-Fixture
        $s.Datasets.PSObject.Properties.Remove('GraphPermissionGrants')
        $r = (Get-Result $s)['APP-04']
        $r.Status | Should -Be 'Skipped'
        $r.Summary | Should -Match 'GraphPermissionGrants was not collected \(NotCollected\)'
    }

    It 'judges dates against the collection time, not the clock' {
        # The fixture's certificate expires 2026-11-20, 19 days after collection.
        (Get-Result (Get-Fixture))['APP-02'].Findings[0].Detail | Should -Match '2026-11-20'
    }
}
