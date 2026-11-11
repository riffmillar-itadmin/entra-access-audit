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
            'STALE-01' = 'Fail'; 'STALE-02' = 'Fail'; 'STALE-03' = 'Fail'; 'STALE-04' = 'Warn'
            'MFA-01' = 'Fail'; 'MFA-02' = 'Warn'; 'MFA-03' = 'Fail'
            'APP-01' = 'Warn'; 'APP-02' = 'Warn'; 'APP-03' = 'Warn'; 'APP-04' = 'Fail'; 'APP-05' = 'Warn'
            'CA-01' = 'Fail'; 'CA-02' = 'Pass'; 'CA-03' = 'Fail'; 'CA-04' = 'Warn'; 'CA-05' = 'Warn'
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
        Get-Subject $r | Should -Be @('dana.kim@westmark.example', 'sam.ortiz@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example')
    }

    It 'ROLE-05 passes when each privileged account has a passkey or security key' {
        $s = Get-Fixture
        foreach ($upn in 'dana.kim@westmark.example', 'sam.ortiz@westmark.example', 'vendor.ops_partner.example#EXT#@westmark.example') {
            (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).methodsRegistered = @('passKeyDeviceBoundAuthenticator')
        }
        (Get-Result $s)['ROLE-05'].Status | Should -Be 'Pass'
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

    It 'every privileged-role check is skipped without role assignments' {
        $s = Get-Fixture; Set-NotCollected $s 'RoleAssignments' 'Error'
        $r = Get-Result $s
        foreach ($id in 'ROLE-01', 'ROLE-02', 'ROLE-03', 'ROLE-04', 'ROLE-05', 'ROLE-06', 'MFA-03') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
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

    It 'MFA-01 passes when every member has registered' {
        $s = Get-Fixture
        foreach ($upn in 'jo.park@westmark.example', 'old.unused@westmark.example') { (Get-FixtureItem $s 'Registration' 'userPrincipalName' $upn).isMfaRegistered = $true }
        (Get-Result $s)['MFA-01'].Status | Should -Be 'Pass'
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
        Get-Subject $r | Should -Be @('vendor.ops_partner.example#EXT#@westmark.example')
        (Get-FixtureItem $s 'Registration' 'userPrincipalName' 'vendor.ops_partner.example#EXT#@westmark.example').isMfaRegistered = $true
        (Get-Result $s)['MFA-03'].Status | Should -Be 'Pass'
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

    It 'APP-01 to APP-03 and APP-05 are skipped without app registrations' {
        $s = Get-Fixture; Set-NotCollected $s 'Applications' 'Error'
        $r = Get-Result $s
        foreach ($id in 'APP-01', 'APP-02', 'APP-03', 'APP-05') { $r[$id].Status | Should -Be 'Skipped' -Because $id }
        $r['APP-04'].Status | Should -Be 'Fail'
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
            'Excludes 1 group(s); their members bypass the policy'
        )
    }

    It 'CA-05 passes when only break-glass accounts are excluded' {
        $s = Get-Fixture
        $p = Get-FixtureItem $s 'ConditionalAccess' 'displayName' 'Require MFA for Office 365'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers | Where-Object { $_ -ne (Get-UserId $s 'jo.park@westmark.example') })
        $p.conditions.users.excludeGroups = @()
        (Get-Result $s)['CA-05'].Status | Should -Be 'Pass'
    }

    It 'CA-05 reports the break-glass exclusions too when none are named' {
        $r = (Get-Result (Get-Fixture) (Get-AuditProfile))['CA-05']
        @($r.Findings).Count | Should -Be 3
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
