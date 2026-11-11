# Pester tests for the collector, with Microsoft Graph replaced by a mock: paging,
# licence and permission failures, the fallbacks, and that what it collects
# survives the JSON round trip the same way on both editions. No tenant needed.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'Invoke-EntraAccessAudit.ps1')

    function New-GraphError {
        # The shape Invoke-MgGraphRequest throws: status in the message, Graph's
        # error body in ErrorDetails.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that changes nothing outside the test.')]
        param([string]$Message, [string]$Body = '')
        $record = [Management.Automation.ErrorRecord]::new([Exception]::new($Message), 'GraphError', 'InvalidOperation', $null)
        if ($Body) { $record.ErrorDetails = [Management.Automation.ErrorDetails]::new($Body) }
        return $record
    }

    $script:NotLicensed = New-GraphError 'Response status code does not indicate success: Forbidden (Forbidden).' `
        '{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant does not have premium license"}}'
    $script:Denied = New-GraphError 'Response status code does not indicate success: Forbidden (Forbidden).' `
        '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}'
    $script:BadRequest = New-GraphError 'Response status code does not indicate success: BadRequest (Bad Request).' `
        '{"error":{"code":"BadRequest","message":"Expand is not supported here."}}'

    function ConvertTo-Page {
        param($Items, [string]$Next)
        $page = [ordered]@{ value = @($Items) }
        if ($Next) { $page['@odata.nextLink'] = $Next }
        return ([pscustomobject]$page)
    }

    # A small tenant, keyed by request. Tests change it to make a read fail.
    function Reset-FakeGraph {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that changes nothing outside the test.')]
        param()
        $script:Fail = @{}
        $script:Calls = [Collections.Generic.List[string]]::new()
        $script:Pages = @{
            "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,signInActivity&`$top=500" =
            ConvertTo-Page @([pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@westmark.example'; userType = 'Member'; accountEnabled = $true
                    createdDateTime = [datetime]::new(2025, 1, 2, 3, 4, 5, [DateTimeKind]::Utc); signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-10-01T00:00:00Z' } }) 'page2'
            'page2' = ConvertTo-Page @([pscustomobject]@{ id = 'u2'; userPrincipalName = 'b@westmark.example'; userType = 'Guest'; accountEnabled = $true })
            "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime&`$top=999" =
            ConvertTo-Page @([pscustomobject]@{ id = 'u1' }, [pscustomobject]@{ id = 'u2' }, [pscustomobject]@{ id = 'u3' })
            '/v1.0/roleManagement/directory/roleDefinitions' = ConvertTo-Page @([pscustomobject]@{ id = $GlobalAdminRoleId; displayName = 'Global Administrator' })
            '/v1.0/roleManagement/directory/roleAssignments?$expand=principal' = ConvertTo-Page @([pscustomobject]@{ id = 'ra1'; principalId = 'u1'; roleDefinitionId = $GlobalAdminRoleId; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1' } })
            '/v1.0/roleManagement/directory/roleAssignments' = ConvertTo-Page @([pscustomobject]@{ id = 'ra1'; principalId = 'u1'; roleDefinitionId = $GlobalAdminRoleId })
            '/v1.0/roleManagement/directory/roleAssignmentSchedules' = ConvertTo-Page @()
            '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal' = ConvertTo-Page @()
            '/v1.0/reports/authenticationMethods/userRegistrationDetails' = ConvertTo-Page @([pscustomobject]@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('fido2SecurityKey') })
            '/v1.0/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$expand=owners($select=id)&$top=100' = ConvertTo-Page @([pscustomobject]@{ id = 'app1'; displayName = 'Westmark App'; passwordCredentials = @(); keyCredentials = @(); owners = @() })
            "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles" = [pscustomobject]@{ id = 'graph-sp'; appRoles = @(
                    [pscustomobject]@{ id = 'r1'; value = 'User.ReadWrite.All' }, [pscustomobject]@{ id = 'r2'; value = 'User.Read.All' }) }
            '/v1.0/servicePrincipals/graph-sp/appRoleAssignedTo?$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ principalId = 'sp1'; principalDisplayName = 'Westmark Sync'; principalType = 'ServicePrincipal'; appRoleId = 'r1'; createdDateTime = '2026-01-01T00:00:00Z' }
                [pscustomobject]@{ principalId = 'sp2'; principalDisplayName = 'Westmark Old'; principalType = 'ServicePrincipal'; appRoleId = 'gone'; createdDateTime = '2026-01-01T00:00:00Z' })
            '/v1.0/identity/conditionalAccess/policies' = ConvertTo-Page @([pscustomobject]@{ id = 'p1'; displayName = 'Policy'; state = 'enabled' })
            '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' = [pscustomobject]@{ id = 'sd'; isEnabled = $false }
        }
    }

    function Invoke-AuditGraphRequest {
        # Replaces the real one: serves Pages, or throws what Fail holds.
        param([string]$Uri)
        $script:Calls.Add($Uri)
        if ($script:Fail.ContainsKey($Uri)) { throw $script:Fail[$Uri] }
        if (-not $script:Pages.ContainsKey($Uri)) { throw "The fake Graph has no page for $Uri" }
        return $script:Pages[$Uri]
    }

    function Get-Collected {
        # Collects, then does the round trip the main script does.
        $snap = Get-TenantSnapshot -TenantId 'tenant' 6>$null
        return ((ConvertTo-SnapshotValue $snap) | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
    }

    $script:UsersWithSignIns = "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,signInActivity&`$top=500"
}

Describe 'Get-GraphErrorStatus' {
    It 'sorts <Text> as <Expected>' -ForEach @(
        @{ Text = 'Forbidden Authentication_RequestFromNonPremiumTenantOrB2CTenant'; Expected = 'NotLicensed' }
        @{ Text = 'The tenant needs an AAD Premium P2 license'; Expected = 'NotLicensed' }
        @{ Text = 'Forbidden Authorization_RequestDenied Insufficient privileges'; Expected = 'Denied' }
        @{ Text = 'Response status code does not indicate success: 401 (Unauthorized)'; Expected = 'Denied' }
        @{ Text = 'BadRequest: Expand is not supported'; Expected = 'Error' }
        @{ Text = 'The operation timed out'; Expected = 'Error' }
    ) {
        Get-GraphErrorStatus $Text | Should -Be $Expected
    }
}

Describe 'Get-TenantSnapshot' {
    BeforeEach { Reset-FakeGraph }

    It 'reads every dataset and follows nextLink pages' {
        $s = Get-Collected
        foreach ($p in $s.Datasets.PSObject.Properties) { $p.Value.Status | Should -Be 'Collected' -Because $p.Name }
        @($s.Datasets.Users.Items | ForEach-Object id) | Should -Be @('u1', 'u2')
        $Calls | Should -Contain 'page2'
        $s.SchemaVersion | Should -Be $SnapshotSchemaVersion
    }

    It 'sends nothing but the reads it lists' {
        $null = Get-Collected
        foreach ($c in $Calls) { $Pages.ContainsKey($c) | Should -BeTrue -Because $c }
    }

    It 'names each granted Graph permission, and keeps the ID when the role is unknown' {
        $s = Get-Collected
        @($s.Datasets.GraphPermissionGrants.Items | ForEach-Object permission) | Should -Be @('User.ReadWrite.All', 'gone')
    }

    It 'reads users without sign-in activity when the tenant has no P1, and marks SignIns NotLicensed' {
        $Fail[$UsersWithSignIns] = $NotLicensed
        $s = Get-Collected
        $s.Datasets.SignIns.Status | Should -Be 'NotLicensed'
        $s.Datasets.SignIns.Reason | Should -Match '^Needs Microsoft Entra ID P1\.'
        $s.Datasets.Users.Status | Should -Be 'Collected'
        @($s.Datasets.Users.Items).Count | Should -Be 3
    }

    It 'marks SignIns Denied when AuditLog.Read.All was not granted' {
        $Fail[$UsersWithSignIns] = $Denied
        $s = Get-Collected
        $s.Datasets.SignIns.Status | Should -Be 'Denied'
        $s.Datasets.Users.Status | Should -Be 'Collected'
    }

    It 'reads role assignments without expansion when the expanded read fails, and says so' {
        $Fail['/v1.0/roleManagement/directory/roleAssignments?$expand=principal'] = $BadRequest
        $s = Get-Collected
        $s.Datasets.RoleAssignments.Status | Should -Be 'Collected'
        $s.Datasets.RoleAssignments.Reason | Should -Match '^Read without principal details'
        @($s.Datasets.RoleAssignments.Items).Count | Should -Be 1
    }

    It 'does not retry role assignments without expansion when the read was denied' {
        $Fail['/v1.0/roleManagement/directory/roleAssignments?$expand=principal'] = $Denied
        $s = Get-Collected
        $s.Datasets.RoleAssignments.Status | Should -Be 'Denied'
        $Calls | Should -Not -Contain '/v1.0/roleManagement/directory/roleAssignments'
    }

    It 'marks PIM data NotLicensed without P2 and carries on' {
        $Fail['/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal'] = $NotLicensed
        $Fail['/v1.0/roleManagement/directory/roleAssignmentSchedules'] = $NotLicensed
        $s = Get-Collected
        $s.Datasets.RoleEligibility.Status | Should -Be 'NotLicensed'
        $s.Datasets.RoleEligibility.Reason | Should -Match 'P2'
        $s.Datasets.RoleAssignmentSchedules.Status | Should -Be 'NotLicensed'
        $s.Datasets.ConditionalAccess.Status | Should -Be 'Collected'
    }

    It 'records a failed read of security defaults and Graph grants' {
        $Fail['/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'] = $Denied
        $Fail["/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"] = $BadRequest
        $s = Get-Collected
        $s.Datasets.SecurityDefaults.Status | Should -Be 'Denied'
        $s.Datasets.GraphPermissionGrants.Status | Should -Be 'Error'
        @($s.Datasets.GraphPermissionGrants.Items).Count | Should -Be 0
    }

    It 'stores dates as ISO 8601 text, whatever the edition parsed them into' {
        $json = (ConvertTo-SnapshotValue (Get-TenantSnapshot -TenantId 'tenant' 6>$null)) | ConvertTo-Json -Depth 20
        $json | Should -Match '"createdDateTime":\s*"2025-01-02T03:04:05Z"'
        $json | Should -Not -Match 'Date\('
    }

    It 'keeps one-item and empty arrays as arrays through the round trip' {
        $s = Get-Collected
        , $s.Datasets.Registration.Items[0].methodsRegistered | Should -BeOfType [object[]]
        @($s.Datasets.Registration.Items[0].methodsRegistered) | Should -Be @('fido2SecurityKey')
        , $s.Datasets.RoleEligibility.Items | Should -BeOfType [object[]]
        @($s.Datasets.RoleEligibility.Items).Count | Should -Be 0
    }

    It 'collects a snapshot the checks can evaluate' {
        $s = Get-Collected
        $results = @(Invoke-AuditCheck -Snapshot $s -AuditProfile (Get-AuditProfile))
        $results.Count | Should -Be $AuditChecks.Count
        @($results | Where-Object Status -eq 'Error').Count | Should -Be 0
    }
}

Describe 'Read-only' {
    BeforeAll { $script:Source = [IO.File]::ReadAllText((Join-Path $Root 'Invoke-EntraAccessAudit.ps1')) }

    It 'calls Invoke-MgGraphRequest once, with GET' {
        $calls = [regex]::Matches($Source, 'Invoke-MgGraphRequest[^\r\n]*')
        $calls.Count | Should -Be 1
        $calls[0].Value | Should -Match '-Method GET\b'
    }

    It 'uses no Graph cmdlet that changes anything' {
        $Source | Should -Not -Match '\b(New|Set|Update|Remove|Add|Grant|Revoke|Invoke)-Mg(?!GraphRequest)\w+'
    }

    It 'asks only for read scopes' {
        foreach ($s in $AuditScopes) { $s | Should -Match '\.Read\.' }
    }
}
