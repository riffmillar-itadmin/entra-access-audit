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
    $script:NotFound = New-GraphError 'Response status code does not indicate success: NotFound (Not Found).' `
        '{"error":{"code":"Request_ResourceNotFound","message":"Resource does not exist or one of its queried reference-property objects are not present."}}'
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
            "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,identities,signInActivity&`$top=500" =
            ConvertTo-Page @([pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@westmark.example'; userType = 'Member'; accountEnabled = $true
                    createdDateTime = [datetime]::new(2025, 1, 2, 3, 4, 5, [DateTimeKind]::Utc); signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-10-01T00:00:00Z' } }) 'page2'
            'page2' = ConvertTo-Page @([pscustomobject]@{ id = 'u2'; userPrincipalName = 'b@westmark.example'; userType = 'Guest'; accountEnabled = $true })
            "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,identities&`$top=999" =
            ConvertTo-Page @([pscustomobject]@{ id = 'u1' }, [pscustomobject]@{ id = 'u2' }, [pscustomobject]@{ id = 'u3' })
            '/v1.0/roleManagement/directory/roleDefinitions' = ConvertTo-Page @([pscustomobject]@{ id = $GlobalAdminRoleId; displayName = 'Global Administrator' })
            '/v1.0/roleManagement/directory/roleAssignments?$expand=principal' = ConvertTo-Page @(
                [pscustomobject]@{ id = 'ra1'; principalId = 'u1'; roleDefinitionId = $GlobalAdminRoleId; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1' } }
                [pscustomobject]@{ id = 'ra2'; principalId = 'g1'; roleDefinitionId = $GlobalAdminRoleId; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Westmark Admins' } })
            '/v1.0/roleManagement/directory/roleAssignments' = ConvertTo-Page @(
                [pscustomobject]@{ id = 'ra1'; principalId = 'u1'; roleDefinitionId = $GlobalAdminRoleId }
                [pscustomobject]@{ id = 'ra2'; principalId = 'g1'; roleDefinitionId = $GlobalAdminRoleId })
            '/v1.0/groups/g1/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; displayName = 'B'; userPrincipalName = 'b@westmark.example' })
            '/v1.0/groups/g1/owners?$select=id,displayName,userPrincipalName&$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; displayName = 'A'; userPrincipalName = 'a@westmark.example' })
            $RolePolicyUri = ConvertTo-Page @([pscustomobject]@{ id = 'pa1'; policyId = 'pol1'; roleDefinitionId = $GlobalAdminRoleId; scopeId = '/'
                    policy = [pscustomobject]@{ id = 'pol1'; rules = @(
                            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_EndUser_Assignment'; isExpirationRequired = $true; maximumDuration = 'PT8H'
                                target = [pscustomobject]@{ caller = 'EndUser'; operations = @('All'); level = 'Assignment' } }
                            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id = 'Approval_EndUser_Assignment'
                                setting = [pscustomobject]@{ isApprovalRequired = $true; approvalMode = 'SingleStage'; approvalStages = @([pscustomobject]@{ approvalStageTimeOutInDays = 1; primaryApprovers = @() }) } }
                            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'; id = 'Notification_Admin_Admin_Eligibility'; notificationType = 'Email'; notificationRecipients = @() }) } })
            $RoleAuditUri = ConvertTo-Page @([pscustomobject]@{ id = 'ae1'; category = 'RoleManagement'; activityDisplayName = 'Add member to role'; activityDateTime = '2026-10-01T00:00:00Z'; result = 'success'
                    loggedByService = 'Core Directory'; additionalDetails = @(); initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@westmark.example'; ipAddress = '192.0.2.1' }; app = $null }
                    targetResources = @([pscustomobject]@{ id = 'u2'; type = 'User'; userPrincipalName = 'b@westmark.example'; modifiedProperties = @() }) })
            '/v1.0/servicePrincipals/sp1/owners?$select=id,displayName,userPrincipalName&$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; displayName = 'B'; userPrincipalName = 'b@westmark.example' })
            '/v1.0/roleManagement/directory/roleAssignmentSchedules' = ConvertTo-Page @()
            '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal' = ConvertTo-Page @()
            '/v1.0/reports/authenticationMethods/userRegistrationDetails' = ConvertTo-Page @([pscustomobject]@{ id = 'u1'; isMfaRegistered = $true; methodsRegistered = @('fido2SecurityKey') })
            '/v1.0/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$expand=owners($select=id,displayName,userPrincipalName)&$top=100' = ConvertTo-Page @([pscustomobject]@{ id = 'app1'; displayName = 'Westmark App'; passwordCredentials = @(); keyCredentials = @(); owners = @() })
            "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles" = [pscustomobject]@{ id = 'graph-sp'; appRoles = @(
                    [pscustomobject]@{ id = 'r1'; value = 'User.ReadWrite.All' }, [pscustomobject]@{ id = 'r2'; value = 'User.Read.All' }) }
            '/v1.0/servicePrincipals/graph-sp/appRoleAssignedTo?$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ principalId = 'sp1'; principalDisplayName = 'Westmark Sync'; principalType = 'ServicePrincipal'; appRoleId = 'r1'; createdDateTime = '2026-01-01T00:00:00Z' }
                [pscustomobject]@{ principalId = 'sp2'; principalDisplayName = 'Westmark Old'; principalType = 'ServicePrincipal'; appRoleId = 'gone'; createdDateTime = '2026-01-01T00:00:00Z' })
            '/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials&$top=999' = ConvertTo-Page @(
                [pscustomobject]@{ id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph' }
                [pscustomobject]@{ id = 'sp1'; appId = 'a1'; displayName = 'Westmark Sync' })
            '/v1.0/oauth2PermissionGrants' = ConvertTo-Page @([pscustomobject]@{ id = 'pg1'; clientId = 'sp1'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'graph-sp'; scope = 'User.Read Mail.Send' })
            '/v1.0/identity/conditionalAccess/policies' = ConvertTo-Page @([pscustomobject]@{ id = 'p1'; displayName = 'Policy'; state = 'enabled' })
            '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' = [pscustomobject]@{ id = 'sd'; isEnabled = $false }
            '/v1.0/policies/authorizationPolicy' = [pscustomobject]@{ id = 'authorizationPolicy'; displayName = 'Authorization Policy'; allowInvitesFrom = 'everyone'
                allowedToUseSSPR = $true; allowEmailVerifiedUsersToJoinOrganization = $false; allowUserConsentForRiskyApps = $null; blockMsolPowerShell = $false
                guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                defaultUserRolePermissions = [pscustomobject]@{ allowedToCreateApps = $true; allowedToCreateSecurityGroups = $true; allowedToCreateTenants = $false
                    allowedToReadOtherUsers = $true; permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') } }
            '/v1.0/policies/authenticationMethodsPolicy' = [pscustomobject]@{ id = 'authenticationMethodsPolicy'; policyVersion = '1.5'; policyMigrationState = 'migrationComplete'
                registrationEnforcement = [pscustomobject]@{ authenticationMethodsRegistrationCampaign = [pscustomobject]@{ state = 'disabled' } }
                authenticationMethodConfigurations = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.smsAuthenticationMethodConfiguration'; id = 'Sms'; state = 'enabled'; excludeTargets = @()
                        includeTargets = @([pscustomobject]@{ targetType = 'group'; id = 'all_users'; isUsableForSignIn = $false }) }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.voiceAuthenticationMethodConfiguration'; id = 'Voice'; state = 'disabled'; isOfficePhoneAllowed = $false; excludeTargets = @() }) }
            '/v1.0/directory/subscriptions' = ConvertTo-Page @([pscustomobject]@{ id = 'sub1'; commerceSubscriptionId = 'cs1'; ownerId = 'o1'; ownerTenantId = 't1'; ownerType = 'User'
                    skuId = 'sku1'; skuPartNumber = 'AAD_PREMIUM_P2'; status = 'Enabled'; isTrial = $true; totalLicenses = 100
                    createdDateTime = [datetime]::new(2026, 10, 14, 0, 0, 0, [DateTimeKind]::Utc); nextLifecycleDateTime = '2026-11-13T00:00:00Z'
                    serviceStatus = @(
                        [pscustomobject]@{ servicePlanId = 'sp-p1'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success'; appliesTo = 'User' }
                        [pscustomobject]@{ servicePlanId = 'sp-p2'; servicePlanName = 'AAD_PREMIUM_P2'; provisioningStatus = 'Success'; appliesTo = 'User' }) })
            '/v1.0/policies/crossTenantAccessPolicy/default' = [pscustomobject]@{ isServiceDefault = $true
                inboundTrust = [pscustomobject]@{ isMfaAccepted = $false }
                automaticUserConsentSettings = [pscustomobject]@{ inboundAllowed = $false; outboundAllowed = $false }
                b2bCollaborationInbound = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'allowed'; targets = @([pscustomobject]@{ target = 'AllUsers'; targetType = 'user' }) } }
                b2bDirectConnectInbound = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @([pscustomobject]@{ target = 'AllUsers'; targetType = 'user' }) }
                    applications = [pscustomobject]@{ accessType = 'blocked'; targets = @([pscustomobject]@{ target = 'AllApplications'; targetType = 'application' }) } }
                b2bDirectConnectOutbound = [pscustomobject]@{ usersAndGroups = [pscustomobject]@{ accessType = 'blocked'; targets = @([pscustomobject]@{ target = 'AllUsers'; targetType = 'user' }) } } }
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

    function Set-FakeCaGroup {
        # Two policies naming one group twice and a deleted group.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that changes nothing outside the test.')]
        param()
        $script:Pages['/v1.0/identity/conditionalAccess/policies'] = ConvertTo-Page @(
            [pscustomobject]@{ id = 'p1'; displayName = 'Policy'; state = 'enabled'
                conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeGroups = @('cg1', 'gone') } } }
            [pscustomobject]@{ id = 'p2'; displayName = 'Other'; state = 'disabled'
                conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeGroups = @('cg1') } } })
        $script:Pages['/v1.0/groups/cg1?$select=id,displayName,isAssignableToRole'] = [pscustomobject]@{ id = 'cg1'; displayName = 'Emergency Access'; isAssignableToRole = $true }
        $script:Pages['/v1.0/groups/cg1/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999'] = ConvertTo-Page @(
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; displayName = 'A'; userPrincipalName = 'a@westmark.example'; mail = 'a@westmark.example' })
        $script:Pages['/v1.0/groups/cg1/owners?$select=id,displayName,userPrincipalName&$top=999'] = ConvertTo-Page @(
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; displayName = 'B'; userPrincipalName = 'b@westmark.example' })
        $script:Fail['/v1.0/groups/gone?$select=id,displayName,isAssignableToRole'] = $NotFound
    }

    function Get-Collected {
        # Collects, then does the round trip the main script does.
        $snap = Get-TenantSnapshot -TenantId 'tenant' 6>$null
        return ((ConvertTo-SnapshotValue $snap) | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
    }

    $script:RolePolicyUri = "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'&`$expand=policy(`$expand=rules)"
    $script:RoleAuditUri = "/v1.0/auditLogs/directoryAudits?`$filter=category%20eq%20'RoleManagement'"
    $script:UsersWithSignIns = "/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,identities,signInActivity&`$top=500"
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

    It 'keeps the tenant settings to the fields the checks read' {
        $s = Get-Collected
        $auth = @($s.Datasets.AuthorizationPolicy.Items)
        $auth.Count | Should -Be 1
        @($auth[0].PSObject.Properties.Name) | Should -Be @('allowInvitesFrom', 'allowEmailVerifiedUsersToJoinOrganization', 'allowUserConsentForRiskyApps', 'guestUserRoleId', 'defaultUserRolePermissions')
        @($auth[0].defaultUserRolePermissions.permissionGrantPoliciesAssigned) | Should -Be @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        $auth[0].defaultUserRolePermissions.allowedToCreateApps | Should -BeTrue
        $methods = @(@($s.Datasets.AuthMethodsPolicy.Items)[0].methods)
        @($methods | ForEach-Object { "$($_.id)=$($_.state)" }) | Should -Be @('Sms=enabled', 'Voice=disabled')
        @($methods[0].PSObject.Properties.Name) | Should -Be @('id', 'state')
        $cross = @($s.Datasets.CrossTenantAccess.Items)[0]
        @($cross.PSObject.Properties.Name) | Should -Be @('isServiceDefault', 'automaticUserConsentSettings', 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound')
        $cross.b2bDirectConnectInbound.usersAndGroups.accessType | Should -Be 'blocked'
        @($cross.b2bDirectConnectInbound.usersAndGroups.targets) | Should -Be @('AllUsers')
    }

    It 'records a tenant setting it was refused as Denied, and still reads the rest' {
        $Fail['/v1.0/policies/authenticationMethodsPolicy'] = $Denied
        $s = Get-Collected
        $s.Datasets.AuthMethodsPolicy.Status | Should -Be 'Denied'
        $s.Datasets.AuthMethodsPolicy.Reason | Should -Match 'Authorization_RequestDenied'
        @($s.Datasets.AuthMethodsPolicy.Items).Count | Should -Be 0
        $s.Datasets.AuthorizationPolicy.Status | Should -Be 'Collected'
        $s.Datasets.CrossTenantAccess.Status | Should -Be 'Collected'
    }

    It 'keeps the subscriptions to the fields TEN-07 reads, with service plans by name' {
        $s = Get-Collected
        $subs = @($s.Datasets.Subscriptions.Items)
        $subs.Count | Should -Be 1
        @($subs[0].PSObject.Properties.Name) | Should -Be @('skuId', 'skuPartNumber', 'status', 'isTrial', 'createdDateTime', 'nextLifecycleDateTime', 'totalLicenses', 'servicePlans')
        @($subs[0].servicePlans) | Should -Be @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
        $subs[0].isTrial | Should -BeTrue
        ConvertTo-UtcDate $subs[0].nextLifecycleDateTime | Should -Be ([datetime]::new(2026, 11, 13, 0, 0, 0, [DateTimeKind]::Utc))
    }

    It 'marks the subscriptions Denied when Organization.Read.All was not granted, and carries on' {
        $Fail['/v1.0/directory/subscriptions'] = $Denied
        $s = Get-Collected
        $s.Datasets.Subscriptions.Status | Should -Be 'Denied'
        @($s.Datasets.Subscriptions.Items).Count | Should -Be 0
        $s.Datasets.ConditionalAccess.Status | Should -Be 'Collected'
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

    It 'reads each Conditional Access group once, with members, owners and whether it is role-assignable' {
        Set-FakeCaGroup
        $s = Get-Collected
        $s.Datasets.CaGroups.Status | Should -Be 'Collected'
        $g = @($s.Datasets.CaGroups.Items)
        @($g | ForEach-Object id) | Should -Be @('cg1', 'gone')
        $g[0].found | Should -BeTrue
        $g[0].isAssignableToRole | Should -BeTrue
        $g[0].displayName | Should -Be 'Emergency Access'
        @($g[0].members | ForEach-Object userPrincipalName) | Should -Be @('a@westmark.example')
        @($g[0].members[0].PSObject.Properties.Name) | Should -Be @('@odata.type', 'id', 'displayName', 'userPrincipalName')
        @($g[0].owners | ForEach-Object id) | Should -Be @('u2')
        # A group a policy still names after it was deleted is kept, marked.
        $g[1].found | Should -BeFalse
        @($Calls | Where-Object { $_ -eq '/v1.0/groups/cg1?$select=id,displayName,isAssignableToRole' }).Count | Should -Be 1
    }

    It 'marks CaGroups Denied when a group can''t be read, rather than keeping part of them' {
        Set-FakeCaGroup
        $Fail['/v1.0/groups/cg1/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999'] = $Denied
        $s = Get-Collected
        $s.Datasets.CaGroups.Status | Should -Be 'Denied'
        @($s.Datasets.CaGroups.Items).Count | Should -Be 0
        $s.Datasets.ConditionalAccess.Status | Should -Be 'Collected'
    }

    It 'marks CaGroups NotCollected without Conditional Access' {
        $Fail['/v1.0/identity/conditionalAccess/policies'] = $NotLicensed
        $s = Get-Collected
        $s.Datasets.CaGroups.Status | Should -Be 'NotCollected'
        $s.Datasets.CaGroups.Reason | Should -Match '^Conditional Access was not collected'
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
        @($s.Datasets.RoleAssignments.Items).Count | Should -Be 2
    }

    It 'reads the members of each group that holds a role' {
        $s = Get-Collected
        $s.Datasets.RoleGroupMembers.Status | Should -Be 'Collected'
        @($s.Datasets.RoleGroupMembers.Items).Count | Should -Be 1
        $s.Datasets.RoleGroupMembers.Items[0].displayName | Should -Be 'Westmark Admins'
        , $s.Datasets.RoleGroupMembers.Items[0].members | Should -BeOfType [object[]]
        @($s.Datasets.RoleGroupMembers.Items[0].members | ForEach-Object userPrincipalName) | Should -Be @('b@westmark.example')
    }

    It 'marks role group members Denied when GroupMember.Read.All was not granted, and carries on' {
        $Fail['/v1.0/groups/g1/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999'] = $Denied
        $s = Get-Collected
        $s.Datasets.RoleGroupMembers.Status | Should -Be 'Denied'
        @($s.Datasets.RoleGroupMembers.Items).Count | Should -Be 0
        $s.Datasets.RoleAssignments.Status | Should -Be 'Collected'
    }

    It 'does not read group members when the roles were read without principal details' {
        $Fail['/v1.0/roleManagement/directory/roleAssignments?$expand=principal'] = $BadRequest
        $s = Get-Collected
        $s.Datasets.RoleGroupMembers.Status | Should -Be 'NotCollected'
        $s.Datasets.RoleGroupMembers.Reason | Should -Match "can't be told apart"
        @($Calls | Where-Object { $_ -like '/v1.0/groups/*' }).Count | Should -Be 0
    }

    It 'reads the owners of each group that holds a role' {
        $s = Get-Collected
        $s.Datasets.RoleGroupOwners.Status | Should -Be 'Collected'
        $s.Datasets.RoleGroupOwners.Items[0].displayName | Should -Be 'Westmark Admins'
        , $s.Datasets.RoleGroupOwners.Items[0].owners | Should -BeOfType [object[]]
        @($s.Datasets.RoleGroupOwners.Items[0].owners | ForEach-Object userPrincipalName) | Should -Be @('a@westmark.example')
    }

    It 'marks role group owners Denied without the permission, and does not read them when groups cannot be told apart' {
        $Fail['/v1.0/groups/g1/owners?$select=id,displayName,userPrincipalName&$top=999'] = $Denied
        (Get-Collected).Datasets.RoleGroupOwners.Status | Should -Be 'Denied'
        Reset-FakeGraph
        $Fail['/v1.0/roleManagement/directory/roleAssignments?$expand=principal'] = $BadRequest
        (Get-Collected).Datasets.RoleGroupOwners.Status | Should -Be 'NotCollected'
    }

    It 'keeps each PIM policy''s role and rules' {
        $s = Get-Collected
        $s.Datasets.RolePolicies.Status | Should -Be 'Collected'
        $s.Datasets.RolePolicies.Items[0].roleDefinitionId | Should -Be $GlobalAdminRoleId
        , $s.Datasets.RolePolicies.Items[0].rules | Should -BeOfType [object[]]
        $s.Datasets.RolePolicies.Items[0].rules[0].maximumDuration | Should -Be 'PT8H'
    }

    It 'keeps only the activation rules ROLE-10 reads, and only their fields' {
        # Regression: the full policies made a live snapshot five times its size.
        $s = Get-Collected
        $rules = @($s.Datasets.RolePolicies.Items[0].rules)
        @($rules | ForEach-Object id) | Should -Be @('Expiration_EndUser_Assignment', 'Approval_EndUser_Assignment')
        $rules[1].setting.isApprovalRequired | Should -BeTrue
        @($rules[1].setting.PSObject.Properties.Name) | Should -Be @('isApprovalRequired')
        @($rules[0].PSObject.Properties.Name) | Should -Not -Contain 'target'
    }

    It 'marks PIM policies NotLicensed without P2' {
        $Fail[$RolePolicyUri] = $NotLicensed
        $s = Get-Collected
        $s.Datasets.RolePolicies.Status | Should -Be 'NotLicensed'
        $s.Datasets.RolePolicies.Reason | Should -Match 'P2'
    }

    It 'keeps only the audit event fields the checks read, leaving out IP addresses' {
        $s = Get-Collected
        $s.Datasets.RoleAuditEvents.Status | Should -Be 'Collected'
        $e = $s.Datasets.RoleAuditEvents.Items[0]
        $e.initiatedBy.userId | Should -Be 'u1'
        $e.targetResources[0].type | Should -Be 'User'
        @($e.PSObject.Properties.Name) | Should -Be @('id', 'activityDisplayName', 'activityDateTime', 'result', 'initiatedBy', 'targetResources')
        ($s | ConvertTo-Json -Depth 20) | Should -Not -Match '192\.0\.2\.1'
    }

    It 'marks the audit log Denied without the permission, and carries on' {
        $Fail[$RoleAuditUri] = $Denied
        $s = Get-Collected
        $s.Datasets.RoleAuditEvents.Status | Should -Be 'Denied'
        $s.Datasets.RolePolicies.Status | Should -Be 'Collected'
    }

    It 'reads the owners of apps that hold a Graph permission or a role, and only those' {
        $s = Get-Collected
        $s.Datasets.AppOwners.Status | Should -Be 'Collected'
        @($s.Datasets.AppOwners.Items | ForEach-Object servicePrincipalId) | Should -Be @('sp1')
        @($s.Datasets.AppOwners.Items[0].owners | ForEach-Object id) | Should -Be @('u2')
        # sp2 holds a grant but isn't in the service principal list, so there's nothing to read.
        $Calls | Should -Not -Contain '/v1.0/servicePrincipals/sp2/owners?$select=id,displayName,userPrincipalName&$top=999'
    }

    It 'does not read app owners when the grants that pick the apps were not read' {
        $Fail["/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"] = $Denied
        $s = Get-Collected
        $s.Datasets.AppOwners.Status | Should -Be 'NotCollected'
        $s.Datasets.AppOwners.Reason | Should -Match 'GraphPermissionGrants'
        @($Calls | Where-Object { $_ -like '*/owners*' -and $_ -like '/v1.0/servicePrincipals/*' }).Count | Should -Be 0
    }

    It 'marks app owners Denied when one app''s owners cannot be read' {
        $Fail['/v1.0/servicePrincipals/sp1/owners?$select=id,displayName,userPrincipalName&$top=999'] = $Denied
        (Get-Collected).Datasets.AppOwners.Status | Should -Be 'Denied'
    }

    It 'marks delegated grants Denied when DelegatedPermissionGrant.Read.All was not granted' {
        $Fail['/v1.0/oauth2PermissionGrants'] = $Denied
        $s = Get-Collected
        $s.Datasets.DelegatedPermissionGrants.Status | Should -Be 'Denied'
        $s.Datasets.ServicePrincipals.Status | Should -Be 'Collected'
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
