<#
.SYNOPSIS
    Audits who can get into a Microsoft Entra ID tenant and how: privileged
    roles, stale and guest accounts, MFA coverage, app credentials and
    permissions, service accounts, Conditional Access gaps and tenant-wide
    settings. Read-only.

.DESCRIPTION
    Read-only by design. Every call to Microsoft Graph goes through one function
    that sends GET requests only, and the scopes it asks for are all .Read.
    scopes. It changes nothing in the tenant.

    It works in two stages so that every rule can be tested without a tenant:
        1. Collect: read the tenant from Microsoft Graph into a snapshot.
        2. Evaluate: judge the snapshot against each check.
    A saved snapshot can be evaluated again later, on any machine, with
    -FromSnapshot. The checks read only the snapshot, never the tenant.

    Each check gives one of these results:
        Fail     evidence collected, and it shows a gap
        Warn     evidence collected, and it shows something to review
        Pass     evidence collected, and it shows no gap
        Skipped  the data the check needs wasn't collected; the reason says why
                 (usually a licence the tenant doesn't have)
        Error    the check threw; the message is in the report
    Nothing passes by default. A check whose data is missing is Skipped and
    counted, never passed.

    Some data needs a premium licence. Sign-in activity, the MFA registration
    report and Conditional Access need Microsoft Entra ID P1; PIM eligibility,
    assignment schedules and activation settings need P2. The directory audit
    log needs no licence, but goes back 7 days without P1 and 30 with it. When the tenant has no licence for them,
    the checks that need them are Skipped, or say what they couldn't see.

    Writes these files into -OutputPath, named by collection time (UTC):
        entra-access-audit-<time>.html   a self-contained report
        entra-access-audit-<time>.csv    one row per finding
        entra-access-audit-<time>.json   results, dataset status and thresholds
    The reports name real accounts and apps. Keep them somewhere private.

    Exit codes: 0 no Fail and no Error; 1 at least one Fail; 2 at least one
    Error, a dataset that couldn't be read for a reason other than licensing,
    or the audit could not start.

    Graph permissions (delegated, read-only):
        User.Read.All                  users, guests, account state
        AuditLog.Read.All              sign-in activity, MFA registration report
        RoleManagement.Read.Directory  role assignments, PIM eligibility
        Application.Read.All           app registrations, enterprise apps,
                                       granted permissions
        Policy.Read.All                Conditional Access, security defaults
        DelegatedPermissionGrant.Read.All
                                       delegated permissions that admins
                                       or users consented to
        GroupMember.Read.All           members of groups that hold a role
    The Global Reader role is enough to run it. For unattended runs, grant an
    app registration the same permissions as Application permissions and use
    -ClientId, -TenantId and -CertificateThumbprint.

.PARAMETER FromSnapshot
    Evaluate a saved snapshot instead of reading the tenant. Works on any
    operating system and needs no Graph module.

.PARAMETER SnapshotPath
    Also save the collected snapshot to this JSON file. The snapshot names real
    accounts and apps.

.PARAMETER OutputPath
    Folder for the report files. Defaults to a Reports folder in the current
    PowerShell folder, created if needed.

.PARAMETER ProfilePath
    Thresholds file to use instead of the defaults (see
    EntraAccessAudit.example.psd1). Without it, an EntraAccessAudit.local.psd1
    beside the script is used if present.

.PARAMETER TenantId
    The tenant to sign in to. Required with -CertificateThumbprint.

.PARAMETER ClientId
    The app registration to sign in with. Without it, Microsoft Graph
    PowerShell's own app is used.

.PARAMETER CertificateThumbprint
    Sign in as the app (-ClientId) with this certificate from the current
    user's or local machine's certificate store, for unattended runs.

.PARAMETER PassThru
    Also write the check results to the pipeline.

.EXAMPLE
    .\Invoke-EntraAccessAudit.ps1
    Signs in interactively with the read-only scopes and audits the tenant.

.EXAMPLE
    .\Invoke-EntraAccessAudit.ps1 -SnapshotPath .\tenant.snapshot.json
    Audits the tenant and keeps the snapshot.

.EXAMPLE
    .\Invoke-EntraAccessAudit.ps1 -FromSnapshot .\tests\fixtures\westmark.snapshot.json
    Evaluates the fictional Westmark tenant that the tests use. No sign-in.

.NOTES
    Version notes (newest last):
    0.1.0  2026-11-10  First release: privileged roles, stale accounts, MFA
                       coverage, app credentials and permissions, and
                       Conditional Access checks; HTML, CSV and JSON reports.
    0.2.0  2026-11-10  Roles held through a group count for each member
                       (GroupMember.Read.All). APP-06 and APP-07: high-risk
                       delegated permissions consented for every user or by
                       users (DelegatedPermissionGrant.Read.All). Snapshot
                       schema 2; schema 1 snapshots still evaluate. An empty
                       MFA registration report skips ROLE-05 and MFA-01 to
                       MFA-03 instead of passing them, and accounts with no
                       record make them Warn.
    0.3.0  2026-11-12  Service accounts area: SVC-01 enterprise app
                       credentials, SVC-02 apps in privileged roles, SVC-03
                       apps from other organizations with high-risk
                       permissions, SVC-04 disabled apps still holding
                       access. Snapshot schema 3.
    0.3.1  2026-11-13  No obsolete-parameter warning when writing the CSV
                       report on PowerShell 7. Test and lint scripts end with
                       a summary banner, table and RESULT bar.
    0.4.0  2026-11-13  ROLE-07 other privileged roles held permanently,
                       ROLE-08 eligible roles that never expire, ROLE-09
                       roles granted to oneself (audit log), ROLE-10 weak PIM
                       activation rules, ROLE-11 owners of role-holding
                       groups, SVC-05 owners of apps with high-risk access.
                       No new scope. Snapshot schema 4.
    0.4.1  2026-11-13  PIM policies keep only the four activation rules and
                       the fields ROLE-10 reads, so a snapshot is about a
                       third of the size.
    0.5.0  2026-11-16  Tenant settings area: TEN-01 user consent, TEN-02
                       app registration and tenant creation, TEN-03 guest
                       access and invitations, TEN-04 SMS and voice, TEN-05
                       cross-tenant defaults, TEN-06 break-glass accounts.
                       ROLE-12 privileged roles assigned outside PIM. ROLE-09
                       no longer lists a self-grant twice when PIM logs it
                       too. No new scope. Snapshot schema 5.
    0.5.1  2026-11-16  Test and lint summaries use the JobSweep layout: one
                       banner line with script, status and counts, a PS line,
                       and a Notes column only when a row needs one.
    0.6.0  2026-11-23  Break-glass checks from a live lab. TEN-06 fails a
                       break-glass account that an enforced Conditional
                       Access policy reaches, and warns when one hasn't
                       signed in within 90 days. CA-05 names who an
                       excluded group lets through, and flags a group that
                       isn't role-assignable or has owners. ROLE-13
                       privileged roles held by personal or external
                       accounts. Fix: TEN-01 called Microsoft's managed
                       consent policies custom. No new scope. Snapshot
                       schema 6.
#>

[CmdletBinding()]
param(
    [string]$FromSnapshot,
    [string]$SnapshotPath,
    [string]$OutputPath,
    [string]$ProfilePath,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [switch]$PassThru
)

Set-StrictMode -Version Latest

$EntraAccessAuditVersion = '0.6.0'
$SnapshotSchemaVersion = 6

# The delegated scopes the collector asks for. All read-only.
$AuditScopes = @(
    'User.Read.All'
    'AuditLog.Read.All'
    'RoleManagement.Read.Directory'
    'Application.Read.All'
    'Policy.Read.All'
    'DelegatedPermissionGrant.Read.All'
    'GroupMember.Read.All'
)

# Microsoft Graph's own service principal, whose app roles are the Graph
# application permissions. The same appId in every tenant.
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$PrivilegedRoleAdminRoleId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'

# Roles that can already change any group's members (ROLE-11) or any app's
# credentials (SVC-05). An owner who holds one gains nothing by owning.
$GroupAdminRoleIds = @($GlobalAdminRoleId, $PrivilegedRoleAdminRoleId)
$AppAdminRoleIds = @(
    $GlobalAdminRoleId
    $PrivilegedRoleAdminRoleId
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'   # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'   # Cloud Application Administrator
)

# Datasets added after the first schema, by the schema that added them. An
# older snapshot lacks them, and the checks that need them are Skipped with
# that reason.
$LaterDatasets = [ordered]@{
    RoleAuditEvents     = 4
    RolePolicies        = 4
    RoleGroupOwners     = 4
    AppOwners           = 4
    AuthorizationPolicy = 5
    AuthMethodsPolicy   = 5
    CrossTenantAccess   = 5
    CaGroups            = 6
}

# The PIM policy rules ROLE-10 reads: what activation needs, and how long it
# lasts. The collector keeps only these.
$RolePolicyRuleIds = @(
    'Enablement_EndUser_Assignment'
    'AuthenticationContext_EndUser_Assignment'
    'Approval_EndUser_Assignment'
    'Expiration_EndUser_Assignment'
)

# What guests can see in the directory, by the role guestUserRoleId names.
# Microsoft's well-known IDs, the same in every tenant.
$GuestAccessLevels = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'the same access as members'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited access (the default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted access'
}
$MemberGuestRoleId = 'a0b1b346-4d3e-4e8b-98f8-753987be4970'

# User consent settings. Legacy lets users consent to any app that asks for
# their data; low lets them consent only to verified publishers asking for
# permissions marked low impact, which Microsoft recommends.
$LegacyConsentPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
$LowConsentPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
# Microsoft-managed built-in policies, not custom ones. Recommended is the
# default for a new tenant and follows Microsoft's current advice; the mail
# client policy lets users consent to popular mail apps for mail access.
$RecommendedConsentPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
$MailAppsConsentPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'

# Microsoft asks that break-glass accounts are tested at least this often.
$BreakGlassTestDays = 90

# The tenants Microsoft's own apps belong to. An app owned by any other tenant
# but this one comes from another organization.
$MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a'   # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft
)

# Built-in roles treated as privileged, by template ID (the same in every
# tenant). A role definition that Graph marks isPrivileged counts too.
$PrivilegedRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
}

# Registered methods that are not phishing-resistant MFA, and the ones that
# are. A user whose methods are all in the first list has only phone-based or
# no real second factor.
$WeakMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'email', 'securityQuestion', 'temporaryAccessPass')
$PhishingResistantMethods = @(
    'fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello', 'passKeySynced', 'macOsSecureEnclaveKey', 'platformCredential',
    'x509CertificateMultiFactor'
)

# Defaults for every threshold. EntraAccessAudit.example.psd1 documents each one.
$DefaultAuditProfile = [ordered]@{
    StaleDays              = 90
    CredentialExpiryDays   = 30
    MaxSecretLifetimeDays  = 365
    MinGlobalAdmins        = 2
    MaxGlobalAdmins        = 4
    MaxActivationHours     = 8
    BreakGlassAccounts     = @()
    AcceptedApps           = @()
    HighRiskPermissions    = @(
        'RoleManagement.ReadWrite.Directory'
        'AppRoleAssignment.ReadWrite.All'
        'Application.ReadWrite.All'
        'Directory.ReadWrite.All'
        'UserAuthenticationMethod.ReadWrite.All'
        'Policy.ReadWrite.ConditionalAccess'
        'PrivilegedAccess.ReadWrite.AzureADGroup'
        'Group.ReadWrite.All'
        'GroupMember.ReadWrite.All'
        'User.ReadWrite.All'
        'Domain.ReadWrite.All'
        'Mail.ReadWrite'
        'Mail.Send'
        'Files.ReadWrite.All'
        'Sites.FullControl.All'
        'Sites.ReadWrite.All'
    )
}

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

function Get-Value {
    # Reads a property, or a path of properties, from a parsed JSON object or a
    # hashtable. Returns $null when any step is missing, which strict mode
    # would otherwise turn into an error.
    param($Object, [string[]]$Path)
    $current = $Object
    foreach ($name in $Path) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($name)) { return $null }
            $current = $current[$name]
        } else {
            $prop = $current.PSObject.Properties[$name]
            if ($null -eq $prop) { return $null }
            $current = $prop.Value
        }
    }
    return $current
}

function ConvertTo-UtcDate {
    # Graph dates arrive as ISO 8601 strings. ConvertFrom-Json turns them into
    # DateTime on PowerShell 7 and leaves them as strings on 5.1, so accept
    # both. Returns $null for an empty value.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    return [DateTimeOffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, $styles).UtcDateTime
}

function ConvertTo-SnapshotValue {
    # Makes collected data safe to save as JSON on both editions: dates become
    # ISO 8601 strings (5.1 would write them as \/Date(...)\/), and hashtables
    # and arrays are walked. Everything else passes through.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return (ConvertTo-UtcDate $Value).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string] -or $Value.GetType().IsPrimitive -or $Value -is [decimal]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in $Value.Keys) { $out["$key"] = ConvertTo-SnapshotValue $Value[$key] }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return , @(foreach ($item in $Value) { ConvertTo-SnapshotValue $item })
    }
    if ($Value -is [psobject]) {
        $out = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $out[$p.Name] = ConvertTo-SnapshotValue $p.Value }
        return $out
    }
    return "$Value"
}

function Format-AuditDate {
    param($Value)
    $d = ConvertTo-UtcDate $Value
    if ($null -eq $d) { return 'never' }
    return $d.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-HtmlText {
    param($Text)
    return [System.Net.WebUtility]::HtmlEncode("$Text")
}

# ---------------------------------------------------------------------------
#  Thresholds
# ---------------------------------------------------------------------------

function Get-AuditProfile {
    # The defaults, with a profile file's values on top. A key the defaults
    # don't have stops the run, so a misspelt threshold isn't silently ignored.
    param([string]$Path)
    $result = [ordered]@{}
    foreach ($key in $DefaultAuditProfile.Keys) { $result[$key] = $DefaultAuditProfile[$key] }
    if (-not $Path) { return $result }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Profile not found: $Path" }
    $data = Import-PowerShellDataFile -LiteralPath $Path
    foreach ($key in $data.Keys) {
        if (-not $DefaultAuditProfile.Contains($key)) {
            throw "Profile $Path has an unknown setting '$key'. Known settings: $($DefaultAuditProfile.Keys -join ', ')."
        }
        $default = $DefaultAuditProfile[$key]
        $value = $data[$key]
        if ($default -is [int]) {
            if ($value -isnot [int] -or $value -lt 0) { throw "Profile $Path setting '$key' must be a whole number of 0 or more, not '$value'." }
        } else {
            $value = @($value | ForEach-Object { "$_" } | Where-Object { $_ -ne '' })
        }
        $result[$key] = $value
    }
    if ($result.MinGlobalAdmins -gt $result.MaxGlobalAdmins) {
        throw "Profile $Path sets MinGlobalAdmins ($($result.MinGlobalAdmins)) above MaxGlobalAdmins ($($result.MaxGlobalAdmins))."
    }
    return $result
}

# ---------------------------------------------------------------------------
#  Collect
# ---------------------------------------------------------------------------

function Invoke-AuditGraphRequest {
    # The only function that talks to Microsoft Graph. GET only: the audit
    # never writes. Tests replace this function with a mock.
    param([Parameter(Mandatory)][string]$Uri)
    $json = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json -ErrorAction Stop
    return ($json | ConvertFrom-Json)
}

function Get-GraphCollection {
    # Reads every page of a Graph collection.
    param([Parameter(Mandatory)][string]$Uri)
    $items = [Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-AuditGraphRequest -Uri $next
        foreach ($item in @(Get-Value $page 'value')) { if ($null -ne $item) { $items.Add($item) } }
        $next = Get-Value $page '@odata.nextLink'
    }
    return , $items.ToArray()
}

function Get-GraphErrorStatus {
    # Sorts a failed Graph read into NotLicensed (the tenant lacks the premium
    # licence the data needs), Denied (the signed-in account or app lacks the
    # permission or role) or Error (anything else).
    param([Parameter(Mandatory)][string]$Message)
    if ($Message -match 'NonPremium|PremiumLicen[cs]e|licen[cs]e|not licensed') { return 'NotLicensed' }
    if ($Message -match 'Forbidden|Authorization_RequestDenied|Unauthorized|insufficient privileges|\b40[13]\b|AccessDenied') { return 'Denied' }
    return 'Error'
}

function Get-ErrorText {
    param($ErrorRecord)
    $text = "$($ErrorRecord.Exception.Message)"
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $text += " $($ErrorRecord.ErrorDetails.Message)" }
    return ($text -replace '\s+', ' ').Trim()
}

function New-Dataset {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object in memory; changes nothing.')]
    param([string]$Status, $Items = @(), [string]$Reason = '')
    return [ordered]@{ Status = $Status; Reason = $Reason; Items = @($Items) }
}

function Read-Dataset {
    # Reads one collection into a dataset, recording why it failed if it did.
    param([Parameter(Mandatory)][string]$Uri, [string]$Needs = '')
    try {
        return (New-Dataset -Status 'Collected' -Items (Get-GraphCollection -Uri $Uri))
    } catch {
        $text = Get-ErrorText $_
        $status = Get-GraphErrorStatus $text
        $reason = $text
        if ($status -eq 'NotLicensed' -and $Needs) { $reason = "Needs $Needs. $text" }
        Write-Verbose "Couldn't read ${Uri}: $status. $text"
        return (New-Dataset -Status $status -Reason $reason)
    }
}

function Read-RoleDataset {
    # Role assignments with each principal expanded, so groups and apps can be
    # told from users. If Graph refuses the expansion, read them without it:
    # users are still matched from the user list, and anything else shows as
    # Unknown.
    param([Parameter(Mandatory)][string]$Path, [string]$Needs = '')
    $first = Read-Dataset -Uri "$Path`?`$expand=principal" -Needs $Needs
    if ($first.Status -ne 'Error') { return $first }
    $second = Read-Dataset -Uri $Path -Needs $Needs
    if ($second.Status -eq 'Collected') { $second.Reason = "Read without principal details, because the expanded read failed: $($first.Reason)" }
    return $second
}

function Get-TenantSnapshot {
    # Reads everything the checks need from Microsoft Graph. Each dataset
    # records whether it was collected, so a check can tell missing data from
    # an empty tenant.
    param([string]$TenantId)
    $datasets = [ordered]@{}
    $userFields = 'id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime,identities'

    Write-Host 'Reading users and sign-in activity...'
    $users = Read-Dataset -Uri "/v1.0/users?`$select=$userFields,signInActivity&`$top=500" -Needs 'Microsoft Entra ID P1'
    if ($users.Status -eq 'Collected') {
        $datasets.SignIns = New-Dataset -Status 'Collected'
    } else {
        # Sign-in activity is what fails without P1 or AuditLog.Read.All; the
        # users themselves can still be read.
        $datasets.SignIns = New-Dataset -Status $users.Status -Reason $users.Reason
        $users = Read-Dataset -Uri "/v1.0/users?`$select=$userFields&`$top=999"
    }
    $datasets.Users = $users

    Write-Host 'Reading directory roles, PIM settings and role changes...'
    $datasets.RoleDefinitions = Read-Dataset -Uri '/v1.0/roleManagement/directory/roleDefinitions'
    $datasets.RoleAssignments = Read-RoleDataset -Path '/v1.0/roleManagement/directory/roleAssignments'
    $datasets.RoleAssignmentSchedules = Read-Dataset -Uri '/v1.0/roleManagement/directory/roleAssignmentSchedules' -Needs 'Microsoft Entra ID P2 (PIM)'
    $datasets.RoleEligibility = Read-RoleDataset -Path '/v1.0/roleManagement/directory/roleEligibilitySchedules' -Needs 'Microsoft Entra ID P2 (PIM)'
    $datasets.RoleGroupMembers = Get-RoleGroupMember -Datasets $datasets
    $datasets.RoleGroupOwners = Get-RoleGroupOwner -Datasets $datasets
    $datasets.RolePolicies = Get-RolePolicy
    $datasets.RoleAuditEvents = Get-RoleAuditEvent

    Write-Host 'Reading MFA registration...'
    $datasets.Registration = Read-Dataset -Uri '/v1.0/reports/authenticationMethods/userRegistrationDetails' -Needs 'Microsoft Entra ID P1'

    Write-Host 'Reading app registrations and permissions...'
    $datasets.Applications = Read-Dataset -Uri '/v1.0/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$expand=owners($select=id,displayName,userPrincipalName)&$top=100'
    $datasets.GraphPermissionGrants = Get-GraphPermissionGrant
    $datasets.ServicePrincipals = Read-Dataset -Uri '/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials&$top=999'
    $datasets.DelegatedPermissionGrants = Read-Dataset -Uri '/v1.0/oauth2PermissionGrants'
    $datasets.AppOwners = Get-AppOwner -Datasets $datasets

    Write-Host 'Reading tenant settings...'
    $datasets.AuthorizationPolicy = Get-AuthorizationPolicy
    $datasets.AuthMethodsPolicy = Get-AuthMethodsPolicy
    $datasets.CrossTenantAccess = Get-CrossTenantAccess

    Write-Host 'Reading Conditional Access and security defaults...'
    $datasets.ConditionalAccess = Read-Dataset -Uri '/v1.0/identity/conditionalAccess/policies' -Needs 'Microsoft Entra ID P1'
    $datasets.CaGroups = Get-CaGroup -Datasets $datasets
    try {
        $sd = Invoke-AuditGraphRequest -Uri '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
        $datasets.SecurityDefaults = New-Dataset -Status 'Collected' -Items @([ordered]@{ isEnabled = [bool](Get-Value $sd 'isEnabled') })
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read security defaults: $text"
        $datasets.SecurityDefaults = New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text
    }

    return [ordered]@{
        SchemaVersion = $SnapshotSchemaVersion
        ToolVersion   = $EntraAccessAuditVersion
        CollectedAt   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        TenantId      = $TenantId
        Datasets      = $datasets
    }
}

function Get-GraphPermissionGrant {
    # Application permissions granted on Microsoft Graph, to any app in the
    # tenant. Graph's service principal lists them as appRoleAssignedTo; its
    # appRoles give each permission's name.
    try {
        $graph = Invoke-AuditGraphRequest -Uri "/v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id,appRoles"
        $names = @{}
        foreach ($role in @(Get-Value $graph 'appRoles')) {
            if ($null -ne $role) { $names["$(Get-Value $role 'id')"] = "$(Get-Value $role 'value')" }
        }
        $grants = Get-GraphCollection -Uri "/v1.0/servicePrincipals/$(Get-Value $graph 'id')/appRoleAssignedTo?`$top=999"
        $items = foreach ($g in $grants) {
            $roleId = "$(Get-Value $g 'appRoleId')"
            [ordered]@{
                principalId          = Get-Value $g 'principalId'
                principalDisplayName = Get-Value $g 'principalDisplayName'
                principalType        = Get-Value $g 'principalType'
                appRoleId            = $roleId
                permission           = $(if ($names.ContainsKey($roleId)) { $names[$roleId] } else { $roleId })
                createdDateTime      = Get-Value $g 'createdDateTime'
            }
        }
        return (New-Dataset -Status 'Collected' -Items @($items))
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read Graph permission grants: $text"
        return (New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text)
    }
}

function Get-RoleGroupId {
    # The groups that hold a directory role, active or eligible, by ID with
    # their names. Unexpanded counts assignments read without principal
    # details, among which groups can't be told apart.
    param([Parameter(Mandatory)]$Datasets)
    $groups = [ordered]@{}
    $unexpanded = 0
    foreach ($name in 'RoleAssignments', 'RoleEligibility') {
        $ds = $Datasets[$name]
        if ($null -eq $ds -or "$(Get-Value $ds 'Status')" -ne 'Collected') { continue }
        foreach ($a in @(Get-Value $ds 'Items')) {
            if ($null -eq $a) { continue }
            $principal = Get-Value $a 'principal'
            if ($null -eq $principal) { $unexpanded++; continue }
            if ("$(Get-Value $principal '@odata.type')" -match 'group$') {
                $groups["$(Get-Value $a 'principalId')"] = "$(Get-Value $principal 'displayName')"
            }
        }
    }
    return [pscustomobject]@{ Groups = $groups; Unexpanded = $unexpanded }
}

function ConvertTo-DirectoryObject {
    # The fields kept for a group member or an owner.
    param($Object)
    return [ordered]@{
        '@odata.type'     = Get-Value $Object '@odata.type'
        id                = Get-Value $Object 'id'
        displayName       = Get-Value $Object 'displayName'
        userPrincipalName = Get-Value $Object 'userPrincipalName'
    }
}

function Read-GroupRelation {
    # Members or owners of every group that holds a directory role. All or
    # nothing: one group that can't be read fails the dataset, so no check
    # judges a partial list.
    param([Parameter(Mandatory)]$Datasets, [Parameter(Mandatory)][string]$Relation, [Parameter(Mandatory)][string]$Property)
    $index = Get-RoleGroupId -Datasets $Datasets
    if ($index.Unexpanded -gt 0) {
        return (New-Dataset -Status 'NotCollected' -Reason "$($index.Unexpanded) role assignment(s) were read without principal details, so groups among them can't be told apart.")
    }
    try {
        $items = foreach ($id in $index.Groups.Keys) {
            $related = Get-GraphCollection -Uri "/v1.0/groups/$id/$Relation`?`$select=id,displayName,userPrincipalName&`$top=999"
            [ordered]@{
                groupId     = $id
                displayName = $index.Groups[$id]
                $Property   = @(foreach ($m in $related) { ConvertTo-DirectoryObject $m })
            }
        }
        return (New-Dataset -Status 'Collected' -Items @($items))
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read role group ${Relation}: $text"
        return (New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text)
    }
}

function Get-CaGroup {
    # Every group a Conditional Access policy includes or excludes: whether
    # it can be assigned roles, its members (nested ones too) and its owners,
    # so the checks can tell whom a policy reaches and who can change that.
    # All or nothing, like the role groups. A group that no longer exists is
    # kept with found = false.
    param([Parameter(Mandatory)]$Datasets)
    $ca = $Datasets['ConditionalAccess']
    if ($null -eq $ca -or "$(Get-Value $ca 'Status')" -ne 'Collected') {
        return (New-Dataset -Status 'NotCollected' -Reason 'Conditional Access was not collected, so neither were its groups.')
    }
    $ids = [ordered]@{}
    foreach ($p in @(Get-Value $ca 'Items')) {
        if ($null -eq $p) { continue }
        foreach ($side in 'includeGroups', 'excludeGroups') {
            foreach ($id in @(Get-Value $p 'conditions', 'users', $side)) { if ("$id") { $ids["$id"] = $true } }
        }
    }
    try {
        $items = foreach ($id in $ids.Keys) {
            $group = $null
            try {
                $group = Invoke-AuditGraphRequest -Uri "/v1.0/groups/$id`?`$select=id,displayName,isAssignableToRole"
            } catch {
                $text = Get-ErrorText $_
                if ($text -notmatch 'Request_ResourceNotFound|NotFound|\b404\b') { throw }
                Write-Verbose "Conditional Access names group $id, which no longer exists: $text"
            }
            if ($null -eq $group) {
                [ordered]@{ id = $id; found = $false; displayName = ''; isAssignableToRole = $null; members = @(); owners = @() }
                continue
            }
            $members = Get-GraphCollection -Uri "/v1.0/groups/$id/transitiveMembers?`$select=id,displayName,userPrincipalName&`$top=999"
            $owners = Get-GraphCollection -Uri "/v1.0/groups/$id/owners?`$select=id,displayName,userPrincipalName&`$top=999"
            [ordered]@{
                id                 = $id
                found              = $true
                displayName        = Get-Value $group 'displayName'
                isAssignableToRole = Get-Value $group 'isAssignableToRole'
                members            = @(foreach ($m in $members) { ConvertTo-DirectoryObject $m })
                owners             = @(foreach ($o in $owners) { ConvertTo-DirectoryObject $o })
            }
        }
        return (New-Dataset -Status 'Collected' -Items @($items))
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read Conditional Access groups: $text"
        return (New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text)
    }
}

function Get-RoleGroupMember {
    # Members of every group that holds a directory role, so each person who
    # holds a role through a group is checked like one who holds it directly.
    # Role-assignable groups can't contain groups, but transitiveMembers
    # covers any that do.
    param([Parameter(Mandatory)]$Datasets)
    return (Read-GroupRelation -Datasets $Datasets -Relation 'transitiveMembers' -Property 'members')
}

function Get-RoleGroupOwner {
    # Owners of every group that holds a directory role. An owner can change
    # the group's members, and so who holds its role.
    param([Parameter(Mandatory)]$Datasets)
    return (Read-GroupRelation -Datasets $Datasets -Relation 'owners' -Property 'owners')
}

function Get-RolePolicy {
    # PIM's settings for each directory role: what activating it needs and how
    # long it lasts. Kept to the role and the four activation rules ROLE-10
    # reads, with only the fields it reads: the full policies run to about
    # 6 KB a role, across every built-in role.
    $ds = Read-Dataset -Uri "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'&`$expand=policy(`$expand=rules)" -Needs 'Microsoft Entra ID P2 (PIM)'
    if ($ds.Status -ne 'Collected') { return $ds }
    $ds.Items = @(foreach ($a in $ds.Items) {
            [ordered]@{
                roleDefinitionId = Get-Value $a 'roleDefinitionId'
                policyId         = Get-Value $a 'policyId'
                rules            = @(foreach ($r in @(Get-Value $a 'policy', 'rules')) {
                        if ($null -eq $r -or $RolePolicyRuleIds -notcontains "$(Get-Value $r 'id')") { continue }
                        [ordered]@{
                            '@odata.type'   = Get-Value $r '@odata.type'
                            id              = Get-Value $r 'id'
                            enabledRules    = @(Get-Value $r 'enabledRules' | Where-Object { $null -ne $_ })
                            isEnabled       = Get-Value $r 'isEnabled'
                            maximumDuration = Get-Value $r 'maximumDuration'
                            setting         = [ordered]@{ isApprovalRequired = Get-Value $r 'setting', 'isApprovalRequired' }
                        }
                    })
            }
        })
    return $ds
}

function Read-PolicyObject {
    # Reads one policy, which Graph returns as a single object rather than a
    # collection, into a dataset of one item kept to what the checks read.
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][scriptblock]$Trim)
    try {
        $policy = Invoke-AuditGraphRequest -Uri $Uri
        return (New-Dataset -Status 'Collected' -Items @(& $Trim $policy))
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read ${Uri}: $text"
        return (New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text)
    }
}

function Get-AuthorizationPolicy {
    # Default user permissions, user consent and guest settings.
    Read-PolicyObject -Uri '/v1.0/policies/authorizationPolicy' -Trim {
        param($p)
        [ordered]@{
            allowInvitesFrom                          = Get-Value $p 'allowInvitesFrom'
            allowEmailVerifiedUsersToJoinOrganization = Get-Value $p 'allowEmailVerifiedUsersToJoinOrganization'
            allowUserConsentForRiskyApps              = Get-Value $p 'allowUserConsentForRiskyApps'
            guestUserRoleId                           = Get-Value $p 'guestUserRoleId'
            defaultUserRolePermissions                = [ordered]@{
                allowedToCreateApps             = Get-Value $p 'defaultUserRolePermissions', 'allowedToCreateApps'
                allowedToCreateTenants          = Get-Value $p 'defaultUserRolePermissions', 'allowedToCreateTenants'
                permissionGrantPoliciesAssigned = @(Get-Value $p 'defaultUserRolePermissions', 'permissionGrantPoliciesAssigned' | Where-Object { $null -ne $_ })
            }
        }
    }
}

function Get-AuthMethodsPolicy {
    # Which sign-in methods are turned on, and whether the old MFA and SSPR
    # settings still apply alongside this policy.
    Read-PolicyObject -Uri '/v1.0/policies/authenticationMethodsPolicy' -Trim {
        param($p)
        [ordered]@{
            policyMigrationState = Get-Value $p 'policyMigrationState'
            methods              = @(foreach ($m in @(Get-Value $p 'authenticationMethodConfigurations')) {
                    if ($null -eq $m) { continue }
                    [ordered]@{ id = Get-Value $m 'id'; state = Get-Value $m 'state' }
                })
        }
    }
}

function Get-CrossTenantAccess {
    # The default cross-tenant access settings, which apply to every other
    # organization without its own settings.
    Read-PolicyObject -Uri '/v1.0/policies/crossTenantAccessPolicy/default' -Trim {
        param($p)
        $setting = [ordered]@{
            isServiceDefault             = Get-Value $p 'isServiceDefault'
            automaticUserConsentSettings = [ordered]@{
                inboundAllowed  = Get-Value $p 'automaticUserConsentSettings', 'inboundAllowed'
                outboundAllowed = Get-Value $p 'automaticUserConsentSettings', 'outboundAllowed'
            }
        }
        foreach ($name in 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound') {
            $setting[$name] = [ordered]@{
                usersAndGroups = [ordered]@{
                    accessType = Get-Value $p $name, 'usersAndGroups', 'accessType'
                    targets    = @(foreach ($x in @(Get-Value $p $name, 'usersAndGroups', 'targets')) { if ($null -ne $x) { "$(Get-Value $x 'target')" } })
                }
            }
        }
        $setting
    }
}

function Get-RoleAuditEvent {
    # Role changes from the directory audit log: who added whom to which
    # role, and when. Kept to the fields the checks read. Microsoft keeps the
    # log for 7 days, or 30 with Microsoft Entra ID P1.
    $ds = Read-Dataset -Uri "/v1.0/auditLogs/directoryAudits?`$filter=category%20eq%20'RoleManagement'"
    if ($ds.Status -ne 'Collected') { return $ds }
    $ds.Items = @(foreach ($e in $ds.Items) {
            [ordered]@{
                id                  = Get-Value $e 'id'
                activityDisplayName = Get-Value $e 'activityDisplayName'
                activityDateTime    = Get-Value $e 'activityDateTime'
                result              = Get-Value $e 'result'
                initiatedBy         = [ordered]@{
                    userId            = Get-Value $e 'initiatedBy', 'user', 'id'
                    userPrincipalName = Get-Value $e 'initiatedBy', 'user', 'userPrincipalName'
                    app               = Get-Value $e 'initiatedBy', 'app', 'displayName'
                }
                targetResources     = @(foreach ($t in @(Get-Value $e 'targetResources')) {
                        if ($null -eq $t) { continue }
                        [ordered]@{
                            id                = Get-Value $t 'id'
                            type              = Get-Value $t 'type'
                            displayName       = Get-Value $t 'displayName'
                            userPrincipalName = Get-Value $t 'userPrincipalName'
                        }
                    })
            }
        })
    return $ds
}

function Get-AppOwner {
    # Owners of the enterprise apps (service principals) that hold a
    # Microsoft Graph application permission or a directory role: an owner
    # can add a secret and act as the app. App registration owners come with
    # the Applications dataset. All or nothing, like the group reads.
    param([Parameter(Mandatory)]$Datasets)
    $needed = @('GraphPermissionGrants', 'RoleAssignments', 'ServicePrincipals')
    $missing = @($needed | Where-Object { "$(Get-Value $Datasets[$_] 'Status')" -ne 'Collected' })
    if ($missing.Count -gt 0) {
        return (New-Dataset -Status 'NotCollected' -Reason "Needs $($missing -join ', ') to know which apps to read, and they weren't collected.")
    }
    $names = @{}
    foreach ($sp in @(Get-Value $Datasets['ServicePrincipals'] 'Items')) { if ($null -ne $sp) { $names["$(Get-Value $sp 'id')"] = "$(Get-Value $sp 'displayName')" } }
    $targets = [ordered]@{}
    foreach ($g in @(Get-Value $Datasets['GraphPermissionGrants'] 'Items')) { if ($null -ne $g) { $targets["$(Get-Value $g 'principalId')"] = $true } }
    foreach ($name in 'RoleAssignments', 'RoleEligibility') {
        $ds = $Datasets[$name]
        if ($null -eq $ds -or "$(Get-Value $ds 'Status')" -ne 'Collected') { continue }
        foreach ($a in @(Get-Value $ds 'Items')) {
            $id = "$(Get-Value $a 'principalId')"
            if ($null -ne $a -and ("$(Get-Value $a 'principal', '@odata.type')" -match 'servicePrincipal$' -or $names.ContainsKey($id))) { $targets[$id] = $true }
        }
    }
    try {
        $items = foreach ($id in $targets.Keys) {
            if (-not $names.ContainsKey($id)) { continue }
            $owners = Get-GraphCollection -Uri "/v1.0/servicePrincipals/$id/owners?`$select=id,displayName,userPrincipalName&`$top=999"
            [ordered]@{
                servicePrincipalId = $id
                displayName        = $names[$id]
                owners             = @(foreach ($o in $owners) { ConvertTo-DirectoryObject $o })
            }
        }
        return (New-Dataset -Status 'Collected' -Items @($items))
    } catch {
        $text = Get-ErrorText $_
        Write-Verbose "Couldn't read app owners: $text"
        return (New-Dataset -Status (Get-GraphErrorStatus $text) -Reason $text)
    }
}

function Connect-AuditGraph {
    # Signs in to Microsoft Graph with the read-only scopes, or as an app with
    # a certificate. Only Microsoft.Graph.Authentication is needed.
    param([string]$TenantId, [string]$ClientId, [string]$CertificateThumbprint)
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
        catch {
            throw ("Microsoft.Graph.Authentication isn't installed. Install it with: " +
                "Install-Module Microsoft.Graph.Authentication -Scope CurrentUser ($($_.Exception.Message))")
        }
    }
    $connect = @{ NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($ClientId) { $connect.ClientId = $ClientId }
    if ($CertificateThumbprint) {
        if (-not $ClientId -or -not $TenantId) { throw '-CertificateThumbprint needs -ClientId and -TenantId.' }
        $connect.CertificateThumbprint = $CertificateThumbprint
    } else {
        $connect.Scopes = $AuditScopes
    }
    Connect-MgGraph @connect | Out-Null
    $context = Get-MgContext
    if (-not $CertificateThumbprint) {
        $missing = @($AuditScopes | Where-Object { @($context.Scopes) -notcontains $_ })
        if ($missing.Count -gt 0) {
            Write-Warning "The sign-in didn't grant $($missing -join ', '). The data those scopes read will show as Denied."
        }
    }
    return $context
}

# ---------------------------------------------------------------------------
#  Evaluate
# ---------------------------------------------------------------------------

function New-RoleHolder {
    # Who a role assignment or group membership names: type, user record and
    # a name to show.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object in memory; changes nothing.')]
    param($Principal, [string]$PrincipalId, [hashtable]$UsersById)
    $type = switch -Regex ("$(Get-Value $Principal '@odata.type')") {
        'user$' { 'User' }
        'group$' { 'Group' }
        'servicePrincipal$' { 'ServicePrincipal' }
        default { if ($UsersById.ContainsKey($PrincipalId)) { 'User' } else { 'Unknown' } }
    }
    $user = $null
    if ($UsersById.ContainsKey($PrincipalId)) { $user = $UsersById[$PrincipalId] }
    $name = Get-Value $user 'userPrincipalName'
    if (-not $name) { $name = Get-Value $Principal 'userPrincipalName' }
    if (-not $name) { $name = Get-Value $Principal 'displayName' }
    if (-not $name) { $name = $PrincipalId }
    return [pscustomobject]@{ PrincipalId = $PrincipalId; PrincipalType = $type; Name = "$name"; User = $user }
}

function New-RoleHolderRow {
    # One holder row: the principal, the role it holds, and how.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object in memory; changes nothing.')]
    param($Holder, [string]$RoleId, [string]$RoleName, [string]$Kind, [bool]$Standing, [hashtable]$BreakGlassIds, [string]$Via, [bool]$NoExpiry)
    return [pscustomobject]@{
        RoleId        = $RoleId
        RoleName      = $RoleName
        PrincipalId   = $Holder.PrincipalId
        PrincipalType = $Holder.PrincipalType
        Name          = $Holder.Name
        User          = $Holder.User
        Kind          = $Kind
        Standing      = $Standing
        BreakGlass    = $BreakGlassIds.ContainsKey($Holder.PrincipalId)
        Via           = $Via
        NoExpiry      = $NoExpiry
    }
}

function Get-AuditContext {
    # Indexes the snapshot once, for every check: users by ID, break-glass
    # accounts, privileged role holders and MFA registration.
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)]$AuditProfile)
    $ds = Get-Value $Snapshot 'Datasets'
    $status = @{}
    foreach ($p in $ds.PSObject.Properties) { $status[$p.Name] = "$(Get-Value $p.Value 'Status')" }
    # Snapshots from 0.1.0 have no group members; say so in the checks.
    if (-not $status.ContainsKey('RoleGroupMembers')) { $status['RoleGroupMembers'] = 'NotCollected' }
    $statusReason = @{}
    # Service principal credentials, owner and state arrived in schema 3. In
    # an older snapshot the service principals have none of them, which must
    # not read as "no credentials", so the checks that need them are Skipped.
    $schema = Get-Value $Snapshot 'SchemaVersion'
    $status['ServicePrincipalDetails'] = $status['ServicePrincipals']
    if (-not $status['ServicePrincipalDetails']) { $status['ServicePrincipalDetails'] = 'NotCollected' }
    if ($status['ServicePrincipalDetails'] -eq 'Collected' -and $schema -lt 3) {
        $status['ServicePrincipalDetails'] = 'NotCollected'
        $statusReason['ServicePrincipalDetails'] = "The snapshot has schema $schema, from before service principal credentials, owners and state were collected."
    } elseif ($status['ServicePrincipalDetails'] -ne 'Collected') {
        $statusReason['ServicePrincipalDetails'] = "$(Get-Value $ds 'ServicePrincipals', 'Reason')"
    }
    # Role audit events, PIM policies and group and app owners arrived in
    # schema 4; tenant settings in schema 5.
    foreach ($name in $LaterDatasets.Keys) {
        if (-not $status.ContainsKey($name)) {
            $status[$name] = 'NotCollected'
            $statusReason[$name] = "The snapshot has schema $schema, from before $name was collected."
        }
    }

    $spsById = @{}
    foreach ($sp in @(Get-Value $ds 'ServicePrincipals', 'Items')) { if ($null -ne $sp) { $spsById["$(Get-Value $sp 'id')"] = $sp } }

    $usersById = @{}
    foreach ($u in @(Get-Value $ds 'Users', 'Items')) { if ($null -ne $u) { $usersById["$(Get-Value $u 'id')"] = $u } }

    $breakGlassUpns = @($AuditProfile.BreakGlassAccounts | ForEach-Object { "$_".ToLowerInvariant() })
    $breakGlassIds = @{}
    foreach ($u in $usersById.Values) {
        $upn = "$(Get-Value $u 'userPrincipalName')".ToLowerInvariant()
        if ($upn -and $breakGlassUpns -contains $upn) { $breakGlassIds["$(Get-Value $u 'id')"] = $true }
    }

    $roleNames = @{}
    $privilegedRoleIds = @{}
    foreach ($id in $PrivilegedRoles.Keys) { $roleNames[$id] = $PrivilegedRoles[$id]; $privilegedRoleIds[$id] = $true }
    foreach ($rd in @(Get-Value $ds 'RoleDefinitions', 'Items')) {
        if ($null -eq $rd) { continue }
        $id = "$(Get-Value $rd 'id')"
        $roleNames[$id] = "$(Get-Value $rd 'displayName')"
        if ((Get-Value $rd 'isPrivileged') -eq $true) { $privilegedRoleIds[$id] = $true }
    }

    # Active assignments that PIM activated or that end on a date are not
    # standing. Without the schedules (no P2), every active assignment is.
    $timeBound = @{}
    foreach ($s in @(Get-Value $ds 'RoleAssignmentSchedules', 'Items')) {
        if ($null -eq $s) { continue }
        $expiry = "$(Get-Value $s 'scheduleInfo', 'expiration', 'type')"
        if ("$(Get-Value $s 'assignmentType')" -eq 'Activated' -or ($expiry -and $expiry -ne 'noExpiration')) {
            $timeBound["$(Get-Value $s 'principalId')|$(Get-Value $s 'roleDefinitionId')"] = $true
        }
    }

    # Members of groups that hold a role, by group ID, when they were read.
    $groupMembers = @{}
    foreach ($g in @(Get-Value $ds 'RoleGroupMembers', 'Items')) {
        if ($null -ne $g) { $groupMembers["$(Get-Value $g 'groupId')"] = @(Get-Value $g 'members' | Where-Object { $null -ne $_ }) }
    }

    # One row per principal and role. A group whose members were read is
    # replaced by a row for each member, marked Via the group, and listed in
    # RoleGroups; a group whose members weren't read stays a row of its own.
    $holders = [Collections.Generic.List[object]]::new()
    $roleGroups = [Collections.Generic.List[object]]::new()
    # Privileged roles each group holds, by group ID, whether or not its
    # members were read.
    $groupRoles = @{}
    $eligibleNoSchedule = 0
    $sources = @(
        @{ Kind = 'Active'; Items = @(Get-Value $ds 'RoleAssignments', 'Items') }
        @{ Kind = 'Eligible'; Items = @(Get-Value $ds 'RoleEligibility', 'Items') }
    )
    foreach ($source in $sources) {
        foreach ($a in $source.Items) {
            if ($null -eq $a) { continue }
            $roleId = "$(Get-Value $a 'roleDefinitionId')"
            if (-not $privilegedRoleIds.ContainsKey($roleId)) { continue }
            $roleName = $(if ($roleNames.ContainsKey($roleId)) { $roleNames[$roleId] } else { $roleId })
            $principalId = "$(Get-Value $a 'principalId')"
            $standing = ($source.Kind -eq 'Active' -and -not $timeBound.ContainsKey("$principalId|$roleId"))
            # Standing active assignments never end; eligible ones never end
            # when their schedule says so.
            $noExpiry = $standing -or ($source.Kind -eq 'Eligible' -and "$(Get-Value $a 'scheduleInfo', 'expiration', 'type')" -eq 'noExpiration')
            if ($source.Kind -eq 'Eligible' -and -not "$(Get-Value $a 'scheduleInfo', 'expiration', 'type')") { $eligibleNoSchedule++ }
            $holder = New-RoleHolder -Principal (Get-Value $a 'principal') -PrincipalId $principalId -UsersById $usersById
            if ($holder.PrincipalType -eq 'Group') {
                if (-not $groupRoles.ContainsKey($principalId)) { $groupRoles[$principalId] = [Collections.Generic.List[string]]::new() }
                $groupRoles[$principalId].Add("$roleName ($($source.Kind))")
            }
            if ($holder.PrincipalType -eq 'Group' -and $groupMembers.ContainsKey($principalId)) {
                $members = $groupMembers[$principalId]
                $roleGroups.Add([pscustomobject]@{ Name = $holder.Name; RoleName = $roleName; Kind = $source.Kind; MemberCount = $members.Count })
                foreach ($m in $members) {
                    $member = New-RoleHolder -Principal $m -PrincipalId "$(Get-Value $m 'id')" -UsersById $usersById
                    $holders.Add((New-RoleHolderRow $member $roleId $roleName $source.Kind $standing $breakGlassIds $holder.Name $noExpiry))
                }
                continue
            }
            $holders.Add((New-RoleHolderRow $holder $roleId $roleName $source.Kind $standing $breakGlassIds '' $noExpiry))
        }
    }

    $registration = @{}
    foreach ($r in @(Get-Value $ds 'Registration', 'Items')) { if ($null -ne $r) { $registration["$(Get-Value $r 'id')"] = $r } }
    # An empty registration report for a tenant with users means Microsoft
    # hasn't filled it yet, not that nobody is registered. Treat it as not
    # collected, so the checks that need it are Skipped, never passed.
    if ($status['Registration'] -eq 'Collected' -and $registration.Count -eq 0 -and $usersById.Count -gt 0) {
        $status['Registration'] = 'Empty'
        $statusReason['Registration'] = "The MFA registration report has no records, though the tenant has $($usersById.Count) user(s). Microsoft fills it in the background, which can take a day in a new tenant."
    }

    # Groups that Conditional Access policies name, by ID, when they were
    # read: members by ID (users and anything else, but not the nested groups
    # themselves, whose members are already listed), owners, and whether the
    # group can be assigned roles.
    $caGroups = @{}
    foreach ($g in @(Get-Value $ds 'CaGroups', 'Items')) {
        if ($null -eq $g) { continue }
        $memberIds = @{}
        $members = @(Get-Value $g 'members' | Where-Object { $null -ne $_ -and "$(Get-Value $_ '@odata.type')" -notmatch 'group$' })
        foreach ($m in $members) { $memberIds["$(Get-Value $m 'id')"] = $true }
        $caGroups["$(Get-Value $g 'id')"] = [pscustomobject]@{
            Id             = "$(Get-Value $g 'id')"
            Name           = "$(Get-Value $g 'displayName')"
            Found          = (Get-Value $g 'found') -ne $false
            RoleAssignable = (Get-Value $g 'isAssignableToRole') -eq $true
            Members        = $members
            MemberIds      = $memberIds
            Owners         = @(Get-Value $g 'owners' | Where-Object { $null -ne $_ })
        }
    }

    $collectedAt = ConvertTo-UtcDate (Get-Value $Snapshot 'CollectedAt')
    if ($null -eq $collectedAt) { throw 'The snapshot has no CollectedAt time.' }

    return [pscustomobject]@{
        Snapshot      = $Snapshot
        Profile       = $AuditProfile
        Status        = $status
        Now           = $collectedAt
        StaleCutoff   = $collectedAt.AddDays(-$AuditProfile.StaleDays)
        UsersById     = $usersById
        BreakGlassIds = $breakGlassIds
        Holders       = $holders.ToArray()
        RoleGroups    = $roleGroups.ToArray()
        Registration  = $registration
        StatusReason  = $statusReason
        SpsById       = $spsById
        TenantId      = "$(Get-Value $Snapshot 'TenantId')"
        GroupRoles    = $groupRoles
        EligibleNoSchedule = $eligibleNoSchedule
        RoleNames     = $roleNames
        PrivilegedRoleIds = $privilegedRoleIds
        CaGroups      = $caGroups
    }
}

function New-Finding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object in memory; changes nothing.')]
    param([string]$Subject, [string]$Detail)
    return [pscustomobject]@{ Subject = $Subject; Detail = $Detail }
}

function New-Outcome {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object in memory; changes nothing.')]
    param([string]$Status, [string]$Summary, $Findings = @())
    return [pscustomobject]@{ Status = $Status; Summary = $Summary; Findings = @($Findings) }
}

function Get-LastSignIn {
    # The latest of the user's interactive, non-interactive and successful
    # sign-ins, or $null if Graph has none recorded.
    param($User)
    $dates = foreach ($field in 'lastSuccessfulSignInDateTime', 'lastSignInDateTime', 'lastNonInteractiveSignInDateTime') {
        $d = ConvertTo-UtcDate (Get-Value $User 'signInActivity', $field)
        if ($null -ne $d) { $d }
    }
    if (@($dates).Count -eq 0) { return $null }
    return (@($dates) | Sort-Object -Descending)[0]
}

function Get-EnabledUser {
    param($Context, [string]$UserType)
    @($Context.UsersById.Values | Where-Object {
            (Get-Value $_ 'accountEnabled') -eq $true -and "$(Get-Value $_ 'userType')" -eq $UserType
        } | Sort-Object { "$(Get-Value $_ 'userPrincipalName')" })
}

function Get-UserHolder {
    # Privileged role holders that are users, one row per user.
    param($Context)
    $seen = @{}
    foreach ($h in $Context.Holders) {
        if ($h.PrincipalType -ne 'User' -or $seen.ContainsKey($h.PrincipalId)) { continue }
        $seen[$h.PrincipalId] = $true
        $roles = @($Context.Holders | Where-Object PrincipalId -eq $h.PrincipalId | ForEach-Object { Get-HolderRoleText $_ } | Sort-Object -Unique)
        [pscustomobject]@{ PrincipalId = $h.PrincipalId; Name = $h.Name; User = $h.User; Roles = $roles -join ', ' }
    }
}

function Get-HolderRoleText {
    # A role as held: 'Helpdesk Administrator', or with 'via <group>' when a
    # group grants it.
    param($Holder)
    if ($Holder.Via) { return "$($Holder.RoleName) via $($Holder.Via)" }
    return $Holder.RoleName
}

function Test-PolicyGrantsMfa {
    param($Policy)
    $controls = @(Get-Value $Policy 'grantControls', 'builtInControls')
    return ($controls -contains 'mfa' -or $null -ne (Get-Value $Policy 'grantControls', 'authenticationStrength'))
}

function Test-PolicyForEveryApp {
    param($Policy)
    return (@(Get-Value $Policy 'conditions', 'applications', 'includeApplications') -contains 'All')
}

function Get-EnabledPolicy {
    param($Context)
    @(Get-Value $Context.Snapshot 'Datasets', 'ConditionalAccess', 'Items' | Where-Object {
            $null -ne $_ -and "$(Get-Value $_ 'state')" -eq 'enabled'
        })
}

function Get-CaBaseline {
    # Shared start of the CA checks that security defaults also satisfy.
    # Returns an outcome when the answer is already known, or $null to go on
    # and look at the policies.
    param($Context, [string]$What)
    $sd = @(Get-Value $Context.Snapshot 'Datasets', 'SecurityDefaults', 'Items')
    if ($Context.Status['SecurityDefaults'] -eq 'Collected' -and $sd.Count -gt 0 -and (Get-Value $sd[0] 'isEnabled') -eq $true) {
        return (New-Outcome Pass "Security defaults are on, which $What.")
    }
    $ca = $Context.Status['ConditionalAccess']
    if ($ca -eq 'Collected') { return $null }
    $sdState = $Context.Status['SecurityDefaults']
    if ($ca -eq 'NotLicensed' -and $sdState -eq 'Collected') {
        return (New-Outcome Fail "Security defaults are off and the tenant has no Conditional Access licence, so nothing $What." `
                @(New-Finding 'Tenant' 'Turn on security defaults, or license Microsoft Entra ID P1 and add a Conditional Access policy.'))
    }
    return (New-Outcome Skipped "Conditional Access was not collected ($ca) and security defaults are $sdState.")
}

function Get-HolderIdsInRole {
    # IDs of every principal that holds one of the roles, active or eligible.
    param($Context, [string[]]$RoleIds)
    $ids = @{}
    foreach ($h in $Context.Holders) { if ($RoleIds -contains $h.RoleId) { $ids[$h.PrincipalId] = $true } }
    return $ids
}

function Get-OwnerName {
    # An owner's name: its UPN, its display name, or its ID.
    param($Context, $Owner)
    $id = "$(Get-Value $Owner 'id')"
    $name = "$(Get-Value $Owner 'userPrincipalName')"
    if (-not $name -and $Context.UsersById.ContainsKey($id)) { $name = "$(Get-Value $Context.UsersById[$id] 'userPrincipalName')" }
    if (-not $name) { $name = "$(Get-Value $Owner 'displayName')" }
    if (-not $name) { $name = $id }
    return $name
}

function Get-PolicyRule {
    # One rule of a PIM policy, by its ID, or $null.
    param($Policy, [string]$RuleId)
    return (@(Get-Value $Policy 'rules' | Where-Object { $null -ne $_ -and "$(Get-Value $_ 'id')" -eq $RuleId }) | Select-Object -First 1)
}

function Get-TenantPolicy {
    # The one policy object a tenant settings dataset holds. A collected
    # dataset with none is an error, never read as default settings.
    param($Context, [string]$Dataset)
    $items = @(Get-Value $Context.Snapshot 'Datasets', $Dataset, 'Items' | Where-Object { $null -ne $_ })
    if ($items.Count -ne 1) { throw "$Dataset holds $($items.Count) policies, not one." }
    return $items[0]
}

function Get-ActiveRoleId {
    # Role IDs a user holds actively: directly, or through a group whose
    # members were read. Conditional Access targets active roles only.
    param($Context, [string]$UserId)
    $ids = @{}
    foreach ($a in @(Get-Value $Context.Snapshot 'Datasets', 'RoleAssignments', 'Items')) {
        if ($null -ne $a -and "$(Get-Value $a 'principalId')" -eq $UserId) { $ids["$(Get-Value $a 'roleDefinitionId')"] = $true }
    }
    foreach ($h in $Context.Holders) { if ($h.PrincipalId -eq $UserId -and $h.Kind -eq 'Active') { $ids[$h.RoleId] = $true } }
    return $ids
}

function Test-CaGroupMember {
    # Whether a user is in any of the groups: $true, $false, or $null when a
    # group's members weren't read and the user wasn't found in the others.
    param($Context, $GroupIds, [string]$UserId)
    $unknown = $false
    foreach ($id in @($GroupIds | Where-Object { "$_" })) {
        if (-not $Context.CaGroups.ContainsKey("$id")) { $unknown = $true; continue }
        if ($Context.CaGroups["$id"].MemberIds.ContainsKey($UserId)) { return $true }
    }
    if ($unknown) { return $null }
    return $false
}

function Get-CaPolicyReach {
    # Whether a Conditional Access policy applies to a member account: Yes,
    # No, or Unknown when it turns on a group whose members weren't read.
    # Included through all users, the account itself, an active role it
    # holds or a group it's in; excluded the same ways.
    param($Context, $Policy, [string]$UserId)
    $users = Get-Value $Policy 'conditions', 'users'
    $roles = Get-ActiveRoleId $Context $UserId
    $excluded = $false
    if (@(Get-Value $users 'excludeUsers') -contains $UserId) { $excluded = $true }
    if (@(Get-Value $users 'excludeRoles' | Where-Object { $roles.ContainsKey("$_") }).Count) { $excluded = $true }
    if (-not $excluded) { $excluded = Test-CaGroupMember $Context @(Get-Value $users 'excludeGroups') $UserId }
    if ($excluded -eq $true) { return 'No' }
    $included = $false
    $includeUsers = @(Get-Value $users 'includeUsers')
    if ($includeUsers -contains 'All' -or $includeUsers -contains $UserId) { $included = $true }
    if (@(Get-Value $users 'includeRoles' | Where-Object { $roles.ContainsKey("$_") }).Count) { $included = $true }
    if (-not $included) { $included = Test-CaGroupMember $Context @(Get-Value $users 'includeGroups') $UserId }
    if ($included -eq $false) { return 'No' }
    if ($included -eq $true -and $excluded -eq $false) { return 'Yes' }
    return 'Unknown'
}

function Get-ExternalIdentity {
    # Where a member account signs in from when it isn't the tenant's own: a
    # personal Microsoft account, another organization, or another provider.
    # $null for the tenant's own accounts. Reads identities (collected from
    # 0.6.0) and falls back to the #EXT# mark in the user principal name.
    param($User, [string]$Upn)
    foreach ($i in @(Get-Value $User 'identities')) {
        if ($null -eq $i -or "$(Get-Value $i 'signInType')" -ne 'federated') { continue }
        $issuer = "$(Get-Value $i 'issuer')"
        if ($issuer -eq 'MicrosoftAccount') { return 'a personal Microsoft account' }
        if ($issuer -eq 'ExternalAzureAD') { return 'an account in another Microsoft Entra organization' }
        if ($issuer) { return "an account from $issuer" }
    }
    if ($Upn -like '*#EXT#@*') { return 'an account from outside the tenant (#EXT# in its user principal name)' }
    return $null
}

function ConvertTo-Hour {
    # An ISO 8601 duration such as PT8H as hours, or $null if it isn't one.
    param([string]$Duration)
    if (-not $Duration) { return $null }
    try { return [Xml.XmlConvert]::ToTimeSpan($Duration).TotalHours }
    catch { Write-Verbose "Not a duration: $Duration"; return $null }
}

# Each check: Id, Area, Title, Severity, the datasets it needs, and a test that
# returns an outcome. A check whose datasets weren't all collected is Skipped
# with the reason, before its test runs.
$AuditChecks = @(
    [pscustomobject]@{
        Id = 'ROLE-01'; Area = 'Privileged roles'; Severity = 'High'
        Title = 'Number of Global Administrators'
        Needs = @('RoleAssignments')
        Test = {
            param($Context)
            $ga = @($Context.Holders | Where-Object RoleId -eq $GlobalAdminRoleId)
            $people = @($ga | ForEach-Object PrincipalId | Sort-Object -Unique)
            $findings = foreach ($id in $people) {
                $h = @($ga | Where-Object PrincipalId -eq $id)
                New-Finding $h[0].Name (@($h | ForEach-Object { if ($_.Via) { "$($_.Kind) via $($_.Via)" } else { $_.Kind } } | Sort-Object -Unique) -join ', ')
            }
            $note = ''
            if ($Context.Status['RoleEligibility'] -ne 'Collected') { $note = " PIM-eligible assignments weren't counted (RoleEligibility: $($Context.Status['RoleEligibility']))." }
            $groups = @($ga | Where-Object PrincipalType -eq 'Group')
            if ($groups.Count -gt 0) { $note += " $($groups.Count) group(s) hold the role and their members weren't read (RoleGroupMembers: $($Context.Status['RoleGroupMembers'])), so each counts as one." }
            $min = $Context.Profile.MinGlobalAdmins; $max = $Context.Profile.MaxGlobalAdmins
            $n = $people.Count
            if ($n -gt $max) { return (New-Outcome Fail "$n accounts hold Global Administrator; the most allowed is $max.$note" $findings) }
            if ($n -lt $min) { return (New-Outcome Warn "$n account(s) hold Global Administrator; at least $min are needed so one can recover the other.$note" $findings) }
            return (New-Outcome Pass "$n accounts hold Global Administrator, within $min to $max.$note" $findings)
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-02'; Area = 'Privileged roles'; Severity = 'High'
        Title = 'Standing Global Administrator assignments'
        Needs = @('RoleAssignments')
        Test = {
            param($Context)
            $standing = @($Context.Holders | Where-Object { $_.RoleId -eq $GlobalAdminRoleId -and $_.Standing -and -not $_.BreakGlass })
            $note = ''
            if ($Context.Status['RoleAssignmentSchedules'] -ne 'Collected') {
                $note = " PIM schedules weren't collected ($($Context.Status['RoleAssignmentSchedules'])), so every active assignment counts as standing."
            }
            $findings = foreach ($h in $standing) {
                $via = if ($h.Via) { " via $($h.Via)" } else { '' }
                New-Finding $h.Name "$($h.PrincipalType), permanently active$via"
            }
            if ($standing.Count -gt 0) { return (New-Outcome Fail "$($standing.Count) account(s) hold Global Administrator permanently, outside break-glass.$note" $findings) }
            return (New-Outcome Pass "No account holds Global Administrator permanently, outside break-glass.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-03'; Area = 'Privileged roles'; Severity = 'High'
        Title = 'Guests in privileged roles'
        Needs = @('RoleAssignments', 'Users')
        Test = {
            param($Context)
            $guests = @(Get-UserHolder $Context | Where-Object { "$(Get-Value $_.User 'userType')" -eq 'Guest' })
            $findings = foreach ($g in $guests) { New-Finding $g.Name $g.Roles }
            if ($guests.Count -gt 0) { return (New-Outcome Fail "$($guests.Count) guest account(s) hold a privileged role." $findings) }
            return (New-Outcome Pass 'No guest account holds a privileged role.')
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-04'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Accounts synced from on-premises in privileged roles'
        Needs = @('RoleAssignments', 'Users')
        Test = {
            param($Context)
            $synced = @(Get-UserHolder $Context | Where-Object { (Get-Value $_.User 'onPremisesSyncEnabled') -eq $true })
            $findings = foreach ($s in $synced) { New-Finding $s.Name $s.Roles }
            if ($synced.Count -gt 0) { return (New-Outcome Fail "$($synced.Count) account(s) synced from on-premises Active Directory hold a privileged role; a compromise there reaches the cloud." $findings) }
            return (New-Outcome Pass 'Every privileged account is cloud-only.')
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-05'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Privileged accounts without phishing-resistant MFA'
        Needs = @('RoleAssignments', 'Registration')
        Test = {
            param($Context)
            $findings = [Collections.Generic.List[object]]::new()
            $unknown = [Collections.Generic.List[object]]::new()
            foreach ($h in @(Get-UserHolder $Context)) {
                if (-not $Context.Registration.ContainsKey($h.PrincipalId)) { $unknown.Add((New-Finding $h.Name "$($h.Roles). No registration record")); continue }
                $methods = @(Get-Value $Context.Registration[$h.PrincipalId] 'methodsRegistered')
                if (-not @($methods | Where-Object { $PhishingResistantMethods -contains $_ })) {
                    $listed = if ($methods.Count) { $methods -join ', ' } else { 'none' }
                    $findings.Add((New-Finding $h.Name "$($h.Roles). Registered: $listed"))
                }
            }
            $note = if ($unknown.Count) { " $($unknown.Count) privileged account(s) had no registration record (disabled accounts aren't in the report)." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) privileged account(s) have no passkey, security key, Windows Hello or certificate registered.$note" $findings) }
            if ($unknown.Count -gt 0) { return (New-Outcome Warn "$($unknown.Count) privileged account(s) have no registration record, so their methods couldn't be checked." $unknown) }
            return (New-Outcome Pass 'Every privileged account has a phishing-resistant method registered.')
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-06'; Area = 'Privileged roles'; Severity = 'Low'
        Title = 'Privileged roles held by groups and service principals'
        Needs = @('RoleAssignments')
        Test = {
            param($Context)
            $other = @($Context.Holders | Where-Object { $_.PrincipalType -ne 'User' } | Sort-Object Name, RoleName)
            $findings = @(
                foreach ($g in @($Context.RoleGroups | Sort-Object Name, RoleName)) {
                    New-Finding $g.Name "$($g.RoleName) ($($g.Kind), group of $($g.MemberCount) member(s); each member is checked as a role holder)"
                }
                foreach ($h in $other) {
                    $what = if ($h.PrincipalType -eq 'Group') { "group; its members weren't read (RoleGroupMembers: $($Context.Status['RoleGroupMembers'])), so they aren't checked" } else { $h.PrincipalType }
                    $via = if ($h.Via) { ", member of $($h.Via)" } else { '' }
                    New-Finding $h.Name "$($h.RoleName) ($($h.Kind), $what$via)"
                }
            )
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) privileged assignment(s) go to a group or an app. Review who controls each." $findings) }
            return (New-Outcome Pass 'Every privileged role is assigned to user accounts directly.')
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-07'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Other privileged roles held permanently'
        Needs = @('RoleAssignments')
        Test = {
            param($Context)
            $standing = @($Context.Holders | Where-Object {
                    $_.Kind -eq 'Active' -and $_.Standing -and $_.RoleId -ne $GlobalAdminRoleId -and -not $_.BreakGlass -and $_.PrincipalType -ne 'ServicePrincipal'
                })
            $note = ''
            if ($Context.Status['RoleAssignmentSchedules'] -ne 'Collected') {
                $note = " PIM schedules weren't collected ($($Context.Status['RoleAssignmentSchedules'])), so every active assignment counts as permanent."
            }
            $findings = foreach ($id in @($standing | ForEach-Object PrincipalId | Sort-Object -Unique)) {
                $h = @($standing | Where-Object PrincipalId -eq $id)
                New-Finding $h[0].Name "$(@($h | ForEach-Object { Get-HolderRoleText $_ } | Sort-Object -Unique) -join ', '); permanently active"
            }
            $findings = @($findings | Sort-Object Subject)
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) account(s) hold a privileged role permanently, with no end date. Make them eligible in PIM, or give each assignment an end date.$note" $findings) }
            return (New-Outcome Pass "No account holds a privileged role permanently, apart from Global Administrator (ROLE-02), apps (SVC-02) and break-glass.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-08'; Area = 'Privileged roles'; Severity = 'Low'
        Title = 'Eligible privileged roles that never expire'
        Needs = @('RoleEligibility')
        Test = {
            param($Context)
            $eligible = @($Context.Holders | Where-Object Kind -eq 'Eligible')
            $open = @($eligible | Where-Object { $_.NoExpiry -and -not $_.BreakGlass })
            $note = if ($Context.EligibleNoSchedule) { " $($Context.EligibleNoSchedule) eligible assignment(s) had no schedule to read, so their end dates weren't checked." } else { '' }
            $findings = foreach ($id in @($open | ForEach-Object PrincipalId | Sort-Object -Unique)) {
                $h = @($open | Where-Object PrincipalId -eq $id)
                New-Finding $h[0].Name "$(@($h | ForEach-Object { Get-HolderRoleText $_ } | Sort-Object -Unique) -join ', '); eligible with no end date"
            }
            $findings = @($findings | Sort-Object Subject)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) account(s) are eligible for a privileged role with no end date, so the eligibility is never reviewed. Give each an end date, or review it with an access review.$note" $findings) }
            if ($eligible.Count -eq 0) { return (New-Outcome Pass "No account is eligible for a privileged role.$note") }
            return (New-Outcome Pass "Every eligible privileged assignment has an end date, apart from break-glass.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-09'; Area = 'Privileged roles'; Severity = 'High'
        Title = 'Roles granted to oneself'
        Needs = @('RoleAuditEvents')
        Test = {
            param($Context)
            $events = @(Get-Value $Context.Snapshot 'Datasets', 'RoleAuditEvents', 'Items' | Where-Object { $null -ne $_ })
            if ($events.Count -eq 0) { return (New-Outcome Pass 'The audit log holds no role changes to check. Microsoft keeps it for 7 days, or 30 with Microsoft Entra ID P1.') }
            $oldest = @($events | ForEach-Object { ConvertTo-UtcDate (Get-Value $_ 'activityDateTime') } | Where-Object { $null -ne $_ } | Sort-Object)[0]
            # Adding a role, eligible or active, directly or through PIM. A PIM
            # activation is a person using their own eligibility, so it doesn't
            # count; nor does a change PIM completes on someone's behalf, which
            # names no user as its initiator. PIM's "outside of PIM" event
            # repeats a change the directory already logged, so it isn't
            # counted twice.
            $adds = @($events | Where-Object {
                    "$(Get-Value $_ 'activityDisplayName')" -match '^Add (eligible |scoped )?member to role' -and
                    "$(Get-Value $_ 'activityDisplayName')" -notmatch 'activat|outside of PIM' -and
                    "$(Get-Value $_ 'result')" -eq 'success'
                })
            $findings = foreach ($e in $adds) {
                $by = "$(Get-Value $e 'initiatedBy', 'userId')"
                if (-not $by) { continue }
                $targets = @(Get-Value $e 'targetResources' | Where-Object { $null -ne $_ })
                if (-not @($targets | Where-Object { "$(Get-Value $_ 'type')" -eq 'User' -and "$(Get-Value $_ 'id')" -eq $by })) { continue }
                $role = @($targets | Where-Object { "$(Get-Value $_ 'type')" -eq 'Role' } | ForEach-Object { "$(Get-Value $_ 'displayName')" } | Where-Object { $_ })
                $roleText = if ($role.Count) { $role -join ', ' } else { 'a role' }
                $name = "$(Get-Value $e 'initiatedBy', 'userPrincipalName')"
                if (-not $name -and $Context.UsersById.ContainsKey($by)) { $name = "$(Get-Value $Context.UsersById[$by] 'userPrincipalName')" }
                if (-not $name) { $name = $by }
                New-Finding $name "$(Get-Value $e 'activityDisplayName'): $roleText, $(Format-AuditDate (Get-Value $e 'activityDateTime'))"
            }
            $findings = @($findings | Sort-Object Subject, Detail)
            $since = if ($null -ne $oldest) { " since $(Format-AuditDate $oldest)" } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) role assignment(s) in the audit log$since were made by the account that received them. Confirm each was approved, and require a second person for role changes." $findings) }
            return (New-Outcome Pass "None of the $($adds.Count) role addition(s) in the audit log$since was made by the account that received it. The log goes back 7 days, or 30 with Microsoft Entra ID P1.")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-10'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Weak PIM activation rules for privileged roles'
        Needs = @('RolePolicies', 'RoleEligibility')
        Test = {
            param($Context)
            $eligible = @($Context.Holders | Where-Object Kind -eq 'Eligible')
            if ($eligible.Count -eq 0) { return (New-Outcome Pass 'No account is eligible for a privileged role, so no activation rule is in use.') }
            $max = $Context.Profile.MaxActivationHours
            $policies = @{}
            foreach ($a in @(Get-Value $Context.Snapshot 'Datasets', 'RolePolicies', 'Items')) { if ($null -ne $a) { $policies["$(Get-Value $a 'roleDefinitionId')"] = $a } }
            $unread = [Collections.Generic.List[string]]::new()
            $findings = foreach ($roleId in @($eligible | ForEach-Object RoleId | Sort-Object -Unique)) {
                $holders = @($eligible | Where-Object RoleId -eq $roleId)
                $roleName = $holders[0].RoleName
                if (-not $policies.ContainsKey($roleId)) { $unread.Add($roleName); continue }
                $policy = $policies[$roleId]
                $issues = [Collections.Generic.List[string]]::new()
                $enabled = @(Get-Value (Get-PolicyRule $policy 'Enablement_EndUser_Assignment') 'enabledRules')
                $authContext = (Get-Value (Get-PolicyRule $policy 'AuthenticationContext_EndUser_Assignment') 'isEnabled') -eq $true
                if ($enabled -notcontains 'MultiFactorAuthentication' -and -not $authContext) { $issues.Add('activation needs no MFA') }
                $hours = ConvertTo-Hour "$(Get-Value (Get-PolicyRule $policy 'Expiration_EndUser_Assignment') 'maximumDuration')"
                if ($null -ne $hours -and $hours -gt $max) { $issues.Add("activation lasts up to $hours hours") }
                if (@($GlobalAdminRoleId, $PrivilegedRoleAdminRoleId) -contains $roleId -and
                    (Get-Value (Get-PolicyRule $policy 'Approval_EndUser_Assignment') 'setting', 'isApprovalRequired') -ne $true) {
                    $issues.Add('activation needs no approval')
                }
                if ($issues.Count -gt 0) {
                    $people = @($holders | ForEach-Object PrincipalId | Sort-Object -Unique).Count
                    New-Finding $roleName "$($issues -join '; '); $people eligible account(s)"
                }
            }
            $findings = @($findings | Sort-Object Subject)
            $note = if ($unread.Count) { " No PIM policy was read for $($unread -join ', '), so it wasn't checked." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) privileged role(s) with eligible accounts can be activated too easily. Require MFA, keep activation to $max hours or less, and require approval for Global and Privileged Role Administrator.$note" $findings) }
            return (New-Outcome Pass "Every privileged role with eligible accounts needs MFA to activate and lasts $max hours or less, and Global and Privileged Role Administrator need approval.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-11'; Area = 'Privileged roles'; Severity = 'High'
        Title = 'Owners of groups that hold privileged roles'
        Needs = @('RoleGroupOwners', 'RoleAssignments')
        Test = {
            param($Context)
            $admins = Get-HolderIdsInRole $Context $GroupAdminRoleIds
            $skipped = 0
            $findings = foreach ($g in @(Get-Value $Context.Snapshot 'Datasets', 'RoleGroupOwners', 'Items' | Where-Object { $null -ne $_ })) {
                $groupId = "$(Get-Value $g 'groupId')"
                if (-not $Context.GroupRoles.ContainsKey($groupId)) { continue }
                $roles = @($Context.GroupRoles[$groupId] | Sort-Object -Unique) -join ', '
                foreach ($o in @(Get-Value $g 'owners' | Where-Object { $null -ne $_ })) {
                    $id = "$(Get-Value $o 'id')"
                    if ($admins.ContainsKey($id) -or $Context.BreakGlassIds.ContainsKey($id)) { $skipped++; continue }
                    New-Finding (Get-OwnerName $Context $o) "Owns $(Get-Value $g 'displayName'), which holds $roles"
                }
            }
            $findings = @($findings | Sort-Object Subject, Detail)
            $note = if ($skipped) { " $skipped owner(s) who are Global or Privileged Role Administrators, or break-glass, were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) group owner(s) can add themselves to a group that holds a privileged role, and so take the role. Remove the owners, or make them hold the role themselves under PIM.$note" $findings) }
            if ($Context.GroupRoles.Count -eq 0) { return (New-Outcome Pass 'No group holds a privileged role.') }
            return (New-Outcome Pass "No one else owns a group that holds a privileged role.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-12'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Privileged roles assigned outside PIM'
        Needs = @('RoleAuditEvents', 'RoleAssignmentSchedules')
        Test = {
            param($Context)
            # PIM logs its own event whenever a role is assigned directly in
            # the directory instead of through PIM. Without PIM (no P2) every
            # assignment is made that way, and the check is Skipped through
            # RoleAssignmentSchedules.
            $events = @(Get-Value $Context.Snapshot 'Datasets', 'RoleAuditEvents', 'Items' | Where-Object {
                    $null -ne $_ -and "$(Get-Value $_ 'activityDisplayName')" -match 'outside of PIM' -and "$(Get-Value $_ 'result')" -eq 'success'
                })
            $breakGlass = 0; $other = 0
            $findings = foreach ($e in $events) {
                $targets = @(Get-Value $e 'targetResources' | Where-Object { $null -ne $_ })
                $role = @($targets | Where-Object { "$(Get-Value $_ 'type')" -eq 'Role' })
                $roleId = if ($role.Count) { "$(Get-Value $role[0] 'id')" } else { '' }
                if (-not $Context.PrivilegedRoleIds.ContainsKey($roleId)) { $other++; continue }
                $roleName = "$(Get-Value $role[0] 'displayName')"
                if (-not $roleName) { $roleName = $Context.RoleNames[$roleId] }
                $user = @($targets | Where-Object { @('User', 'ServicePrincipal', 'Group') -contains "$(Get-Value $_ 'type')" })
                $userId = if ($user.Count) { "$(Get-Value $user[0] 'id')" } else { '' }
                if ($Context.BreakGlassIds.ContainsKey($userId)) { $breakGlass++; continue }
                $name = ''
                if ($Context.UsersById.ContainsKey($userId)) { $name = "$(Get-Value $Context.UsersById[$userId] 'userPrincipalName')" }
                if (-not $name -and $user.Count) { $name = "$(Get-Value $user[0] 'userPrincipalName')" }
                if (-not $name -and $user.Count) { $name = "$(Get-Value $user[0] 'displayName')" }
                if (-not $name) { $name = $(if ($userId) { $userId } else { 'Unknown account' }) }
                $by = "$(Get-Value $e 'initiatedBy', 'userPrincipalName')"
                if (-not $by) { $by = "$(Get-Value $e 'initiatedBy', 'app')" }
                $byText = if ($by) { " by $by" } else { '' }
                New-Finding $name "$roleName$byText, $(Format-AuditDate (Get-Value $e 'activityDateTime'))"
            }
            $findings = @($findings | Sort-Object Subject, Detail)
            $note = ''
            if ($breakGlass) { $note += " $breakGlass assignment(s) to break-glass accounts weren't counted." }
            if ($other) { $note += " $other assignment(s) of roles that aren't privileged weren't counted." }
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) privileged role assignment(s) in the audit log were made directly, outside PIM, so they skipped its approval, justification and end date. Make them eligible in PIM instead.$note" $findings) }
            return (New-Outcome Pass "No privileged role was assigned outside PIM in the audit log, which goes back 7 days, or 30 with Microsoft Entra ID P1.$note")
        }
    }
    [pscustomobject]@{
        Id = 'ROLE-13'; Area = 'Privileged roles'; Severity = 'Medium'
        Title = 'Privileged roles held by personal or external accounts'
        Needs = @('RoleAssignments', 'Users')
        Test = {
            param($Context)
            $findings = foreach ($h in @(Get-UserHolder $Context)) {
                # Guests are ROLE-03's.
                if ("$(Get-Value $h.User 'userType')" -eq 'Guest') { continue }
                $source = Get-ExternalIdentity $h.User $h.Name
                if ($source) { New-Finding $h.Name "$($h.Roles). Signs in with $source." }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) member account(s) holding a privileged role sign in with an identity from outside this tenant, whose password, recovery and lifecycle this tenant doesn't control. Give the role to a cloud-only account in this tenant instead." $findings) }
            return (New-Outcome Pass "Every member account holding a privileged role is the tenant's own.")
        }
    }
    [pscustomobject]@{
        Id = 'STALE-01'; Area = 'Stale accounts'; Severity = 'Medium'
        Title = 'Enabled members with no recent sign-in'
        Needs = @('Users', 'SignIns')
        Test = {
            param($Context)
            $findings = foreach ($u in (Get-EnabledUser $Context 'Member')) {
                if ($Context.BreakGlassIds.ContainsKey("$(Get-Value $u 'id')")) { continue }
                $last = Get-LastSignIn $u
                if ($null -ne $last -and $last -lt $Context.StaleCutoff) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Last sign-in $(Format-AuditDate $last)"
                }
            }
            $findings = @($findings)
            $days = $Context.Profile.StaleDays
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) enabled member account(s) haven't signed in for $days days." $findings) }
            return (New-Outcome Pass "Every enabled member that has signed in did so in the last $days days.")
        }
    }
    [pscustomobject]@{
        Id = 'STALE-02'; Area = 'Stale accounts'; Severity = 'Low'
        Title = 'Enabled members that never signed in'
        Needs = @('Users', 'SignIns')
        Test = {
            param($Context)
            $findings = foreach ($u in (Get-EnabledUser $Context 'Member')) {
                if ($Context.BreakGlassIds.ContainsKey("$(Get-Value $u 'id')")) { continue }
                $created = ConvertTo-UtcDate (Get-Value $u 'createdDateTime')
                if ($null -eq (Get-LastSignIn $u) -and $null -ne $created -and $created -lt $Context.StaleCutoff) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Created $(Format-AuditDate $created), no sign-in recorded"
                }
            }
            $findings = @($findings)
            $days = $Context.Profile.StaleDays
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) enabled member account(s) older than $days days have never signed in." $findings) }
            return (New-Outcome Pass "No enabled member account older than $days days is unused.")
        }
    }
    [pscustomobject]@{
        Id = 'STALE-03'; Area = 'Stale accounts'; Severity = 'Medium'
        Title = 'Enabled guests with no recent sign-in'
        Needs = @('Users', 'SignIns')
        Test = {
            param($Context)
            $findings = foreach ($u in (Get-EnabledUser $Context 'Guest')) {
                if ("$(Get-Value $u 'externalUserState')" -eq 'PendingAcceptance') { continue }
                $last = Get-LastSignIn $u
                $created = ConvertTo-UtcDate (Get-Value $u 'createdDateTime')
                if ($null -ne $last -and $last -lt $Context.StaleCutoff) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Last sign-in $(Format-AuditDate $last)"
                } elseif ($null -eq $last -and $null -ne $created -and $created -lt $Context.StaleCutoff) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Invited $(Format-AuditDate $created), no sign-in recorded"
                }
            }
            $findings = @($findings)
            $days = $Context.Profile.StaleDays
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) enabled guest account(s) haven't signed in for $days days." $findings) }
            return (New-Outcome Pass "Every enabled guest has signed in within $days days, or was invited since.")
        }
    }
    [pscustomobject]@{
        Id = 'STALE-04'; Area = 'Stale accounts'; Severity = 'Low'
        Title = 'Guest invitations never accepted'
        Needs = @('Users')
        Test = {
            param($Context)
            $findings = foreach ($u in @($Context.UsersById.Values | Sort-Object { "$(Get-Value $_ 'userPrincipalName')" })) {
                if ("$(Get-Value $u 'externalUserState')" -ne 'PendingAcceptance') { continue }
                $since = ConvertTo-UtcDate (Get-Value $u 'externalUserStateChangeDateTime')
                if ($null -eq $since) { $since = ConvertTo-UtcDate (Get-Value $u 'createdDateTime') }
                if ($null -ne $since -and $since -lt $Context.StaleCutoff) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Invited $(Format-AuditDate $since)"
                }
            }
            $findings = @($findings)
            $days = $Context.Profile.StaleDays
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) guest invitation(s) have waited more than $days days. Remove them or send them again." $findings) }
            return (New-Outcome Pass "No guest invitation has waited more than $days days.")
        }
    }
    [pscustomobject]@{
        Id = 'MFA-01'; Area = 'MFA coverage'; Severity = 'High'
        Title = 'Enabled members without MFA registered'
        Needs = @('Users', 'Registration')
        Test = {
            param($Context)
            $unknown = [Collections.Generic.List[object]]::new()
            $findings = foreach ($u in (Get-EnabledUser $Context 'Member')) {
                $id = "$(Get-Value $u 'id')"
                if (-not $Context.Registration.ContainsKey($id)) { $unknown.Add((New-Finding "$(Get-Value $u 'userPrincipalName')" 'No registration record')); continue }
                if ((Get-Value $Context.Registration[$id] 'isMfaRegistered') -ne $true) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" 'No MFA method registered'
                }
            }
            $findings = @($findings)
            $note = if ($unknown.Count) { " $($unknown.Count) enabled member(s) had no registration record yet." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) enabled member account(s) have no MFA method registered.$note" $findings) }
            if ($unknown.Count -gt 0) { return (New-Outcome Warn "$($unknown.Count) enabled member(s) have no registration record, so their MFA couldn't be checked." $unknown) }
            return (New-Outcome Pass 'Every enabled member has an MFA method registered.')
        }
    }
    [pscustomobject]@{
        Id = 'MFA-02'; Area = 'MFA coverage'; Severity = 'Medium'
        Title = 'Users whose only MFA is a phone call or text'
        Needs = @('Users', 'Registration')
        Test = {
            param($Context)
            $findings = foreach ($u in @($Context.UsersById.Values | Where-Object { (Get-Value $_ 'accountEnabled') -eq $true } | Sort-Object { "$(Get-Value $_ 'userPrincipalName')" })) {
                $id = "$(Get-Value $u 'id')"
                if (-not $Context.Registration.ContainsKey($id)) { continue }
                $methods = @(Get-Value $Context.Registration[$id] 'methodsRegistered' | Where-Object { $_ })
                $phone = @($methods | Where-Object { $_ -in 'mobilePhone', 'alternateMobilePhone', 'officePhone' })
                $strong = @($methods | Where-Object { $WeakMethods -notcontains $_ })
                if ($phone.Count -gt 0 -and $strong.Count -eq 0) {
                    New-Finding "$(Get-Value $u 'userPrincipalName')" "Registered: $($methods -join ', ')"
                }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) enabled account(s) rely on SMS or voice calls, which SIM swaps and phishing defeat. Move them to the Authenticator app or a passkey." $findings) }
            return (New-Outcome Pass 'No enabled account relies on SMS or voice alone.')
        }
    }
    [pscustomobject]@{
        Id = 'MFA-03'; Area = 'MFA coverage'; Severity = 'High'
        Title = 'Privileged accounts without MFA registered'
        Needs = @('RoleAssignments', 'Registration')
        Test = {
            param($Context)
            $unknown = [Collections.Generic.List[object]]::new()
            $findings = foreach ($h in @(Get-UserHolder $Context)) {
                if (-not $Context.Registration.ContainsKey($h.PrincipalId)) { $unknown.Add((New-Finding $h.Name "$($h.Roles). No registration record")); continue }
                if ((Get-Value $Context.Registration[$h.PrincipalId] 'isMfaRegistered') -ne $true) {
                    New-Finding $h.Name $h.Roles
                }
            }
            $findings = @($findings)
            $note = if ($unknown.Count) { " $($unknown.Count) privileged account(s) had no registration record." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) privileged account(s) have no MFA method registered.$note" $findings) }
            if ($unknown.Count -gt 0) { return (New-Outcome Warn "$($unknown.Count) privileged account(s) have no registration record, so their MFA couldn't be checked." $unknown) }
            return (New-Outcome Pass 'Every privileged account has MFA registered.')
        }
    }
    [pscustomobject]@{
        Id = 'APP-01'; Area = 'Apps'; Severity = 'Low'
        Title = 'Expired app secrets and certificates'
        Needs = @('Applications')
        Test = {
            param($Context)
            $findings = foreach ($c in (Get-AppCredential $Context)) {
                if ($null -ne $c.End -and $c.End -lt $Context.Now) {
                    New-Finding $c.App "$($c.Type) '$($c.Name)' expired $(Format-AuditDate $c.End)"
                }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) expired credential(s) are still on app registrations. Remove them." $findings) }
            return (New-Outcome Pass 'No app registration keeps an expired credential.')
        }
    }
    [pscustomobject]@{
        Id = 'APP-02'; Area = 'Apps'; Severity = 'Medium'
        Title = 'App secrets and certificates about to expire'
        Needs = @('Applications')
        Test = {
            param($Context)
            $limit = $Context.Now.AddDays($Context.Profile.CredentialExpiryDays)
            $findings = foreach ($c in (Get-AppCredential $Context)) {
                if ($null -ne $c.End -and $c.End -ge $Context.Now -and $c.End -le $limit) {
                    New-Finding $c.App "$($c.Type) '$($c.Name)' expires $(Format-AuditDate $c.End)"
                }
            }
            $findings = @($findings)
            $days = $Context.Profile.CredentialExpiryDays
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) credential(s) expire in the next $days days." $findings) }
            return (New-Outcome Pass "No credential expires in the next $days days.")
        }
    }
    [pscustomobject]@{
        Id = 'APP-03'; Area = 'Apps'; Severity = 'Low'
        Title = 'Long-lived client secrets'
        Needs = @('Applications')
        Test = {
            param($Context)
            $max = $Context.Profile.MaxSecretLifetimeDays
            $findings = foreach ($c in (Get-AppCredential $Context)) {
                if ($c.Type -ne 'Secret' -or $null -eq $c.Start -or $null -eq $c.End -or $c.End -lt $Context.Now) { continue }
                $days = [int][math]::Floor(($c.End - $c.Start).TotalDays)
                if ($days -gt $max) { New-Finding $c.App "Secret '$($c.Name)' is valid for $days days, to $(Format-AuditDate $c.End)" }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) client secret(s) are valid for more than $max days. Prefer certificates or managed identities, or shorter secrets." $findings) }
            return (New-Outcome Pass "No current client secret is valid for more than $max days.")
        }
    }
    [pscustomobject]@{
        Id = 'APP-04'; Area = 'Apps'; Severity = 'High'
        Title = 'High-risk Microsoft Graph application permissions'
        Needs = @('GraphPermissionGrants')
        Test = {
            param($Context)
            $risky = @($Context.Profile.HighRiskPermissions)
            $accepted = @($Context.Profile.AcceptedApps | ForEach-Object { "$_".ToLowerInvariant() })
            $acceptedCount = 0
            $findings = foreach ($g in @(Get-Value $Context.Snapshot 'Datasets', 'GraphPermissionGrants', 'Items' | Sort-Object { "$(Get-Value $_ 'principalDisplayName')" }, { "$(Get-Value $_ 'permission')" })) {
                if ($null -eq $g) { continue }
                $permission = "$(Get-Value $g 'permission')"
                if ($risky -notcontains $permission) { continue }
                $name = "$(Get-Value $g 'principalDisplayName')"
                if ($accepted -contains $name.ToLowerInvariant() -or $accepted -contains "$(Get-Value $g 'principalId')".ToLowerInvariant()) { $acceptedCount++; continue }
                New-Finding $name "$permission (granted $(Format-AuditDate (Get-Value $g 'createdDateTime')))"
            }
            $findings = @($findings)
            $note = if ($acceptedCount) { " $acceptedCount grant(s) to apps listed in AcceptedApps were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) high-risk application permission(s) are granted. Each lets an app act across the tenant with no user signed in.$note" $findings) }
            return (New-Outcome Pass "No app holds a high-risk application permission.$note")
        }
    }
    [pscustomobject]@{
        Id = 'APP-05'; Area = 'Apps'; Severity = 'Low'
        Title = 'App registrations without an owner'
        Needs = @('Applications')
        Test = {
            param($Context)
            $findings = foreach ($a in @(Get-Value $Context.Snapshot 'Datasets', 'Applications', 'Items' | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
                if ($null -eq $a) { continue }
                if (@(Get-Value $a 'owners' | Where-Object { $null -ne $_ }).Count -eq 0) {
                    New-Finding "$(Get-Value $a 'displayName')" "Created $(Format-AuditDate (Get-Value $a 'createdDateTime'))"
                }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) app registration(s) have no owner to answer for them." $findings) }
            return (New-Outcome Pass 'Every app registration has an owner.')
        }
    }
    [pscustomobject]@{
        Id = 'APP-06'; Area = 'Apps'; Severity = 'Medium'
        Title = 'High-risk delegated permissions consented for every user'
        Needs = @('DelegatedPermissionGrants', 'ServicePrincipals')
        Test = {
            param($Context)
            $grants = @(Get-DelegatedGrant $Context | Where-Object ConsentType -eq 'AllPrincipals')
            $accepted = @($grants | Where-Object Accepted)
            $findings = foreach ($g in @($grants | Where-Object { -not $_.Accepted })) {
                New-Finding $g.App "$($g.Scopes -join ', '), consented for every user"
            }
            $findings = @($findings)
            $note = if ($accepted.Count) { " $($accepted.Count) grant(s) to apps listed in AcceptedApps were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) app(s) can use high-risk Microsoft Graph permissions on behalf of any user who signs in to them, by tenant-wide consent.$note" $findings) }
            return (New-Outcome Pass "No app has tenant-wide consent to a high-risk delegated permission.$note")
        }
    }
    [pscustomobject]@{
        Id = 'APP-07'; Area = 'Apps'; Severity = 'Low'
        Title = 'High-risk delegated permissions consented by users'
        Needs = @('DelegatedPermissionGrants', 'ServicePrincipals')
        Test = {
            param($Context)
            $grants = @(Get-DelegatedGrant $Context | Where-Object { $_.ConsentType -eq 'Principal' -and -not $_.Accepted })
            $findings = foreach ($app in @($grants | Group-Object App | Sort-Object Name)) {
                $scopes = @($app.Group | ForEach-Object Scopes | Sort-Object -Unique)
                $people = @($app.Group | ForEach-Object PrincipalId | Sort-Object -Unique)
                $names = foreach ($id in $people) {
                    if ($Context.UsersById.ContainsKey($id)) { "$(Get-Value $Context.UsersById[$id] 'userPrincipalName')" } else { $id }
                }
                New-Finding $app.Name "$($scopes -join ', '), consented by $($people.Count) user(s): $(@($names | Sort-Object) -join ', ')"
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) app(s) hold high-risk Microsoft Graph permissions that users consented to themselves. Review each, and consider requiring admin consent." $findings) }
            return (New-Outcome Pass 'No user has consented to a high-risk delegated permission.')
        }
    }
    [pscustomobject]@{
        Id = 'SVC-01'; Area = 'Service accounts'; Severity = 'Medium'
        Title = 'Secrets and certificates on enterprise apps'
        Needs = @('ServicePrincipalDetails')
        Test = {
            param($Context)
            $creds = @(Get-SpCredential $Context | Where-Object { $null -eq $_.End -or $_.End -ge $Context.Now })
            $accepted = @($creds | Where-Object { Test-AcceptedApp $Context $_.Sp })
            $findings = foreach ($c in @($creds | Where-Object { -not (Test-AcceptedApp $Context $_.Sp) })) {
                $until = if ($null -ne $c.End) { "valid to $(Format-AuditDate $c.End)" } else { 'no end date' }
                New-Finding $c.App "$($c.Type) '$($c.Name)', $until"
            }
            $findings = @($findings)
            $note = if ($accepted.Count) { " $($accepted.Count) credential(s) on apps listed in AcceptedApps were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) secret(s) or certificate(s) let someone sign in as an enterprise app, outside its app registration. Check each was added on purpose.$note" $findings) }
            return (New-Outcome Pass "No enterprise app has a current secret or certificate of its own, apart from SAML signing certificates.$note")
        }
    }
    [pscustomobject]@{
        Id = 'SVC-02'; Area = 'Service accounts'; Severity = 'High'
        Title = 'Service principals in privileged roles'
        Needs = @('RoleAssignments')
        Test = {
            param($Context)
            $sps = @($Context.Holders | Where-Object PrincipalType -eq 'ServicePrincipal')
            $accepted = 0
            $findings = foreach ($id in @($sps | ForEach-Object PrincipalId | Sort-Object -Unique)) {
                $h = @($sps | Where-Object PrincipalId -eq $id)
                $sp = $Context.SpsById[$id]
                if ($null -eq $sp) { $sp = [pscustomobject]@{ id = $id; displayName = $h[0].Name } }
                if (Test-AcceptedApp $Context $sp) { $accepted++; continue }
                $roles = @($h | ForEach-Object { "$(Get-HolderRoleText $_) ($($_.Kind))" } | Sort-Object -Unique)
                New-Finding $h[0].Name ($roles -join ', ')
            }
            $findings = @($findings | Sort-Object Subject)
            $note = if ($accepted) { " $accepted app(s) listed in AcceptedApps were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) app(s) hold a privileged role. Anyone with the app's credentials holds it too, with no MFA.$note" $findings) }
            return (New-Outcome Pass "No app holds a privileged role.$note")
        }
    }
    [pscustomobject]@{
        Id = 'SVC-03'; Area = 'Service accounts'; Severity = 'High'
        Title = 'Apps from other organizations with high-risk permissions'
        Needs = @('ServicePrincipalDetails', 'GraphPermissionGrants', 'DelegatedPermissionGrants')
        Test = {
            param($Context)
            if (-not $Context.TenantId) { return (New-Outcome Skipped "The snapshot doesn't record the tenant's ID, so apps from other organizations can't be told apart.") }
            $risky = @($Context.Profile.HighRiskPermissions)
            $byApp = [ordered]@{}
            foreach ($g in @(Get-Value $Context.Snapshot 'Datasets', 'GraphPermissionGrants', 'Items')) {
                if ($null -eq $g -or $risky -notcontains "$(Get-Value $g 'permission')") { continue }
                $id = "$(Get-Value $g 'principalId')"
                if (-not $byApp.Contains($id)) { $byApp[$id] = [Collections.Generic.List[string]]::new() }
                $byApp[$id].Add("$(Get-Value $g 'permission') (application)")
            }
            foreach ($g in @(Get-DelegatedGrant $Context | Where-Object ConsentType -eq 'AllPrincipals')) {
                if (-not $byApp.Contains($g.ClientId)) { $byApp[$g.ClientId] = [Collections.Generic.List[string]]::new() }
                foreach ($scope in $g.Scopes) { $byApp[$g.ClientId].Add("$scope (delegated, every user)") }
            }
            $accepted = 0
            $findings = foreach ($id in $byApp.Keys) {
                $sp = $Context.SpsById[$id]
                if ($null -eq $sp) { continue }
                $owner = "$(Get-Value $sp 'appOwnerOrganizationId')"
                if (-not $owner -or $owner -eq $Context.TenantId -or $MicrosoftTenantIds -contains $owner) { continue }
                if (Test-AcceptedApp $Context $sp) { $accepted++; continue }
                New-Finding "$(Get-Value $sp 'displayName')" "$(@($byApp[$id] | Sort-Object -Unique) -join ', '); published by tenant $owner"
            }
            $findings = @($findings | Sort-Object Subject)
            $note = if ($accepted) { " $accepted app(s) listed in AcceptedApps were not counted." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) app(s) published by another organization hold high-risk permissions in this tenant. Whoever controls the app there controls that access here.$note" $findings) }
            return (New-Outcome Pass "No app from another organization holds a high-risk permission.$note")
        }
    }
    [pscustomobject]@{
        Id = 'SVC-04'; Area = 'Service accounts'; Severity = 'Low'
        Title = 'Disabled apps that still hold permissions or roles'
        Needs = @('ServicePrincipalDetails', 'GraphPermissionGrants', 'DelegatedPermissionGrants', 'RoleAssignments')
        Test = {
            param($Context)
            $findings = foreach ($sp in @($Context.SpsById.Values | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
                if ((Get-Value $sp 'accountEnabled') -ne $false) { continue }
                $id = "$(Get-Value $sp 'id')"
                $held = @(
                    @(Get-Value $Context.Snapshot 'Datasets', 'GraphPermissionGrants', 'Items' | Where-Object { $null -ne $_ -and "$(Get-Value $_ 'principalId')" -eq $id }) |
                        ForEach-Object { "$(Get-Value $_ 'permission') (application)" }
                    @(Get-Value $Context.Snapshot 'Datasets', 'DelegatedPermissionGrants', 'Items' | Where-Object { $null -ne $_ -and "$(Get-Value $_ 'clientId')" -eq $id }) |
                        ForEach-Object { "delegated: $(Get-Value $_ 'scope')".Trim() }
                    @($Context.Holders | Where-Object PrincipalId -eq $id) | ForEach-Object { Get-HolderRoleText $_ }
                )
                if ($held.Count -gt 0) { New-Finding "$(Get-Value $sp 'displayName')" "Disabled, still holds: $(@($held | Sort-Object -Unique) -join '; ')" }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) disabled app(s) still hold permissions or roles. Remove what they no longer need, so turning them back on doesn't restore it." $findings) }
            return (New-Outcome Pass 'No disabled app holds a permission or role.')
        }
    }
    [pscustomobject]@{
        Id = 'SVC-05'; Area = 'Service accounts'; Severity = 'High'
        Title = 'Owners of apps with high-risk access'
        Needs = @('AppOwners', 'Applications', 'ServicePrincipals', 'GraphPermissionGrants', 'RoleAssignments')
        Test = {
            param($Context)
            # What each app can do: high-risk application permissions and
            # privileged roles.
            $risky = @($Context.Profile.HighRiskPermissions)
            $access = @{}
            foreach ($g in @(Get-Value $Context.Snapshot 'Datasets', 'GraphPermissionGrants', 'Items')) {
                if ($null -eq $g -or $risky -notcontains "$(Get-Value $g 'permission')") { continue }
                $id = "$(Get-Value $g 'principalId')"
                if (-not $access.ContainsKey($id)) { $access[$id] = [Collections.Generic.List[string]]::new() }
                $access[$id].Add("$(Get-Value $g 'permission')")
            }
            foreach ($h in @($Context.Holders | Where-Object PrincipalType -eq 'ServicePrincipal')) {
                if (-not $access.ContainsKey($h.PrincipalId)) { $access[$h.PrincipalId] = [Collections.Generic.List[string]]::new() }
                $access[$h.PrincipalId].Add((Get-HolderRoleText $h))
            }
            $spOwners = @{}
            foreach ($o in @(Get-Value $Context.Snapshot 'Datasets', 'AppOwners', 'Items')) { if ($null -ne $o) { $spOwners["$(Get-Value $o 'servicePrincipalId')"] = @(Get-Value $o 'owners' | Where-Object { $null -ne $_ }) } }
            $appsByAppId = @{}
            foreach ($a in @(Get-Value $Context.Snapshot 'Datasets', 'Applications', 'Items')) { if ($null -ne $a) { $appsByAppId["$(Get-Value $a 'appId')"] = $a } }
            $admins = Get-HolderIdsInRole $Context $AppAdminRoleIds
            $skipped = 0; $accepted = 0
            $findings = foreach ($id in $access.Keys) {
                $sp = $Context.SpsById[$id]
                if ($null -eq $sp) { continue }
                if (Test-AcceptedApp $Context $sp) { $accepted++; continue }
                $what = @($access[$id] | Sort-Object -Unique) -join ', '
                $app = $appsByAppId["$(Get-Value $sp 'appId')"]
                $owned = @(
                    foreach ($o in @($spOwners[$id])) { if ($null -ne $o) { @{ Owner = $o; Of = 'enterprise app' } } }
                    if ($null -ne $app) { foreach ($o in @(Get-Value $app 'owners' | Where-Object { $null -ne $_ })) { @{ Owner = $o; Of = 'app registration' } } }
                )
                foreach ($x in $owned) {
                    $ownerId = "$(Get-Value $x.Owner 'id')"
                    if ($admins.ContainsKey($ownerId) -or $Context.BreakGlassIds.ContainsKey($ownerId)) { $skipped++; continue }
                    New-Finding (Get-OwnerName $Context $x.Owner) "Owns the $($x.Of) $(Get-Value $sp 'displayName'), which holds $what"
                }
            }
            $findings = @($findings | Sort-Object Subject, Detail)
            $note = ''
            if ($skipped) { $note += " $skipped owner(s) who already hold an admin role over apps, or are break-glass, were not counted." }
            if ($accepted) { $note += " $accepted app(s) listed in AcceptedApps were not counted." }
            if ($findings.Count -gt 0) { return (New-Outcome Fail "$($findings.Count) owner(s) can add a secret to an app that holds high-risk access, and act as it with no MFA. Remove the owners, or reduce what the app holds.$note" $findings) }
            return (New-Outcome Pass "No one outside the admin roles owns an app that holds a high-risk permission or a privileged role.$note")
        }
    }
    [pscustomobject]@{
        Id = 'CA-01'; Area = 'Conditional Access'; Severity = 'High'
        Title = 'MFA required for all users'
        Needs = @()
        Test = {
            param($Context)
            $base = Get-CaBaseline $Context 'requires MFA for all users'
            if ($base) { return $base }
            $match = @(Get-EnabledPolicy $Context | Where-Object {
                    (@(Get-Value $_ 'conditions', 'users', 'includeUsers') -contains 'All') -and (Test-PolicyForEveryApp $_) -and (Test-PolicyGrantsMfa $_)
                })
            if ($match.Count -gt 0) {
                return (New-Outcome Pass "Enabled policy requires MFA for all users and apps: $(@($match | ForEach-Object { Get-Value $_ 'displayName' }) -join '; ').")
            }
            return (New-Outcome Fail 'No enabled policy requires MFA for all users on all apps.' @(New-Finding 'Conditional Access' 'Add a policy: all users, all resources, grant require MFA or an authentication strength.'))
        }
    }
    [pscustomobject]@{
        Id = 'CA-02'; Area = 'Conditional Access'; Severity = 'High'
        Title = 'MFA required for administrators'
        Needs = @()
        Test = {
            param($Context)
            $base = Get-CaBaseline $Context 'requires MFA for administrators'
            if ($base) { return $base }
            $match = @(Get-EnabledPolicy $Context | Where-Object {
                    $users = @(Get-Value $_ 'conditions', 'users', 'includeUsers')
                    $roles = @(Get-Value $_ 'conditions', 'users', 'includeRoles')
                    ($users -contains 'All' -or $roles -contains $GlobalAdminRoleId) -and (Test-PolicyForEveryApp $_) -and (Test-PolicyGrantsMfa $_)
                })
            if ($match.Count -gt 0) {
                return (New-Outcome Pass "Enabled policy requires MFA for Global Administrators: $(@($match | ForEach-Object { Get-Value $_ 'displayName' }) -join '; ').")
            }
            return (New-Outcome Fail 'No enabled policy requires MFA for Global Administrators on all apps.' @(New-Finding 'Conditional Access' 'Add a policy: directory roles (at least Global Administrator), all resources, grant require MFA.'))
        }
    }
    [pscustomobject]@{
        Id = 'CA-03'; Area = 'Conditional Access'; Severity = 'High'
        Title = 'Legacy authentication blocked'
        Needs = @()
        Test = {
            param($Context)
            $base = Get-CaBaseline $Context 'blocks legacy authentication'
            if ($base) { return $base }
            $match = @(Get-EnabledPolicy $Context | Where-Object {
                    $clients = @(Get-Value $_ 'conditions', 'clientAppTypes')
                    (@(Get-Value $_ 'conditions', 'users', 'includeUsers') -contains 'All') -and (Test-PolicyForEveryApp $_) -and
                    $clients -contains 'exchangeActiveSync' -and $clients -contains 'other' -and
                    @(Get-Value $_ 'grantControls', 'builtInControls') -contains 'block'
                })
            if ($match.Count -gt 0) {
                return (New-Outcome Pass "Enabled policy blocks legacy authentication: $(@($match | ForEach-Object { Get-Value $_ 'displayName' }) -join '; ').")
            }
            return (New-Outcome Fail 'No enabled policy blocks legacy authentication (Exchange ActiveSync and other clients) for all users.' @(New-Finding 'Conditional Access' 'Add a policy: all users, all resources, client apps Exchange ActiveSync and Other clients, grant block.'))
        }
    }
    [pscustomobject]@{
        Id = 'CA-04'; Area = 'Conditional Access'; Severity = 'Low'
        Title = 'Policies left in report-only mode'
        Needs = @('ConditionalAccess')
        Test = {
            param($Context)
            $findings = foreach ($p in @(Get-Value $Context.Snapshot 'Datasets', 'ConditionalAccess', 'Items' | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
                if ($null -ne $p -and "$(Get-Value $p 'state')" -eq 'enabledForReportingButNotEnforced') {
                    New-Finding "$(Get-Value $p 'displayName')" "Report-only since $(Format-AuditDate (Get-Value $p 'modifiedDateTime'))"
                }
            }
            $findings = @($findings)
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) policy(ies) are report-only and enforce nothing. Turn them on or remove them." $findings) }
            return (New-Outcome Pass 'No policy is left in report-only mode.')
        }
    }
    [pscustomobject]@{
        Id = 'CA-05'; Area = 'Conditional Access'; Severity = 'Medium'
        Title = 'Exclusions from enabled policies'
        Needs = @('ConditionalAccess', 'Users')
        Test = {
            param($Context)
            $expected = 0
            $findings = foreach ($p in @(Get-EnabledPolicy $Context | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
                $name = "$(Get-Value $p 'displayName')"
                $users = @(Get-Value $p 'conditions', 'users', 'excludeUsers' | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' -and -not $Context.BreakGlassIds.ContainsKey("$_") })
                $groups = @(Get-Value $p 'conditions', 'users', 'excludeGroups' | Where-Object { $_ })
                $roles = @(Get-Value $p 'conditions', 'users', 'excludeRoles' | Where-Object { $_ })
                if ($users.Count) {
                    $names = foreach ($id in $users) {
                        if ($Context.UsersById.ContainsKey("$id")) { "$(Get-Value $Context.UsersById["$id"] 'userPrincipalName')" } else { "$id" }
                    }
                    New-Finding $name "Excludes $($users.Count) account(s) that aren't break-glass: $(@($names | Sort-Object) -join ', ')"
                }
                $unread = @($groups | Where-Object { -not $Context.CaGroups.ContainsKey("$_") })
                if ($unread.Count) { New-Finding $name "Excludes $($unread.Count) group(s) whose members weren't collected; they bypass the policy" }
                foreach ($gid in @($groups | Where-Object { $Context.CaGroups.ContainsKey("$_") })) {
                    $g = $Context.CaGroups["$gid"]
                    if (-not $g.Found) { New-Finding $name "Excludes group $gid, which no longer exists. Remove it from the policy."; continue }
                    $others = @($g.Members | Where-Object { -not $Context.BreakGlassIds.ContainsKey("$(Get-Value $_ 'id')") })
                    $problems = [Collections.Generic.List[string]]::new()
                    if ($others.Count) {
                        $names = @($others | ForEach-Object { Get-OwnerName $Context $_ } | Sort-Object)
                        $problems.Add("$($others.Count) member(s) that aren't break-glass bypass it: $($names -join ', ')")
                    }
                    if (-not $g.RoleAssignable) { $problems.Add("it isn't role-assignable, so Groups, User and Intune Administrators can add anyone to it") }
                    if ($g.Owners.Count) {
                        $owners = @($g.Owners | ForEach-Object { Get-OwnerName $Context $_ } | Sort-Object)
                        $problems.Add("its $($g.Owners.Count) owner(s) can add anyone to it: $($owners -join ', ')")
                    }
                    if ($problems.Count) { New-Finding $name "Excludes group '$($g.Name)'; $($problems -join '; ')" } else { $expected++ }
                }
                if ($roles.Count) { New-Finding $name "Excludes $($roles.Count) directory role(s)" }
            }
            $findings = @($findings)
            $groupNote = if ($expected) { " $expected exclusion(s) of a role-assignable, ownerless group holding only break-glass accounts are expected." } else { '' }
            if ($findings.Count -gt 0) { return (New-Outcome Warn "$($findings.Count) exclusion(s) from enabled policies, beyond the break-glass accounts. Check each is still needed.$groupNote" $findings) }
            if (@(Get-EnabledPolicy $Context).Count -eq 0) { return (New-Outcome Pass 'No policy is enabled, so none has exclusions.') }
            return (New-Outcome Pass "Enabled policies exclude only the break-glass accounts.$groupNote")
        }
    }
    [pscustomobject]@{
        Id = 'TEN-01'; Area = 'Tenant settings'; Severity = 'High'
        Title = 'Users can consent to apps'
        Needs = @('AuthorizationPolicy')
        Test = {
            param($Context)
            $p = Get-TenantPolicy $Context 'AuthorizationPolicy'
            $consent = @(Get-Value $p 'defaultUserRolePermissions', 'permissionGrantPoliciesAssigned' | Where-Object { "$_" -like 'ManagePermissionGrantsForSelf.*' })
            $fail = [Collections.Generic.List[object]]::new()
            if ($consent -contains $LegacyConsentPolicy) { $fail.Add((New-Finding 'User consent' 'Users can consent to any app that asks for their data. Allow consent only for verified publishers and low-impact permissions, or none.')) }
            if ((Get-Value $p 'allowUserConsentForRiskyApps') -eq $true) { $fail.Add((New-Finding 'Risky apps' 'Users can consent to apps Microsoft has flagged as risky.')) }
            if ($fail.Count) { return (New-Outcome Fail 'Users can grant apps access to their data without an admin, which is how consent phishing works.' $fail.ToArray()) }
            $builtIn = @($LowConsentPolicy, $RecommendedConsentPolicy, $MailAppsConsentPolicy)
            $custom = @($consent | Where-Object { $builtIn -notcontains $_ } | ForEach-Object { New-Finding 'User consent' "Custom consent policy: $("$_".Substring(30))" })
            if ($custom.Count) { return (New-Outcome Warn "Users can consent under $($custom.Count) custom policy(ies). Check what each allows." $custom) }
            $mail = if ($consent -contains $MailAppsConsentPolicy) { ' Users can also consent to popular mail apps reading their mail (Microsoft-managed).' } else { '' }
            if ($consent -contains $LowConsentPolicy) { return (New-Outcome Pass "Users can consent only to verified publishers' apps asking for low-impact permissions, as Microsoft recommends.$mail") }
            if ($consent -contains $RecommendedConsentPolicy) { return (New-Outcome Pass "Microsoft manages user consent (its recommended setting, the default): users can't consent to apps reading mail, files, calendars, chats or contacts.$mail") }
            if ($consent -contains $MailAppsConsentPolicy) { return (New-Outcome Pass "Users can consent only to popular mail apps reading their mail (Microsoft-managed).") }
            return (New-Outcome Pass 'Users cannot consent to apps; an admin approves each one.')
        }
    }
    [pscustomobject]@{
        Id = 'TEN-02'; Area = 'Tenant settings'; Severity = 'Medium'
        Title = 'Users can register apps or create tenants'
        Needs = @('AuthorizationPolicy')
        Test = {
            param($Context)
            $p = Get-TenantPolicy $Context 'AuthorizationPolicy'
            $findings = @(
                if ((Get-Value $p 'defaultUserRolePermissions', 'allowedToCreateApps') -ne $false) { New-Finding 'App registrations' 'Any user can register an app, and owns its credentials.' }
                if ((Get-Value $p 'defaultUserRolePermissions', 'allowedToCreateTenants') -ne $false) { New-Finding 'Tenant creation' 'Any user can create a new tenant, outside this one''s policies.' }
            )
            if ($findings.Count) { return (New-Outcome Warn "$($findings.Count) default user permission(s) are on that most users don't need. Turn them off, and give the people who need them the Application Developer or Tenant Creator role." $findings) }
            return (New-Outcome Pass 'Users cannot register apps or create tenants without a role.')
        }
    }
    [pscustomobject]@{
        Id = 'TEN-03'; Area = 'Tenant settings'; Severity = 'Medium'
        Title = 'Guest access and invitations'
        Needs = @('AuthorizationPolicy')
        Test = {
            param($Context)
            $p = Get-TenantPolicy $Context 'AuthorizationPolicy'
            $guestRole = "$(Get-Value $p 'guestUserRoleId')"
            $level = if ($GuestAccessLevels.ContainsKey($guestRole)) { $GuestAccessLevels[$guestRole] } else { "a role this audit doesn't know ($guestRole)" }
            $findings = @(
                if ($guestRole -eq $MemberGuestRoleId) { New-Finding 'Guest access' 'Guests can read the directory as members can.' }
                if ("$(Get-Value $p 'allowInvitesFrom')" -eq 'everyone') { New-Finding 'Guest invitations' 'Anyone, guests included, can invite more guests.' }
                if ((Get-Value $p 'allowEmailVerifiedUsersToJoinOrganization') -eq $true) { New-Finding 'Self-service sign-up' 'Anyone with a verified email address on one of the tenant''s domains can join it.' }
            )
            if ($findings.Count) { return (New-Outcome Warn "$($findings.Count) guest setting(s) let outsiders in or see more than they need. Guests have $level." $findings) }
            return (New-Outcome Pass "Guests have $level, and invitations are limited to $("$(Get-Value $p 'allowInvitesFrom')").")
        }
    }
    [pscustomobject]@{
        Id = 'TEN-04'; Area = 'Tenant settings'; Severity = 'Medium'
        Title = 'Text message and voice call sign-in methods'
        Needs = @('AuthMethodsPolicy')
        Test = {
            param($Context)
            $p = Get-TenantPolicy $Context 'AuthMethodsPolicy'
            $names = @{ Sms = 'Text message (SMS)'; Voice = 'Voice call' }
            $findings = @(foreach ($m in @(Get-Value $p 'methods' | Where-Object { $null -ne $_ })) {
                    $id = "$(Get-Value $m 'id')"
                    if ($names.ContainsKey($id) -and "$(Get-Value $m 'state')" -eq 'enabled') { New-Finding $names[$id] 'Enabled in the authentication methods policy.' }
                })
            $migration = "$(Get-Value $p 'policyMigrationState')"
            $note = ''
            if ($migration -and $migration -ne 'migrationComplete') { $note = " The legacy MFA and SSPR settings still apply too (migration state: $migration), and this audit doesn't read them; check them in the portal." }
            if ($findings.Count) { return (New-Outcome Warn "$($findings.Count) phone-based method(s) are on. Codes sent by text or call can be intercepted or SIM-swapped; move users to the Authenticator app or passkeys.$note" @($findings | Sort-Object Subject)) }
            return (New-Outcome Pass "Text message and voice call are off in the authentication methods policy.$note")
        }
    }
    [pscustomobject]@{
        Id = 'TEN-05'; Area = 'Tenant settings'; Severity = 'Low'
        Title = 'Cross-tenant access defaults'
        Needs = @('CrossTenantAccess')
        Test = {
            param($Context)
            $p = Get-TenantPolicy $Context 'CrossTenantAccess'
            $findings = @(
                foreach ($dir in 'Inbound', 'Outbound') {
                    $u = Get-Value $p "b2bDirectConnect$dir", 'usersAndGroups'
                    if ("$(Get-Value $u 'accessType')" -eq 'allowed') {
                        $who = @(Get-Value $u 'targets' | Where-Object { $_ })
                        $whoText = if ($who -contains 'AllUsers') { 'all users' } else { "$($who.Count) user(s) or group(s)" }
                        New-Finding "B2B direct connect ($($dir.ToLowerInvariant()))" "Allowed for $whoText with every other organization, by default."
                    }
                    if ((Get-Value $p 'automaticUserConsentSettings', "$($dir.ToLowerInvariant())Allowed") -eq $true) {
                        New-Finding "Automatic redemption ($($dir.ToLowerInvariant()))" 'Invitations are accepted without the user being asked, for every other organization.'
                    }
                }
            )
            if ($findings.Count) { return (New-Outcome Warn "$($findings.Count) default cross-tenant setting(s) open access to every other organization. Allow these per organization instead." $findings) }
            $origin = if ((Get-Value $p 'isServiceDefault') -eq $true) { "Microsoft's defaults" } else { 'changed from Microsoft''s defaults' }
            return (New-Outcome Pass "B2B direct connect and automatic redemption are off by default ($origin).")
        }
    }
    [pscustomobject]@{
        Id = 'TEN-06'; Area = 'Tenant settings'; Severity = 'High'
        Title = 'Break-glass accounts'
        Needs = @('Users', 'RoleAssignments')
        Test = {
            param($Context)
            $listed = @($Context.Profile.BreakGlassAccounts | Where-Object { "$_" })
            $how = 'Microsoft recommends two cloud-only accounts holding Global Administrator, kept out of daily use, for when sign-in is otherwise locked out.'
            if ($listed.Count -eq 0) { return (New-Outcome Warn "No break-glass accounts are listed in BreakGlassAccounts, so they can't be checked. $how" @(New-Finding 'Profile' 'List the break-glass accounts in BreakGlassAccounts.')) }
            $byUpn = @{}
            foreach ($u in $Context.UsersById.Values) { $byUpn["$(Get-Value $u 'userPrincipalName')".ToLowerInvariant()] = $u }
            $fail = [Collections.Generic.List[object]]::new()
            $warn = [Collections.Generic.List[object]]::new()
            $notes = [Collections.Generic.List[string]]::new()
            $caState = $Context.Status['ConditionalAccess']
            $policies = @(Get-EnabledPolicy $Context | Sort-Object { "$(Get-Value $_ 'displayName')" })
            if ($caState -ne 'Collected' -and $caState -ne 'NotLicensed') {
                $warn.Add((New-Finding 'Conditional Access' "Not collected ($caState), so whether a policy could lock the break-glass accounts out wasn't checked."))
            }
            $signIns = $Context.Status['SignIns'] -eq 'Collected'
            if (-not $signIns) { $notes.Add("Sign-in activity wasn't collected, so the last test sign-in wasn't checked.") }
            foreach ($upn in $listed) {
                $u = $byUpn["$upn".ToLowerInvariant()]
                if ($null -eq $u) { $fail.Add((New-Finding "$upn" 'Not found in the tenant.')); continue }
                $id = "$(Get-Value $u 'id')"
                if ((Get-Value $u 'accountEnabled') -eq $false) { $fail.Add((New-Finding "$upn" 'Disabled.')) }
                if ((Get-Value $u 'onPremisesSyncEnabled') -eq $true) { $fail.Add((New-Finding "$upn" 'Synced from on-premises, so an outage there can lock it out.')) }
                $ga = @($Context.Holders | Where-Object { $_.PrincipalId -eq $id -and $_.RoleId -eq $GlobalAdminRoleId })
                if (-not @($ga | Where-Object Kind -eq 'Active')) {
                    $detail = if ($ga.Count) { 'Only eligible for Global Administrator, so it must activate through PIM before it can help.' } else { 'Does not hold Global Administrator.' }
                    $fail.Add((New-Finding "$upn" $detail))
                }
                if ($caState -eq 'Collected') {
                    $applies = [Collections.Generic.List[string]]::new()
                    $unknown = [Collections.Generic.List[string]]::new()
                    foreach ($p in $policies) {
                        switch (Get-CaPolicyReach $Context $p $id) {
                            'Yes' { $applies.Add("$(Get-Value $p 'displayName')") }
                            'Unknown' { $unknown.Add("$(Get-Value $p 'displayName')") }
                        }
                    }
                    if ($applies.Count) { $fail.Add((New-Finding "$upn" "Enforced Conditional Access applies to it, so an outage of what a policy requires can lock it out. Exclude it from: $($applies -join '; ').")) }
                    if ($unknown.Count) { $warn.Add((New-Finding "$upn" "Couldn't tell whether these policies apply, because their groups' members weren't collected: $($unknown -join '; ').")) }
                }
                if ($signIns) {
                    $last = Get-LastSignIn $u
                    if ($null -eq $last) {
                        $warn.Add((New-Finding "$upn" "No sign-in recorded, so it has never been tested. Test it at least every $BreakGlassTestDays days. Sign-in activity can take a few hours to appear."))
                    } elseif ($last -lt $Context.Now.AddDays(-$BreakGlassTestDays)) {
                        $warn.Add((New-Finding "$upn" "Last signed in $(Format-AuditDate $last). Test it at least every $BreakGlassTestDays days."))
                    }
                }
            }
            $note = if ($notes.Count) { ' ' + ($notes -join ' ') } else { '' }
            if ($fail.Count) { return (New-Outcome Fail "$($fail.Count) problem(s) with the break-glass accounts would stop them working in an emergency.$note" @($fail.ToArray() + $warn.ToArray())) }
            if ($listed.Count -lt 2) { $warn.Add((New-Finding "$($listed[0])" "The only break-glass account. $how")) }
            if ($warn.Count) { return (New-Outcome Warn "$($warn.Count) thing(s) to review about the break-glass accounts.$note" $warn.ToArray()) }
            $tested = if ($signIns) { " and signed in within $BreakGlassTestDays days" } else { '' }
            return (New-Outcome Pass "All $($listed.Count) break-glass accounts exist, are enabled and cloud-only, hold Global Administrator, are outside every enforced Conditional Access policy$tested.$note")
        }
    }
)

function Get-AppCredential {
    # Every secret and certificate on every app registration, flattened.
    param($Context)
    foreach ($a in @(Get-Value $Context.Snapshot 'Datasets', 'Applications', 'Items' | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
        if ($null -eq $a) { continue }
        foreach ($pair in @(@('passwordCredentials', 'Secret'), @('keyCredentials', 'Certificate'))) {
            foreach ($c in @(Get-Value $a $pair[0])) {
                if ($null -eq $c) { continue }
                $name = "$(Get-Value $c 'displayName')"
                if (-not $name) { $name = "$(Get-Value $c 'keyId')" }
                [pscustomobject]@{
                    App   = "$(Get-Value $a 'displayName')"
                    Type  = $pair[1]
                    Name  = $name
                    Start = ConvertTo-UtcDate (Get-Value $c 'startDateTime')
                    End   = ConvertTo-UtcDate (Get-Value $c 'endDateTime')
                }
            }
        }
    }
}

function Test-AcceptedApp {
    # True when a service principal is named in AcceptedApps, by display
    # name, object ID or app ID.
    param($Context, $Sp)
    $accepted = @($Context.Profile.AcceptedApps | ForEach-Object { "$_".ToLowerInvariant() })
    foreach ($key in "$(Get-Value $Sp 'displayName')", "$(Get-Value $Sp 'id')", "$(Get-Value $Sp 'appId')") {
        if ($key -and $accepted -contains $key.ToLowerInvariant()) { return $true }
    }
    return $false
}

function Get-SpCredential {
    # Secrets and certificates on service principals, flattened. Left out:
    # managed identities, whose certificates Azure rotates itself, and SAML
    # signing certificates (a Sign key and its paired Verify key), which an
    # SSO app is meant to have.
    param($Context)
    foreach ($sp in @($Context.SpsById.Values | Sort-Object { "$(Get-Value $_ 'displayName')" })) {
        if ("$(Get-Value $sp 'servicePrincipalType')" -eq 'ManagedIdentity') { continue }
        $keys = @(Get-Value $sp 'keyCredentials' | Where-Object { $null -ne $_ })
        $signing = @($keys | Where-Object { "$(Get-Value $_ 'usage')" -eq 'Sign' } | ForEach-Object { "$(Get-Value $_ 'customKeyIdentifier')" } | Where-Object { $_ })
        $creds = @(
            foreach ($c in @(Get-Value $sp 'passwordCredentials' | Where-Object { $null -ne $_ })) { , @($c, 'Secret') }
            foreach ($c in $keys) {
                if ("$(Get-Value $c 'usage')" -eq 'Sign' -or $signing -contains "$(Get-Value $c 'customKeyIdentifier')") { continue }
                , @($c, 'Certificate')
            }
        )
        foreach ($pair in $creds) {
            $c = $pair[0]
            $name = "$(Get-Value $c 'displayName')"
            if (-not $name) { $name = "$(Get-Value $c 'keyId')" }
            [pscustomobject]@{
                Sp   = $sp
                App  = "$(Get-Value $sp 'displayName')"
                Type = $pair[1]
                Name = $name
                End  = ConvertTo-UtcDate (Get-Value $c 'endDateTime')
            }
        }
    }
}

function Get-DelegatedGrant {
    # Delegated permission grants on Microsoft Graph that include a permission
    # in HighRiskPermissions, one row per grant, with the app's name. Grants
    # on other APIs are left out, since their permission names mean
    # something else.
    param($Context)
    $sps = $Context.SpsById
    $risky = @($Context.Profile.HighRiskPermissions)
    $accepted = @($Context.Profile.AcceptedApps | ForEach-Object { "$_".ToLowerInvariant() })
    foreach ($g in @(Get-Value $Context.Snapshot 'Datasets', 'DelegatedPermissionGrants', 'Items')) {
        if ($null -eq $g) { continue }
        $resource = $sps["$(Get-Value $g 'resourceId')"]
        if ("$(Get-Value $resource 'appId')" -ne $GraphAppId) { continue }
        $high = @("$(Get-Value $g 'scope')" -split '\s+' | Where-Object { $_ -and $risky -contains $_ } | Sort-Object -Unique)
        if ($high.Count -eq 0) { continue }
        $clientId = "$(Get-Value $g 'clientId')"
        $client = $sps[$clientId]
        $name = "$(Get-Value $client 'displayName')"
        if (-not $name) { $name = $clientId }
        $keys = @($name, $clientId, "$(Get-Value $client 'appId')" | ForEach-Object { $_.ToLowerInvariant() })
        [pscustomobject]@{
            App         = $name
            ClientId    = $clientId
            ConsentType = "$(Get-Value $g 'consentType')"
            PrincipalId = "$(Get-Value $g 'principalId')"
            Scopes      = $high
            Accepted    = (@($keys | Where-Object { $_ -and $accepted -contains $_ }).Count -gt 0)
        }
    }
}

function Invoke-AuditCheck {
    # Runs every check against a snapshot. A check whose datasets weren't
    # collected is Skipped with the reason; one that throws is an Error.
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)]$AuditProfile)
    $context = Get-AuditContext -Snapshot $Snapshot -AuditProfile $AuditProfile
    foreach ($check in $AuditChecks) {
        $missing = @($check.Needs | Where-Object { $context.Status[$_] -ne 'Collected' })
        if ($missing.Count -gt 0) {
            $why = foreach ($m in $missing) {
                $state = $context.Status[$m]; if (-not $state) { $state = 'NotCollected' }
                $reason = if ($context.StatusReason.ContainsKey($m)) { $context.StatusReason[$m] } else { "$(Get-Value $Snapshot 'Datasets', $m, 'Reason')" }
                if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 200) + '...' }
                if ($reason) { "$m was not collected ($state): $reason" } else { "$m was not collected ($state)." }
            }
            $outcome = New-Outcome Skipped (@($why) -join ' ')
        } else {
            try {
                $outcome = & $check.Test $context
                if ($null -eq $outcome -or @($outcome).Count -ne 1) { throw "The check returned $(@($outcome).Count) outcomes, not one." }
            } catch {
                $outcome = New-Outcome Error "The check failed: $($_.Exception.Message)"
            }
        }
        [pscustomobject]@{
            Id       = $check.Id
            Area     = $check.Area
            Title    = $check.Title
            Severity = $check.Severity
            Status   = $outcome.Status
            Summary  = $outcome.Summary
            Findings = @($outcome.Findings)
        }
    }
}

function Get-AuditExitCode {
    # 2 for an Error or a dataset that failed for a reason other than
    # licensing; 1 for a Fail; else 0.
    param($Results, $Snapshot)
    $broken = @(foreach ($p in (Get-Value $Snapshot 'Datasets').PSObject.Properties) {
            if ("$(Get-Value $p.Value 'Status')" -in 'Denied', 'Error') { $p.Name }
        })
    if (@($Results | Where-Object Status -eq 'Error').Count -gt 0 -or $broken.Count -gt 0) { return 2 }
    if (@($Results | Where-Object Status -eq 'Fail').Count -gt 0) { return 1 }
    return 0
}

# ---------------------------------------------------------------------------
#  Reports
# ---------------------------------------------------------------------------

function Get-StatusCount {
    param($Results)
    $counts = [ordered]@{}
    foreach ($s in 'Fail', 'Warn', 'Pass', 'Skipped', 'Error') { $counts[$s] = @($Results | Where-Object Status -eq $s).Count }
    return $counts
}

function ConvertTo-AuditCsvRow {
    # One row per finding; a check with no findings gets one row of its own.
    param($Results)
    foreach ($r in $Results) {
        $findings = @($r.Findings)
        if ($findings.Count -eq 0) { $findings = @([pscustomobject]@{ Subject = ''; Detail = '' }) }
        foreach ($f in $findings) {
            [pscustomobject][ordered]@{
                CheckId = $r.Id; Area = $r.Area; Title = $r.Title; Severity = $r.Severity; Status = $r.Status
                Summary = $r.Summary; Subject = $f.Subject; Detail = $f.Detail
            }
        }
    }
}

function ConvertTo-AuditHtml {
    # A self-contained page: no scripts, no external files.
    param($Results, $Snapshot, $AuditProfile)
    $counts = Get-StatusCount $Results
    $collected = Format-AuditDate (Get-Value $Snapshot 'CollectedAt')
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>Entra access audit $collected</title><style>")
    [void]$sb.AppendLine(':root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;--fail:#cf222e;--warn:#9a6700;--pass:#1a7f37;--skip:#59636e;--error:#8250df}')
    [void]$sb.AppendLine('@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--card:#151b23;--fail:#ff7b72;--warn:#d29922;--pass:#3fb950;--skip:#9198a1;--error:#bc8cff}}')
    [void]$sb.AppendLine('body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;line-height:1.45}main{max-width:1100px;margin:0 auto}')
    [void]$sb.AppendLine('h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:28px 0 8px}.muted{color:var(--muted)}')
    [void]$sb.AppendLine('.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.tile{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 14px;min-width:80px}.tile b{display:block;font-size:1.4rem}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}')
    [void]$sb.AppendLine('.s{font-weight:600}.Fail{color:var(--fail)}.Warn{color:var(--warn)}.Pass{color:var(--pass)}.Skipped{color:var(--skip)}.Error{color:var(--error)}')
    [void]$sb.AppendLine('details{margin-top:4px}summary{cursor:pointer;color:var(--muted)}ul{margin:4px 0 0;padding-left:18px}.wrap{overflow-x:auto}')
    [void]$sb.AppendLine('</style></head><body><main>')
    [void]$sb.AppendLine('<h1>Entra ID access audit</h1>')
    [void]$sb.AppendLine("<div class=""muted"">Collected $collected (UTC) &middot; Entra access audit $(ConvertTo-HtmlText (Get-Value $Snapshot 'ToolVersion')) &middot; read-only</div>")
    [void]$sb.AppendLine('<div class="tiles">')
    foreach ($k in $counts.Keys) { [void]$sb.AppendLine("<div class=""tile""><b class=""$k"">$($counts[$k])</b>$k</div>") }
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<p class="muted">Evidence for a review, not a verdict. Skipped means the data a check needs wasn''t collected; the reason says why.</p>')

    # Areas in the order the checks run, so a new area can't be left out.
    $areaOrder = @($AuditChecks | ForEach-Object Area | Select-Object -Unique)
    foreach ($area in $areaOrder) {
        $rows = @($Results | Where-Object Area -eq $area)
        if ($rows.Count -eq 0) { continue }
        [void]$sb.AppendLine("<h2>$(ConvertTo-HtmlText $area)</h2><div class=""wrap""><table><thead><tr><th>Check</th><th>Result</th><th>Severity</th><th>What it found</th></tr></thead><tbody>")
        foreach ($r in $rows) {
            [void]$sb.Append("<tr><td><b>$(ConvertTo-HtmlText $r.Id)</b><br>$(ConvertTo-HtmlText $r.Title)</td><td class=""s $($r.Status)"">$($r.Status)</td><td>$(ConvertTo-HtmlText $r.Severity)</td><td>$(ConvertTo-HtmlText $r.Summary)")
            if (@($r.Findings).Count -gt 0) {
                [void]$sb.Append("<details><summary>$(@($r.Findings).Count) item(s)</summary><ul>")
                foreach ($f in $r.Findings) { [void]$sb.Append("<li><b>$(ConvertTo-HtmlText $f.Subject)</b>: $(ConvertTo-HtmlText $f.Detail)</li>") }
                [void]$sb.Append('</ul></details>')
            }
            [void]$sb.AppendLine('</td></tr>')
        }
        [void]$sb.AppendLine('</tbody></table></div>')
    }

    [void]$sb.AppendLine('<h2>Data collected</h2><div class="wrap"><table><thead><tr><th>Dataset</th><th>Status</th><th>Items</th><th>Reason</th></tr></thead><tbody>')
    foreach ($p in (Get-Value $Snapshot 'Datasets').PSObject.Properties) {
        $st = "$(Get-Value $p.Value 'Status')"
        $cls = if ($st -eq 'Collected') { 'Pass' } elseif ($st -eq 'NotLicensed') { 'Skipped' } else { 'Error' }
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $p.Name)</td><td class=""s $cls"">$(ConvertTo-HtmlText $st)</td><td>$(@(Get-Value $p.Value 'Items').Count)</td><td>$(ConvertTo-HtmlText (Get-Value $p.Value 'Reason'))</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Thresholds</h2><div class="wrap"><table><tbody>')
    foreach ($k in $AuditProfile.Keys) {
        $v = $AuditProfile[$k]
        $shown = if ($v -is [array]) { if ($v.Count) { $v -join ', ' } else { '(none)' } } else { "$v" }
        [void]$sb.AppendLine("<tr><th>$(ConvertTo-HtmlText $k)</th><td>$(ConvertTo-HtmlText $shown)</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></div></main></body></html>')
    return $sb.ToString()
}

function Write-AuditReport {
    # Writes the HTML, CSV and JSON reports and returns their paths.
    param([Parameter(Mandatory)]$Results, [Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)]$AuditProfile, [Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $stamp = (ConvertTo-UtcDate (Get-Value $Snapshot 'CollectedAt')).ToString('yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture)
    $base = Join-Path $Path "entra-access-audit-$stamp"
    $utf8 = [Text.UTF8Encoding]::new($false)

    [IO.File]::WriteAllText("$base.html", (ConvertTo-AuditHtml -Results $Results -Snapshot $Snapshot -AuditProfile $AuditProfile), $utf8)

    # 5.1 adds a type line unless told not to; 7 never does, and newer 7
    # releases warn that -NoTypeInformation is obsolete.
    $csvArgs = @{}
    if ($PSVersionTable.PSVersion.Major -lt 6) { $csvArgs.NoTypeInformation = $true }
    $csv = @(ConvertTo-AuditCsvRow $Results | ConvertTo-Csv @csvArgs)
    [IO.File]::WriteAllText("$base.csv", (($csv -join "`r`n") + "`r`n"), $utf8)

    $datasets = [ordered]@{}
    foreach ($p in (Get-Value $Snapshot 'Datasets').PSObject.Properties) {
        $datasets[$p.Name] = [ordered]@{ Status = "$(Get-Value $p.Value 'Status')"; Items = @(Get-Value $p.Value 'Items').Count; Reason = "$(Get-Value $p.Value 'Reason')" }
    }
    $json = [ordered]@{
        Tool        = 'entra-access-audit'
        Version     = $EntraAccessAuditVersion
        CollectedAt = ConvertTo-SnapshotValue (ConvertTo-UtcDate (Get-Value $Snapshot 'CollectedAt'))
        Counts      = Get-StatusCount $Results
        Datasets    = $datasets
        Thresholds  = $AuditProfile
        Results     = @($Results)
    }
    [IO.File]::WriteAllText("$base.json", ((ConvertTo-SnapshotValue $json) | ConvertTo-Json -Depth 10), $utf8)
    return @("$base.html", "$base.csv", "$base.json")
}

function Write-AuditSummary {
    # The console view: one coloured line per check, then the counts.
    param($Results)
    $colours = @{ Fail = 'Red'; Warn = 'Yellow'; Pass = 'Green'; Skipped = 'DarkGray'; Error = 'Magenta' }
    foreach ($r in $Results) {
        $count = @($r.Findings).Count
        $tail = if ($count) { " ($count)" } else { '' }
        Write-Host ('{0,-8} {1,-8} {2}{3}' -f $r.Status, $r.Id, $r.Title, $tail) -ForegroundColor $colours[$r.Status]
    }
    $c = Get-StatusCount $Results
    Write-Host ''
    Write-Host ("Fail {0}  Warn {1}  Pass {2}  Skipped {3}  Error {4}" -f $c.Fail, $c.Warn, $c.Pass, $c.Skipped, $c.Error)
}

function Read-Snapshot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Snapshot not found: $Path" }
    $snapshot = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $schema = Get-Value $snapshot 'SchemaVersion'
    # Each schema only adds datasets, so an older snapshot still reads: the
    # checks that need what it lacks are Skipped.
    if ($schema -isnot [int] -and $schema -isnot [long]) { throw "Snapshot $Path has no schema version." }
    if ($schema -lt 1 -or $schema -gt $SnapshotSchemaVersion) { throw "Snapshot $Path has schema version $schema; this version reads 1 to $SnapshotSchemaVersion." }
    if ($null -eq (Get-Value $snapshot 'Datasets')) { throw "Snapshot $Path has no Datasets." }
    return $snapshot
}

# Dot-sourcing (the tests do) defines the functions and stops here.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
try {
    if (-not $ProfilePath) {
        $local = Join-Path $PSScriptRoot 'EntraAccessAudit.local.psd1'
        if (Test-Path -LiteralPath $local) { $ProfilePath = $local }
    }
    $auditProfile = Get-AuditProfile -Path $ProfilePath
    if ($ProfilePath) { Write-Host "Thresholds from $ProfilePath" }

    if ($FromSnapshot) {
        $snapshot = Read-Snapshot -Path $FromSnapshot
        Write-Host "Evaluating snapshot $FromSnapshot (collected $(ConvertTo-SnapshotValue (ConvertTo-UtcDate (Get-Value $snapshot 'CollectedAt'))))"
    } else {
        $context = Connect-AuditGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint
        Write-Host "Signed in as $($context.Account)$(if ($context.AppName) { " ($($context.AppName))" })"
        $collected = Get-TenantSnapshot -TenantId "$($context.TenantId)"
        # Round-trip through JSON so the checks always read the same shape,
        # whether the snapshot came from Graph or from a file.
        $json = (ConvertTo-SnapshotValue $collected) | ConvertTo-Json -Depth 20
        if ($SnapshotPath) {
            $dir = Split-Path -Parent $SnapshotPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [IO.File]::WriteAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SnapshotPath), $json, [Text.UTF8Encoding]::new($false))
            Write-Host "Snapshot saved to $SnapshotPath"
        }
        $snapshot = $json | ConvertFrom-Json
    }

    $results = @(Invoke-AuditCheck -Snapshot $snapshot -AuditProfile $auditProfile)
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).Path 'Reports' }
    $files = Write-AuditReport -Results $results -Snapshot $snapshot -AuditProfile $auditProfile -Path $OutputPath
    Write-Host ''
    Write-AuditSummary $results
    Write-Host ''
    foreach ($f in $files) { Write-Host "Report: $f" }
    foreach ($p in (Get-Value $snapshot 'Datasets').PSObject.Properties) {
        $st = "$(Get-Value $p.Value 'Status')"
        if ($st -in 'Denied', 'Error') { Write-Warning "$($p.Name) couldn't be read ($st): $(Get-Value $p.Value 'Reason')" }
    }
    if ($PassThru) { $results }
    exit (Get-AuditExitCode -Results $results -Snapshot $snapshot)
} catch {
    Write-Host "The audit could not run: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
