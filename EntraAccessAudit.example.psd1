# Thresholds for Invoke-EntraAccessAudit.ps1, with their defaults.
#
# Copy this file to EntraAccessAudit.local.psd1 beside the script (git ignores
# it) and change what you need, or pass another file with -ProfilePath. Leave
# out any setting to keep its default. A setting the script doesn't know stops
# the run, so a typo can't be silently ignored.
#
# Data only: the file is read in PowerShell's restricted data language.

@{
    # Days without a sign-in before an enabled account counts as stale
    # (STALE-01 to STALE-03), and before a guest invitation that was never
    # accepted is reported (STALE-04).
    StaleDays             = 90

    # Days ahead to warn about app secrets and certificates expiring (APP-02).
    CredentialExpiryDays  = 30

    # Longest a client secret should be valid, in days (APP-03).
    MaxSecretLifetimeDays = 365

    # Fewest and most accounts that should hold Global Administrator, active
    # and PIM-eligible together, break-glass accounts included (ROLE-01).
    MinGlobalAdmins       = 2
    MaxGlobalAdmins       = 4

    # Emergency access accounts, by user principal name. They are expected to
    # hold Global Administrator permanently, to be excluded from Conditional
    # Access and to sign in rarely, so ROLE-02, STALE-01, STALE-02 and CA-05
    # leave them out. They still count in ROLE-01, and still need MFA.
    BreakGlassAccounts    = @(
        # 'bg.one@westmark.example'
    )

    # Apps whose high-risk permissions you have reviewed and accept, by display
    # name, service principal object ID or, for delegated permissions, app ID
    # (APP-04, APP-06, APP-07, SVC-01 to SVC-03). They are counted, not listed.
    AcceptedApps          = @(
        # 'Westmark Backup'
    )

    # Microsoft Graph permissions treated as high-risk. APP-04 reports them as
    # application permissions, where an app can use them across the tenant
    # with no user signed in; APP-06 and APP-07 report them as delegated
    # permissions, where an app can use them as any user who signs in to it.
    # Setting this replaces the whole list.
    HighRiskPermissions   = @(
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
