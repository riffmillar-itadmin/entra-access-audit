# PSScriptAnalyzer settings for entra-access-audit.
#
# Picked up automatically by the VS Code PowerShell extension, and by
#   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
# Test-EntraAccessAuditLint.ps1 runs exactly that, pinned to PSScriptAnalyzer 1.25.0.

@{
    Severity     = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        # The console summary is coloured status text for a person to read;
        # the reports are the data. Write-Host is the right tool.
        'PSAvoidUsingWriteHost'
        # New-Outcome Fail 'summary' is the readable form across 23 checks.
        'PSAvoidUsingPositionalParameters'
    )
}
