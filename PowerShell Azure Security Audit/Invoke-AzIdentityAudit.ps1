<#
.SYNOPSIS
    Audits Azure AD (Entra ID) identity and access management for security risks.

.DESCRIPTION
    Invoke-AzIdentityAudit performs a comprehensive identity security assessment against
    Azure Active Directory (Microsoft Entra ID). The script evaluates MFA registration,
    stale account hygiene, privileged role assignment practices, guest account risk,
    Conditional Access policy coverage, service principal permissions, and application
    credential lifecycle management.

    Results are displayed as a risk summary dashboard in the console with optional CSV export.

    Designed for enterprise cloud security operations at First Carolina Bank.

.PARAMETER StaleThresholdDays
    Number of days without sign-in activity before an account is considered stale.
    Default: 90

.PARAMETER CredentialExpiryDays
    Number of days before credential expiration to flag as a warning.
    Default: 30

.PARAMETER ExportPath
    File path for CSV export of findings. If omitted, results are displayed in the console only.

.PARAMETER IncludeDisabledAccounts
    Include disabled user accounts in the stale account assessment.

.EXAMPLE
    .\Invoke-AzIdentityAudit.ps1
    Runs the full identity audit with default thresholds.

.EXAMPLE
    .\Invoke-AzIdentityAudit.ps1 -StaleThresholdDays 60 -CredentialExpiryDays 60 -ExportPath "C:\Reports\Identity-Audit.csv"
    Custom thresholds with CSV export.

.NOTES
    Author:  Jacob Phillips
    Role:    Cloud Security Engineer, First Carolina Bank
    Version: 2.0.0
    Requires: Microsoft.Graph module
    Permissions: User.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
                 Policy.Read.All, Application.Read.All, AuditLog.Read.All
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$CredentialExpiryDays = 30,

    [Parameter()]
    [ValidateScript({
        $directory = Split-Path $_ -Parent
        if ($directory -and -not (Test-Path $directory)) {
            throw "Export directory '$directory' does not exist."
        }
        if ($_ -notmatch '\.csv$') {
            throw "Export path must end with .csv extension."
        }
        return $true
    })]
    [string]$ExportPath,

    [Parameter()]
    [switch]$IncludeDisabledAccounts
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$PRIVILEGED_ROLES = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'User Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Authentication Administrator',
    'Privileged Authentication Administrator',
    'Conditional Access Administrator',
    'Intune Administrator'
)

$GRAPH_SCOPES = @(
    'User.Read.All',
    'Directory.Read.All',
    'RoleManagement.Read.Directory',
    'Policy.Read.All',
    'Application.Read.All',
    'AuditLog.Read.All'
)

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function New-IdentityFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object for the identity audit report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Finding,
        [Parameter()]          [string]$AffectedObject,
        [Parameter()]          [string]$Detail,
        [Parameter()]          [string]$Remediation
    )

    [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Category       = $Category
        Severity       = $Severity
        Finding        = $Finding
        AffectedObject = if ($AffectedObject) { $AffectedObject } else { '' }
        Detail         = if ($Detail) { $Detail } else { '' }
        Remediation    = if ($Remediation) { $Remediation } else { '' }
    }
}

function Write-RiskDashboard {
    <#
    .SYNOPSIS
        Displays a formatted risk summary dashboard in the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Stats,
        [Parameter(Mandatory)] [array]$Findings
    )

    $critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high     = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium   = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low      = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    $mfaPct = if ($Stats.TotalUsers -gt 0) {
        [math]::Round((($Stats.TotalUsers - $Stats.UsersWithoutMFA) / $Stats.TotalUsers) * 100, 1)
    } else { 'N/A' }

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║          IDENTITY SECURITY AUDIT — RISK DASHBOARD           ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host '║  ENVIRONMENT STATISTICS                                     ║' -ForegroundColor White
    Write-Host "║    Total Users                : $($Stats.TotalUsers.ToString().PadLeft(6))                      ║" -ForegroundColor White
    Write-Host "║    Guest Accounts             : $($Stats.GuestAccounts.ToString().PadLeft(6))                      ║" -ForegroundColor White
    Write-Host "║    Service Principals         : $($Stats.ServicePrincipals.ToString().PadLeft(6))                      ║" -ForegroundColor White
    Write-Host "║    App Registrations          : $($Stats.AppRegistrations.ToString().PadLeft(6))                      ║" -ForegroundColor White
    Write-Host '║──────────────────────────────────────────────────────────────║' -ForegroundColor DarkGray
    Write-Host '║  IDENTITY HEALTH                                            ║' -ForegroundColor White
    Write-Host "║    MFA Coverage               : $("$mfaPct%".PadLeft(6))                      ║" -ForegroundColor $(if ($mfaPct -is [string] -or $mfaPct -lt 80) { 'Red' } elseif ($mfaPct -lt 95) { 'Yellow' } else { 'Green' })
    Write-Host "║    Stale Accounts (>$($StaleThresholdDays)d)     : $($Stats.StaleAccounts.ToString().PadLeft(6))                      ║" -ForegroundColor $(if ($Stats.StaleAccounts -gt 10) { 'Red' } elseif ($Stats.StaleAccounts -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "║    Permanent Privileged       : $($Stats.PermanentPrivileged.ToString().PadLeft(6))                      ║" -ForegroundColor $(if ($Stats.PermanentPrivileged -gt 5) { 'Red' } elseif ($Stats.PermanentPrivileged -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "║    Risky Guest Accounts       : $($Stats.RiskyGuests.ToString().PadLeft(6))                      ║" -ForegroundColor $(if ($Stats.RiskyGuests -gt 0) { 'Red' } else { 'Green' })
    Write-Host "║    Expiring/Expired Creds     : $($Stats.ExpiringCredentials.ToString().PadLeft(6))                      ║" -ForegroundColor $(if ($Stats.ExpiringCredentials -gt 5) { 'Red' } elseif ($Stats.ExpiringCredentials -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host '║──────────────────────────────────────────────────────────────║' -ForegroundColor DarkGray
    Write-Host '║  FINDINGS BY SEVERITY                                       ║' -ForegroundColor White
    Write-Host "║    Critical : $($critical.ToString().PadLeft(4))                                            ║" -ForegroundColor Red
    Write-Host "║    High     : $($high.ToString().PadLeft(4))                                            ║" -ForegroundColor Yellow
    Write-Host "║    Medium   : $($medium.ToString().PadLeft(4))                                            ║" -ForegroundColor DarkYellow
    Write-Host "║    Low      : $($low.ToString().PadLeft(4))                                            ║" -ForegroundColor Gray
    Write-Host "║    Total    : $($Findings.Count.ToString().PadLeft(4))                                            ║" -ForegroundColor White
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Audit Functions
# ---------------------------------------------------------------------------

function Test-MFARegistration {
    <#
    .SYNOPSIS
        Identifies users who have not registered for MFA.
    #>
    [CmdletBinding()]
    param()

    Write-Host '  [1/7] Checking MFA registration status...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usersWithoutMFA = 0

    try {
        # Get authentication method registration details
        $registrationDetails = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999' `
            -ErrorAction Stop

        $allRegistrations = [System.Collections.Generic.List[object]]::new()
        $allRegistrations.AddRange($registrationDetails.value)

        # Handle pagination
        while ($registrationDetails.'@odata.nextLink') {
            $registrationDetails = Invoke-MgGraphRequest -Method GET -Uri $registrationDetails.'@odata.nextLink'
            $allRegistrations.AddRange($registrationDetails.value)
        }

        foreach ($reg in $allRegistrations) {
            $isMfaRegistered = $reg.isMfaRegistered
            if (-not $isMfaRegistered) {
                $usersWithoutMFA++
                $findings.Add((New-IdentityFinding `
                    -Category       'MFA' `
                    -Severity       'High' `
                    -Finding        'User has not registered for multi-factor authentication.' `
                    -AffectedObject $reg.userPrincipalName `
                    -Detail         "MFA Registered: $isMfaRegistered, Methods: $($reg.methodsRegistered -join ', ')" `
                    -Remediation    'Enforce MFA registration through Conditional Access or Security Defaults.'))
            }
        }

        Write-Verbose "    Found $usersWithoutMFA user(s) without MFA registration."
    }
    catch {
        Write-Warning "    Failed to retrieve MFA registration data: $_"
        $findings.Add((New-IdentityFinding `
            -Category       'MFA' `
            -Severity       'Medium' `
            -Finding        'Unable to retrieve MFA registration data. Verify Microsoft Graph permissions.' `
            -AffectedObject 'N/A' `
            -Remediation    'Ensure the AuditLog.Read.All permission is granted.'))
    }

    return @{ Findings = $findings; Count = $usersWithoutMFA }
}

function Test-StaleAccounts {
    <#
    .SYNOPSIS
        Identifies accounts with no sign-in activity beyond the configured threshold.
    #>
    [CmdletBinding()]
    param(
        [int]$ThresholdDays,
        [switch]$IncludeDisabled
    )

    Write-Host '  [2/7] Checking for stale accounts...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $staleCount = 0
    $cutoffDate = (Get-Date).AddDays(-$ThresholdDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

    try {
        $filter = "signInActivity/lastSignInDateTime le $cutoffDate"
        if (-not $IncludeDisabled) {
            $filter += " and accountEnabled eq true"
        }

        $staleUsers = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=displayName,userPrincipalName,accountEnabled,signInActivity,userType&`$top=999" `
            -ErrorAction Stop

        $allStale = [System.Collections.Generic.List[object]]::new()
        $allStale.AddRange($staleUsers.value)

        while ($staleUsers.'@odata.nextLink') {
            $staleUsers = Invoke-MgGraphRequest -Method GET -Uri $staleUsers.'@odata.nextLink'
            $allStale.AddRange($staleUsers.value)
        }

        foreach ($user in $allStale) {
            $lastSignIn = $user.signInActivity.lastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) {
                [math]::Round(((Get-Date) - [DateTime]$lastSignIn).TotalDays)
            } else { 'Never' }

            $severity = if ($daysSinceSignIn -eq 'Never' -or $daysSinceSignIn -gt 180) { 'High' } else { 'Medium' }

            $staleCount++
            $findings.Add((New-IdentityFinding `
                -Category       'StaleAccount' `
                -Severity       $severity `
                -Finding        "Account has not signed in for $daysSinceSignIn day(s)." `
                -AffectedObject $user.userPrincipalName `
                -Detail         "Last Sign-In: $lastSignIn, Enabled: $($user.accountEnabled), Type: $($user.userType)" `
                -Remediation    'Disable or delete stale accounts. Implement an automated account lifecycle policy.'))
        }

        Write-Verbose "    Found $staleCount stale account(s) exceeding $ThresholdDays-day threshold."
    }
    catch {
        Write-Warning "    Failed to retrieve stale account data: $_"
    }

    return @{ Findings = $findings; Count = $staleCount }
}

function Test-PermanentPrivilegedAssignments {
    <#
    .SYNOPSIS
        Checks for permanent (active) privileged role assignments that should use PIM eligible assignments.
    #>
    [CmdletBinding()]
    param()

    Write-Host '  [3/7] Checking for permanent privileged role assignments...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $permanentCount = 0

    try {
        # Get all directory role assignments
        $roleAssignments = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition&$top=999' `
            -ErrorAction Stop

        $allAssignments = [System.Collections.Generic.List[object]]::new()
        $allAssignments.AddRange($roleAssignments.value)

        while ($roleAssignments.'@odata.nextLink') {
            $roleAssignments = Invoke-MgGraphRequest -Method GET -Uri $roleAssignments.'@odata.nextLink'
            $allAssignments.AddRange($roleAssignments.value)
        }

        # Check PIM eligible assignments for comparison
        $eligibleAssignments = @{}
        try {
            $eligible = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$top=999' `
                -ErrorAction Stop
            foreach ($e in $eligible.value) {
                $key = "$($e.principalId)|$($e.roleDefinitionId)"
                $eligibleAssignments[$key] = $true
            }
        }
        catch {
            Write-Verbose "    Could not retrieve PIM eligible assignments (PIM may not be licensed): $_"
        }

        foreach ($assignment in $allAssignments) {
            $roleName    = $assignment.roleDefinition.displayName
            $principalId = $assignment.principalId
            $principalDisplayName = $assignment.principal.displayName
            $principalUPN = $assignment.principal.userPrincipalName

            # Only flag privileged roles
            if ($roleName -notin $PRIVILEGED_ROLES) {
                continue
            }

            # Check if this is a permanent assignment (not PIM eligible)
            $key = "$principalId|$($assignment.roleDefinitionId)"
            $isEligibleOnly = $eligibleAssignments.ContainsKey($key)

            if (-not $isEligibleOnly) {
                $severity = if ($roleName -eq 'Global Administrator') { 'Critical' } else { 'High' }
                $permanentCount++
                $findings.Add((New-IdentityFinding `
                    -Category       'PrivilegedAccess' `
                    -Severity       $severity `
                    -Finding        "Permanent (active) assignment to '$roleName' role. Should use PIM eligible assignment." `
                    -AffectedObject $(if ($principalUPN) { $principalUPN } else { $principalDisplayName }) `
                    -Detail         "Role: $roleName, PrincipalId: $principalId" `
                    -Remediation    'Convert to PIM eligible assignment with time-limited activation and approval workflow.'))
            }
        }

        Write-Verbose "    Found $permanentCount permanent privileged role assignment(s)."
    }
    catch {
        Write-Warning "    Failed to retrieve role assignments: $_"
    }

    return @{ Findings = $findings; Count = $permanentCount }
}

function Test-GuestAccountRisk {
    <#
    .SYNOPSIS
        Identifies guest accounts with elevated directory or subscription-level permissions.
    #>
    [CmdletBinding()]
    param()

    Write-Host '  [4/7] Checking guest accounts for elevated permissions...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $riskyGuestCount = 0

    try {
        # Get all guest users
        $guests = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,mail,accountEnabled&`$top=999" `
            -ErrorAction Stop

        $allGuests = [System.Collections.Generic.List[object]]::new()
        $allGuests.AddRange($guests.value)

        while ($guests.'@odata.nextLink') {
            $guests = Invoke-MgGraphRequest -Method GET -Uri $guests.'@odata.nextLink'
            $allGuests.AddRange($guests.value)
        }

        # Get all role assignments once
        $roleAssignments = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition&$top=999' `
            -ErrorAction Stop

        $allRoleAssignments = [System.Collections.Generic.List[object]]::new()
        $allRoleAssignments.AddRange($roleAssignments.value)

        while ($roleAssignments.'@odata.nextLink') {
            $roleAssignments = Invoke-MgGraphRequest -Method GET -Uri $roleAssignments.'@odata.nextLink'
            $allRoleAssignments.AddRange($roleAssignments.value)
        }

        foreach ($guest in $allGuests) {
            $guestRoles = $allRoleAssignments | Where-Object { $_.principalId -eq $guest.id }

            foreach ($roleAssignment in $guestRoles) {
                $roleName = $roleAssignment.roleDefinition.displayName
                $severity = if ($roleName -in $PRIVILEGED_ROLES) { 'Critical' } else { 'High' }

                $riskyGuestCount++
                $findings.Add((New-IdentityFinding `
                    -Category       'GuestAccess' `
                    -Severity       $severity `
                    -Finding        "Guest account has directory role assignment: '$roleName'." `
                    -AffectedObject $(if ($guest.userPrincipalName) { $guest.userPrincipalName } else { $guest.mail }) `
                    -Detail         "Display Name: $($guest.displayName), Enabled: $($guest.accountEnabled)" `
                    -Remediation    'Review guest access necessity. Remove elevated roles or convert to member account if justified.'))
            }
        }

        Write-Verbose "    Found $riskyGuestCount guest account(s) with elevated permissions."
    }
    catch {
        Write-Warning "    Failed to evaluate guest account risk: $_"
    }

    return @{ Findings = $findings; Count = $riskyGuestCount; TotalGuests = $allGuests.Count }
}

function Test-ConditionalAccessCoverage {
    <#
    .SYNOPSIS
        Evaluates Conditional Access policies for coverage gaps.
    #>
    [CmdletBinding()]
    param()

    Write-Host '  [5/7] Evaluating Conditional Access policy coverage...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $policies = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
            -ErrorAction Stop

        $allPolicies = $policies.value
        $enabledPolicies  = $allPolicies | Where-Object { $_.state -eq 'enabled' }
        $reportOnlyPolicies = $allPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }
        $disabledPolicies = $allPolicies | Where-Object { $_.state -eq 'disabled' }

        Write-Verbose "    Total CA policies: $($allPolicies.Count), Enabled: $($enabledPolicies.Count), Report-only: $($reportOnlyPolicies.Count), Disabled: $($disabledPolicies.Count)"

        # Check: No CA policies at all
        if ($allPolicies.Count -eq 0) {
            $findings.Add((New-IdentityFinding `
                -Category       'ConditionalAccess' `
                -Severity       'Critical' `
                -Finding        'No Conditional Access policies found. The tenant has no CA protection.' `
                -Remediation    'Implement baseline CA policies: require MFA for all users, block legacy auth, require compliant devices.'))
            return @{ Findings = $findings }
        }

        # Check: MFA policy exists
        $mfaPolicy = $enabledPolicies | Where-Object {
            $_.grantControls.builtInControls -contains 'mfa'
        }
        if (-not $mfaPolicy) {
            $findings.Add((New-IdentityFinding `
                -Category       'ConditionalAccess' `
                -Severity       'Critical' `
                -Finding        'No enabled Conditional Access policy requires MFA.' `
                -Remediation    'Create a CA policy requiring MFA for all users and all cloud apps.'))
        }

        # Check: Legacy authentication block
        $legacyBlock = $enabledPolicies | Where-Object {
            $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
            $_.conditions.clientAppTypes -contains 'other'
        } | Where-Object {
            $_.grantControls.builtInControls -contains 'block'
        }
        if (-not $legacyBlock) {
            $findings.Add((New-IdentityFinding `
                -Category       'ConditionalAccess' `
                -Severity       'High' `
                -Finding        'No Conditional Access policy blocks legacy authentication protocols.' `
                -Remediation    'Create a CA policy blocking legacy auth clients (Exchange ActiveSync, other clients).'))
        }

        # Check: Policies with broad exclusions
        foreach ($policy in $enabledPolicies) {
            $excludedUsers  = $policy.conditions.users.excludeUsers
            $excludedGroups = $policy.conditions.users.excludeGroups

            $totalExclusions = ($excludedUsers | Measure-Object).Count + ($excludedGroups | Measure-Object).Count
            if ($totalExclusions -gt 5) {
                $findings.Add((New-IdentityFinding `
                    -Category       'ConditionalAccess' `
                    -Severity       'Medium' `
                    -Finding        "Policy '$($policy.displayName)' has $totalExclusions exclusions, which may create coverage gaps." `
                    -AffectedObject $policy.displayName `
                    -Remediation    'Minimize CA policy exclusions. Use a dedicated break-glass account group only.'))
            }
        }

        # Check: Report-only policies that should be enforced
        if ($reportOnlyPolicies.Count -gt 0) {
            foreach ($roPolicy in $reportOnlyPolicies) {
                $findings.Add((New-IdentityFinding `
                    -Category       'ConditionalAccess' `
                    -Severity       'Low' `
                    -Finding        "Policy '$($roPolicy.displayName)' is in report-only mode and not enforcing controls." `
                    -AffectedObject $roPolicy.displayName `
                    -Remediation    'Review report-only impact and promote to enabled if results are satisfactory.'))
            }
        }
    }
    catch {
        Write-Warning "    Failed to evaluate Conditional Access policies: $_"
        $findings.Add((New-IdentityFinding `
            -Category       'ConditionalAccess' `
            -Severity       'Medium' `
            -Finding        'Unable to retrieve Conditional Access policies. Verify Policy.Read.All permission.' `
            -Remediation    'Grant the Policy.Read.All Microsoft Graph permission to the audit identity.'))
    }

    return @{ Findings = $findings }
}

function Test-ServicePrincipalPermissions {
    <#
    .SYNOPSIS
        Identifies service principals with excessive Microsoft Graph or Azure permissions.
    #>
    [CmdletBinding()]
    param()

    Write-Host '  [6/7] Checking service principal permissions...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $spCount  = 0

    $highRiskPermissions = @(
        'Application.ReadWrite.All',
        'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'Mail.ReadWrite',
        'Files.ReadWrite.All',
        'Sites.ReadWrite.All',
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All'
    )

    try {
        # Get all application registrations
        $apps = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,requiredResourceAccess&$top=999' `
            -ErrorAction Stop

        $allApps = [System.Collections.Generic.List[object]]::new()
        $allApps.AddRange($apps.value)

        while ($apps.'@odata.nextLink') {
            $apps = Invoke-MgGraphRequest -Method GET -Uri $apps.'@odata.nextLink'
            $allApps.AddRange($apps.value)
        }

        $spCount = $allApps.Count

        # Get Microsoft Graph service principal for permission name resolution
        $graphSP = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles,oauth2PermissionScopes" `
            -ErrorAction Stop

        $graphAppRoles = @{}
        if ($graphSP.value.Count -gt 0) {
            foreach ($role in $graphSP.value[0].appRoles) {
                $graphAppRoles[$role.id] = $role.value
            }
        }

        foreach ($app in $allApps) {
            foreach ($resource in $app.requiredResourceAccess) {
                foreach ($permission in $resource.resourceAccess) {
                    # Only check application permissions (type 'Role'), not delegated (type 'Scope')
                    if ($permission.type -eq 'Role') {
                        $permissionName = $graphAppRoles[$permission.id]
                        if ($permissionName -and $permissionName -in $highRiskPermissions) {
                            $findings.Add((New-IdentityFinding `
                                -Category       'ServicePrincipal' `
                                -Severity       'High' `
                                -Finding        "Application has high-risk application permission: $permissionName." `
                                -AffectedObject "$($app.displayName) ($($app.appId))" `
                                -Detail         "Permission: $permissionName (Application type)" `
                                -Remediation    'Review whether this permission level is necessary. Apply least-privilege permissions.'))
                        }
                    }
                }
            }
        }

        Write-Verbose "    Evaluated $spCount application registration(s)."
    }
    catch {
        Write-Warning "    Failed to evaluate service principal permissions: $_"
    }

    return @{ Findings = $findings; Count = $spCount }
}

function Test-ApplicationCredentials {
    <#
    .SYNOPSIS
        Identifies applications with expiring or expired client secrets and certificates.
    #>
    [CmdletBinding()]
    param(
        [int]$ExpiryWindowDays
    )

    Write-Host '  [7/7] Checking application credential lifecycle...' -ForegroundColor DarkGray
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $expiringCount = 0
    $now = Get-Date
    $expiryThreshold = $now.AddDays($ExpiryWindowDays)

    try {
        $apps = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials&$top=999' `
            -ErrorAction Stop

        $allApps = [System.Collections.Generic.List[object]]::new()
        $allApps.AddRange($apps.value)

        while ($apps.'@odata.nextLink') {
            $apps = Invoke-MgGraphRequest -Method GET -Uri $apps.'@odata.nextLink'
            $allApps.AddRange($apps.value)
        }

        foreach ($app in $allApps) {
            # Check client secrets
            foreach ($secret in $app.passwordCredentials) {
                $endDate = [DateTime]$secret.endDateTime

                if ($endDate -lt $now) {
                    $daysExpired = [math]::Round(($now - $endDate).TotalDays)
                    $expiringCount++
                    $findings.Add((New-IdentityFinding `
                        -Category       'AppCredential' `
                        -Severity       'High' `
                        -Finding        "Client secret has been expired for $daysExpired day(s)." `
                        -AffectedObject "$($app.displayName) ($($app.appId))" `
                        -Detail         "Secret: $($secret.displayName), Expired: $($endDate.ToString('yyyy-MM-dd'))" `
                        -Remediation    'Remove the expired secret and rotate to a new credential. Consider using managed identities or certificates.'))
                }
                elseif ($endDate -lt $expiryThreshold) {
                    $daysUntilExpiry = [math]::Round(($endDate - $now).TotalDays)
                    $expiringCount++
                    $findings.Add((New-IdentityFinding `
                        -Category       'AppCredential' `
                        -Severity       'Medium' `
                        -Finding        "Client secret expires in $daysUntilExpiry day(s)." `
                        -AffectedObject "$($app.displayName) ($($app.appId))" `
                        -Detail         "Secret: $($secret.displayName), Expires: $($endDate.ToString('yyyy-MM-dd'))" `
                        -Remediation    'Rotate the secret before expiration to prevent service disruption.'))
                }
            }

            # Check certificates
            foreach ($cert in $app.keyCredentials) {
                $endDate = [DateTime]$cert.endDateTime

                if ($endDate -lt $now) {
                    $daysExpired = [math]::Round(($now - $endDate).TotalDays)
                    $expiringCount++
                    $findings.Add((New-IdentityFinding `
                        -Category       'AppCredential' `
                        -Severity       'High' `
                        -Finding        "Certificate has been expired for $daysExpired day(s)." `
                        -AffectedObject "$($app.displayName) ($($app.appId))" `
                        -Detail         "Certificate: $($cert.displayName), Expired: $($endDate.ToString('yyyy-MM-dd'))" `
                        -Remediation    'Remove the expired certificate and upload a renewed certificate.'))
                }
                elseif ($endDate -lt $expiryThreshold) {
                    $daysUntilExpiry = [math]::Round(($endDate - $now).TotalDays)
                    $expiringCount++
                    $findings.Add((New-IdentityFinding `
                        -Category       'AppCredential' `
                        -Severity       'Medium' `
                        -Finding        "Certificate expires in $daysUntilExpiry day(s)." `
                        -AffectedObject "$($app.displayName) ($($app.appId))" `
                        -Detail         "Certificate: $($cert.displayName), Expires: $($endDate.ToString('yyyy-MM-dd'))" `
                        -Remediation    'Renew the certificate before expiration to prevent service disruption.'))
                }
            }
        }

        Write-Verbose "    Found $expiringCount expiring or expired credential(s)."
    }
    catch {
        Write-Warning "    Failed to evaluate application credentials: $_"
    }

    return @{ Findings = $findings; Count = $expiringCount }
}

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

try {
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '  Azure AD / Entra ID Identity Security Audit' -ForegroundColor Cyan
    Write-Host '  Author: Jacob Phillips — First Carolina Bank' -ForegroundColor DarkGray
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host ''

    # Verify Microsoft Graph connection
    try {
        $graphContext = Get-MgContext
        if (-not $graphContext) {
            throw 'Not connected.'
        }
        Write-Verbose "Connected to Microsoft Graph as: $($graphContext.Account)"
        Write-Verbose "Tenant ID: $($graphContext.TenantId)"
    }
    catch {
        Write-Host 'Not connected to Microsoft Graph. Initiating connection...' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $GRAPH_SCOPES -ErrorAction Stop
        $graphContext = Get-MgContext
    }

    # Check required scopes
    $currentScopes = $graphContext.Scopes
    $missingScopes = $GRAPH_SCOPES | Where-Object { $_ -notin $currentScopes }
    if ($missingScopes) {
        Write-Warning "The following Graph scopes are missing and some checks may fail: $($missingScopes -join ', ')"
    }

    Write-Host "Tenant: $($graphContext.TenantId)" -ForegroundColor Green
    Write-Host ''

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Gather baseline statistics
    $totalUsers = 0
    $totalGuests = 0
    try {
        $userCount = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/`$count" `
            -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
        $totalUsers = $userCount
    }
    catch {
        Write-Verbose "    Could not retrieve user count: $_"
    }

    # ---- Run all audit checks ----
    $mfaResult       = Test-MFARegistration
    $staleResult     = Test-StaleAccounts -ThresholdDays $StaleThresholdDays -IncludeDisabled:$IncludeDisabledAccounts
    $privResult      = Test-PermanentPrivilegedAssignments
    $guestResult     = Test-GuestAccountRisk
    $caResult        = Test-ConditionalAccessCoverage
    $spResult        = Test-ServicePrincipalPermissions
    $credResult      = Test-ApplicationCredentials -ExpiryWindowDays $CredentialExpiryDays

    # Aggregate all findings
    foreach ($result in @($mfaResult, $staleResult, $privResult, $guestResult, $caResult, $spResult, $credResult)) {
        foreach ($f in $result.Findings) {
            $allFindings.Add($f)
        }
    }

    # Build statistics hashtable
    $stats = @{
        TotalUsers          = if ($totalUsers) { $totalUsers } else { 0 }
        GuestAccounts       = if ($guestResult.TotalGuests) { $guestResult.TotalGuests } else { 0 }
        ServicePrincipals   = if ($spResult.Count) { $spResult.Count } else { 0 }
        AppRegistrations    = if ($spResult.Count) { $spResult.Count } else { 0 }
        UsersWithoutMFA     = if ($mfaResult.Count) { $mfaResult.Count } else { 0 }
        StaleAccounts       = if ($staleResult.Count) { $staleResult.Count } else { 0 }
        PermanentPrivileged = if ($privResult.Count) { $privResult.Count } else { 0 }
        RiskyGuests         = if ($guestResult.Count) { $guestResult.Count } else { 0 }
        ExpiringCredentials = if ($credResult.Count) { $credResult.Count } else { 0 }
    }

    # ---- Output results ----
    if ($allFindings.Count -eq 0) {
        Write-Host ''
        Write-Host 'No security findings detected. Identity posture passed all validation checks.' -ForegroundColor Green
    }
    else {
        Write-RiskDashboard -Stats $stats -Findings $allFindings

        # Display detailed findings by category
        $allFindings |
            Sort-Object @{Expression = {
                switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } }
            }}, Category |
            Format-Table -Property Severity, Category, AffectedObject, Finding -AutoSize -Wrap

        # CSV export
        if ($ExportPath) {
            try {
                $allFindings | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Findings exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to export CSV: $_"
            }
        }
    }

    # Return findings for pipeline consumption
    return $allFindings
}
catch {
    Write-Error "Identity Audit encountered a fatal error: $_"
    Write-Debug $_.ScriptStackTrace
    throw
}
