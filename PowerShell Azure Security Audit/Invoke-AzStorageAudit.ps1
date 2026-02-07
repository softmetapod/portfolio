<#
.SYNOPSIS
    Audits Azure Storage Accounts for security misconfigurations and compliance violations.

.DESCRIPTION
    Invoke-AzStorageAudit evaluates all Azure Storage Accounts across one or more subscriptions
    for public access exposure, encryption posture, transport security, network isolation, and
    authentication configuration. Each finding is assigned a severity rating and results are
    displayed in the console with optional CSV export.

    Designed for enterprise cloud security operations at First Carolina Bank.

.PARAMETER SubscriptionId
    Specifies a single Azure subscription ID to audit. If omitted, the current subscription context is used.

.PARAMETER AllSubscriptions
    Audits storage accounts across all subscriptions the authenticated account has access to.

.PARAMETER ResourceGroupName
    Limits the audit to storage accounts within a specific resource group.

.PARAMETER ExportPath
    File path for CSV export of findings. If omitted, results are displayed in the console only.

.EXAMPLE
    .\Invoke-AzStorageAudit.ps1
    Audits storage accounts in the current subscription context.

.EXAMPLE
    .\Invoke-AzStorageAudit.ps1 -AllSubscriptions -ExportPath "C:\Reports\Storage-Audit.csv"
    Audits all subscriptions and exports results to CSV.

.EXAMPLE
    .\Invoke-AzStorageAudit.ps1 -ResourceGroupName "rg-production-data" -Verbose
    Audits storage accounts in a specific resource group with verbose output.

.NOTES
    Author:  Jacob Phillips
    Role:    Cloud Security Engineer, First Carolina Bank
    Version: 2.0.0
    Requires: Az.Storage module, Az.Accounts module
    Permissions: Reader role; Storage Blob Data Reader for container-level checks
#>

[CmdletBinding(DefaultParameterSetName = 'CurrentSubscription')]
param(
    [Parameter(ParameterSetName = 'SingleSubscription', Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(ParameterSetName = 'AllSubscriptions')]
    [switch]$AllSubscriptions,

    [Parameter()]
    [string]$ResourceGroupName,

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
    [string]$ExportPath
)

#Requires -Modules Az.Accounts, Az.Storage

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$MINIMUM_TLS_VERSION = 'TLS1_2'
$TLS_SEVERITY_MAP = @{
    'TLS1_0' = 'Critical'
    'TLS1_1' = 'High'
}

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function New-StorageFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object for the storage audit report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Subscription,
        [Parameter(Mandatory)] [string]$ResourceGroup,
        [Parameter(Mandatory)] [string]$StorageAccount,
        [Parameter(Mandatory)] [string]$CheckName,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Finding,
        [Parameter()]          [string]$CurrentValue,
        [Parameter()]          [string]$Remediation
    )

    [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Subscription   = $Subscription
        ResourceGroup  = $ResourceGroup
        StorageAccount = $StorageAccount
        CheckName      = $CheckName
        Severity       = $Severity
        Finding        = $Finding
        CurrentValue   = if ($CurrentValue) { $CurrentValue } else { '' }
        Remediation    = if ($Remediation) { $Remediation } else { '' }
    }
}

function Write-StorageSummary {
    <#
    .SYNOPSIS
        Displays a formatted summary of storage audit findings to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Findings,

        [Parameter(Mandatory = $true)]
        [int]$AccountsAudited
    )

    $critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high     = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium   = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low      = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║      STORAGE ACCOUNT AUDIT — FINDING SUMMARY        ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Accounts Audited : $($AccountsAudited.ToString().PadLeft(4))                           ║" -ForegroundColor White
    Write-Host '║──────────────────────────────────────────────────────║' -ForegroundColor DarkGray
    Write-Host "║  Critical         : $($critical.ToString().PadLeft(4))                           ║" -ForegroundColor Red
    Write-Host "║  High             : $($high.ToString().PadLeft(4))                           ║" -ForegroundColor Yellow
    Write-Host "║  Medium           : $($medium.ToString().PadLeft(4))                           ║" -ForegroundColor DarkYellow
    Write-Host "║  Low              : $($low.ToString().PadLeft(4))                           ║" -ForegroundColor Gray
    Write-Host "║  Total Findings   : $($Findings.Count.ToString().PadLeft(4))                           ║" -ForegroundColor White
    Write-Host '╚══════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Core Audit Function
# ---------------------------------------------------------------------------

function Invoke-StorageAccountSecurityCheck {
    <#
    .SYNOPSIS
        Performs all security checks against a single Azure Storage Account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$Account,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionName
    )

    $findings      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resourceGroup = $Account.ResourceGroupName
    $accountName   = $Account.StorageAccountName

    Write-Verbose "  Evaluating storage account: $accountName"

    # ---- Check 1: Public blob access enabled ----
    try {
        $allowBlobPublicAccess = $Account.AllowBlobPublicAccess
        if ($null -eq $allowBlobPublicAccess -or $allowBlobPublicAccess -eq $true) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'PublicBlobAccess' `
                -Severity       'High' `
                -Finding        'Public blob access is allowed at the account level.' `
                -CurrentValue   "AllowBlobPublicAccess: $allowBlobPublicAccess" `
                -Remediation    'Set AllowBlobPublicAccess to false: Set-AzStorageAccount -AllowBlobPublicAccess $false'))
        }
        else {
            Write-Verbose "    PASS: Public blob access is disabled on $accountName."
        }
    }
    catch {
        Write-Warning "    Failed to check public blob access on $accountName : $_"
    }

    # ---- Check 2: HTTPS-only transfer ----
    try {
        if (-not $Account.EnableHttpsTrafficOnly) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'HttpsOnly' `
                -Severity       'High' `
                -Finding        'HTTPS-only transfer is not enforced. HTTP traffic is allowed.' `
                -CurrentValue   "EnableHttpsTrafficOnly: $($Account.EnableHttpsTrafficOnly)" `
                -Remediation    'Enable HTTPS-only: Set-AzStorageAccount -EnableHttpsTrafficOnly $true'))
        }
        else {
            Write-Verbose "    PASS: HTTPS-only transfer is enforced on $accountName."
        }
    }
    catch {
        Write-Warning "    Failed to check HTTPS setting on $accountName : $_"
    }

    # ---- Check 3: Minimum TLS version ----
    try {
        $tlsVersion = $Account.MinimumTlsVersion
        if ($null -eq $tlsVersion -or $tlsVersion -ne $MINIMUM_TLS_VERSION) {
            $severity = if ($TLS_SEVERITY_MAP.ContainsKey($tlsVersion)) { $TLS_SEVERITY_MAP[$tlsVersion] } else { 'High' }
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'MinimumTLS' `
                -Severity       $severity `
                -Finding        "Minimum TLS version is below 1.2. Older TLS versions have known vulnerabilities." `
                -CurrentValue   "MinimumTlsVersion: $tlsVersion" `
                -Remediation    'Set minimum TLS to 1.2: Set-AzStorageAccount -MinimumTlsVersion TLS1_2'))
        }
        else {
            Write-Verbose "    PASS: Minimum TLS version is $MINIMUM_TLS_VERSION on $accountName."
        }
    }
    catch {
        Write-Warning "    Failed to check TLS version on $accountName : $_"
    }

    # ---- Check 4: Encryption settings ----
    try {
        $encryption = $Account.Encryption
        # Check if infrastructure encryption (double encryption) is enabled
        if (-not $encryption.RequireInfrastructureEncryption) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'InfrastructureEncryption' `
                -Severity       'Low' `
                -Finding        'Infrastructure encryption (double encryption) is not enabled.' `
                -CurrentValue   "RequireInfrastructureEncryption: $($encryption.RequireInfrastructureEncryption)" `
                -Remediation    'Consider enabling infrastructure encryption for defense-in-depth (requires account recreation).'))
        }

        # Check key source — customer-managed keys recommended for sensitive data
        $blobKeySource = $encryption.Services.Blob.KeyType
        $fileKeySource = $encryption.Services.File.KeyType
        if ($blobKeySource -eq 'Account' -and $fileKeySource -eq 'Account') {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'EncryptionKeySource' `
                -Severity       'Low' `
                -Finding        'Storage account uses Microsoft-managed encryption keys (not customer-managed keys).' `
                -CurrentValue   "KeySource: Microsoft.Storage (MMK)" `
                -Remediation    'For sensitive data, consider using customer-managed keys (CMK) stored in Azure Key Vault.'))
        }
    }
    catch {
        Write-Verbose "    Could not fully evaluate encryption settings on $accountName : $_"
    }

    # ---- Check 5: Private endpoint connections ----
    try {
        $privateEndpoints = $Account.PrivateEndpointConnections
        if ($null -eq $privateEndpoints -or $privateEndpoints.Count -eq 0) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'PrivateEndpoint' `
                -Severity       'Medium' `
                -Finding        'No private endpoint connections configured. Storage is accessible over the public internet.' `
                -CurrentValue   'PrivateEndpointConnections: 0' `
                -Remediation    'Create a private endpoint for the storage account and restrict public network access.'))
        }
        else {
            Write-Verbose "    PASS: $($privateEndpoints.Count) private endpoint(s) found on $accountName."
        }
    }
    catch {
        Write-Warning "    Failed to check private endpoints on $accountName : $_"
    }

    # ---- Check 6: Shared key access enabled ----
    try {
        $allowSharedKey = $Account.AllowSharedKeyAccess
        if ($null -eq $allowSharedKey -or $allowSharedKey -eq $true) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'SharedKeyAccess' `
                -Severity       'Medium' `
                -Finding        'Shared key (storage account key) access is enabled. Azure AD authentication is preferred.' `
                -CurrentValue   "AllowSharedKeyAccess: $allowSharedKey" `
                -Remediation    'Disable shared key access: Set-AzStorageAccount -AllowSharedKeyAccess $false. Use Azure AD RBAC instead.'))
        }
        else {
            Write-Verbose "    PASS: Shared key access is disabled on $accountName."
        }
    }
    catch {
        Write-Warning "    Failed to check shared key access on $accountName : $_"
    }

    # ---- Check 7: Network default action ----
    try {
        $networkRuleSet = $Account.NetworkRuleSet
        if ($networkRuleSet -and $networkRuleSet.DefaultAction -eq 'Allow') {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'NetworkDefaultAction' `
                -Severity       'High' `
                -Finding        'Network default action is Allow. All networks can access this storage account.' `
                -CurrentValue   "DefaultAction: Allow" `
                -Remediation    'Set default action to Deny and add explicit network rules for trusted networks.'))
        }
    }
    catch {
        Write-Verbose "    Could not check network rule set on $accountName : $_"
    }

    # ---- Check 8: Blob containers with anonymous access ----
    try {
        $storageContext = $Account.Context
        if ($storageContext) {
            $containers = Get-AzStorageContainer -Context $storageContext -ErrorAction Stop

            foreach ($container in $containers) {
                $publicAccess = $container.PublicAccess
                if ($publicAccess -ne 'Off' -and $publicAccess -ne 'None' -and $null -ne $publicAccess) {
                    $severity = if ($publicAccess -eq 'Container') { 'Critical' } else { 'High' }
                    $findings.Add((New-StorageFinding `
                        -Subscription   $SubscriptionName `
                        -ResourceGroup  $resourceGroup `
                        -StorageAccount $accountName `
                        -CheckName      'ContainerAnonymousAccess' `
                        -Severity       $severity `
                        -Finding        "Blob container '$($container.Name)' has anonymous public access level: $publicAccess." `
                        -CurrentValue   "Container: $($container.Name), PublicAccess: $publicAccess" `
                        -Remediation    "Set container access to Private: Set-AzStorageContainerAcl -Name '$($container.Name)' -Permission Off"))
                }
            }
        }
    }
    catch {
        Write-Verbose "    Could not enumerate containers on $accountName (may require elevated permissions): $_"
    }

    # ---- Check 9: Blob soft delete ----
    try {
        $blobServiceProperties = Get-AzStorageBlobServiceProperty -ResourceGroupName $resourceGroup -StorageAccountName $accountName -ErrorAction Stop
        if (-not $blobServiceProperties.DeleteRetentionPolicy.Enabled) {
            $findings.Add((New-StorageFinding `
                -Subscription   $SubscriptionName `
                -ResourceGroup  $resourceGroup `
                -StorageAccount $accountName `
                -CheckName      'BlobSoftDelete' `
                -Severity       'Medium' `
                -Finding        'Blob soft delete is not enabled. Accidental or malicious deletion cannot be recovered.' `
                -CurrentValue   'DeleteRetentionPolicy.Enabled: False' `
                -Remediation    'Enable blob soft delete with a minimum 7-day retention period.'))
        }
    }
    catch {
        Write-Verbose "    Could not check blob soft delete on $accountName : $_"
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

try {
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '  Azure Storage Account Security Audit' -ForegroundColor Cyan
    Write-Host '  Author: Jacob Phillips — First Carolina Bank' -ForegroundColor DarkGray
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host ''

    # Verify Azure connection
    $context = Get-AzContext
    if (-not $context) {
        throw 'Not connected to Azure. Run Connect-AzAccount before executing this script.'
    }
    Write-Verbose "Authenticated as: $($context.Account.Id)"

    # Determine subscriptions to audit
    $subscriptions = @()
    switch ($PSCmdlet.ParameterSetName) {
        'AllSubscriptions' {
            $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
            Write-Host "Discovered $($subscriptions.Count) enabled subscription(s)." -ForegroundColor Green
        }
        'SingleSubscription' {
            $subscriptions = Get-AzSubscription -SubscriptionId $SubscriptionId
        }
        default {
            $subscriptions = @([PSCustomObject]@{
                Id   = $context.Subscription.Id
                Name = $context.Subscription.Name
            })
        }
    }

    $allFindings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalAccounts  = 0

    foreach ($sub in $subscriptions) {
        Write-Host "Auditing subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Yellow
        Write-Verbose "Setting subscription context to $($sub.Id)"

        try {
            $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to set context for subscription $($sub.Name): $_"
            continue
        }

        # Retrieve storage accounts
        try {
            $getParams = @{ ErrorAction = 'Stop' }
            if ($ResourceGroupName) {
                $getParams['ResourceGroupName'] = $ResourceGroupName
            }
            $storageAccounts = Get-AzStorageAccount @getParams
        }
        catch {
            Write-Warning "Failed to retrieve storage accounts from subscription $($sub.Name): $_"
            continue
        }

        Write-Host "  Found $($storageAccounts.Count) storage account(s) in $($sub.Name)." -ForegroundColor DarkGray
        $totalAccounts += $storageAccounts.Count

        foreach ($account in $storageAccounts) {
            $accountFindings = Invoke-StorageAccountSecurityCheck `
                -Account $account `
                -SubscriptionName $sub.Name

            foreach ($f in $accountFindings) {
                $allFindings.Add($f)
            }
        }
    }

    # ---- Output results ----
    Write-Host ''
    Write-Host "Audit complete. Evaluated $totalAccounts storage account(s) across $($subscriptions.Count) subscription(s)." -ForegroundColor Green

    if ($allFindings.Count -eq 0) {
        Write-Host 'No security findings detected. All storage accounts passed validation checks.' -ForegroundColor Green
    }
    else {
        Write-StorageSummary -Findings $allFindings -AccountsAudited $totalAccounts

        # Display detailed findings table
        $allFindings |
            Sort-Object @{Expression = {
                switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } }
            }} |
            Format-Table -Property Severity, StorageAccount, CheckName, Finding -AutoSize -Wrap

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
    Write-Error "Storage Audit encountered a fatal error: $_"
    Write-Debug $_.ScriptStackTrace
    throw
}
