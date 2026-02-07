<#
.SYNOPSIS
    Audits Azure Network Security Groups for security misconfigurations and overly permissive rules.

.DESCRIPTION
    Invoke-AzNSGAudit enumerates all Network Security Groups across one or more Azure subscriptions
    and evaluates each rule against a set of security checks. The script flags overly permissive rules,
    dangerous inbound access patterns (RDP/SSH from the internet), unused NSGs, wide port ranges,
    and priority conflicts. Each finding is assigned a risk severity (Critical, High, Medium, Low)
    and results are displayed in the console with optional CSV export.

    Designed for enterprise cloud security operations at First Carolina Bank.

.PARAMETER SubscriptionId
    Specifies a single Azure subscription ID to audit. If omitted, the current subscription context is used.

.PARAMETER AllSubscriptions
    Audits NSGs across all subscriptions the authenticated account has access to.

.PARAMETER ExportPath
    File path for CSV export of findings. If omitted, results are displayed in the console only.

.PARAMETER IncludeDefaultRules
    Include Azure default NSG rules in the audit. By default, only custom rules are evaluated.

.EXAMPLE
    .\Invoke-AzNSGAudit.ps1
    Audits NSGs in the current subscription context and displays findings in the console.

.EXAMPLE
    .\Invoke-AzNSGAudit.ps1 -AllSubscriptions -ExportPath "C:\Reports\NSG-Audit.csv"
    Audits NSGs across all accessible subscriptions and exports findings to CSV.

.EXAMPLE
    .\Invoke-AzNSGAudit.ps1 -SubscriptionId "a1b2c3d4-e5f6-7890-abcd-ef1234567890" -Verbose
    Audits a specific subscription with verbose diagnostic output.

.NOTES
    Author:  Jacob Phillips
    Role:    Cloud Security Engineer, First Carolina Bank
    Version: 2.1.0
    Requires: Az.Network module, Az.Accounts module
    Permissions: Reader role on target subscriptions
#>

[CmdletBinding(DefaultParameterSetName = 'CurrentSubscription')]
param(
    [Parameter(ParameterSetName = 'SingleSubscription', Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(ParameterSetName = 'AllSubscriptions')]
    [switch]$AllSubscriptions,

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
    [switch]$IncludeDefaultRules
)

#Requires -Modules Az.Accounts, Az.Network

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$INTERNET_SOURCES = @('*', '0.0.0.0/0', 'Internet', 'Any')
$HIGH_RISK_PORTS  = @('3389', '22', '445', '1433', '3306', '5432', '27017')
$WIDE_PORT_RANGE_THRESHOLD = 100

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Get-PortRangeSize {
    <#
    .SYNOPSIS
        Calculates the number of ports covered by a port range string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PortRange
    )

    if ($PortRange -eq '*' -or $PortRange -eq 'Any') {
        return 65535
    }

    if ($PortRange -match '^\d+$') {
        return 1
    }

    if ($PortRange -match '^(\d+)-(\d+)$') {
        $start = [int]$Matches[1]
        $end   = [int]$Matches[2]
        return ($end - $start + 1)
    }

    # Comma-separated ports or ranges
    $total = 0
    foreach ($segment in $PortRange -split ',') {
        $segment = $segment.Trim()
        if ($segment -match '^(\d+)-(\d+)$') {
            $total += ([int]$Matches[2] - [int]$Matches[1] + 1)
        }
        elseif ($segment -match '^\d+$') {
            $total += 1
        }
    }
    return $total
}

function Test-InternetSource {
    <#
    .SYNOPSIS
        Determines if a source address prefix represents internet-facing access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SourcePrefix,

        [Parameter()]
        [string[]]$SourcePrefixes
    )

    foreach ($src in @($SourcePrefix) + @($SourcePrefixes | Where-Object { $_ })) {
        if ($INTERNET_SOURCES -contains $src) {
            return $true
        }
    }
    return $false
}

function Test-PortInRange {
    <#
    .SYNOPSIS
        Checks if a specific port number falls within a destination port range string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PortRange,

        [Parameter(Mandatory = $true)]
        [string]$TargetPort
    )

    if ($PortRange -eq '*' -or $PortRange -eq 'Any') {
        return $true
    }

    $target = [int]$TargetPort
    foreach ($segment in $PortRange -split ',') {
        $segment = $segment.Trim()
        if ($segment -match '^(\d+)-(\d+)$') {
            if ($target -ge [int]$Matches[1] -and $target -le [int]$Matches[2]) {
                return $true
            }
        }
        elseif ($segment -eq $TargetPort) {
            return $true
        }
    }
    return $false
}

function New-AuditFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object for the audit report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Subscription,
        [Parameter(Mandatory)] [string]$ResourceGroup,
        [Parameter(Mandatory)] [string]$NSGName,
        [Parameter()]          [string]$RuleName,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Finding,
        [Parameter()]          [string]$Remediation
    )

    [PSCustomObject]@{
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Subscription  = $Subscription
        ResourceGroup = $ResourceGroup
        NSGName       = $NSGName
        RuleName      = if ($RuleName) { $RuleName } else { 'N/A' }
        Severity      = $Severity
        Finding       = $Finding
        Remediation   = if ($Remediation) { $Remediation } else { '' }
    }
}

function Write-FindingSummary {
    <#
    .SYNOPSIS
        Displays a formatted summary of audit findings to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high     = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium   = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low      = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║         NSG SECURITY AUDIT — FINDING SUMMARY        ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Critical : $($critical.ToString().PadLeft(4))                                    ║" -ForegroundColor Red
    Write-Host "║  High     : $($high.ToString().PadLeft(4))                                    ║" -ForegroundColor Yellow
    Write-Host "║  Medium   : $($medium.ToString().PadLeft(4))                                    ║" -ForegroundColor DarkYellow
    Write-Host "║  Low      : $($low.ToString().PadLeft(4))                                    ║" -ForegroundColor Gray
    Write-Host "║  Total    : $($Findings.Count.ToString().PadLeft(4))                                    ║" -ForegroundColor White
    Write-Host '╚══════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Core Audit Function
# ---------------------------------------------------------------------------

function Invoke-NSGSecurityCheck {
    <#
    .SYNOPSIS
        Performs all security checks against a single NSG and its rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSNetworkSecurityGroup]$NSG,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionName,

        [Parameter()]
        [switch]$IncludeDefault
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resourceGroup = $NSG.ResourceGroupName
    $nsgName       = $NSG.Name

    Write-Verbose "  Evaluating NSG: $nsgName in $resourceGroup"

    # ---- Check: Unused NSG (not associated with any subnet or NIC) ----
    $subnetAssociations = ($NSG.Subnets | Measure-Object).Count
    $nicAssociations    = ($NSG.NetworkInterfaces | Measure-Object).Count

    if ($subnetAssociations -eq 0 -and $nicAssociations -eq 0) {
        $findings.Add((New-AuditFinding `
            -Subscription  $SubscriptionName `
            -ResourceGroup $resourceGroup `
            -NSGName       $nsgName `
            -Severity      'Low' `
            -Finding       'NSG is not associated with any subnet or network interface. It may be orphaned.' `
            -Remediation   'Review whether this NSG is still needed. Delete orphaned NSGs to reduce clutter.'))
    }

    # ---- Gather rules to evaluate ----
    $rules = $NSG.SecurityRules
    if ($IncludeDefault) {
        $rules = $rules + $NSG.DefaultSecurityRules
    }

    if (-not $rules -or $rules.Count -eq 0) {
        Write-Verbose "    No custom rules found on $nsgName."
        return $findings
    }

    # ---- Check for priority conflicts (duplicate priorities in same direction) ----
    $inboundPriorities  = $rules | Where-Object { $_.Direction -eq 'Inbound' }  | Group-Object Priority | Where-Object { $_.Count -gt 1 }
    $outboundPriorities = $rules | Where-Object { $_.Direction -eq 'Outbound' } | Group-Object Priority | Where-Object { $_.Count -gt 1 }

    foreach ($conflict in $inboundPriorities) {
        $ruleNames = ($conflict.Group | ForEach-Object { $_.Name }) -join ', '
        $findings.Add((New-AuditFinding `
            -Subscription  $SubscriptionName `
            -ResourceGroup $resourceGroup `
            -NSGName       $nsgName `
            -RuleName      $ruleNames `
            -Severity      'Medium' `
            -Finding       "Inbound priority conflict: multiple rules share priority $($conflict.Name)." `
            -Remediation   'Assign unique priorities to each rule to ensure predictable traffic evaluation.'))
    }

    foreach ($conflict in $outboundPriorities) {
        $ruleNames = ($conflict.Group | ForEach-Object { $_.Name }) -join ', '
        $findings.Add((New-AuditFinding `
            -Subscription  $SubscriptionName `
            -ResourceGroup $resourceGroup `
            -NSGName       $nsgName `
            -RuleName      $ruleNames `
            -Severity      'Medium' `
            -Finding       "Outbound priority conflict: multiple rules share priority $($conflict.Name)." `
            -Remediation   'Assign unique priorities to each rule to ensure predictable traffic evaluation.'))
    }

    # ---- Evaluate each rule ----
    foreach ($rule in $rules) {
        $ruleName    = $rule.Name
        $direction   = $rule.Direction
        $access      = $rule.Access
        $protocol    = $rule.Protocol
        $srcPrefix   = $rule.SourceAddressPrefix
        $srcPrefixes = $rule.SourceAddressPrefixes
        $dstPort     = $rule.DestinationPortRange
        $dstPorts    = $rule.DestinationPortRanges

        # Only evaluate Allow rules for permissiveness
        if ($access -ne 'Allow') {
            continue
        }

        $isInbound       = $direction -eq 'Inbound'
        $isInternetSrc   = Test-InternetSource -SourcePrefix $srcPrefix -SourcePrefixes $srcPrefixes
        $allDestPorts    = @($dstPort) + @($dstPorts | Where-Object { $_ })
        $effectivePortRange = ($allDestPorts | Where-Object { $_ }) -join ','

        # ---- Check: Allow-All Inbound (Any source, Any port, Any protocol) ----
        if ($isInbound -and $isInternetSrc -and ($effectivePortRange -eq '*' -or $effectivePortRange -eq 'Any') -and ($protocol -eq '*' -or $protocol -eq 'Any')) {
            $findings.Add((New-AuditFinding `
                -Subscription  $SubscriptionName `
                -ResourceGroup $resourceGroup `
                -NSGName       $nsgName `
                -RuleName      $ruleName `
                -Severity      'Critical' `
                -Finding       'Rule allows ALL inbound traffic from the internet (any port, any protocol).' `
                -Remediation   'Immediately restrict this rule to specific source IPs, ports, and protocols.'))
            continue  # No need to check further; this is the worst case
        }

        # ---- Check: RDP from internet ----
        if ($isInbound -and $isInternetSrc) {
            foreach ($portRange in $allDestPorts) {
                if ($portRange -and (Test-PortInRange -PortRange $portRange -TargetPort '3389')) {
                    $findings.Add((New-AuditFinding `
                        -Subscription  $SubscriptionName `
                        -ResourceGroup $resourceGroup `
                        -NSGName       $nsgName `
                        -RuleName      $ruleName `
                        -Severity      'Critical' `
                        -Finding       'Rule allows inbound RDP (port 3389) from the internet.' `
                        -Remediation   'Disable direct RDP from the internet. Use Azure Bastion or a VPN gateway instead.'))
                    break
                }
            }
        }

        # ---- Check: SSH from internet ----
        if ($isInbound -and $isInternetSrc) {
            foreach ($portRange in $allDestPorts) {
                if ($portRange -and (Test-PortInRange -PortRange $portRange -TargetPort '22')) {
                    $findings.Add((New-AuditFinding `
                        -Subscription  $SubscriptionName `
                        -ResourceGroup $resourceGroup `
                        -NSGName       $nsgName `
                        -RuleName      $ruleName `
                        -Severity      'Critical' `
                        -Finding       'Rule allows inbound SSH (port 22) from the internet.' `
                        -Remediation   'Disable direct SSH from the internet. Use Azure Bastion or a VPN gateway instead.'))
                    break
                }
            }
        }

        # ---- Check: Other high-risk ports from internet ----
        if ($isInbound -and $isInternetSrc) {
            foreach ($riskyPort in $HIGH_RISK_PORTS | Where-Object { $_ -notin @('3389', '22') }) {
                foreach ($portRange in $allDestPorts) {
                    if ($portRange -and (Test-PortInRange -PortRange $portRange -TargetPort $riskyPort)) {
                        $findings.Add((New-AuditFinding `
                            -Subscription  $SubscriptionName `
                            -ResourceGroup $resourceGroup `
                            -NSGName       $nsgName `
                            -RuleName      $ruleName `
                            -Severity      'High' `
                            -Finding       "Rule allows inbound traffic to high-risk port $riskyPort from the internet." `
                            -Remediation   "Restrict access to port $riskyPort to known source IPs or use private endpoints."))
                        break
                    }
                }
            }
        }

        # ---- Check: Wide port range ----
        foreach ($portRange in $allDestPorts) {
            if ($portRange) {
                $size = Get-PortRangeSize -PortRange $portRange
                if ($size -ge $WIDE_PORT_RANGE_THRESHOLD -and $portRange -ne '*') {
                    $severity = if ($isInternetSrc -and $isInbound) { 'High' } else { 'Medium' }
                    $findings.Add((New-AuditFinding `
                        -Subscription  $SubscriptionName `
                        -ResourceGroup $resourceGroup `
                        -NSGName       $nsgName `
                        -RuleName      $ruleName `
                        -Severity      $severity `
                        -Finding       "Rule opens a wide port range ($portRange, covering $size ports)." `
                        -Remediation   'Narrow the port range to only the specific ports required by the application.'))
                }
            }
        }

        # ---- Check: Any source with any protocol (non-internet but still permissive) ----
        if ($isInbound -and -not $isInternetSrc -and ($protocol -eq '*' -or $protocol -eq 'Any') -and ($effectivePortRange -eq '*' -or $effectivePortRange -eq 'Any')) {
            $findings.Add((New-AuditFinding `
                -Subscription  $SubscriptionName `
                -ResourceGroup $resourceGroup `
                -NSGName       $nsgName `
                -RuleName      $ruleName `
                -Severity      'Medium' `
                -Finding       "Rule allows all ports and protocols inbound from source '$srcPrefix'." `
                -Remediation   'Apply the principle of least privilege — restrict to specific ports and protocols.'))
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

try {
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '  Azure NSG Security Audit' -ForegroundColor Cyan
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

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalNSGs   = 0

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

        # Enumerate all NSGs in the subscription
        try {
            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to retrieve NSGs from subscription $($sub.Name): $_"
            continue
        }

        Write-Host "  Found $($nsgs.Count) NSG(s) in $($sub.Name)." -ForegroundColor DarkGray
        $totalNSGs += $nsgs.Count

        foreach ($nsg in $nsgs) {
            $params = @{
                NSG              = $nsg
                SubscriptionName = $sub.Name
            }
            if ($IncludeDefaultRules) {
                $params['IncludeDefault'] = $true
            }

            $nsgFindings = Invoke-NSGSecurityCheck @params
            foreach ($f in $nsgFindings) {
                $allFindings.Add($f)
            }
        }
    }

    # ---- Output results ----
    Write-Host ''
    Write-Host "Audit complete. Evaluated $totalNSGs NSG(s) across $($subscriptions.Count) subscription(s)." -ForegroundColor Green

    if ($allFindings.Count -eq 0) {
        Write-Host 'No security findings detected. All NSG rules passed validation checks.' -ForegroundColor Green
    }
    else {
        Write-FindingSummary -Findings $allFindings

        # Display detailed findings table
        $allFindings |
            Sort-Object @{Expression = {
                switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } }
            }} |
            Format-Table -Property Severity, NSGName, RuleName, Finding -AutoSize -Wrap

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
    Write-Error "NSG Audit encountered a fatal error: $_"
    Write-Debug $_.ScriptStackTrace
    throw
}
