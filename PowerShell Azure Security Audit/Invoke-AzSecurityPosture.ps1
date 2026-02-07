<#
.SYNOPSIS
    Orchestrates all Azure security audit scripts and generates a unified HTML report.

.DESCRIPTION
    Invoke-AzSecurityPosture is the master orchestrator for the Azure Security Audit Toolkit.
    It executes the NSG, Storage, and Identity audit scripts, aggregates all findings into a
    unified HTML report with an executive summary, calculates an overall risk score, and
    optionally delivers the report via email.

    The script supports scheduling through Azure Automation or Windows Task Scheduler and
    includes comprehensive error handling and logging throughout.

    Designed for enterprise cloud security operations at First Carolina Bank.

.PARAMETER OutputDirectory
    Directory path where the HTML report and CSV exports will be saved.

.PARAMETER AllSubscriptions
    Passes the -AllSubscriptions flag to NSG and Storage audit scripts.

.PARAMETER SubscriptionId
    Passes a specific subscription ID to NSG and Storage audit scripts.

.PARAMETER SkipNSGAudit
    Skips the NSG security audit module.

.PARAMETER SkipStorageAudit
    Skips the Storage Account security audit module.

.PARAMETER SkipIdentityAudit
    Skips the Identity (Azure AD / Entra ID) security audit module.

.PARAMETER SendEmail
    Sends the HTML report via email upon completion.

.PARAMETER SmtpServer
    SMTP server hostname for email delivery. Required when -SendEmail is specified.

.PARAMETER SmtpPort
    SMTP port number. Default: 587

.PARAMETER EmailFrom
    Sender email address. Required when -SendEmail is specified.

.PARAMETER EmailTo
    Recipient email address(es). Required when -SendEmail is specified.

.PARAMETER EmailCredential
    PSCredential for SMTP authentication. If omitted, anonymous relay is attempted.

.PARAMETER UseSsl
    Use SSL/TLS for the SMTP connection. Default: $true

.EXAMPLE
    .\Invoke-AzSecurityPosture.ps1 -OutputDirectory "C:\Reports"
    Runs all audit modules for the current subscription and saves the HTML report.

.EXAMPLE
    .\Invoke-AzSecurityPosture.ps1 -AllSubscriptions -OutputDirectory "C:\Reports" -SendEmail -SmtpServer "smtp.firstcarolina.bank" -EmailFrom "secops@firstcarolina.bank" -EmailTo "ciso@firstcarolina.bank"
    Full audit across all subscriptions with email delivery.

.EXAMPLE
    .\Invoke-AzSecurityPosture.ps1 -SkipIdentityAudit -OutputDirectory "C:\Reports" -Verbose
    Runs only NSG and Storage audits with verbose output.

.NOTES
    Author:  Jacob Phillips
    Role:    Cloud Security Engineer, First Carolina Bank
    Version: 2.0.0
    Requires: Az module, Microsoft.Graph module
#>

[CmdletBinding(DefaultParameterSetName = 'CurrentSubscription')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Container)) {
            throw "Output directory '$_' does not exist."
        }
        return $true
    })]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName = 'AllSubscriptions')]
    [switch]$AllSubscriptions,

    [Parameter(ParameterSetName = 'SingleSubscription')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [switch]$SkipNSGAudit,
    [switch]$SkipStorageAudit,
    [switch]$SkipIdentityAudit,

    [switch]$SendEmail,

    [Parameter()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$SmtpPort = 587,

    [Parameter()]
    [string]$EmailFrom,

    [Parameter()]
    [string[]]$EmailTo,

    [Parameter()]
    [PSCredential]$EmailCredential,

    [Parameter()]
    [bool]$UseSsl = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Validate email parameters
# ---------------------------------------------------------------------------
if ($SendEmail) {
    if (-not $SmtpServer) { throw 'SmtpServer is required when -SendEmail is specified.' }
    if (-not $EmailFrom)  { throw 'EmailFrom is required when -SendEmail is specified.' }
    if (-not $EmailTo)    { throw 'EmailTo is required when -SendEmail is specified.' }
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$scriptRoot   = $PSScriptRoot
$timestamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportName   = "AzureSecurityPosture-$timestamp"
$htmlPath     = Join-Path $OutputDirectory "$reportName.html"
$logPath      = Join-Path $OutputDirectory "$reportName.log"
$auditStart   = Get-Date

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes a timestamped message to both the console and log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Message,
        [Parameter()] [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO'
    )

    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"

    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor White }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }

    Add-Content -Path $logPath -Value $entry -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Risk Score Calculation
# ---------------------------------------------------------------------------

function Get-OverallRiskScore {
    <#
    .SYNOPSIS
        Calculates a 0-100 risk score from aggregated findings.
        Higher score = higher risk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    if ($Findings.Count -eq 0) { return 0 }

    $weights = @{
        Critical = 10
        High     = 5
        Medium   = 2
        Low      = 1
    }

    $totalWeight = 0
    foreach ($f in $Findings) {
        $totalWeight += $weights[$f.Severity]
    }

    # Normalize to 0-100 scale (cap at 100)
    $score = [math]::Min(100, [math]::Round($totalWeight / 2))
    return $score
}

function Get-RiskRating {
    <#
    .SYNOPSIS
        Converts a numeric risk score to a qualitative rating.
    #>
    [CmdletBinding()]
    param([int]$Score)

    switch ($Score) {
        { $_ -ge 80 } { return 'Critical' }
        { $_ -ge 60 } { return 'High' }
        { $_ -ge 35 } { return 'Medium' }
        { $_ -ge 10 } { return 'Low' }
        default        { return 'Healthy' }
    }
}

function Get-RiskColor {
    <#
    .SYNOPSIS
        Returns a CSS color for a risk rating.
    #>
    [CmdletBinding()]
    param([string]$Rating)

    switch ($Rating) {
        'Critical' { return '#dc3545' }
        'High'     { return '#fd7e14' }
        'Medium'   { return '#ffc107' }
        'Low'      { return '#28a745' }
        'Healthy'  { return '#17a2b8' }
        default    { return '#6c757d' }
    }
}

# ---------------------------------------------------------------------------
# HTML Report Generation
# ---------------------------------------------------------------------------

function New-HtmlReport {
    <#
    .SYNOPSIS
        Generates a styled HTML report from aggregated audit findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array]$NSGFindings,
        [Parameter(Mandatory)] [array]$StorageFindings,
        [Parameter(Mandatory)] [array]$IdentityFindings,
        [Parameter(Mandatory)] [int]$RiskScore,
        [Parameter(Mandatory)] [string]$RiskRating,
        [Parameter(Mandatory)] [datetime]$StartTime,
        [Parameter(Mandatory)] [datetime]$EndTime,
        [Parameter(Mandatory)] [hashtable]$ModuleStatus
    )

    $allFindings = @($NSGFindings) + @($StorageFindings) + @($IdentityFindings)
    $critical = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high     = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium   = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low      = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $duration = ($EndTime - $StartTime).ToString('hh\:mm\:ss')
    $riskColor = Get-RiskColor -Rating $RiskRating

    # Build findings table rows for each module
    function ConvertTo-FindingRows {
        param([array]$Findings, [string]$Module)
        $rows = ''
        $sorted = $Findings | Sort-Object @{Expression = {
            switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } }
        }}
        foreach ($f in $sorted) {
            $sevColor = switch ($f.Severity) {
                'Critical' { '#dc3545' }
                'High'     { '#fd7e14' }
                'Medium'   { '#ffc107' }
                'Low'      { '#28a745' }
            }
            $sevBg = switch ($f.Severity) {
                'Critical' { '#f8d7da' }
                'High'     { '#fff3cd' }
                'Medium'   { '#fff9e6' }
                'Low'      { '#d4edda' }
            }

            $objectCol = ''
            if ($f.PSObject.Properties.Name -contains 'NSGName') {
                $objectCol = "$($f.NSGName) / $($f.RuleName)"
            } elseif ($f.PSObject.Properties.Name -contains 'StorageAccount') {
                $objectCol = $f.StorageAccount
            } elseif ($f.PSObject.Properties.Name -contains 'AffectedObject') {
                $objectCol = $f.AffectedObject
            }

            $remediation = ''
            if ($f.PSObject.Properties.Name -contains 'Remediation') {
                $remediation = $f.Remediation
            }

            $rows += @"
            <tr>
                <td><span style="background-color:$sevBg;color:$sevColor;padding:2px 8px;border-radius:3px;font-weight:bold;font-size:0.85em;">$($f.Severity)</span></td>
                <td style="font-size:0.9em;">$([System.Web.HttpUtility]::HtmlEncode($objectCol))</td>
                <td style="font-size:0.9em;">$([System.Web.HttpUtility]::HtmlEncode($f.Finding))</td>
                <td style="font-size:0.85em;color:#555;">$([System.Web.HttpUtility]::HtmlEncode($remediation))</td>
            </tr>
"@
        }
        return $rows
    }

    $nsgRows      = if ($NSGFindings.Count -gt 0) { ConvertTo-FindingRows -Findings $NSGFindings -Module 'NSG' } else { '' }
    $storageRows  = if ($StorageFindings.Count -gt 0) { ConvertTo-FindingRows -Findings $StorageFindings -Module 'Storage' } else { '' }
    $identityRows = if ($IdentityFindings.Count -gt 0) { ConvertTo-FindingRows -Findings $IdentityFindings -Module 'Identity' } else { '' }

    $nsgStatus      = if ($ModuleStatus.NSG)      { $ModuleStatus.NSG }      else { 'Skipped' }
    $storageStatus  = if ($ModuleStatus.Storage)   { $ModuleStatus.Storage }  else { 'Skipped' }
    $identityStatus = if ($ModuleStatus.Identity)  { $ModuleStatus.Identity } else { 'Skipped' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Security Posture Report - $($StartTime.ToString('yyyy-MM-dd'))</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; color: #333; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%); color: white; padding: 30px 40px; }
        .header h1 { font-size: 1.8em; font-weight: 300; }
        .header .subtitle { opacity: 0.85; margin-top: 5px; font-size: 0.95em; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .summary-grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr 1fr; gap: 15px; margin: 20px 0; }
        .summary-card { background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card .number { font-size: 2em; font-weight: 700; }
        .summary-card .label { font-size: 0.85em; color: #666; margin-top: 5px; }
        .risk-banner { background: white; border-radius: 8px; padding: 25px 30px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 25px; }
        .risk-score-circle { width: 90px; height: 90px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 1.8em; font-weight: 700; flex-shrink: 0; }
        .risk-details h2 { font-size: 1.3em; margin-bottom: 5px; }
        .risk-details p { color: #666; font-size: 0.9em; }
        .section { background: white; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .section-header { padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .section-header h3 { font-size: 1.1em; color: #1a237e; }
        .section-header .badge { padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
        .section-body { padding: 0; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f1f3f5; padding: 10px 15px; text-align: left; font-size: 0.85em; color: #555; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #dee2e6; }
        td { padding: 10px 15px; border-bottom: 1px solid #f1f3f5; vertical-align: top; }
        tr:hover { background: #f8f9ff; }
        .module-status { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: 600; }
        .status-completed { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-skipped { background: #e2e3e5; color: #383d41; }
        .no-findings { padding: 20px; text-align: center; color: #28a745; font-style: italic; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 0.85em; margin-top: 30px; }
        .meta-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin: 15px 0; }
        .meta-item { font-size: 0.9em; }
        .meta-item .meta-label { color: #888; font-size: 0.85em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure Security Posture Assessment</h1>
        <div class="subtitle">First Carolina Bank &mdash; Cloud Security Operations &mdash; Generated $(Get-Date -Format 'MMMM dd, yyyy h:mm tt')</div>
    </div>

    <div class="container">
        <!-- Risk Score Banner -->
        <div class="risk-banner">
            <div class="risk-score-circle" style="background-color: $riskColor;">$RiskScore</div>
            <div class="risk-details">
                <h2>Overall Risk Rating: $RiskRating</h2>
                <p>Based on $($allFindings.Count) finding(s) across $( @(@('NSG','Storage','Identity') | Where-Object { $ModuleStatus[$_] -eq 'Completed' }).Count ) audit module(s). A score of 0 indicates no findings; 100 indicates critical exposure.</p>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number" style="color: #dc3545;">$critical</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #fd7e14;">$high</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #ffc107;">$medium</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #28a745;">$low</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #1a237e;">$($allFindings.Count)</div>
                <div class="label">Total Findings</div>
            </div>
        </div>

        <!-- Audit Metadata -->
        <div class="section">
            <div class="section-header">
                <h3>Audit Execution Details</h3>
            </div>
            <div style="padding: 15px 20px;">
                <div class="meta-grid">
                    <div class="meta-item">
                        <div class="meta-label">Start Time</div>
                        <div>$($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Duration</div>
                        <div>$duration</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Executed By</div>
                        <div>Jacob Phillips (Automated Audit)</div>
                    </div>
                </div>
                <div class="meta-grid" style="margin-top: 10px;">
                    <div class="meta-item">
                        <div class="meta-label">NSG Audit</div>
                        <div><span class="module-status status-$(($nsgStatus).ToLower())">$nsgStatus</span></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Storage Audit</div>
                        <div><span class="module-status status-$(($storageStatus).ToLower())">$storageStatus</span></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Identity Audit</div>
                        <div><span class="module-status status-$(($identityStatus).ToLower())">$identityStatus</span></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- NSG Findings -->
        <div class="section">
            <div class="section-header">
                <h3>Network Security Group Findings</h3>
                <span class="badge" style="background: $(if ($NSGFindings.Count -gt 0) { '#f8d7da' } else { '#d4edda' }); color: $(if ($NSGFindings.Count -gt 0) { '#721c24' } else { '#155724' });">$($NSGFindings.Count) finding(s)</span>
            </div>
            <div class="section-body">
                $(if ($nsgStatus -eq 'Skipped') {
                    '<div class="no-findings">Module was skipped.</div>'
                } elseif ($NSGFindings.Count -eq 0) {
                    '<div class="no-findings">No findings. All NSG rules passed security checks.</div>'
                } else {
                    "<table><thead><tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$nsgRows</tbody></table>"
                })
            </div>
        </div>

        <!-- Storage Findings -->
        <div class="section">
            <div class="section-header">
                <h3>Storage Account Findings</h3>
                <span class="badge" style="background: $(if ($StorageFindings.Count -gt 0) { '#f8d7da' } else { '#d4edda' }); color: $(if ($StorageFindings.Count -gt 0) { '#721c24' } else { '#155724' });">$($StorageFindings.Count) finding(s)</span>
            </div>
            <div class="section-body">
                $(if ($storageStatus -eq 'Skipped') {
                    '<div class="no-findings">Module was skipped.</div>'
                } elseif ($StorageFindings.Count -eq 0) {
                    '<div class="no-findings">No findings. All storage accounts passed security checks.</div>'
                } else {
                    "<table><thead><tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$storageRows</tbody></table>"
                })
            </div>
        </div>

        <!-- Identity Findings -->
        <div class="section">
            <div class="section-header">
                <h3>Identity (Azure AD / Entra ID) Findings</h3>
                <span class="badge" style="background: $(if ($IdentityFindings.Count -gt 0) { '#f8d7da' } else { '#d4edda' }); color: $(if ($IdentityFindings.Count -gt 0) { '#721c24' } else { '#155724' });">$($IdentityFindings.Count) finding(s)</span>
            </div>
            <div class="section-body">
                $(if ($identityStatus -eq 'Skipped') {
                    '<div class="no-findings">Module was skipped.</div>'
                } elseif ($IdentityFindings.Count -eq 0) {
                    '<div class="no-findings">No findings. Identity posture passed all security checks.</div>'
                } else {
                    "<table><thead><tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>$identityRows</tbody></table>"
                })
            </div>
        </div>
    </div>

    <div class="footer">
        Azure Security Posture Assessment &mdash; First Carolina Bank &mdash; Cloud Security Engineering<br>
        Generated by Invoke-AzSecurityPosture.ps1 v2.0.0 &mdash; Jacob Phillips
    </div>
</body>
</html>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

try {
    # Initialize log
    $null = New-Item -Path $logPath -ItemType File -Force
    Write-AuditLog 'Azure Security Posture Assessment starting.'

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║         AZURE SECURITY POSTURE ASSESSMENT                   ║' -ForegroundColor Cyan
    Write-Host '║         First Carolina Bank — Cloud Security                ║' -ForegroundColor Cyan
    Write-Host '║         Author: Jacob Phillips                              ║' -ForegroundColor DarkGray
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    # Build subscription parameters to pass to child scripts
    $subParams = @{}
    if ($AllSubscriptions) {
        $subParams['AllSubscriptions'] = $true
    }
    elseif ($SubscriptionId) {
        $subParams['SubscriptionId'] = $SubscriptionId
    }

    $moduleStatus    = @{}
    $nsgFindings     = @()
    $storageFindings = @()
    $identityFindings = @()

    # =====================================================================
    # Module 1: NSG Audit
    # =====================================================================
    if (-not $SkipNSGAudit) {
        Write-AuditLog 'Starting NSG Security Audit module...'
        $nsgScript = Join-Path $scriptRoot 'Invoke-AzNSGAudit.ps1'

        if (Test-Path $nsgScript) {
            try {
                $nsgCsvPath = Join-Path $OutputDirectory "$reportName-NSG.csv"
                $nsgParams = $subParams.Clone()
                $nsgParams['ExportPath'] = $nsgCsvPath

                $nsgFindings = & $nsgScript @nsgParams
                if (-not $nsgFindings) { $nsgFindings = @() }
                $moduleStatus['NSG'] = 'Completed'
                Write-AuditLog "NSG Audit completed: $($nsgFindings.Count) finding(s)."
            }
            catch {
                $moduleStatus['NSG'] = 'Failed'
                Write-AuditLog "NSG Audit failed: $_" -Level 'ERROR'
            }
        }
        else {
            $moduleStatus['NSG'] = 'Failed'
            Write-AuditLog "NSG Audit script not found at: $nsgScript" -Level 'ERROR'
        }
    }
    else {
        $moduleStatus['NSG'] = 'Skipped'
        Write-AuditLog 'NSG Audit module skipped by user request.'
    }

    # =====================================================================
    # Module 2: Storage Audit
    # =====================================================================
    if (-not $SkipStorageAudit) {
        Write-AuditLog 'Starting Storage Account Security Audit module...'
        $storageScript = Join-Path $scriptRoot 'Invoke-AzStorageAudit.ps1'

        if (Test-Path $storageScript) {
            try {
                $storageCsvPath = Join-Path $OutputDirectory "$reportName-Storage.csv"
                $storageParams = $subParams.Clone()
                $storageParams['ExportPath'] = $storageCsvPath

                $storageFindings = & $storageScript @storageParams
                if (-not $storageFindings) { $storageFindings = @() }
                $moduleStatus['Storage'] = 'Completed'
                Write-AuditLog "Storage Audit completed: $($storageFindings.Count) finding(s)."
            }
            catch {
                $moduleStatus['Storage'] = 'Failed'
                Write-AuditLog "Storage Audit failed: $_" -Level 'ERROR'
            }
        }
        else {
            $moduleStatus['Storage'] = 'Failed'
            Write-AuditLog "Storage Audit script not found at: $storageScript" -Level 'ERROR'
        }
    }
    else {
        $moduleStatus['Storage'] = 'Skipped'
        Write-AuditLog 'Storage Audit module skipped by user request.'
    }

    # =====================================================================
    # Module 3: Identity Audit
    # =====================================================================
    if (-not $SkipIdentityAudit) {
        Write-AuditLog 'Starting Identity Security Audit module...'
        $identityScript = Join-Path $scriptRoot 'Invoke-AzIdentityAudit.ps1'

        if (Test-Path $identityScript) {
            try {
                $identityCsvPath = Join-Path $OutputDirectory "$reportName-Identity.csv"
                $identityParams = @{
                    ExportPath = $identityCsvPath
                }

                $identityFindings = & $identityScript @identityParams
                if (-not $identityFindings) { $identityFindings = @() }
                $moduleStatus['Identity'] = 'Completed'
                Write-AuditLog "Identity Audit completed: $($identityFindings.Count) finding(s)."
            }
            catch {
                $moduleStatus['Identity'] = 'Failed'
                Write-AuditLog "Identity Audit failed: $_" -Level 'ERROR'
            }
        }
        else {
            $moduleStatus['Identity'] = 'Failed'
            Write-AuditLog "Identity Audit script not found at: $identityScript" -Level 'ERROR'
        }
    }
    else {
        $moduleStatus['Identity'] = 'Skipped'
        Write-AuditLog 'Identity Audit module skipped by user request.'
    }

    # =====================================================================
    # Aggregate and Report
    # =====================================================================
    $auditEnd    = Get-Date
    $allFindings = @($nsgFindings) + @($storageFindings) + @($identityFindings)
    $riskScore   = Get-OverallRiskScore -Findings $allFindings
    $riskRating  = Get-RiskRating -Score $riskScore

    Write-AuditLog "Generating unified HTML report..."

    # Load System.Web for HTML encoding in the report
    try {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose 'System.Web assembly already loaded or not available.'
    }

    $htmlContent = New-HtmlReport `
        -NSGFindings      $nsgFindings `
        -StorageFindings  $storageFindings `
        -IdentityFindings $identityFindings `
        -RiskScore        $riskScore `
        -RiskRating       $riskRating `
        -StartTime        $auditStart `
        -EndTime          $auditEnd `
        -ModuleStatus     $moduleStatus

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-AuditLog "HTML report saved to: $htmlPath"

    # ---- Console Summary ----
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║           POSTURE ASSESSMENT — EXECUTIVE SUMMARY            ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Overall Risk Score  : $($riskScore.ToString().PadLeft(3)) / 100                              ║" -ForegroundColor $(if ($riskScore -ge 60) { 'Red' } elseif ($riskScore -ge 35) { 'Yellow' } else { 'Green' })
    Write-Host "║  Risk Rating         : $($riskRating.PadRight(10))                              ║" -ForegroundColor $(if ($riskRating -in @('Critical','High')) { 'Red' } elseif ($riskRating -eq 'Medium') { 'Yellow' } else { 'Green' })
    Write-Host '║──────────────────────────────────────────────────────────────║' -ForegroundColor DarkGray

    $criticalTotal = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highTotal     = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumTotal   = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowTotal      = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    Write-Host "║  Critical            : $($criticalTotal.ToString().PadLeft(4))                                    ║" -ForegroundColor Red
    Write-Host "║  High                : $($highTotal.ToString().PadLeft(4))                                    ║" -ForegroundColor Yellow
    Write-Host "║  Medium              : $($mediumTotal.ToString().PadLeft(4))                                    ║" -ForegroundColor DarkYellow
    Write-Host "║  Low                 : $($lowTotal.ToString().PadLeft(4))                                    ║" -ForegroundColor Gray
    Write-Host "║  Total Findings      : $($allFindings.Count.ToString().PadLeft(4))                                    ║" -ForegroundColor White
    Write-Host '║──────────────────────────────────────────────────────────────║' -ForegroundColor DarkGray
    Write-Host "║  NSG Module          : $($nsgFindings.Count.ToString().PadLeft(4)) findings ($($moduleStatus['NSG']))              ║" -ForegroundColor White
    Write-Host "║  Storage Module      : $($storageFindings.Count.ToString().PadLeft(4)) findings ($($moduleStatus['Storage']))              ║" -ForegroundColor White
    Write-Host "║  Identity Module     : $($identityFindings.Count.ToString().PadLeft(4)) findings ($($moduleStatus['Identity']))              ║" -ForegroundColor White
    Write-Host '║──────────────────────────────────────────────────────────────║' -ForegroundColor DarkGray
    Write-Host "║  Report              : $htmlPath" -ForegroundColor White
    Write-Host "║  Log                 : $logPath" -ForegroundColor White
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    # =====================================================================
    # Email Delivery
    # =====================================================================
    if ($SendEmail) {
        Write-AuditLog "Sending report via email to: $($EmailTo -join ', ')"

        try {
            $mailParams = @{
                From       = $EmailFrom
                To         = $EmailTo
                Subject    = "Azure Security Posture Report — Risk: $riskRating ($riskScore/100) — $(Get-Date -Format 'yyyy-MM-dd')"
                Body       = $htmlContent
                BodyAsHtml = $true
                SmtpServer = $SmtpServer
                Port       = $SmtpPort
                UseSsl     = $UseSsl
            }

            if ($EmailCredential) {
                $mailParams['Credential'] = $EmailCredential
            }

            # Attach the CSV exports if they exist
            $attachments = @()
            foreach ($csvFile in @($nsgCsvPath, $storageCsvPath, $identityCsvPath)) {
                if ($csvFile -and (Test-Path $csvFile)) {
                    $attachments += $csvFile
                }
            }
            if ($attachments.Count -gt 0) {
                $mailParams['Attachments'] = $attachments
            }

            Send-MailMessage @mailParams
            Write-AuditLog 'Email sent successfully.'
        }
        catch {
            Write-AuditLog "Failed to send email: $_" -Level 'ERROR'
        }
    }

    Write-AuditLog 'Azure Security Posture Assessment completed.'

    # Return summary object for pipeline consumption
    return [PSCustomObject]@{
        RiskScore        = $riskScore
        RiskRating       = $riskRating
        TotalFindings    = $allFindings.Count
        CriticalFindings = $criticalTotal
        HighFindings     = $highTotal
        MediumFindings   = $mediumTotal
        LowFindings      = $lowTotal
        ReportPath       = $htmlPath
        LogPath          = $logPath
        ModuleStatus     = $moduleStatus
        Duration         = ($auditEnd - $auditStart).ToString('hh\:mm\:ss')
    }
}
catch {
    Write-AuditLog "Security Posture Assessment encountered a fatal error: $_" -Level 'ERROR'
    Write-Debug $_.ScriptStackTrace
    throw
}
