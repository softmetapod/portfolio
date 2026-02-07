# Azure Security Audit Toolkit

**Author:** Jacob Phillips
**Role:** Cloud Security Engineer, First Carolina Bank
**Platform:** Microsoft Azure | Azure AD (Entra ID) | PowerShell 7+

---

## Overview

The Azure Security Audit Toolkit is a collection of PowerShell scripts designed to perform comprehensive security assessments across Microsoft Azure environments. Built for enterprise use at First Carolina Bank, these scripts automate the identification of misconfigurations, policy violations, and security risks across networking, storage, identity, and overall cloud posture.

Each script operates independently for targeted audits or can be orchestrated together through the master posture assessment script to produce a unified security report suitable for executive review, compliance documentation, and remediation tracking.

---

## Scripts

### 1. Invoke-AzNSGAudit.ps1 — Network Security Group Auditor

**Purpose:** Evaluates all Network Security Groups across one or more Azure subscriptions for overly permissive rules, dangerous inbound access, unused NSGs, and priority conflicts.

**Key Checks:**
- Rules allowing Any/Any traffic patterns
- Inbound rules with `0.0.0.0/0` (internet) as source
- Wide port ranges that expose unnecessary attack surface
- Inbound RDP (3389) and SSH (22) open to the internet
- NSGs not associated with any subnet or network interface
- Rules with overlapping or conflicting priorities
- Allow-all inbound rules

**Usage:**
```powershell
# Audit NSGs in the current subscription
.\Invoke-AzNSGAudit.ps1

# Audit across all accessible subscriptions with CSV export
.\Invoke-AzNSGAudit.ps1 -AllSubscriptions -ExportPath "C:\Reports\NSG-Audit.csv"

# Audit a specific subscription with verbose output
.\Invoke-AzNSGAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -Verbose
```

**Output:** Console table with risk-scored findings (Critical/High/Medium/Low) and optional CSV export.

---

### 2. Invoke-AzStorageAudit.ps1 — Storage Account Security Auditor

**Purpose:** Assesses all Azure Storage Accounts for encryption, access control, network exposure, and transport security compliance.

**Key Checks:**
- Public blob access enabled on the storage account
- HTTPS-only transfer enforcement
- Minimum TLS version below 1.2
- Encryption configuration (Microsoft-managed vs. customer-managed keys)
- Missing private endpoint connections
- Shared key access still enabled (should use Azure AD auth)
- Individual blob containers with anonymous public access

**Usage:**
```powershell
# Audit storage accounts in current subscription
.\Invoke-AzStorageAudit.ps1

# Audit all subscriptions and export findings
.\Invoke-AzStorageAudit.ps1 -AllSubscriptions -ExportPath "C:\Reports\Storage-Audit.csv"

# Target a specific resource group
.\Invoke-AzStorageAudit.ps1 -ResourceGroupName "rg-production-data"
```

**Output:** Console findings with severity ratings and optional CSV export.

---

### 3. Invoke-AzIdentityAudit.ps1 — Azure AD / Entra ID Identity Security Auditor

**Purpose:** Evaluates identity and access management posture across Azure Active Directory (Entra ID), focusing on MFA coverage, stale accounts, privileged access, and application credential hygiene.

**Key Checks:**
- Users without MFA registration
- Stale accounts with no sign-in activity for 90+ days
- Permanent privileged role assignments (should use PIM eligible assignments)
- Guest accounts with elevated directory or subscription roles
- Conditional Access policy coverage gaps
- Service principals with excessive Microsoft Graph or Azure permissions
- Applications with expired or soon-to-expire client secrets and certificates

**Usage:**
```powershell
# Run full identity audit
.\Invoke-AzIdentityAudit.ps1

# Customize stale account threshold
.\Invoke-AzIdentityAudit.ps1 -StaleThresholdDays 60

# Export results to CSV
.\Invoke-AzIdentityAudit.ps1 -ExportPath "C:\Reports\Identity-Audit.csv"

# Check credential expiry within 60 days
.\Invoke-AzIdentityAudit.ps1 -CredentialExpiryDays 60
```

**Output:** Console risk summary dashboard with categorized findings and optional CSV export.

---

### 4. Invoke-AzSecurityPosture.ps1 — Master Orchestrator & Unified Report

**Purpose:** Runs all three audit scripts, aggregates findings, calculates an overall risk score, and generates a unified HTML report with executive summary. Supports automated scheduling and email delivery.

**Usage:**
```powershell
# Run full posture assessment with HTML report
.\Invoke-AzSecurityPosture.ps1 -OutputDirectory "C:\Reports"

# Run across all subscriptions with email notification
.\Invoke-AzSecurityPosture.ps1 -AllSubscriptions `
    -OutputDirectory "C:\Reports" `
    -SendEmail `
    -SmtpServer "smtp.firstcarolina.bank" `
    -EmailFrom "security-automation@firstcarolina.bank" `
    -EmailTo "secops-team@firstcarolina.bank"

# Skip specific audit modules
.\Invoke-AzSecurityPosture.ps1 -SkipIdentityAudit -OutputDirectory "C:\Reports"
```

**Output:** Unified HTML report with executive summary, per-module findings, and overall risk score. Optional email delivery.

---

## Prerequisites

### Required PowerShell Modules

```powershell
# Az module (core Azure management)
Install-Module -Name Az -Scope CurrentUser -Force

# Microsoft Graph module (identity audit)
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

### Required Permissions

| Script | Minimum Permissions Required |
|---|---|
| Invoke-AzNSGAudit | `Reader` role on target subscriptions |
| Invoke-AzStorageAudit | `Reader` role on target subscriptions; `Storage Blob Data Reader` for container-level checks |
| Invoke-AzIdentityAudit | Microsoft Graph: `User.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.All`, `Application.Read.All`, `AuditLog.Read.All` |
| Invoke-AzSecurityPosture | All of the above combined |

### Authentication

```powershell
# Interactive login for manual execution
Connect-AzAccount

# Service principal for automation
$credential = New-Object System.Management.Automation.PSCredential($appId, $securePassword)
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantId

# Microsoft Graph connection (identity audit)
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","RoleManagement.Read.Directory"
```

---

## Sample Output

### Console Output — NSG Audit
The NSG audit displays a color-coded table in the console showing each finding with the NSG name, rule name, risk severity, resource group, and a description of the misconfiguration. Critical findings (such as RDP open to internet) are highlighted in red.

### Console Output — Identity Audit Risk Dashboard
The identity audit prints a summary dashboard showing total users audited, MFA coverage percentage, count of stale accounts, permanent privileged assignments, risky guest accounts, and application credential health — all presented as a formatted box in the terminal.

### HTML Report — Unified Posture Assessment
The orchestrator script generates a styled HTML report containing:
- Executive summary banner with overall risk score (0-100)
- Donut-style breakdown of findings by severity
- Collapsible sections for each audit module
- Individual finding detail tables with remediation guidance
- Timestamp and environment metadata in the footer

---

## Scheduling Automated Audits

### Option A: Windows Task Scheduler

```powershell
$action = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument '-NoProfile -File "C:\Scripts\Invoke-AzSecurityPosture.ps1" -AllSubscriptions -OutputDirectory "C:\Reports" -SendEmail -SmtpServer "smtp.firstcarolina.bank" -EmailFrom "security-automation@firstcarolina.bank" -EmailTo "secops-team@firstcarolina.bank"'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am

Register-ScheduledTask `
    -TaskName "Azure Security Posture Audit" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest `
    -User "SYSTEM"
```

### Option B: Azure Automation Runbook

1. Create an Azure Automation Account with a System-Assigned Managed Identity.
2. Grant the managed identity `Reader` on all target subscriptions and the required Microsoft Graph API permissions.
3. Import the `Az` and `Microsoft.Graph` modules into the Automation Account.
4. Upload `Invoke-AzSecurityPosture.ps1` as a Runbook (PowerShell 7.2 runtime).
5. Create a Schedule (e.g., weekly) and link it to the Runbook.
6. Configure Runbook parameters (output to Azure Blob Storage, email via SendGrid or SMTP relay).

### Option C: Azure DevOps Pipeline

```yaml
schedules:
  - cron: "0 6 * * 1"
    displayName: Weekly Azure Security Audit
    branches:
      include:
        - main

steps:
  - task: AzurePowerShell@5
    inputs:
      azureSubscription: 'Security-Audit-SPN'
      ScriptPath: 'scripts/Invoke-AzSecurityPosture.ps1'
      ScriptArguments: '-AllSubscriptions -OutputDirectory $(Build.ArtifactStagingDirectory)'
      azurePowerShellVersion: LatestVersion
      pwsh: true
```

---

## Repository Structure

```
PowerShell Azure Security Audit/
    Azure Security Audit.md          # This documentation
    Invoke-AzNSGAudit.ps1            # Network Security Group auditor
    Invoke-AzStorageAudit.ps1        # Storage Account auditor
    Invoke-AzIdentityAudit.ps1       # Azure AD / Entra ID identity auditor
    Invoke-AzSecurityPosture.ps1     # Master orchestrator and HTML report generator
```

---

## License

Internal tooling developed by Jacob Phillips for First Carolina Bank cloud security operations. Shared in this portfolio for demonstration purposes.
