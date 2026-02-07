# KQL Detection Rules Library

**Author:** Jacob Phillips | Cloud Security Engineer | Microsoft SC-200 Certified
**Platform:** Microsoft Sentinel / Microsoft Defender XDR
**Last Updated:** 2026-02-07

---

## Overview

This repository contains a curated library of KQL (Kusto Query Language) detection rules designed for deployment in Microsoft Sentinel and Microsoft Defender XDR environments. Each rule is mapped to the MITRE ATT&CK framework, includes severity ratings, false positive guidance, and recommended response actions.

These rules were developed and refined through hands-on experience operating Microsoft Defender and Elastic SIEM in enterprise environments. They are intended to serve as production-ready analytics rules or as baselines for further tuning to fit specific organizational telemetry.

---

## Table of Contents

- [Usage: Importing Rules into Sentinel](#usage-importing-rules-into-sentinel)
- [Initial Access](#initial-access)
  - [1. Brute Force Authentication](#1-brute-force-authentication)
  - [2. Impossible Travel Detection](#2-impossible-travel-detection)
- [Execution](#execution)
  - [3. Suspicious PowerShell Execution](#3-suspicious-powershell-execution)
  - [4. Scheduled Task Creation via Command Line](#4-scheduled-task-creation-via-command-line)
- [Persistence](#persistence)
  - [5. New Service Installation](#5-new-service-installation)
  - [6. Registry Run Key Modification](#6-registry-run-key-modification)
- [Privilege Escalation](#privilege-escalation)
  - [7. Unusual Privilege Escalation](#7-unusual-privilege-escalation)
- [Defense Evasion](#defense-evasion)
  - [8. Security Tool Tampering](#8-security-tool-tampering)
- [Credential Access](#credential-access)
  - [9. Credential Dumping Indicators](#9-credential-dumping-indicators)
- [Lateral Movement](#lateral-movement)
  - [10. Suspicious RDP Activity](#10-suspicious-rdp-activity)
- [Collection & Exfiltration](#collection--exfiltration)
  - [11. Large Data Transfer to External IP](#11-large-data-transfer-to-external-ip)
  - [12. Sensitive File Access Anomaly](#12-sensitive-file-access-anomaly)

---

## Usage: Importing Rules into Sentinel

### Method 1: Manual Creation via Analytics Rules

1. Navigate to **Microsoft Sentinel** > **Analytics** > **Create** > **Scheduled query rule**.
2. Provide the rule name, description, severity, and MITRE ATT&CK mapping as listed for each rule below.
3. Paste the KQL query into the **Rule query** field.
4. Set the **Query scheduling** (run frequency and lookup period) as recommended per rule.
5. Configure **Alert threshold** to trigger when the number of results is greater than 0.
6. Under **Incident settings**, enable incident creation and alert grouping as appropriate.
7. Assign the relevant **Automated response** playbook if available.

### Method 2: ARM Template Deployment

Each rule can be exported as an ARM template and deployed via Azure Resource Manager for infrastructure-as-code workflows. Use the Sentinel GitHub repository structure:

```
/Detections
  /InitialAccess
    BruteForceAuthentication.json
    ImpossibleTravel.json
  /Execution
    SuspiciousPowerShell.json
    ScheduledTaskCreation.json
  ...
```

### Method 3: Microsoft Sentinel Content Hub

Package rules as a Solution for distribution via the Sentinel Content Hub, which allows versioned deployment across multiple workspaces.

### Query Scheduling Guidance

| Rule Type | Recommended Frequency | Lookup Period |
|---|---|---|
| Authentication-based rules | Every 5 minutes | 15 minutes |
| Process/endpoint rules | Every 10 minutes | 30 minutes |
| Network/exfiltration rules | Every 15 minutes | 1 hour |
| Privilege change rules | Every 30 minutes | 1 hour |

---

## Initial Access

### 1. Brute Force Authentication

| Field | Value |
|---|---|
| **Rule Name** | Brute Force Sign-In Followed by Successful Authentication |
| **MITRE ATT&CK** | Initial Access - Brute Force (T1110) |
| **Severity** | High |
| **Data Sources** | SigninLogs, AADNonInteractiveUserSignInLogs |
| **Frequency** | Every 5 minutes |
| **Lookup Period** | 15 minutes |

**Description:**
Detects a pattern where a single IP address generates multiple failed authentication attempts against one or more accounts, followed by a successful sign-in. This pattern is a strong indicator of password spraying or brute force credential attacks targeting Azure AD / Entra ID.

**KQL Query:**

```kql
let failure_threshold = 10;
let time_window = 15m;
let FailedSignins = SigninLogs
    | where TimeGenerated > ago(time_window)
    | where ResultType != "0"
    | where ResultType in ("50126", "50053", "50055", "50056", "53003")
    | summarize
        FailedAttempts = count(),
        TargetAccounts = make_set(UserPrincipalName, 100),
        TargetAccountCount = dcount(UserPrincipalName),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by IPAddress, Location, UserAgent
    | where FailedAttempts >= failure_threshold;
let SuccessfulSignins = SigninLogs
    | where TimeGenerated > ago(time_window)
    | where ResultType == "0"
    | project
        SuccessTime = TimeGenerated,
        IPAddress,
        SuccessAccount = UserPrincipalName,
        AppDisplayName,
        DeviceDetail,
        Location;
FailedSignins
| join kind=inner (SuccessfulSignins) on IPAddress
| where SuccessTime > LastFailure
| extend TimeBetweenLastFailureAndSuccess = datetime_diff('second', SuccessTime, LastFailure)
| project
    SuccessTime,
    IPAddress,
    Location,
    SuccessAccount,
    FailedAttempts,
    TargetAccountCount,
    TargetAccounts,
    FirstFailure,
    LastFailure,
    TimeBetweenLastFailureAndSuccess,
    AppDisplayName,
    UserAgent
| sort by FailedAttempts desc
```

**False Positive Guidance:**
- Automated service accounts with expired or rotating credentials can generate repeated failures. Maintain an exclusion list for known service account IPs.
- Users who have recently changed their password may trigger a small number of failures from cached credentials on multiple devices. The threshold of 10 helps filter these out.
- Shared NAT IPs (corporate egress) may aggregate failures from multiple distinct users. Correlate with `TargetAccountCount` to distinguish spray attacks from coincidental failures.

**Recommended Response Actions:**
1. Confirm whether the successful sign-in account was among the targeted accounts during the brute force window.
2. Check the IP reputation via threat intelligence feeds.
3. If the sign-in is confirmed malicious, immediately revoke the user's active sessions and reset credentials.
4. Apply a Conditional Access policy to block the source IP.
5. Review the account's activity post-authentication for signs of mailbox rule creation, data access, or lateral movement.

---

### 2. Impossible Travel Detection

| Field | Value |
|---|---|
| **Rule Name** | Impossible Travel - Geographically Implausible Sign-In Pair |
| **MITRE ATT&CK** | Initial Access - Valid Accounts (T1078) |
| **Severity** | Medium |
| **Data Sources** | SigninLogs |
| **Frequency** | Every 10 minutes |
| **Lookup Period** | 24 hours |

**Description:**
Identifies pairs of successful sign-ins from the same user account originating from two geographically distant locations within a timeframe that makes physical travel between them implausible. This is a common indicator of credential compromise where an attacker is authenticating from a different region while the legitimate user continues normal activity.

**KQL Query:**

```kql
let max_travel_speed_km_per_hour = 900;
let min_distance_km = 500;
let time_window = 24h;
SigninLogs
| where TimeGenerated > ago(time_window)
| where ResultType == "0"
| where isnotempty(LocationDetails.geoCoordinates.latitude)
| extend
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state),
    Country = tostring(LocationDetails.countryOrRegion)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Latitude,
    Longitude,
    City,
    State,
    Country,
    AppDisplayName,
    DeviceDetail,
    ConditionalAccessStatus
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevTime = prev(TimeGenerated, 1),
    PrevLat = prev(Latitude, 1),
    PrevLon = prev(Longitude, 1),
    PrevIP = prev(IPAddress, 1),
    PrevCity = prev(City, 1),
    PrevCountry = prev(Country, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where IPAddress != PrevIP
| extend
    TimeDiffHours = datetime_diff('second', TimeGenerated, PrevTime) / 3600.0,
    DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000.0
| where DistanceKm >= min_distance_km
| where TimeDiffHours > 0
| extend RequiredSpeedKmH = round(DistanceKm / TimeDiffHours, 0)
| where RequiredSpeedKmH > max_travel_speed_km_per_hour
| project
    UserPrincipalName,
    FirstSignIn = PrevTime,
    FirstLocation = strcat(PrevCity, ", ", PrevCountry),
    FirstIP = PrevIP,
    SecondSignIn = TimeGenerated,
    SecondLocation = strcat(City, ", ", Country),
    SecondIP = IPAddress,
    DistanceKm = round(DistanceKm, 0),
    TimeDiffHours = round(TimeDiffHours, 2),
    RequiredSpeedKmH,
    AppDisplayName
| sort by RequiredSpeedKmH desc
```

**False Positive Guidance:**
- VPN usage is the most common source of false positives. Users connecting through a VPN will appear to sign in from the VPN egress location. Maintain a list of known corporate VPN egress IPs and exclude them.
- Cloud-based proxy services (such as Zscaler or Netskope) route traffic through regional nodes. Exclude known proxy IP ranges.
- Consider tuning `min_distance_km` upward if your organization has offices in relatively nearby cities that still trigger alerts.

**Recommended Response Actions:**
1. Contact the user to verify whether the sign-in from the unexpected location was legitimate.
2. Check whether either IP is a known VPN or proxy endpoint.
3. If unrecognized, force a password reset and revoke all active sessions via `Revoke-AzureADUserAllRefreshToken`.
4. Review the account for suspicious post-authentication activity such as inbox rule changes, file downloads, or new MFA device registration.
5. Enrich both IPs against threat intelligence to identify known malicious infrastructure.

---

## Execution

### 3. Suspicious PowerShell Execution

| Field | Value |
|---|---|
| **Rule Name** | Suspicious PowerShell - Encoded Commands, Download Cradles, and AMSI Bypass |
| **MITRE ATT&CK** | Execution - Command and Scripting Interpreter: PowerShell (T1059.001) |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents, SecurityEvent (Event ID 4688) |
| **Frequency** | Every 10 minutes |
| **Lookup Period** | 30 minutes |

**Description:**
Detects PowerShell execution patterns commonly associated with offensive tooling. This includes base64-encoded command arguments (often used to obfuscate payloads), download cradle patterns (Net.WebClient, Invoke-WebRequest, Start-BitsTransfer), and AMSI bypass techniques that attempt to disable the Antimalware Scan Interface before executing malicious scripts.

**KQL Query:**

```kql
let time_window = 30m;
// Pattern 1: Encoded commands
let EncodedCommands = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (
        "-EncodedCommand", "-enc ", "-ec ", "-e ",
        "FromBase64String", "[Convert]::"
    )
    | where ProcessCommandLine !has "Microsoft Monitoring Agent"
    | extend DetectionPattern = "EncodedCommand";
// Pattern 2: Download cradles
let DownloadCradles = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (
        "Net.WebClient", "DownloadString", "DownloadFile",
        "Invoke-WebRequest", "IWR ", "Invoke-RestMethod",
        "Start-BitsTransfer", "wget ", "curl ",
        "Net.Sockets.TCPClient", "IO.StreamReader",
        "IO.MemoryStream", "IO.Compression"
    )
    | where ProcessCommandLine has_any ("http://", "https://", "ftp://")
    | extend DetectionPattern = "DownloadCradle";
// Pattern 3: AMSI bypass attempts
let AMSIBypass = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (
        "AmsiInitFailed", "amsiContext", "AmsiUtils",
        "amsi.dll", "SetField", "NonPublic,Static",
        "Reflection.Assembly", "AmsiScanBuffer"
    )
    | extend DetectionPattern = "AMSIBypass";
// Pattern 4: Suspicious execution flags combined with obfuscation
let ObfuscatedExecution = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (
        "-nop", "-noni", "-windowstyle hidden", "-w hidden",
        "-ep bypass", "-executionpolicy bypass"
    )
    | where ProcessCommandLine has_any (
        "IEX", "Invoke-Expression", ".Invoke(",
        "ICM", "Invoke-Command"
    )
    | extend DetectionPattern = "ObfuscatedExecution";
union EncodedCommands, DownloadCradles, AMSIBypass, ObfuscatedExecution
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    DetectionPattern,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FolderPath
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Some legitimate management tools (SCCM, Intune scripts, monitoring agents) use `-EncodedCommand` for script deployment. Whitelist known management tool hashes and parent processes.
- IT automation frameworks (Ansible WinRM, Terraform provisioners) may trigger download cradle patterns. Exclude known automation service accounts.
- Decode any base64 content to inspect the actual payload before escalating. Use: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<string>'))`.

**Recommended Response Actions:**
1. Decode any encoded command payloads and analyze the plaintext content.
2. If a download cradle is detected, identify the remote URL and check it against threat intelligence.
3. Isolate the endpoint if AMSI bypass techniques are confirmed.
4. Collect the full PowerShell script block logs (Event ID 4104) from the host for deeper analysis.
5. Investigate the parent process chain to determine how PowerShell was invoked.
6. Check for persistence mechanisms that may have been established during execution.

---

### 4. Scheduled Task Creation via Command Line

| Field | Value |
|---|---|
| **Rule Name** | Scheduled Task Created via schtasks.exe |
| **MITRE ATT&CK** | Execution - Scheduled Task/Job: Scheduled Task (T1053.005) |
| **Severity** | Medium |
| **Data Sources** | DeviceProcessEvents, SecurityEvent (Event ID 4698) |
| **Frequency** | Every 10 minutes |
| **Lookup Period** | 30 minutes |

**Description:**
Detects the creation of scheduled tasks via the `schtasks.exe` command-line utility. Adversaries frequently use scheduled tasks to execute malicious payloads at system startup, on a recurring schedule, or under the context of a different user account. This rule focuses on command-line creation rather than GUI to capture scripted and automated persistence techniques.

**KQL Query:**

```kql
let time_window = 30m;
// Detect schtasks.exe creating new tasks
let CommandLineCreation = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create" or ProcessCommandLine has "-create"
    | extend
        TaskName = extract(@'(?i)/tn\s+"?([^"/]+)"?', 1, ProcessCommandLine),
        TaskAction = extract(@'(?i)/tr\s+"?([^"/]+)"?', 1, ProcessCommandLine),
        RunLevel = iff(ProcessCommandLine has_any ("/rl highest", "/rl HIGHEST"), "Highest", "Default"),
        Schedule = extract(@'(?i)/sc\s+(\w+)', 1, ProcessCommandLine),
        RunAsUser = extract(@'(?i)/ru\s+"?([^"/]+)"?', 1, ProcessCommandLine)
    | extend SuspiciousIndicators = pack_array(
        iff(ProcessCommandLine has_any ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"), "ScriptEnginePayload", ""),
        iff(ProcessCommandLine has_any ("/rl highest", "SYSTEM"), "ElevatedExecution", ""),
        iff(ProcessCommandLine has_any ("http://", "https://", "\\\\"), "RemotePayload", ""),
        iff(ProcessCommandLine has_any ("AppData", "Temp", "ProgramData", "Public"), "SuspiciousPath", "")
    )
    | mv-expand SuspiciousIndicators
    | where SuspiciousIndicators != ""
    | summarize
        SuspiciousFlags = make_set(SuspiciousIndicators),
        take_any(TaskName, TaskAction, RunLevel, Schedule, RunAsUser,
                 InitiatingProcessFileName, InitiatingProcessCommandLine)
        by TimeGenerated, DeviceName, AccountName, ProcessCommandLine;
// Correlate with Event ID 4698 for additional context where available
let EventLogCreation = SecurityEvent
    | where TimeGenerated > ago(time_window)
    | where EventID == 4698
    | extend TaskContent = tostring(EventData)
    | extend
        TaskNameFromEvent = extract(@'<Name>(.*?)</Name>', 1, TaskContent),
        TaskCommandFromEvent = extract(@'<Command>(.*?)</Command>', 1, TaskContent)
    | project
        TimeGenerated,
        Computer,
        Account,
        TaskNameFromEvent,
        TaskCommandFromEvent;
CommandLineCreation
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    TaskName,
    TaskAction,
    RunLevel,
    Schedule,
    RunAsUser,
    SuspiciousFlags,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Software installers and update mechanisms (e.g., Google Update, Adobe Updater) routinely create scheduled tasks. Baseline known installer task names for exclusion.
- System administrators may use schtasks.exe for legitimate automation. Correlate with change management records.
- SCCM and Intune task deployments create scheduled tasks under the SYSTEM context. Exclude the known parent processes for these management tools.

**Recommended Response Actions:**
1. Examine the task action payload to determine what binary or script will be executed.
2. Check whether the task is configured to run as SYSTEM or with elevated privileges.
3. If the payload references a remote path or URL, retrieve and analyze the file.
4. Review the initiating process chain to understand how schtasks.exe was invoked.
5. If malicious, remove the scheduled task with `schtasks /delete /tn "<TaskName>" /f` and investigate the host for further compromise.

---

## Persistence

### 5. New Service Installation

| Field | Value |
|---|---|
| **Rule Name** | New Windows Service Installed |
| **MITRE ATT&CK** | Persistence - Create or Modify System Process: Windows Service (T1543.003) |
| **Severity** | Medium |
| **Data Sources** | SecurityEvent (Event ID 7045, 4697), DeviceProcessEvents |
| **Frequency** | Every 10 minutes |
| **Lookup Period** | 30 minutes |

**Description:**
Detects the installation of new Windows services, which is a common persistence and privilege escalation technique. Adversaries create malicious services to execute payloads under the SYSTEM context, survive reboots, and blend in with legitimate system services. This rule flags new service installations and highlights those with suspicious characteristics.

**KQL Query:**

```kql
let time_window = 30m;
// Detect via System Event Log - Event ID 7045 (Service Installed)
let ServiceEventLog = SecurityEvent
    | where TimeGenerated > ago(time_window)
    | where EventID in (7045, 4697)
    | extend
        ServiceName = extract(@'Service Name:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        ServiceFileName = extract(@'Service File Name:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        ServiceType = extract(@'Service Type:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        ServiceStartType = extract(@'Service Start Type:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        ServiceAccount = extract(@'Service Account:\s+(.+?)(?:\r|\n|$)', 1, EventData)
    | extend SuspiciousTraits = pack_array(
        iff(ServiceFileName has_any ("cmd.exe", "powershell", "mshta", "rundll32",
            "regsvr32", "wscript", "cscript"), "ScriptEngineBinary", ""),
        iff(ServiceFileName has_any ("Temp", "AppData", "Downloads", "Public",
            "ProgramData", "Recycle"), "SuspiciousPath", ""),
        iff(ServiceFileName matches regex @"^[a-zA-Z]:\\[^\\]+\.exe$", "RootDirectoryBinary", ""),
        iff(ServiceAccount has "LocalSystem" or ServiceAccount has "SYSTEM", "RunsAsSystem", ""),
        iff(ServiceFileName has_any (".bat", ".cmd", ".vbs", ".js", ".ps1"), "ScriptPayload", ""),
        iff(ServiceName matches regex @"^[a-z]{8,}$", "RandomizedName", "")
    )
    | mv-expand SuspiciousTraits
    | where SuspiciousTraits != ""
    | summarize SuspiciousFlags = make_set(SuspiciousTraits)
        by TimeGenerated, Computer, Account, ServiceName, ServiceFileName,
           ServiceType, ServiceStartType, ServiceAccount;
// Detect via sc.exe command line
let ScExeCreation = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where FileName =~ "sc.exe"
    | where ProcessCommandLine has_any ("create", "config")
    | where ProcessCommandLine has "binpath" or ProcessCommandLine has "binPath"
    | extend
        ServiceNameCli = extract(@'(?:create|config)\s+(\S+)', 1, ProcessCommandLine),
        BinPath = extract(@'(?i)binpath=\s*"?([^"]+)"?', 1, ProcessCommandLine)
    | project
        TimeGenerated,
        DeviceName,
        AccountName,
        ServiceNameCli,
        BinPath,
        ProcessCommandLine,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine;
// Output combined results
ServiceEventLog
| project
    TimeGenerated,
    Computer,
    Account,
    ServiceName,
    ServiceFileName,
    ServiceType,
    ServiceStartType,
    ServiceAccount,
    SuspiciousFlags,
    Source = "EventLog"
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Legitimate software installations frequently create services. Correlate with recent software deployment activity and change management windows.
- Security agents (CrowdStrike, Defender for Endpoint, Carbon Black) install and update their own services. Maintain a whitelist of known security tool service names and binary paths.
- Windows Updates and feature installations create system services. Exclude well-known Microsoft service binary paths.

**Recommended Response Actions:**
1. Verify the service binary exists on disk and inspect it (file hash, signature, compilation timestamp).
2. Submit the binary hash to VirusTotal or an internal sandbox.
3. If the service runs as SYSTEM and has suspicious traits, stop the service and disable it immediately.
4. Trace the process chain that created the service to identify the initial entry vector.
5. Check for related persistence mechanisms (scheduled tasks, registry run keys) on the same host.

---

### 6. Registry Run Key Modification

| Field | Value |
|---|---|
| **Rule Name** | Registry Autostart Run Key Modified |
| **MITRE ATT&CK** | Persistence - Boot or Logon Autostart Execution: Registry Run Keys (T1547.001) |
| **Severity** | Medium |
| **Data Sources** | DeviceRegistryEvents, SecurityEvent |
| **Frequency** | Every 10 minutes |
| **Lookup Period** | 30 minutes |

**Description:**
Detects modifications to Windows registry Run and RunOnce keys, which cause programs to execute automatically when a user logs in or the system boots. These keys are among the most commonly abused persistence mechanisms. This rule monitors both HKLM and HKCU hives and flags entries pointing to suspicious binaries or paths.

**KQL Query:**

```kql
let time_window = 30m;
let RunKeyPaths = dynamic([
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
]);
DeviceRegistryEvents
| where TimeGenerated > ago(time_window)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (RunKeyPaths)
| extend RegistryValueData = tostring(RegistryValueData)
| where isnotempty(RegistryValueData)
| extend SuspiciousIndicators = pack_array(
    iff(RegistryValueData has_any ("powershell", "cmd.exe", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32"), "ScriptEngine", ""),
    iff(RegistryValueData has_any ("Temp", "AppData\\Local\\Temp", "Downloads",
        "%TEMP%", "%TMP%", "Public"), "SuspiciousPath", ""),
    iff(RegistryValueData has_any ("http://", "https://", "\\\\"), "RemoteReference", ""),
    iff(RegistryValueData has_any ("-enc", "-encoded", "frombase64", "bypass"), "Obfuscation", ""),
    iff(RegistryValueData matches regex @"\.[a-z]{2,4}\s", "HiddenExtension", "")
)
| mv-expand SuspiciousIndicators
| where SuspiciousIndicators != ""
| summarize SuspiciousFlags = make_set(SuspiciousIndicators)
    by TimeGenerated, DeviceName, AccountName = InitiatingProcessAccountName,
       RegistryKey, RegistryValueName, RegistryValueData, ActionType,
       InitiatingProcessFileName, InitiatingProcessCommandLine,
       InitiatingProcessFolderPath
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    SuspiciousFlags,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Many legitimate applications register themselves in Run keys during installation (chat clients, cloud storage sync, hardware drivers). Baseline your environment and exclude known-good entries.
- Software updates may modify existing Run key values. Compare the new value against known legitimate paths for the application.
- Group Policy can push Run key entries across the domain. Verify against GPO configurations.

**Recommended Response Actions:**
1. Examine the binary or script referenced in the registry value data.
2. Check the digital signature and file hash of the target executable.
3. Determine whether the initiating process is expected to modify registry autostart keys.
4. If malicious, remove the registry value and quarantine the referenced binary.
5. Scan the endpoint for additional persistence mechanisms.

---

## Privilege Escalation

### 7. Unusual Privilege Escalation

| Field | Value |
|---|---|
| **Rule Name** | Account Granted Administrative Privileges Unexpectedly |
| **MITRE ATT&CK** | Privilege Escalation - Valid Accounts: Domain Accounts (T1078.002) |
| **Severity** | High |
| **Data Sources** | AuditLogs, IdentityInfo, AzureActivity |
| **Frequency** | Every 30 minutes |
| **Lookup Period** | 1 hour |

**Description:**
Detects when a user account is added to a high-privilege Azure AD / Entra ID directory role or administrative group outside of normal change management patterns. Adversaries who gain access to a privileged account may elevate other accounts to maintain access or broaden their control. This rule identifies role assignments to sensitive roles and flags those that deviate from historical baselines.

**KQL Query:**

```kql
let time_window = 1h;
let SensitiveRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Privileged Authentication Administrator",
    "Intune Administrator", "Azure AD Joined Device Local Administrator"
]);
// Detect Azure AD role assignments
let RoleAssignments = AuditLogs
    | where TimeGenerated > ago(time_window)
    | where OperationName has_any (
        "Add member to role", "Add eligible member to role",
        "Add scoped member to role"
    )
    | where Result == "success"
    | extend
        TargetUser = tostring(TargetResources[0].userPrincipalName),
        RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue),
        AssignedBy = tostring(InitiatedBy.user.userPrincipalName),
        AssignedByIP = tostring(InitiatedBy.user.ipAddress)
    | where RoleName has_any (SensitiveRoles)
    | project
        TimeGenerated,
        OperationName,
        TargetUser,
        RoleName,
        AssignedBy,
        AssignedByIP,
        CorrelationId;
// Detect additions to privileged on-premises AD groups synced to Azure
let GroupAdditions = AuditLogs
    | where TimeGenerated > ago(time_window)
    | where OperationName == "Add member to group"
    | where Result == "success"
    | extend
        GroupName = tostring(TargetResources[0].displayName),
        TargetUser = tostring(TargetResources[0].userPrincipalName),
        AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
    | where GroupName has_any (
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators"
    )
    | project
        TimeGenerated,
        OperationName,
        TargetUser,
        GroupName,
        AssignedBy;
// Detect Azure RBAC Owner/Contributor role assignments at subscription level
let AzureRBAC = AzureActivity
    | where TimeGenerated > ago(time_window)
    | where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
    | where ActivityStatusValue == "Success"
    | extend
        RoleDefinition = tostring(parse_json(Properties).requestbody)
    | where RoleDefinition has_any ("Owner", "Contributor", "User Access Administrator")
    | project
        TimeGenerated,
        Caller,
        CallerIpAddress,
        ResourceGroup,
        RoleDefinition,
        SubscriptionId;
RoleAssignments
| project
    TimeGenerated,
    AlertType = "AAD Role Assignment",
    TargetUser,
    PrivilegeGranted = RoleName,
    PerformedBy = AssignedBy,
    SourceIP = AssignedByIP
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Planned role assignments during onboarding, team changes, or break-glass procedures will trigger this rule. Correlate with IT ticketing systems.
- PIM (Privileged Identity Management) eligible role activations are expected behavior for organizations using just-in-time access. Filter on `OperationName` to separate permanent assignments from PIM activations.
- Automated provisioning systems (e.g., SCIM, HR-driven lifecycle workflows) may assign roles. Exclude known automation service principal IDs.

**Recommended Response Actions:**
1. Verify the role assignment against approved change requests or PIM activation records.
2. If unplanned, contact the assigning administrator to confirm intent.
3. Check whether the assigning account itself was recently compromised (review its sign-in logs for anomalies).
4. If unauthorized, immediately remove the role assignment and investigate the assigning account.
5. Audit all actions performed by the target account after the privilege was granted.

---

## Defense Evasion

### 8. Security Tool Tampering

| Field | Value |
|---|---|
| **Rule Name** | Attempt to Disable Security Controls |
| **MITRE ATT&CK** | Defense Evasion - Impair Defenses: Disable or Modify Tools (T1562.001) |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents, DeviceRegistryEvents, SecurityEvent |
| **Frequency** | Every 5 minutes |
| **Lookup Period** | 15 minutes |

**Description:**
Detects attempts to disable or tamper with security tools including Windows Defender, Windows Firewall, event logging, and Sysmon. Adversaries commonly attempt to disable defenses early in an intrusion to operate undetected. This rule captures command-line, PowerShell, registry, and service-based tampering methods.

**KQL Query:**

```kql
let time_window = 15m;
// Pattern 1: Disabling Defender via command line or PowerShell
let DefenderTampering = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where (
        // Set-MpPreference disabling detections
        (ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has_any (
            "DisableRealtimeMonitoring $true",
            "DisableRealtimeMonitoring 1",
            "DisableBehaviorMonitoring $true",
            "DisableIOAVProtection $true",
            "DisableScriptScanning $true",
            "DisableBlockAtFirstSeen $true"
        ))
        or
        // Stopping Defender service
        (ProcessCommandLine has_any (
            "sc stop WinDefend", "sc delete WinDefend",
            "sc config WinDefend start= disabled",
            "net stop WinDefend"
        ))
        or
        // Removing Defender definitions
        (FileName =~ "MpCmdRun.exe" and ProcessCommandLine has "-RemoveDefinitions -All")
    )
    | extend TamperTarget = "WindowsDefender";
// Pattern 2: Firewall tampering
let FirewallTampering = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where (
        (FileName =~ "netsh.exe" and ProcessCommandLine has "advfirewall" and
            ProcessCommandLine has_any ("set allprofiles state off", "set currentprofile state off",
                "firewall set opmode disable"))
        or
        (ProcessCommandLine has "Set-NetFirewallProfile" and ProcessCommandLine has "-Enabled False")
    )
    | extend TamperTarget = "WindowsFirewall";
// Pattern 3: Event log tampering
let LogTampering = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where (
        // Clearing event logs
        (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ", "clear-log"))
        or
        // Stopping event log service
        (ProcessCommandLine has_any (
            "sc stop EventLog", "net stop EventLog",
            "Stop-Service EventLog"
        ))
        or
        // Disabling audit policy
        (FileName =~ "auditpol.exe" and ProcessCommandLine has "/clear")
    )
    | extend TamperTarget = "EventLogging";
// Pattern 4: Sysmon tampering
let SysmonTampering = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where (
        (FileName =~ "sysmon.exe" and ProcessCommandLine has "-u")
        or
        (FileName =~ "fltMC.exe" and ProcessCommandLine has_any ("unload SysmonDrv", "unload sysmon"))
        or
        (ProcessCommandLine has_any ("sc stop Sysmon", "sc delete Sysmon"))
    )
    | extend TamperTarget = "Sysmon";
union DefenderTampering, FirewallTampering, LogTampering, SysmonTampering
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    TamperTarget,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FolderPath
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- IT administrators may temporarily disable Defender real-time protection during software installation or troubleshooting. Verify against change tickets.
- Automated deployment scripts may modify firewall rules during provisioning. Exclude known deployment automation accounts.
- Log rotation and maintenance scripts may clear event logs on a schedule. Verify against operational runbooks.
- Defender definition removal via `MpCmdRun.exe -RemoveDefinitions` is sometimes used legitimately before reinstalling definitions. Check if definitions are reapplied immediately afterward.

**Recommended Response Actions:**
1. Immediately verify the state of security tools on the affected endpoint.
2. Re-enable any disabled security controls.
3. Isolate the endpoint if tampering is confirmed and no legitimate justification exists.
4. Investigate the full process tree to identify what initiated the tampering.
5. Check for lateral movement or additional compromise indicators on the host, as defense evasion typically occurs mid-intrusion.
6. Preserve forensic artifacts before remediation.

---

## Credential Access

### 9. Credential Dumping Indicators

| Field | Value |
|---|---|
| **Rule Name** | LSASS Memory Access Indicating Credential Dumping |
| **MITRE ATT&CK** | Credential Access - OS Credential Dumping (T1003) |
| **Severity** | Critical |
| **Data Sources** | DeviceProcessEvents, SecurityEvent (Event ID 4656, 4663, 10) |
| **Frequency** | Every 5 minutes |
| **Lookup Period** | 15 minutes |

**Description:**
Detects processes accessing the LSASS (Local Security Authority Subsystem Service) memory in patterns consistent with credential dumping tools such as Mimikatz, comsvcs.dll MiniDump, ProcDump, or direct LSASS memory reads. LSASS holds cached credentials and Kerberos tickets, making it the primary target for credential theft.

**KQL Query:**

```kql
let time_window = 15m;
// Pattern 1: Known credential dumping tool indicators
let KnownToolPatterns = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where (
        // Mimikatz command patterns
        ProcessCommandLine has_any (
            "sekurlsa::", "lsadump::", "kerberos::", "crypto::",
            "privilege::debug", "token::elevate",
            "dpapi::", "vault::cred"
        )
        or
        // ProcDump targeting LSASS
        (FileName =~ "procdump.exe" and ProcessCommandLine has_any ("lsass", "-ma"))
        or
        // comsvcs.dll MiniDump method
        (ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has_any (
            "MiniDump", "#24", "minidump"
        ))
        or
        // rundll32 with comsvcs for dump
        (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs" and
            ProcessCommandLine has_any ("full", "#24"))
        or
        // Task Manager LSASS dump
        (ProcessCommandLine has "taskmgr" and ProcessCommandLine has "lsass")
        or
        // PowerShell credential dumping modules
        (ProcessCommandLine has_any (
            "Invoke-Mimikatz", "Out-Minidump", "Get-LsassMemoryDump",
            "MiniDumpWriteDump"
        ))
    )
    | extend DumpMethod = "KnownTool";
// Pattern 2: Suspicious LSASS access via Sysmon Event ID 10
let SysmonLsassAccess = SecurityEvent
    | where TimeGenerated > ago(time_window)
    | where EventID == 10
    | where EventData has "lsass.exe"
    | extend
        SourceProcess = extract(@'SourceImage:\s+(.+?)(?:\r|\n)', 1, EventData),
        TargetProcess = extract(@'TargetImage:\s+(.+?)(?:\r|\n)', 1, EventData),
        GrantedAccess = extract(@'GrantedAccess:\s+(\S+)', 1, EventData)
    | where TargetProcess has "lsass.exe"
    // Suspicious access rights: 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ
    // 0x1FFFFF = PROCESS_ALL_ACCESS
    | where GrantedAccess in ("0x1010", "0x1038", "0x1FFFFF", "0x143a")
    | where SourceProcess !has_any (
        "csrss.exe", "wininit.exe", "wmiprvse.exe",
        "svchost.exe", "MsMpEng.exe", "services.exe"
    )
    | extend DumpMethod = "DirectMemoryAccess";
// Pattern 3: Suspicious file creation in context of credential dumping
let DumpFileCreation = DeviceProcessEvents
    | where TimeGenerated > ago(time_window)
    | where ProcessCommandLine has_any (
        "lsass.dmp", "lsass.zip", "credentials.dmp",
        "ntds.dit", "SAM", "SECURITY", "SYSTEM"
    )
    | where ProcessCommandLine has_any (
        "copy", "move", "compress", "7z", "rar", "makecab",
        "esentutl", "ntdsutil", "reg save"
    )
    | extend DumpMethod = "CredentialFileExfil";
union KnownToolPatterns, DumpFileCreation
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    DumpMethod,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| sort by TimeGenerated desc
```

**False Positive Guidance:**
- Security tools that perform LSASS protection checks (Credential Guard assessments) may trigger memory access alerts. Whitelist the specific security tool process paths.
- Crash dump collection tools used by Microsoft Support may access LSASS. Verify against open support tickets.
- The `GrantedAccess` filter in the Sysmon portion excludes common legitimate system processes, but custom enterprise agents may need to be added to the exclusion list.

**Recommended Response Actions:**
1. Immediately isolate the endpoint from the network.
2. This is a critical severity event. Assume credentials on the host are compromised.
3. Reset passwords for all accounts that were logged into the affected machine.
4. Revoke Kerberos tickets (reset the KRBTGT account twice if domain-wide compromise is suspected).
5. Collect a forensic image of the endpoint before remediation.
6. Search for the attacker's lateral movement using the stolen credentials across the environment.

---

## Lateral Movement

### 10. Suspicious RDP Activity

| Field | Value |
|---|---|
| **Rule Name** | Anomalous Remote Desktop Connections |
| **MITRE ATT&CK** | Lateral Movement - Remote Services: Remote Desktop Protocol (T1021.001) |
| **Severity** | Medium |
| **Data Sources** | SecurityEvent (Event IDs 4624, 4625), DeviceNetworkEvents, DeviceLogonEvents |
| **Frequency** | Every 15 minutes |
| **Lookup Period** | 1 hour |

**Description:**
Detects unusual RDP connection patterns including connections to servers that have not historically received RDP sessions, connections from accounts that do not normally use RDP, and RDP connections to sensitive infrastructure. This rule helps identify lateral movement after initial compromise.

**KQL Query:**

```kql
let time_window = 1h;
let lookback_baseline = 14d;
let SensitiveServers = dynamic([
    "DC01", "DC02", "ADFS01", "CA01", "SQL01",
    "EXCH01", "SCCM01", "PAW-"
]);
// Current RDP logon events (Type 10 = RemoteInteractive)
let CurrentRDP = SecurityEvent
    | where TimeGenerated > ago(time_window)
    | where EventID == 4624
    | where LogonType == 10
    | extend
        SourceIP = IpAddress,
        TargetHost = Computer,
        LogonAccount = TargetUserName,
        LogonDomain = TargetDomainName
    | where LogonAccount !in ("DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1")
    | project
        TimeGenerated,
        SourceIP,
        TargetHost,
        LogonAccount,
        LogonDomain;
// Historical RDP baseline
let HistoricalRDP = SecurityEvent
    | where TimeGenerated between (ago(lookback_baseline) .. ago(time_window))
    | where EventID == 4624
    | where LogonType == 10
    | extend LogonAccount = TargetUserName, TargetHost = Computer
    | summarize
        HistoricalConnectionCount = count(),
        KnownSourceIPs = make_set(IpAddress, 50)
        by LogonAccount, TargetHost;
// Identify new account-to-host RDP relationships
let NewRDPRelationships = CurrentRDP
    | join kind=leftanti (HistoricalRDP) on LogonAccount, TargetHost
    | extend AlertReason = "NewAccountHostPair";
// Identify RDP to sensitive servers
let SensitiveServerRDP = CurrentRDP
    | where TargetHost has_any (SensitiveServers)
    | extend AlertReason = "SensitiveServerAccess";
// Identify RDP from new source IPs for known users
let NewSourceIPs = CurrentRDP
    | join kind=inner (HistoricalRDP) on LogonAccount, TargetHost
    | where KnownSourceIPs !has SourceIP
    | extend AlertReason = "NewSourceIPForKnownPair";
union NewRDPRelationships, SensitiveServerRDP, NewSourceIPs
| summarize
    AlertReasons = make_set(AlertReason),
    ConnectionCount = count()
    by TimeGenerated, SourceIP, TargetHost, LogonAccount, LogonDomain
| extend
    IsSensitiveTarget = iff(TargetHost has_any (SensitiveServers), true, false)
| project
    TimeGenerated,
    SourceIP,
    TargetHost,
    LogonAccount,
    LogonDomain,
    AlertReasons,
    IsSensitiveTarget,
    ConnectionCount
| sort by IsSensitiveTarget desc, TimeGenerated desc
```

**False Positive Guidance:**
- IT support staff use RDP extensively and may connect to new hosts routinely. Create exclusions for help desk and sysadmin groups by cross-referencing with group membership.
- Adjust `SensitiveServers` to match your environment's naming conventions and critical infrastructure inventory.
- New employee accounts will lack historical baseline data and will trigger "NewAccountHostPair" alerts. Suppress alerts for accounts less than 7 days old.
- The 14-day lookback window should be adjusted based on your organization's environment change rate.

**Recommended Response Actions:**
1. Verify the RDP session is expected by contacting the account owner.
2. If the source IP is an internal workstation, check that workstation for compromise indicators.
3. For sensitive server connections, verify the user has authorized access and a business justification.
4. Review what actions were taken during the RDP session by correlating with process and file events on the target host.
5. If unauthorized, terminate the RDP session and disable the account pending investigation.

---

## Collection & Exfiltration

### 11. Large Data Transfer to External IP

| Field | Value |
|---|---|
| **Rule Name** | Anomalous Outbound Data Transfer Volume |
| **MITRE ATT&CK** | Exfiltration - Exfiltration Over Alternative Protocol (T1048) |
| **Severity** | High |
| **Data Sources** | DeviceNetworkEvents, CommonSecurityLog |
| **Frequency** | Every 15 minutes |
| **Lookup Period** | 1 hour |

**Description:**
Detects endpoints transferring unusually large volumes of data to external IP addresses. This rule establishes a per-device baseline of outbound transfer volumes and flags significant deviations that may indicate data exfiltration. It accounts for known cloud service IPs to reduce noise from legitimate SaaS traffic.

**KQL Query:**

```kql
let time_window = 1h;
let lookback_baseline = 7d;
let min_transfer_bytes = 104857600; // 100 MB minimum threshold
let deviation_multiplier = 3;
// Known cloud service IP ranges to exclude (customize per environment)
let ExcludedDomains = dynamic([
    "microsoft.com", "office365.com", "office.com",
    "windows.net", "azure.com", "sharepoint.com",
    "onedrive.com", "teams.microsoft.com",
    "googleapis.com", "amazon.com", "cloudfront.net"
]);
// Build per-device baseline of outbound traffic
let DeviceBaseline = DeviceNetworkEvents
    | where TimeGenerated between (ago(lookback_baseline) .. ago(time_window))
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | where isnotempty(RemoteUrl)
    | where not(RemoteUrl has_any (ExcludedDomains))
    | summarize
        BaselineTotalBytes = sum(SentBytes),
        BaselineDailyAvgBytes = sum(SentBytes) / 7,
        BaselineMaxSingleTransfer = max(SentBytes),
        NormalDestinations = make_set(RemoteUrl, 100)
        by DeviceName;
// Current outbound traffic
let CurrentTraffic = DeviceNetworkEvents
    | where TimeGenerated > ago(time_window)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | where isnotempty(RemoteUrl)
    | where not(RemoteUrl has_any (ExcludedDomains))
    | summarize
        CurrentTransferBytes = sum(SentBytes),
        DestinationIPs = make_set(RemoteIP, 50),
        DestinationUrls = make_set(RemoteUrl, 50),
        ConnectionCount = count(),
        FirstConnection = min(TimeGenerated),
        LastConnection = max(TimeGenerated)
        by DeviceName, InitiatingProcessFileName;
// Compare current against baseline
CurrentTraffic
| join kind=leftouter (DeviceBaseline) on DeviceName
| extend
    BaselineHourlyAvg = BaselineDailyAvgBytes / 24,
    IsAboveMinThreshold = CurrentTransferBytes > min_transfer_bytes
| where IsAboveMinThreshold
| extend
    DeviationFactor = iff(BaselineHourlyAvg > 0,
        round(toreal(CurrentTransferBytes) / toreal(BaselineHourlyAvg), 1),
        toreal(999)),
    TransferMB = round(toreal(CurrentTransferBytes) / 1048576, 2)
| where DeviationFactor > deviation_multiplier or BaselineHourlyAvg == 0
| project
    FirstConnection,
    LastConnection,
    DeviceName,
    InitiatingProcessFileName,
    TransferMB,
    DeviationFactor,
    BaselineHourlyAvgMB = round(toreal(BaselineHourlyAvg) / 1048576, 2),
    ConnectionCount,
    DestinationIPs,
    DestinationUrls
| sort by TransferMB desc
```

**False Positive Guidance:**
- Large file uploads to sanctioned cloud storage (OneDrive, SharePoint, Google Drive) are expected. The `ExcludedDomains` list should be tuned to include all sanctioned SaaS providers.
- Software developers pushing large repositories or container images will generate significant outbound traffic. Exclude known CI/CD pipeline endpoints.
- Backup solutions transferring data to offsite or cloud targets produce regular large transfers. Exclude known backup destination IPs.
- Adjust `min_transfer_bytes` and `deviation_multiplier` based on your environment's normal traffic patterns.

**Recommended Response Actions:**
1. Identify the destination IPs and URLs, and check them against threat intelligence feeds.
2. Determine what data was transferred by reviewing the initiating process and correlating with file access events.
3. If the destination is a known file-sharing service (Mega, Dropbox, anonymous FTP), investigate with higher priority.
4. Contact the device owner to verify whether the transfer was authorized.
5. If exfiltration is confirmed, isolate the endpoint, preserve evidence, and initiate incident response.
6. Assess the sensitivity of the transferred data to determine notification and regulatory obligations.

---

### 12. Sensitive File Access Anomaly

| Field | Value |
|---|---|
| **Rule Name** | Bulk Access to Sensitive File Shares |
| **MITRE ATT&CK** | Collection - Data from Network Shared Drive (T1039) |
| **Severity** | High |
| **Data Sources** | SecurityEvent (Event IDs 5140, 5145), DeviceFileEvents |
| **Frequency** | Every 15 minutes |
| **Lookup Period** | 1 hour |

**Description:**
Detects a single account accessing an unusually high number of files across sensitive network shares within a short time window. This pattern is consistent with data collection and staging activity, where an attacker or malicious insider enumerates and copies files from shared drives before exfiltration. The rule uses both network share audit logs and endpoint file access telemetry.

**KQL Query:**

```kql
let time_window = 1h;
let file_access_threshold = 100;
let sensitive_share_keywords = dynamic([
    "Finance", "HR", "Legal", "Executive", "Confidential",
    "Restricted", "PII", "PHI", "Secret", "Board",
    "M&A", "Payroll", "Strategy", "Compliance"
]);
// Network share access events
let ShareAccess = SecurityEvent
    | where TimeGenerated > ago(time_window)
    | where EventID in (5140, 5145)
    | extend
        ShareName = extract(@'Share Name:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        SharePath = extract(@'Share Path:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        AccessedFile = extract(@'Relative Target Name:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        SourceAddress = extract(@'Source Address:\s+(.+?)(?:\r|\n|$)', 1, EventData),
        AccessAccount = TargetUserName
    | where ShareName has_any (sensitive_share_keywords) or SharePath has_any (sensitive_share_keywords)
    | summarize
        FilesAccessed = dcount(AccessedFile),
        UniqueShares = dcount(ShareName),
        ShareList = make_set(ShareName, 20),
        SampleFiles = make_set(AccessedFile, 25),
        FirstAccess = min(TimeGenerated),
        LastAccess = max(TimeGenerated)
        by AccessAccount, SourceAddress, Computer
    | where FilesAccessed >= file_access_threshold;
// Endpoint file access events for sensitive paths
let EndpointFileAccess = DeviceFileEvents
    | where TimeGenerated > ago(time_window)
    | where ActionType in ("FileRead", "FileCopied", "FileRenamed")
    | where FolderPath has_any (sensitive_share_keywords)
    | where FolderPath startswith "\\\\"
    | summarize
        FilesAccessed = dcount(FolderPath),
        UniqueDirectories = dcount(tostring(split(FolderPath, "\\", 4))),
        SamplePaths = make_set(FolderPath, 25),
        FileExtensions = make_set(extract(@'\.(\w+)$', 1, FileName), 20),
        FirstAccess = min(TimeGenerated),
        LastAccess = max(TimeGenerated)
        by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
    | where FilesAccessed >= file_access_threshold;
// Output share-level detections
ShareAccess
| extend
    AccessDurationMinutes = datetime_diff('minute', LastAccess, FirstAccess),
    FilesPerMinute = iff(
        datetime_diff('minute', LastAccess, FirstAccess) > 0,
        round(toreal(FilesAccessed) / datetime_diff('minute', LastAccess, FirstAccess), 1),
        toreal(FilesAccessed)
    )
| project
    FirstAccess,
    LastAccess,
    AccessAccount,
    SourceAddress,
    TargetServer = Computer,
    FilesAccessed,
    UniqueShares,
    ShareList,
    SampleFiles,
    AccessDurationMinutes,
    FilesPerMinute
| sort by FilesAccessed desc
```

**False Positive Guidance:**
- Backup service accounts that crawl file shares will access large file volumes. Exclude known backup service accounts.
- Data Loss Prevention (DLP) scanners and classification engines enumerate files by design. Exclude DLP scanner service accounts and source IPs.
- Migration or archival projects involve bulk file access. Correlate with approved migration project schedules.
- Search indexing services (Windows Search, enterprise search appliances) crawl shares continuously. Exclude their service accounts.
- Adjust `file_access_threshold` based on normal user behavior in your environment.

**Recommended Response Actions:**
1. Identify what files and shares were accessed, focusing on the sensitivity of the data.
2. Check whether the account owner had a business reason to access this volume of files.
3. Correlate with outbound network events from the same device to check for immediate exfiltration.
4. If the access is unauthorized, disable the account and revoke access to the affected shares.
5. Review the source device for compromise indicators.
6. Preserve file access logs for potential forensic and legal proceedings.

---

## Rule Maintenance and Tuning

### Baseline Calibration

Each rule should be run in **audit mode** for 2 weeks before enabling alerting. During this period:
1. Collect false positive data and build exclusion lists.
2. Adjust thresholds to match your environment's normal activity levels.
3. Validate that the required data sources are ingesting correctly into the Sentinel workspace.

### Required Data Connectors

| Data Source | Sentinel Connector |
|---|---|
| SigninLogs | Azure Active Directory |
| AuditLogs | Azure Active Directory |
| SecurityEvent | Windows Security Events via AMA |
| DeviceProcessEvents | Microsoft Defender for Endpoint |
| DeviceNetworkEvents | Microsoft Defender for Endpoint |
| DeviceRegistryEvents | Microsoft Defender for Endpoint |
| DeviceFileEvents | Microsoft Defender for Endpoint |
| DeviceLogonEvents | Microsoft Defender for Endpoint |
| AzureActivity | Azure Activity |
| CommonSecurityLog | Common Event Format (CEF) |
| IdentityInfo | Microsoft Defender for Identity |

### Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-02-07 | Initial release with 12 detection rules |

---

*Developed by Jacob Phillips | Cloud Security Engineer | Microsoft SC-200 Certified*
*For questions or contributions, submit a pull request or open an issue.*
