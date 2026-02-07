# Incident Response Playbooks

**Author:** Jacob Phillips | Cloud Security Engineer
**Certifications:** CompTIA Security+, Microsoft SC-200
**Version:** 2.0
**Last Updated:** 2026-02-07
**Classification:** Internal Use Only

---

## Table of Contents

1. [Introduction](#introduction)
2. [IR Lifecycle Overview](#ir-lifecycle-overview)
3. [Severity Classification Matrix](#severity-classification-matrix)
4. [Roles and Responsibilities](#roles-and-responsibilities)
5. [Playbook 1: Ransomware Incident](#playbook-1-ransomware-incident)
6. [Playbook 2: Phishing / Business Email Compromise](#playbook-2-phishing--business-email-compromise)
7. [Playbook 3: Compromised Credentials / Account Takeover](#playbook-3-compromised-credentials--account-takeover)
8. [Playbook 4: Data Exfiltration](#playbook-4-data-exfiltration)
9. [Appendix A: Evidence Collection Checklist](#appendix-a-evidence-collection-checklist)
10. [Appendix B: Chain of Custody Log Template](#appendix-b-chain-of-custody-log-template)
11. [Appendix C: Incident Severity Decision Tree](#appendix-c-incident-severity-decision-tree)
12. [Appendix D: External Contact List Template](#appendix-d-external-contact-list-template)
13. [Appendix E: Post-Incident Review Template](#appendix-e-post-incident-review-template)

---

## Introduction

This document provides a set of structured, actionable incident response playbooks aligned with the **NIST Special Publication 800-61 Revision 2** (*Computer Security Incident Handling Guide*) framework. Each playbook is designed to guide security personnel through the complete lifecycle of an incident, from initial detection through post-incident review.

These playbooks address the most prevalent threat categories encountered in modern enterprise environments, with specific emphasis on cloud-native and hybrid infrastructure. They are intended to reduce response times, ensure consistency across incidents, and preserve forensic integrity throughout the investigation process.

**Guiding Principles:**

- Every incident is unique; these playbooks provide a structured baseline, not a rigid script.
- Evidence preservation is paramount. When in doubt, capture first, analyze second.
- Containment actions must balance business continuity with security requirements.
- All actions taken during an incident must be documented with timestamps and personnel attribution.
- Assume compromise may be broader than initial indicators suggest.

---

## IR Lifecycle Overview

All playbooks in this document follow the NIST 800-61 incident response lifecycle:

```
┌──────────────┐     ┌──────────────────────┐     ┌────────────────────────────────────────┐     ┌────────────────────────┐
│              │     │                      │     │                                        │     │                        │
│  Preparation │────>│  Detection &         │────>│  Containment, Eradication              │────>│  Post-Incident         │
│              │     │  Analysis            │     │  & Recovery                             │     │  Activity              │
│              │     │                      │     │                                        │     │                        │
└──────────────┘     └──────────────────────┘     └────────────────────────────────────────┘     └────────────────────────┘
       ^                                                                                                   │
       │                                                                                                   │
       └───────────────────────────────────── Lessons Learned ─────────────────────────────────────────────┘
```

| Phase | Description | Key Activities |
|-------|-------------|----------------|
| **Preparation** | Establish capability to respond to incidents before they occur | Tool deployment, team training, runbook development, communication plan establishment, tabletop exercises |
| **Detection & Analysis** | Identify potential security incidents and determine their scope and impact | Alert triage, log analysis, indicator correlation, severity classification, initial scoping |
| **Containment, Eradication & Recovery** | Limit damage, remove the threat, and restore normal operations | Network isolation, malware removal, system rebuilds, credential resets, phased restoration |
| **Post-Incident Activity** | Document lessons learned and improve future response capability | Root cause analysis, timeline reconstruction, process improvements, metrics collection |

---

## Severity Classification Matrix

All incidents must be classified upon detection and reclassified as new information emerges. Severity determines escalation paths, response timelines, and communication requirements.

| Severity | Definition | Examples | Response Time | Escalation |
|----------|-----------|----------|---------------|------------|
| **Critical (P1)** | Active, widespread threat causing or imminently causing significant business disruption, data loss, or regulatory exposure | Active ransomware encryption across multiple systems; confirmed exfiltration of regulated data (PII/PHI/PCI); compromise of domain admin or root cloud credentials | **Immediate** (within 15 minutes of detection) | CISO, Executive Leadership, Legal Counsel, Cyber Insurance Carrier |
| **High (P2)** | Confirmed security incident with potential for significant impact if not contained promptly | Single-system ransomware (not yet spread); confirmed BEC with financial transaction initiated; compromised privileged account with evidence of misuse | **Within 1 hour** of detection | IR Lead, Security Management, IT Operations Lead |
| **Medium (P3)** | Confirmed or highly likely security incident with limited immediate impact | Successful phishing with credential harvest (no confirmed misuse); malware infection on single non-critical endpoint; unauthorized access attempt with partial success | **Within 4 hours** of detection | IR Lead, Security Analyst Team |
| **Low (P4)** | Potential security incident requiring investigation but posing minimal immediate risk | Phishing email reported (no click); policy violation detected; single failed brute-force attempt from known bad IP | **Within 24 hours** of detection | Security Analyst (on-call) |

**Reclassification Triggers:** Severity must be reassessed when (a) scope expands beyond initial assessment, (b) data classification of affected assets changes, (c) lateral movement is confirmed, or (d) regulatory notification thresholds are met.

---

## Roles and Responsibilities

| Role | Personnel | Responsibilities | Activation Threshold |
|------|-----------|-----------------|---------------------|
| **IR Lead** | Senior Security Engineer / SOC Manager | Overall incident coordination; decision authority for containment actions; manages incident timeline and documentation; primary point of contact for all IR activities | All P1 and P2 incidents; P3 at discretion |
| **Security Analyst** | SOC Analysts / Threat Hunters | Alert triage and initial analysis; evidence collection and forensic investigation; indicator of compromise (IOC) identification and enrichment; log analysis and correlation; malware analysis (initial triage) | All incidents |
| **IT Operations** | System Administrators / Network Engineers / Cloud Engineers | Execute containment actions (network isolation, firewall changes); system rebuild and restoration; backup validation and recovery operations; infrastructure monitoring during recovery | P1 through P3 when infrastructure action is required |
| **Communications** | Corporate Communications / PR | Internal communications to employees; external communications to customers, partners, media; coordination with Marketing on public-facing statements; social media monitoring | P1 incidents; P2 when external visibility is possible |
| **Legal Counsel** | General Counsel / Outside Cyber Counsel | Regulatory notification assessment; attorney-client privilege guidance; law enforcement coordination; contract review for breach notification obligations; litigation hold directives | P1 incidents; any incident involving regulated data |
| **Management** | CISO / VP of IT / Executive Leadership | Strategic decision-making (business impact trade-offs); resource allocation and budget authority; board and executive communication; cyber insurance carrier notification | P1 incidents; P2 at IR Lead discretion |

---

## Playbook 1: Ransomware Incident

**Objective:** Contain the spread of ransomware, preserve evidence, eradicate the threat, and restore operations from known-good sources while maintaining forensic integrity.

**Typical MITRE ATT&CK Mapping:**

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Initial Access | T1566 | Phishing | Spearphishing attachment or link delivering loader |
| Execution | T1059 | Command and Scripting Interpreter | PowerShell, CMD, or WScript executing payload |
| Persistence | T1547 | Boot or Logon Autostart Execution | Registry run keys, startup folder entries |
| Privilege Escalation | T1078 | Valid Accounts | Use of compromised credentials to escalate |
| Defense Evasion | T1562 | Impair Defenses | Disabling AV, EDR, or tamper protection |
| Credential Access | T1003 | OS Credential Dumping | LSASS dumping, SAM extraction, DCSync |
| Lateral Movement | T1021 | Remote Services | RDP, SMB/Windows Admin Shares, PsExec |
| Collection | T1560 | Archive Collected Data | Staging data for exfiltration before encryption |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data theft before encryption (double extortion) |
| Impact | T1486 | Data Encrypted for Impact | File encryption with ransom demand |
| Impact | T1490 | Inhibit System Recovery | Deletion of shadow copies and backups |

### 1.1 Detection Indicators

| Indicator | Source | Confidence |
|-----------|--------|------------|
| Mass file rename operations with known ransomware extensions (.encrypted, .locked, .crypt) | EDR / File Integrity Monitoring | High |
| Ransom note files appearing on endpoints or network shares (README.txt, DECRYPT_INSTRUCTIONS.html) | EDR / File System Alerts | High |
| Volume Shadow Copy deletion (`vssadmin delete shadows /all`) | EDR / Windows Event Log (Event ID 524) | High |
| Unusual process execution: `wmic`, `bcedit`, `cipher /w` | EDR / Sysmon (Event ID 1) | High |
| Outbound connections to known C2 infrastructure | Firewall / Proxy / NDR | Medium-High |
| Spike in SMB traffic or lateral movement patterns | NDR / Firewall | Medium |
| Disabling of endpoint protection or tamper protection | EDR Console / Windows Event Log | High |
| Encryption of cloud storage (OneDrive, SharePoint) files at unusual volume | Microsoft Defender for Cloud Apps / Azure AD Sign-in Logs | Medium |
| LSASS memory access by non-standard processes | EDR / Sysmon (Event ID 10) | High |

### 1.2 Initial Triage Checklist

- [ ] Confirm the alert is a true positive (verify file encryption, locate ransom note, check affected file extensions)
- [ ] Classify incident severity per the severity matrix (typically starts as P1 if spreading, P2 if isolated)
- [ ] Identify the initial affected system(s) and user account(s)
- [ ] Determine the ransomware variant if possible (check ransom note content, file extensions, and services like ID Ransomware)
- [ ] Assess whether encryption is still active or has completed
- [ ] Identify the likely initial access vector (phishing email, exposed RDP, vulnerable public-facing application)
- [ ] Begin incident documentation and open an incident ticket with a unique tracking ID
- [ ] Activate the IR team per the severity classification escalation path
- [ ] Initiate an incident bridge call (P1 only)

### 1.3 Containment

**Immediate Containment (first 30 minutes):**

- [ ] **Network Isolation:** Disconnect affected systems from the network. For physical endpoints, disable the network adapter or disconnect the cable (do NOT power off -- this preserves volatile evidence). For VMs, isolate via hypervisor network policy or NSG.
- [ ] **Disable Affected User Accounts:** Disable all user accounts associated with compromised systems in Active Directory and Azure AD / Entra ID. Revoke all active sessions and refresh tokens.
- [ ] **Block C2 Communication:** Add known C2 IPs and domains to firewall deny lists, DNS sinkhole, and proxy block lists. Submit IOCs to the threat intelligence platform for automated blocking.
- [ ] **Isolate Network Segments:** If the ransomware is spreading via SMB or lateral movement techniques, implement emergency network segmentation. Disable SMBv1. Consider disabling administrative shares temporarily.
- [ ] **Disable Shared Drives:** Disconnect or set network shares to read-only to prevent further encryption of shared data.

**Short-Term Containment (first 4 hours):**

- [ ] **Preserve Evidence:** Capture memory dumps of affected systems before any remediation. Collect forensic images of at least one fully-encrypted and one partially-encrypted system if available.
- [ ] **Identify Scope:** Use EDR telemetry to identify all systems exhibiting ransomware indicators. Query for known IOCs (file hashes, C2 IPs, mutex names) across the entire environment.
- [ ] **Protect Backups:** Verify that backup infrastructure (on-premises and cloud) has not been compromised. Disconnect backup systems from the production network if there is any doubt. Verify immutable backup copies exist.
- [ ] **Password Reset for Privileged Accounts:** Reset passwords for all domain admin, enterprise admin, and cloud admin accounts. Rotate KRBTGT password (twice, 12 hours apart). Reset service account passwords for accounts with broad access.

### 1.4 Eradication

- [ ] **Malware Identification:** Determine the exact ransomware family and variant. Obtain samples for analysis. Check for available decryptors (No More Ransom Project, vendor-specific decryptors).
- [ ] **Persistence Mechanism Removal:** Scan all affected systems for persistence mechanisms including: registry run keys, scheduled tasks, WMI event subscriptions, startup folder items, Group Policy modifications, and unauthorized services.
- [ ] **Rebuild vs. Clean Decision:**

| Factor | Rebuild (Recommended) | Clean |
|--------|-----------------------|-------|
| Confidence in eradication | Lower confidence required | Requires high confidence that all malware and persistence are removed |
| Time to restore | Longer initial effort, higher assurance | Faster initial effort, risk of reinfection |
| Forensic integrity | Preserves evidence (image before rebuild) | May destroy evidence during cleaning |
| **Recommendation** | **Preferred approach for all Critical/High incidents** | Acceptable for Low/Medium isolated incidents with verified eradication |

- [ ] **Patch Initial Access Vector:** Identify and remediate the vulnerability or misconfiguration that enabled initial access. Apply relevant security patches. Close exposed RDP ports. Enforce MFA on all external access points.
- [ ] **Scan Clean Systems:** Run comprehensive antimalware scans on all systems that were in the blast radius but not confirmed compromised. Use IOCs from the investigation to perform targeted sweeps.
- [ ] **Verify Active Directory Integrity:** Check for unauthorized Group Policy Objects, rogue domain admin accounts, modified ACLs on sensitive objects, and Golden Ticket / Silver Ticket indicators.

### 1.5 Recovery

- [ ] **Validate Backups:** Before restoration, verify backup integrity. Scan backup data for ransomware artifacts to avoid restoring infected files. Confirm the backup predates the initial compromise (not just the encryption event).
- [ ] **Staged Restoration Priority:**
  1. Domain controllers and identity infrastructure
  2. Security tooling (EDR, SIEM, vulnerability scanners)
  3. Critical business applications (as defined by BIA)
  4. General user workstations and non-critical systems
- [ ] **Staged Reconnection:** Reconnect restored systems to an isolated VLAN first. Monitor for 24-48 hours for re-infection indicators before moving to production network.
- [ ] **Enhanced Monitoring:** Deploy additional monitoring on restored systems. Increase EDR policy sensitivity. Add custom detection rules for IOCs identified during investigation.
- [ ] **User Communication:** Notify affected users when their systems are ready. Reset passwords and require MFA re-enrollment at first login.

### 1.6 Communication Plan

| Audience | Timing | Owner | Content |
|----------|--------|-------|---------|
| IR Team | Immediate upon detection | IR Lead | Full technical details, IOCs, assigned responsibilities |
| IT Operations | Within 30 minutes of P1 classification | IR Lead | Containment actions required, affected systems list |
| Executive Leadership / CISO | Within 1 hour of P1 classification | IR Lead | Business impact assessment, estimated recovery timeline, resource needs |
| Legal Counsel | Within 2 hours of P1 classification | IR Lead / CISO | Nature of incident, potential data exposure, regulatory implications |
| Cyber Insurance Carrier | Within 24 hours (or per policy terms) | Legal / CISO | Incident notification per policy requirements |
| Law Enforcement (FBI IC3) | Within 72 hours (recommended) | Legal / IR Lead | Sanitized incident details, ransomware variant, ransom demand |
| Regulatory Bodies | Per applicable regulation (e.g., 72 hrs for GDPR) | Legal | Required notification if PII/PHI/PCI data confirmed compromised |
| Affected Customers / Public | Per legal guidance and regulatory obligation | Communications / Legal | Approved messaging only; coordinate with PR |

### 1.7 Key Decision Points: Ransom Payment

**Recommendation: Do not pay the ransom.**

| Consideration | Details |
|---------------|---------|
| **No guarantee of recovery** | Payment does not guarantee a working decryptor. Multiple ransomware groups have provided faulty or incomplete decryption tools. |
| **Funds criminal operations** | Payment directly finances criminal organizations and incentivizes future attacks against your organization and others. |
| **Legal risk** | Payment to sanctioned entities (OFAC-designated groups) may violate U.S. law and result in civil or criminal penalties. |
| **Double extortion** | Even with payment, threat actors may retain exfiltrated data and demand additional payment to prevent publication. |
| **Regulatory scrutiny** | Regulators increasingly scrutinize organizations that pay ransoms, particularly in critical infrastructure sectors. |
| **When payment is discussed** | If leadership insists on exploring payment, involve legal counsel, law enforcement, and the cyber insurance carrier before any action. Engage a professional ransomware negotiation firm through the insurance carrier. |

---

## Playbook 2: Phishing / Business Email Compromise

**Objective:** Identify the scope of the phishing campaign or BEC attack, contain credential compromise and unauthorized access, eradicate malicious artifacts from the email environment, and prevent recurrence.

**Typical MITRE ATT&CK Mapping:**

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious document delivered via email |
| Initial Access | T1566.002 | Spearphishing Link | Credential harvesting page or drive-by download |
| Execution | T1204 | User Execution | User opens attachment or clicks link |
| Persistence | T1137 | Office Application Startup | Malicious Outlook rules or add-ins |
| Persistence | T1098 | Account Manipulation | Mail forwarding rules, delegate access, OAuth app grants |
| Credential Access | T1556 | Modify Authentication Process | Token theft, session hijacking |
| Collection | T1114 | Email Collection | Mailbox search, mail forwarding to external address |
| Lateral Movement | T1534 | Internal Spearphishing | Using compromised account to phish internal targets |
| Impact | T1657 | Financial Theft | BEC wire transfer fraud, invoice manipulation |

### 2.1 Detection Indicators

| Indicator | Source | Confidence |
|-----------|--------|------------|
| User reports a suspicious email | User report / Help desk ticket | Medium (requires validation) |
| Email gateway blocks message with malicious attachment or URL | Email Security Gateway / Defender for Office 365 | High |
| Credential harvesting page detected on click analysis | URL sandboxing / Safe Links | High |
| Impossible travel on user account shortly after email delivery | Azure AD / Entra ID Sign-in Logs | High |
| New inbox rules created (delete or forward rules) | Microsoft 365 Unified Audit Log | High |
| OAuth application consent granted to unknown application | Azure AD / Entra ID Audit Logs | High |
| Executive impersonation or domain lookalike detected | Email authentication (DMARC/DKIM/SPF failure) | Medium |
| Multiple users reporting similar suspicious emails | Aggregated help desk reports | High |
| Mail forwarding to external address configured | Exchange Admin Audit Log | High |

### 2.2 Initial Triage

- [ ] **Confirm the Threat:** Analyze the reported email. Examine headers (SPF/DKIM/DMARC results, originating IP, return-path). Detonate attachments and URLs in a sandbox environment.
- [ ] **Assess Scope -- Single User vs. Campaign:**
  - [ ] Search email logs for all recipients of the same message (Message-ID, sender, subject line, attachment hash)
  - [ ] Identify all users who received the message
  - [ ] Determine how many users interacted with the message (clicked link, opened attachment, replied)
  - [ ] Check for internal forwarding of the malicious message
- [ ] **Determine the Objective:** Classify the attack type:
  - Credential harvesting (link to fake login page)
  - Malware delivery (attachment-based)
  - BEC / financial fraud (impersonation, invoice manipulation)
  - Data exfiltration request (W-2 scam, sensitive data request)
- [ ] **Classify Severity:**
  - No user interaction: P4 (Low)
  - User clicked but no credential entry or download: P3 (Medium)
  - Credentials entered or malware executed: P2 (High)
  - Active BEC with financial transaction or data loss: P1 (Critical)

### 2.3 Containment

- [ ] **Reset Credentials:** For any user who entered credentials, immediately reset their password from an admin console (not from the user's own session).
- [ ] **Revoke Sessions:** Revoke all active sessions and refresh tokens for affected accounts. In Azure AD / Entra ID: `Revoke-AzureADUserAllRefreshToken` or via the Entra admin portal.
- [ ] **Block the Sender:** Add the sender address and sending domain to the email gateway block list. If a domain lookalike, block the entire lookalike domain.
- [ ] **Block Malicious URLs and IPs:** Add credential harvesting URLs and hosting IPs to the proxy block list, firewall deny list, and DNS sinkhole.
- [ ] **Search and Quarantine:** Search all mailboxes for the malicious message and remove it. (See Microsoft 365-specific steps in Section 2.6.)
- [ ] **Warn Users (if campaign):** If the phishing campaign hit multiple users, send an internal advisory describing the threat and instructing users not to interact with the message.

### 2.4 Eradication

- [ ] **Purge Malicious Emails:** Remove the malicious message from all mailboxes organization-wide, including Deleted Items and Recoverable Items folders.
- [ ] **Audit and Remove Mail Rules:**
  - [ ] Check for inbox rules forwarding mail to external addresses
  - [ ] Check for inbox rules deleting or hiding messages (often used to intercept BEC replies)
  - [ ] Check for server-side forwarding (Exchange transport rules) modifications
  - [ ] Remove all unauthorized rules
- [ ] **Audit OAuth Application Grants:**
  - [ ] Review all OAuth / enterprise application consents for affected accounts
  - [ ] Revoke consent for any suspicious or unrecognized applications
  - [ ] Review tenant-wide application consent settings
- [ ] **Check for Delegate Access:**
  - [ ] Review mailbox delegation (Full Access, Send As, Send on Behalf)
  - [ ] Check for calendar sharing changes
  - [ ] Remove any unauthorized delegate permissions
- [ ] **Malware Cleanup (if applicable):** If the phishing email delivered malware, follow appropriate malware response procedures. Run EDR scans on affected endpoints. Check for persistence mechanisms.
- [ ] **Internal Phishing Check:** Determine if the compromised account was used to send internal phishing emails. If so, treat those as a secondary campaign and repeat triage.

### 2.5 Recovery

- [ ] **Re-enable Accounts with MFA:** Require MFA re-enrollment for all affected accounts. Verify MFA methods are legitimate (check for attacker-registered methods such as unrecognized phone numbers or authenticator apps).
- [ ] **Conditional Access Review:** Verify conditional access policies are enforced on affected accounts. Consider adding a Named Location block or requiring compliant device for high-risk accounts.
- [ ] **Monitor for Re-compromise:** Place affected accounts on enhanced monitoring for 30 days. Alert on: new inbox rules, new OAuth consents, sign-ins from new locations, impossible travel events.
- [ ] **User Education:** Provide targeted security awareness follow-up to affected users (not punitive; focused on recognition skills).

### 2.6 Microsoft 365 / Defender for Office 365 Specific Steps

**Email Investigation and Remediation:**

```
# Threat Explorer (Defender for Office 365 Plan 2)
# 1. Navigate to: security.microsoft.com > Email & collaboration > Explorer
# 2. Filter by sender, subject, or Message-ID
# 3. Select all instances of the malicious message
# 4. Action > Move to > Deleted Items / Soft Delete / Hard Delete

# PowerShell: Compliance Search and Purge
# Step 1: Create the search
New-ComplianceSearch -Name "Phishing_Incident_<ID>" `
  -ExchangeLocation All `
  -ContentMatchQuery '(From:<malicious@sender.com>) AND (Subject:"<subject>")'

# Step 2: Start the search
Start-ComplianceSearch -Identity "Phishing_Incident_<ID>"

# Step 3: Review results
Get-ComplianceSearch -Identity "Phishing_Incident_<ID>" | Format-List Items

# Step 4: Purge (Hard Delete removes from Recoverable Items)
New-ComplianceSearchAction -SearchName "Phishing_Incident_<ID>" -Purge -PurgeType HardDelete
```

**Audit Sign-In Activity:**

```
# Azure AD / Entra ID Sign-In Logs via PowerShell
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'user@domain.com'" `
  -Top 50 | Select-Object CreatedDateTime, IpAddress, Location, Status, `
  AppDisplayName, ConditionalAccessStatus

# Check for inbox rules via Exchange Online PowerShell
Get-InboxRule -Mailbox user@domain.com | Where-Object {
  $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
} | Format-List Name, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage
```

**Review OAuth App Consents:**

```
# List OAuth permissions granted by the user
Get-AzureADUserOAuth2PermissionGrant -ObjectId <UserObjectId> | Format-List

# Revoke consent
Remove-AzureADOAuth2PermissionGrant -ObjectId <GrantObjectId>
```

---

## Playbook 3: Compromised Credentials / Account Takeover

**Objective:** Identify compromised accounts, contain unauthorized access, determine the extent of attacker activity, and restore account integrity with enhanced security controls.

**Typical MITRE ATT&CK Mapping:**

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Initial Access | T1078 | Valid Accounts | Use of stolen credentials from phishing, infostealer, or dark web |
| Initial Access | T1110 | Brute Force | Password spraying or credential stuffing |
| Persistence | T1098 | Account Manipulation | Adding MFA devices, modifying account properties |
| Persistence | T1136 | Create Account | Creation of new accounts for persistent access |
| Privilege Escalation | T1078.004 | Cloud Accounts | Abuse of compromised cloud identities |
| Defense Evasion | T1550 | Use Alternate Authentication Material | Token theft, pass-the-cookie, pass-the-hash |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | MFA fatigue / push bombing |
| Lateral Movement | T1021 | Remote Services | Use of compromised credentials to access additional systems |
| Collection | T1530 | Data from Cloud Storage | Access to SharePoint, OneDrive, blob storage |

### 3.1 Detection Indicators

| Indicator | Source | Confidence |
|-----------|--------|------------|
| Impossible travel (sign-in from two distant geolocations within infeasible time) | Azure AD / Entra ID Identity Protection | High |
| MFA fatigue attempts (repeated MFA push notifications denied by user, then approved) | Azure AD / Entra ID Sign-in Logs / MFA Logs | High |
| Unusual sign-in properties (unfamiliar browser, OS, IP, or ASN) | Azure AD / Entra ID Identity Protection | Medium |
| Sign-in from new device or location not previously associated with user | Azure AD / Entra ID Sign-in Logs | Medium |
| Sign-in from anonymizing service (Tor, VPN provider IP) | Azure AD / Entra ID / Threat Intelligence | Medium-High |
| Credential found on dark web or paste site | Threat Intelligence Feed / Dark Web Monitoring | Medium |
| Multiple failed sign-in attempts followed by a success (password spray pattern) | Azure AD / Entra ID Sign-in Logs | High |
| Anomalous activity after sign-in (mass download, privilege changes, resource creation) | SIEM / UEBA / Microsoft Defender for Cloud Apps | High |
| Legacy authentication protocol used (IMAP, POP3, SMTP AUTH) bypassing MFA | Azure AD / Entra ID Sign-in Logs | Medium-High |

### 3.2 Initial Triage

- [ ] **Confirm Compromise:** Review sign-in logs for the flagged account. Correlate the suspicious sign-in with the user's known location, devices, and work patterns. Contact the user to verify whether the activity is legitimate.
- [ ] **Determine Scope:**
  - [ ] Single compromised account (targeted credential theft or reuse)
  - [ ] Credential stuffing campaign (multiple accounts targeted simultaneously)
  - [ ] Service account or privileged account (elevated risk)
  - [ ] Federated or SSO identity (may provide access to multiple platforms)
- [ ] **Assess Privilege Level:** Determine the account's roles and group memberships. Prioritize based on:
  - Global Admin / Domain Admin (P1 Critical)
  - Privileged role holder (P1-P2)
  - Standard user with access to sensitive data (P2-P3)
  - Standard user with limited access (P3)
- [ ] **Identify the Credential Source:** Determine how credentials were compromised:
  - Phishing (link to Playbook 2)
  - Infostealer malware on the user's device
  - Credential reuse from a third-party breach
  - Password spray / brute force
  - Token theft (adversary-in-the-middle, browser session hijack)

### 3.3 Containment

- [ ] **Disable the Account:** Immediately disable the compromised account in Active Directory and Azure AD / Entra ID. For federated environments, disable in both the on-premises IdP and the cloud IdP.
- [ ] **Revoke All Sessions:**
  - Revoke Azure AD / Entra ID refresh tokens
  - Invalidate SSO sessions across all integrated applications
  - Terminate active VPN sessions
  - Terminate active RDP / SSH sessions
- [ ] **Block Source IPs:** Add the attacker's source IP addresses to the firewall deny list and conditional access named locations (blocked). If the source is a proxy/VPN service, consider blocking the entire ASN temporarily.
- [ ] **Isolate Endpoint (if applicable):** If the compromise vector is an infostealer on the user's device, isolate that endpoint via EDR network containment.
- [ ] **Protect Adjacent Accounts:** If credential stuffing is detected, enforce password resets for all potentially affected accounts. Enable account lockout policies if not already active.

### 3.4 Investigation

**Sign-In Log Analysis (Azure AD / Entra ID):**

- [ ] Export sign-in logs for the compromised account for the past 90 days
- [ ] Identify the first suspicious sign-in (initial compromise timestamp)
- [ ] Map all attacker sign-in sessions (IP addresses, user agents, locations)
- [ ] Identify all applications accessed during attacker sessions
- [ ] Check for MFA method modifications (registration of new phone numbers, authenticator apps, or FIDO2 keys)

```
# Azure AD / Entra ID Sign-In Log Query (KQL - Sentinel)
SigninLogs
| where UserPrincipalName == "compromised.user@domain.com"
| where TimeGenerated > ago(90d)
| project TimeGenerated, IPAddress, Location, AppDisplayName,
          ResultType, ResultDescription, UserAgent,
          AuthenticationRequirement, ConditionalAccessStatus,
          RiskLevelAggregated, MfaDetail
| order by TimeGenerated desc
```

**Lateral Movement Assessment:**

- [ ] Check if the compromised account accessed other systems or applications
- [ ] Review Azure resource activity logs for cloud infrastructure access
- [ ] Check for new role assignments, group membership changes, or permission grants made by the attacker
- [ ] Review email sent from the account during the compromise window
- [ ] Check for OAuth application consents granted during the compromise window

**Audit Privileged Actions:**

- [ ] Review Azure AD / Entra ID Audit Logs for actions performed by the compromised account
- [ ] Check for: new user creation, role assignment changes, application registration, conditional access policy modifications, MFA setting changes
- [ ] Review Exchange audit logs for mailbox access, rule creation, and delegate assignments
- [ ] Review SharePoint / OneDrive access logs for file downloads or sharing changes

```
# Azure AD Audit Log Query (KQL - Sentinel)
AuditLogs
| where InitiatedBy.user.userPrincipalName == "compromised.user@domain.com"
| where TimeGenerated > ago(90d)
| project TimeGenerated, OperationName, Result, TargetResources,
          AdditionalDetails
| order by TimeGenerated desc
```

### 3.5 Eradication

- [ ] **Password Reset:** Reset the account password using a secure out-of-band method. Generate a strong temporary password and require change at next sign-in.
- [ ] **MFA Re-enrollment:** Delete all existing MFA methods for the account. Require the user to re-enroll MFA through an identity-verified process (in-person or verified video call for privileged accounts).
- [ ] **Review and Remove Unauthorized Changes:**
  - [ ] Revert any role assignments or group memberships added by the attacker
  - [ ] Remove any applications registered or consented to by the attacker
  - [ ] Delete any accounts created by the attacker
  - [ ] Remove any inbox rules, delegates, or forwarding configurations set by the attacker
  - [ ] Revert any conditional access policy or security setting changes
- [ ] **Remediate Credential Source:**
  - If phishing: follow Playbook 2 eradication steps
  - If infostealer: reimage the affected endpoint, reset all credentials stored in the browser or credential manager
  - If credential reuse: user education on unique passwords, recommend a password manager
  - If password spray: enforce stronger password policies, implement smart lockout

### 3.6 Recovery

- [ ] **Staged Re-enablement:**
  1. Re-enable the account with the new password and MFA
  2. Apply a temporary restrictive conditional access policy (e.g., require compliant device, block legacy auth, limit to trusted locations for initial 72 hours)
  3. Monitor the account closely for 30 days
- [ ] **Enhanced Monitoring:**
  - Enable Azure AD / Entra ID Identity Protection risk-based policies for the account
  - Create custom SIEM alerts for the account (new sign-in locations, new MFA methods, role changes)
  - Schedule a 30-day follow-up review
- [ ] **User Communication:** Brief the user on what happened, what was changed, and what they should watch for. Provide instructions for reporting suspicious activity.

### 3.7 Azure AD / Entra ID Specific Investigation Steps

**Identity Protection Risk Assessment:**

```
# Check user risk level
# Entra Admin Center > Protection > Identity Protection > Risky Users
# Filter by the affected user
# Review: Risk level, Risk state, last risk update, Risk detections

# Dismiss or confirm risk after investigation
# If confirmed compromise: Confirm User Compromised (enforces password reset + MFA re-registration)
# If false positive: Dismiss User Risk
```

**Conditional Access Gap Analysis:**

- [ ] Review which conditional access policies applied (or failed to apply) during the attacker's sign-in
- [ ] Identify gaps: Was MFA required? Was device compliance checked? Was the sign-in location evaluated?
- [ ] Verify legacy authentication protocols are blocked
- [ ] Verify token lifetime policies are appropriate (consider Continuous Access Evaluation)

**Service Principal and Managed Identity Review:**

- [ ] If the compromised account had access to Azure resources, review service principal activity
- [ ] Check for new service principal credentials (client secrets, certificates)
- [ ] Review managed identity assignments for unauthorized changes

---

## Playbook 4: Data Exfiltration

**Objective:** Detect and halt unauthorized data transfer, identify the scope and sensitivity of exposed data, preserve evidence for regulatory compliance and potential litigation, and fulfill breach notification obligations.

**Typical MITRE ATT&CK Mapping:**

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Collection | T1005 | Data from Local System | Staging sensitive files from local storage |
| Collection | T1039 | Data from Network Shared Drive | Accessing file shares to collect data |
| Collection | T1530 | Data from Cloud Storage | Downloading from SharePoint, S3, Azure Blob |
| Collection | T1114 | Email Collection | Exfiltration of mailbox contents |
| Collection | T1560 | Archive Collected Data | Compressing data before exfiltration |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data sent over existing C2 infrastructure |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | DNS tunneling, ICMP tunneling, HTTPS to non-standard ports |
| Exfiltration | T1567 | Exfiltration Over Web Service | Upload to cloud storage (Mega, Dropbox, Google Drive, personal OneDrive) |
| Exfiltration | T1052 | Exfiltration Over Physical Medium | USB drives, external hard drives |
| Exfiltration | T1029 | Scheduled Transfer | Automated exfiltration at set intervals |

### 4.1 Detection Indicators

| Indicator | Source | Confidence |
|-----------|--------|------------|
| Large outbound data transfers exceeding baseline for user or system | NDR / Firewall / Proxy Logs | Medium-High |
| Unusual uploads to personal cloud storage services (Mega, Dropbox, personal Google Drive) | CASB / Proxy / DLP | High |
| DNS tunneling activity (high-volume DNS queries, long subdomain strings, high entropy in DNS requests) | DNS Logs / NDR | High |
| USB mass storage device connected and large file copy detected | EDR / DLP / Windows Event Log | Medium-High |
| Bulk email forwarding to external addresses | Email Gateway / Exchange Audit Logs | High |
| Anomalous SharePoint / OneDrive download volume | Microsoft Defender for Cloud Apps / SharePoint Audit Logs | Medium-High |
| Data staging activity (compression, encryption, renaming of collected files) | EDR (Process monitoring, file system events) | Medium |
| Sensitive file access outside of normal business pattern | DLP / File Access Auditing | Medium |
| Outbound connections to file sharing sites or paste sites | Proxy / Firewall | Medium |
| Print volume spike for sensitive documents | Print server logs / DLP | Low-Medium |

### 4.2 Initial Triage

- [ ] **Classify Data Sensitivity:**
  - [ ] Identify what data is being (or was) exfiltrated
  - [ ] Determine data classification: Public, Internal, Confidential, Restricted/Regulated
  - [ ] Determine if regulated data is involved: PII, PHI (HIPAA), PCI, financial records, trade secrets, attorney-client privileged
  - [ ] Estimate the volume of data transferred
- [ ] **Determine Scope:**
  - [ ] Identify all systems and data repositories accessed by the threat actor or insider
  - [ ] Determine the exfiltration method and destination
  - [ ] Identify whether this is ongoing or has concluded
  - [ ] Determine if this is an external threat actor or an insider threat
- [ ] **Classify Severity:**
  - Regulated data confirmed exfiltrated: P1 (Critical)
  - Confidential data confirmed exfiltrated: P1-P2
  - Internal data exfiltrated, or regulated data accessed but exfiltration unconfirmed: P2-P3
  - Suspicious activity detected, no confirmed exfiltration: P3-P4

### 4.3 Containment

- [ ] **Block Destination:** Add the exfiltration destination IPs, domains, and URLs to the firewall deny list, proxy block list, and DNS sinkhole.
- [ ] **Disable Accounts:** Disable user accounts involved in the exfiltration (whether compromised external attacker or suspected insider).
- [ ] **Network Segmentation:** Isolate affected network segments to prevent continued access to sensitive data repositories.
- [ ] **Disable Exfiltration Channels:**
  - Block the specific cloud storage service at the proxy/firewall if not business-critical
  - Disable USB ports via Group Policy or EDR policy on affected endpoints
  - Block outbound DNS to unauthorized resolvers (force traffic through monitored DNS)
  - Restrict outbound connections from servers to allow-listed destinations only
- [ ] **Preserve the Exfiltration Endpoint:** If a specific system was used to stage or exfiltrate data, isolate it (do not power off) and capture a forensic image.
- [ ] **Notify Legal Counsel:** Immediately engage legal counsel when data exfiltration is confirmed. Attorney-client privilege should govern the investigation from this point.

### 4.4 Investigation

**DLP and Proxy Log Analysis:**

- [ ] Review DLP alerts for the timeframe surrounding the detected exfiltration
- [ ] Identify all files flagged by DLP that were transmitted to external destinations
- [ ] Review proxy logs for outbound connections to cloud storage, file sharing, and paste sites
- [ ] Correlate DLP events with user identity, source system, and destination

**Endpoint Activity Analysis:**

- [ ] Review EDR telemetry for data staging behavior (compression tools: 7zip, WinRAR, tar; encryption tools; file renaming patterns)
- [ ] Check for use of data transfer tools (rclone, WinSCP, FileZilla, curl, Invoke-WebRequest)
- [ ] Review USB device connection history
- [ ] Analyze browser history for uploads to file sharing services
- [ ] Check for screen capture or recording activity

**Email Analysis:**

- [ ] Review sent mail for the suspect account for attachments containing sensitive data
- [ ] Check for auto-forwarding rules to external addresses
- [ ] Review email DLP policy violations

**Cloud Activity Analysis:**

- [ ] Review SharePoint / OneDrive / Azure Blob access logs for bulk downloads
- [ ] Check for sharing link creation (especially anonymous links or links shared externally)
- [ ] Review AWS CloudTrail / Azure Activity Log / GCP Audit Log for API-based data access
- [ ] Check for new storage accounts, S3 buckets, or equivalent created by the attacker

**Timeline Reconstruction:**

- [ ] Build a comprehensive timeline of all data access and exfiltration events
- [ ] Identify the earliest evidence of unauthorized data access (may predate the detected exfiltration)
- [ ] Document every file or dataset confirmed or suspected to have been exfiltrated
- [ ] Quantify the total volume of data exfiltrated

### 4.5 Eradication

- [ ] **Close the Exfiltration Channel:** Permanently block the method used for exfiltration (firewall rules, proxy policies, USB restrictions, DLP policies).
- [ ] **Patch Exploited Vulnerability:** If the threat actor gained access through a technical vulnerability, patch it immediately. This includes misconfigured cloud storage permissions, overly permissive firewall rules, or unpatched software.
- [ ] **Revoke Unauthorized Access:** Remove any access mechanisms the attacker established (backdoor accounts, OAuth apps, API keys, SSH keys, VPN credentials).
- [ ] **Insider Threat (if applicable):** Coordinate with HR and Legal. Preserve all evidence per litigation hold requirements. Do not alert the insider until Legal and HR have directed the appropriate course of action.

### 4.6 Recovery

- [ ] **Assess Regulatory Obligations:**

| Regulation | Notification Requirement | Timeline | Authority |
|-----------|------------------------|----------|-----------|
| GDPR (EU) | Notify supervisory authority; notify data subjects if high risk | 72 hours from awareness | National DPA |
| HIPAA (US) | Notify HHS, affected individuals, and potentially media | 60 days from discovery | HHS OCR |
| PCI DSS | Notify payment card brands and acquiring bank | Immediately upon confirmation | Card brands |
| State Breach Laws (US) | Varies by state; most require individual notification | Varies (30-90 days typical) | State AG |
| SEC (public companies) | Material cybersecurity incident disclosure | 4 business days of materiality determination | SEC |
| CCPA/CPRA (California) | Notify affected California residents | Without unreasonable delay | California AG |

- [ ] **Breach Notification Assessment:** Work with Legal to determine notification obligations based on the type and volume of data exfiltrated, the jurisdictions of affected individuals, and applicable regulations.
- [ ] **Engage Breach Counsel:** If not already engaged, retain outside breach counsel to manage notification process and regulatory communications.
- [ ] **Remediate Data Exposure:** Where possible, request takedown of exfiltrated data from hosting providers. Engage threat intelligence services to monitor for data appearing on dark web forums or paste sites.
- [ ] **Strengthen DLP Controls:** Based on the exfiltration method, enhance DLP policies to detect and prevent similar activity in the future.

### 4.7 Legal and Compliance Considerations

- [ ] **Litigation Hold:** If litigation is anticipated, issue a litigation hold to preserve all relevant evidence, logs, and communications. Coordinate with Legal to define the scope of the hold.
- [ ] **Attorney-Client Privilege:** Ensure the investigation is conducted under the direction of legal counsel to preserve privilege where possible. Label investigation documents as "Privileged and Confidential -- Attorney Work Product."
- [ ] **Regulatory Cooperation:** If a regulatory investigation is initiated, cooperate fully under the guidance of legal counsel. Do not destroy or alter any evidence.
- [ ] **Cyber Insurance Notification:** Notify the cyber insurance carrier per policy terms. Many policies require notification within a specific timeframe as a condition of coverage.

### 4.8 Evidence Preservation Requirements

- [ ] **Forensic Imaging:** Create bit-for-bit forensic images of all relevant systems. Use write-blockers for physical media. Compute and record SHA-256 hashes of all forensic images.
- [ ] **Log Preservation:** Export and preserve all relevant logs beyond their normal retention period. This includes: firewall logs, proxy logs, DNS logs, EDR telemetry, email logs, cloud audit logs, DLP alerts, authentication logs.
- [ ] **Chain of Custody:** Document the chain of custody for all evidence per Appendix B. Every transfer of evidence must be recorded.
- [ ] **Third-Party Forensics:** For P1 incidents or when litigation is likely, engage a third-party digital forensics firm (through legal counsel to preserve privilege).

---

## Appendix A: Evidence Collection Checklist

Evidence must be collected in order of volatility. The most volatile data should be captured first, as it will be lost if the system is powered off or rebooted.

**Order of Volatility (collect in this order):**

| Priority | Evidence Type | Collection Method | Tool Examples |
|----------|--------------|-------------------|---------------|
| 1 | **CPU registers and cache** | Rarely practical; captured as part of memory dump | Specialized hardware tools |
| 2 | **Memory (RAM)** | Live memory acquisition from running system | WinPMem, DumpIt, AVML (Linux), Magnet RAM Capture |
| 3 | **Network connections and state** | Capture active network connections, routing tables, ARP cache, DNS cache | `netstat -anob`, `Get-NetTCPConnection`, `arp -a`, `ipconfig /displaydns` |
| 4 | **Running processes** | Capture running processes with full command lines and loaded modules | `tasklist /v`, `Get-Process`, `wmic process list full`, Volatility (from memory image) |
| 5 | **Disk (file system)** | Forensic image of disk (bit-for-bit copy) | FTK Imager, dd, ewfacquire, Arsenal Image Mounter |
| 6 | **Logs (local)** | Export Windows Event Logs, application logs, web server logs | `wevtutil epl`, Log collection script |
| 7 | **Logs (remote/cloud)** | Export SIEM data, cloud audit logs, email logs | SIEM export, Azure/AWS/GCP log export, Exchange audit log search |
| 8 | **Network traffic captures** | If NDR or full packet capture is available, preserve relevant captures | Zeek, Suricata, full PCAP from NDR appliance |
| 9 | **Physical media and backups** | Preserve relevant backup tapes, USB devices, external drives | Physical evidence bags, write-blockers |

**Evidence Collection Checklist:**

- [ ] Record the date, time (UTC), and name of the person collecting evidence
- [ ] Photograph the physical system (screen, cables, indicators) before touching anything
- [ ] Capture live memory before any other action on the system
- [ ] Record all running processes and network connections
- [ ] Create forensic disk image (do not work from the original)
- [ ] Calculate SHA-256 hash of all forensic images and record them
- [ ] Store evidence in a secure, access-controlled location
- [ ] Complete chain of custody form (Appendix B) for each piece of evidence
- [ ] Export all relevant remote logs to a secure evidence repository
- [ ] Document everything: every command run, every file created, every action taken

---

## Appendix B: Chain of Custody Log Template

**Incident ID:** ____________________
**Evidence ID:** ____________________

| Field | Details |
|-------|---------|
| **Description of Evidence** | |
| **Source System (hostname/IP)** | |
| **Date/Time Collected (UTC)** | |
| **Collected By (name/title)** | |
| **Collection Method** | |
| **Hash (SHA-256)** | |
| **Storage Location** | |

**Transfer Log:**

| Date/Time (UTC) | Released By (Name/Title) | Received By (Name/Title) | Purpose of Transfer | Signature Released By | Signature Received By |
|-----------------|-------------------------|-------------------------|--------------------|-----------------------|-----------------------|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

**Notes:**
_Document any anomalies, deviations from procedure, or relevant observations._

---

## Appendix C: Incident Severity Decision Tree

```
START: Security event detected
  │
  ├─ Is there confirmed malicious activity?
  │   ├─ NO  ──> Investigate as potential incident (P4 Low)
  │   │           Monitor and escalate if confirmed.
  │   │
  │   └─ YES ──> Is it actively ongoing?
  │               ├─ YES ──> Are critical systems or data affected?
  │               │           ├─ YES ──> P1 CRITICAL
  │               │           │           Activate full IR team.
  │               │           │           Initiate incident bridge.
  │               │           │           Notify executive leadership.
  │               │           │
  │               │           └─ NO  ──> Is there potential for spread or escalation?
  │               │                       ├─ YES ──> P2 HIGH
  │               │                       │           Activate IR Lead + Analysts.
  │               │                       │           Begin containment immediately.
  │               │                       │
  │               │                       └─ NO  ──> P3 MEDIUM
  │               │                                   Assign to Security Analyst.
  │               │                                   Contain and investigate.
  │               │
  │               └─ NO (historical/contained) ──>
  │                   Is regulated data (PII/PHI/PCI) involved?
  │                   ├─ YES ──> P2 HIGH (minimum)
  │                   │           Engage Legal Counsel.
  │                   │           Assess notification requirements.
  │                   │
  │                   └─ NO  ──> What is the data classification?
  │                               ├─ Confidential/Restricted ──> P2 HIGH
  │                               ├─ Internal                 ──> P3 MEDIUM
  │                               └─ Public/None              ──> P4 LOW
  │
  └─ REASSESSMENT: Re-evaluate severity at each phase
      and whenever new information emerges.
```

---

## Appendix D: External Contact List Template

**Maintain this list with current contact information. Verify and update quarterly.**

| Organization | Contact Type | Contact Details | When to Engage |
|-------------|-------------|----------------|----------------|
| **FBI Internet Crime Complaint Center (IC3)** | Law enforcement | ic3.gov / Local field office: __________ | Ransomware, BEC with financial loss, nation-state activity |
| **CISA (Cybersecurity and Infrastructure Security Agency)** | Federal assistance | central@cisa.dhs.gov / 888-282-0870 | Critical infrastructure incidents, ransomware, request for technical assistance |
| **U.S. Secret Service** | Law enforcement (financial crimes) | Local field office: __________ | Financial fraud, BEC, payment card fraud |
| **Legal Counsel (Internal)** | Legal | Name: __________ / Phone: __________ | All P1/P2 incidents, any incident involving regulated data |
| **Outside Breach Counsel** | Legal (specialized) | Firm: __________ / Phone: __________ | Data breach with notification obligations, regulatory exposure |
| **Cyber Insurance Carrier** | Insurance | Carrier: __________ / Policy #: __________ / Claims: __________ | All P1 incidents, any incident likely to exceed $__________ in costs |
| **Digital Forensics Firm** | Third-party forensics | Firm: __________ / Phone: __________ / Retainer: Y/N | P1 incidents, litigation-anticipated incidents, incidents exceeding internal capability |
| **Ransomware Negotiation Firm** | Specialized vendor | Firm: __________ / Phone: __________ | Only if ransom payment is being considered (coordinate through insurance carrier) |
| **PR / Crisis Communications Firm** | Public relations | Firm: __________ / Phone: __________ | P1 incidents with public visibility or customer impact |
| **State Attorney General Offices** | Regulatory notification | Varies by state (maintain list per applicable jurisdictions) | Data breach involving PII of state residents |
| **HHS Office for Civil Rights** | Regulatory (HIPAA) | hhs.gov/ocr / Phone: __________ | Breach of unsecured PHI affecting 500+ individuals |

---

## Appendix E: Post-Incident Review Template

**Conduct the post-incident review within 5 business days of incident closure. Include all personnel who participated in the response.**

**Incident ID:** ____________________
**Incident Type:** ____________________
**Severity:** ____________________
**Date of Incident:** ____________________
**Date of Review:** ____________________
**Review Facilitator:** ____________________
**Attendees:** ____________________

---

### 1. Incident Summary

_Provide a brief, factual summary of the incident (3-5 sentences)._

### 2. Timeline

| Date/Time (UTC) | Event | Actor | Source |
|-----------------|-------|-------|--------|
| | Initial compromise / first indicator | | |
| | Detection (alert fired or report received) | | |
| | Triage completed, severity classified | | |
| | IR team activated | | |
| | Containment actions initiated | | |
| | Containment achieved (threat isolated) | | |
| | Eradication completed | | |
| | Recovery initiated | | |
| | Full recovery achieved | | |
| | Incident closed | | |

**Key Metrics:**

| Metric | Value |
|--------|-------|
| Time to Detect (Initial Compromise to Detection) | |
| Time to Triage (Detection to Severity Classification) | |
| Time to Contain (Detection to Containment Achieved) | |
| Time to Eradicate (Containment to Eradication Complete) | |
| Time to Recover (Eradication to Full Recovery) | |
| Total Incident Duration (Initial Compromise to Closure) | |

### 3. Root Cause Analysis

_What was the root cause of the incident? What vulnerability, misconfiguration, or human factor enabled the attack?_

### 4. What Worked Well

- [ ] Detection capabilities identified the threat effectively
- [ ] Response procedures were followed correctly
- [ ] Communication was timely and accurate
- [ ] Containment was achieved before significant spread
- [ ] Evidence was properly preserved
- [ ] External coordination (legal, law enforcement, insurance) was smooth

_Additional notes on what worked well:_

### 5. What Did Not Work Well / Areas for Improvement

- [ ] Detection gap: incident was not detected by automated tooling
- [ ] Delayed response due to unclear escalation procedures
- [ ] Communication breakdown between teams
- [ ] Containment was delayed due to access or authorization issues
- [ ] Evidence was inadvertently destroyed or modified
- [ ] Playbook did not adequately cover this scenario
- [ ] Tool or technology gap identified

_Additional notes on areas for improvement:_

### 6. Action Items

| # | Action Item | Owner | Due Date | Priority | Status |
|---|------------|-------|----------|----------|--------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

### 7. Recommendations

_List strategic recommendations for improving the organization's security posture based on this incident._

### 8. Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| IR Lead | | | |
| CISO / Security Management | | | |

---

*This document is maintained by Jacob Phillips and should be reviewed and updated at minimum quarterly, after every P1/P2 incident, and whenever there are significant changes to the organization's technology environment or threat landscape.*
