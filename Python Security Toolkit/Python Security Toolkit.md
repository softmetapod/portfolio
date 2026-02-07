# Python Security Toolkit

**Author:** Jacob Phillips | Cloud Security Engineer
**Certifications:** SC-200 (Microsoft Security Operations Analyst), CompTIA Security+
**Core Platforms:** Microsoft Defender, Power BI, Elastic SIEM, Microsoft Azure

---

## Overview

The Python Security Toolkit is a collection of practical security automation scripts built for day-to-day use in security operations, incident response, and threat hunting workflows. Each tool is designed to be lightweight, dependency-minimal, and immediately useful in real-world environments -- from SOC triage to proactive threat hunting.

These scripts complement enterprise platforms like Microsoft Defender and Elastic SIEM by providing flexible, scriptable capabilities that can be integrated into custom workflows, automated pipelines, or ad-hoc investigations.

---

## Table of Contents

| # | Tool | Description |
|---|------|-------------|
| 1 | [IOC Scanner](#1-ioc-scanner) | File hash scanner with IOC feed comparison |
| 2 | [Log Analyzer](#2-log-analyzer) | Linux auth log parser with brute-force detection |
| 3 | [Network Scanner](#3-network-scanner) | Host discovery and TCP port scanner |
| 4 | [Phishing Analyzer](#4-phishing-analyzer) | URL and email header phishing indicator analysis |

---

## 1. IOC Scanner

**File:** `ioc_scanner.py`

Scans a directory tree, computes file hashes (MD5, SHA-1, SHA-256), and compares them against a local IOC feed in CSV format. Designed for rapid triage when you need to sweep an endpoint or file share for known-bad artifacts.

### Usage

```bash
# Scan a directory against an IOC feed
python ioc_scanner.py --target /var/log --ioc-feed sample_data/sample_ioc_feed.csv

# Scan with JSON report output
python ioc_scanner.py --target /home/user/downloads --ioc-feed iocs.csv --output report.json

# Scan specific hash types only
python ioc_scanner.py --target /tmp --ioc-feed iocs.csv --hash-types sha256
```

### Sample Output

```
[2025-01-15 09:23:41] INFO     Scanning /var/log against 142 IOC entries...
[2025-01-15 09:23:42] WARNING  MATCH FOUND: /var/log/payload.bin
                                Hash Type : SHA-256
                                Hash      : a1b2c3d4e5f6...
                                Threat    : Cobalt Strike Beacon
                                Severity  : critical

==============================================================
                    IOC SCAN SUMMARY
==============================================================
Files scanned    : 847
IOC matches      : 1
Scan duration    : 3.2s
Report saved     : report.json
==============================================================
```

### IOC Feed Format

The scanner expects a CSV file with the following columns:

```csv
hash,type,threat_name,severity
d41d8cd98f00b204e9800998ecf8427e,md5,EmptyFile Test,low
```

---

## 2. Log Analyzer

**File:** `log_analyzer.py`

Parses Linux authentication logs (`auth.log`, `syslog`) and detects security-relevant events including brute-force login attempts, privilege escalation, SSH anomalies, and account lockouts. Configurable thresholds let you tune detection sensitivity.

### Usage

```bash
# Analyze auth.log with default thresholds
python log_analyzer.py --logfile /var/log/auth.log

# Custom brute-force threshold and time window
python log_analyzer.py --logfile /var/log/auth.log --threshold 3 --window 300

# Export findings to JSON
python log_analyzer.py --logfile /var/log/auth.log --output findings.json
```

### Sample Output

```
==============================================================
              SECURITY LOG ANALYSIS REPORT
==============================================================
Log file         : /var/log/auth.log
Lines parsed     : 14,329
Time range       : 2025-01-10 00:00:01 -> 2025-01-15 23:59:58
--------------------------------------------------------------

[BRUTE FORCE DETECTION]
  ALERT: 10.0.0.47 - 87 failed attempts in 120s (threshold: 5)
  ALERT: 192.168.1.200 - 23 failed attempts in 60s (threshold: 5)

[SUCCESSFUL LOGIN AFTER FAILURES]
  WARNING: User 'admin' logged in from 10.0.0.47 after 87 failures

[PRIVILEGE ESCALATION]
  INFO: 12 sudo events detected across 3 users

[SSH PATTERNS]
  INFO: 4 unique source IPs for SSH logins
  WARNING: SSH login from 10.0.0.47 (flagged source)

--------------------------------------------------------------
Total alerts  : 3
Total warnings: 2
==============================================================
```

---

## 3. Network Scanner

**File:** `network_scanner.py`

Performs host discovery via ICMP ping sweep and TCP port scanning on the top 25 security-relevant ports. Includes service identification by port number and basic banner grabbing. Built entirely on the Python standard library.

### Usage

```bash
# Scan a /24 subnet
python network_scanner.py --subnet 192.168.1.0/24

# Scan with custom ports and timeout
python network_scanner.py --subnet 10.0.0.0/24 --ports 22,80,443,3389 --timeout 2

# Full scan with JSON output
python network_scanner.py --subnet 172.16.0.0/24 --output scan_results.json
```

### Sample Output

```
==============================================================
              NETWORK SCAN RESULTS
==============================================================
Subnet           : 192.168.1.0/24
Hosts discovered : 7
Scan duration    : 34.8s
--------------------------------------------------------------

Host: 192.168.1.1
  PORT      STATE    SERVICE           BANNER
  22/tcp    open     SSH               OpenSSH_8.9
  80/tcp    open     HTTP              nginx/1.18
  443/tcp   open     HTTPS             --

Host: 192.168.1.50
  PORT      STATE    SERVICE           BANNER
  3389/tcp  open     RDP               --
  445/tcp   open     SMB               --

--------------------------------------------------------------
Total open ports : 5
==============================================================
```

### Disclaimer

This tool is intended for authorized security assessments only. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical. Always obtain written authorization before scanning.

---

## 4. Phishing Analyzer

**File:** `phishing_analyzer.py`

Analyzes URLs and email headers for phishing indicators. Checks for suspicious TLDs, lookalike domains (typosquatting), URL shorteners, homoglyph characters, IP-based URLs, and email header spoofing indicators (SPF/DKIM/DMARC). Produces a weighted risk score from 0 to 100.

### Usage

```bash
# Analyze a single URL
python phishing_analyzer.py --url "http://paypa1-secure.login.com/verify?id=12345"

# Analyze URLs from a file (one per line)
python phishing_analyzer.py --url-file suspicious_urls.txt

# Analyze email headers from a file
python phishing_analyzer.py --email-headers headers.txt

# Full analysis with JSON output
python phishing_analyzer.py --url "http://example.com" --output analysis.json
```

### Sample Output

```
==============================================================
              PHISHING ANALYSIS REPORT
==============================================================
URL: http://paypa1-secure.login.com/verify?id=12345

Risk Score: 82/100 [HIGH]

Indicators Found:
  [+35] Lookalike domain detected: "paypa1" resembles "paypal"
  [+15] Excessive subdomains (3 levels)
  [+10] HTTP (no TLS) on login/financial page
  [+10] Contains suspicious path: /verify
  [+12] Homoglyph substitution: '1' for 'l'

Recommendation: HIGH RISK - Block and investigate
==============================================================
```

---

## Requirements

Most tools rely exclusively on the Python standard library (Python 3.8+). See `requirements.txt` for optional dependencies.

### Core Dependencies (Standard Library)

- `hashlib` - File hashing
- `socket` - Network operations
- `subprocess` - ICMP ping
- `argparse` - CLI interfaces
- `json` - Report generation
- `csv` - IOC feed parsing
- `logging` - Structured logging
- `re` - Pattern matching
- `ipaddress` - CIDR parsing
- `datetime` - Timestamp handling
- `collections` - Data aggregation
- `concurrent.futures` - Parallel scanning
- `urllib.parse` - URL analysis
- `email` - Header parsing

### Optional Dependencies

```bash
pip install -r requirements.txt
```

---

## Sample Data

The `sample_data/` directory contains test files for development and demonstration:

- `sample_ioc_feed.csv` - Example IOC feed with fake hashes for testing the IOC scanner
- `sample_auth.log` - Simulated auth.log with brute-force attempts, sudo events, and normal activity

---

## Responsible Use

These tools are built for **authorized security operations only**. They are intended to be used by security professionals in environments where they have explicit permission to operate.

- **IOC Scanner** - Run only on systems you are authorized to inspect.
- **Log Analyzer** - Process only logs you are authorized to access.
- **Network Scanner** - Scan only networks you own or have written authorization to test.
- **Phishing Analyzer** - Use for defensive analysis of suspicious artifacts.

Misuse of these tools for unauthorized access, surveillance, or any activity that violates applicable laws is strictly prohibited. The author assumes no liability for misuse.

---

## Integration Notes

These tools are designed to complement enterprise security platforms:

- **Microsoft Defender** - IOC scanner output can be cross-referenced with Defender threat intelligence. Export JSON reports for ingestion into custom Defender workflows.
- **Elastic SIEM** - Log analyzer findings can be shipped to Elasticsearch for correlation with other data sources.
- **Power BI** - JSON output from all tools is structured for easy ingestion into Power BI dashboards for executive reporting.
- **Azure** - Scripts can be deployed as Azure Functions or run within Azure Automation for scheduled scanning operations.

---

*Built by Jacob Phillips -- Cloud Security Engineer*
