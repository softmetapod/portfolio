# Passive Information Gathering on wordpress.org

## Objective

To perform passive reconnaissance against the domain `wordpress.org` using standard enumeration tools. Passive information gathering is a critical first phase in any security assessment, allowing the collection of actionable intelligence without directly interacting with the target's application layer.

## Tools Used

| Tool | Purpose |
|------|---------|
| `nslookup` | DNS resolution and server identification |
| `Nmap` | Port scanning and service enumeration |
| `dig` | Detailed DNS record queries |
| `WPscan` | WordPress-specific vulnerability scanning |

---

## Methods and Findings

### nslookup — DNS Resolution

`nslookup` queries the Domain Name System to resolve domain names to IP addresses and identify the responding DNS server.

**Findings for `wordpress.org`:**
- Identified the DNS server used for resolution and its IP address.
- Received a non-authoritative response containing the domain's associated IP address.

![nslookup Results](../Images/nslookup1.png)

---

### Nmap — Port Scanning and Service Detection

Nmap ("Network Mapper") was used to scan the resolved IP addresses for open ports and running services — key information for identifying potential attack vectors.

**Findings:**
- Identified open ports and their associated services, providing a map of the target's externally accessible services.

![Nmap Scan Results](../Images/nmap1.png)

---

### dig — DNS Record Enumeration

The `dig` command performs detailed DNS queries, retrieving A records, MX records, and other DNS data.

**Findings:**
- Retrieved A records revealing the IP addresses behind `wordpress.org`, which can be used to bypass DNS resolution in subsequent testing or to identify hosting infrastructure.

![dig Command Results](../Images/dig1.png)

---

### WPscan — WordPress Vulnerability Scanning

WPscan is a black-box WordPress vulnerability scanner that enumerates plugins, themes, users, and known CVEs. An attempt was made to scan `wordpress.org` for WordPress-specific vulnerabilities.

**Finding:**
- The scan was aborted because the target did not present as a standard WordPress installation. This demonstrates the importance of verifying the target platform before running platform-specific tools to avoid wasted effort and potential false results.

![WPscan Error](../Images/wpscan1.png)

---

## Key Takeaways

- Passive reconnaissance with DNS tools (`nslookup`, `dig`) provides foundational intelligence about a target's infrastructure without generating suspicious traffic.
- Port scanning with Nmap reveals the external attack surface — which services are exposed and potentially exploitable.
- Platform-specific tools like WPscan should only be used after confirming the target technology stack.
- The information gathered in this phase informs all subsequent assessment activities, from vulnerability scanning to exploitation.
