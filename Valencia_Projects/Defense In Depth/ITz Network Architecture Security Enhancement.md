# ITz Network Architecture Security Enhancement

## Objective

To review and enhance the security architecture of ITz's network by implementing a defense-in-depth strategy — adding multiple layers of security controls so that no single point of failure can compromise the entire environment.

## Security Devices Implemented

### 1. Web Application Firewall (WAF)

The WAF operates as a specialized layer of protection for HTTP servers, monitoring and filtering incoming web traffic. Its primary function is to inspect application-layer traffic flowing from external servers to the internal LAN, identifying and neutralizing threats such as SQL injection, cross-site scripting (XSS), and other OWASP Top 10 attacks before they reach backend systems.

### 2. Reverse Proxy

The reverse proxy serves dual purposes within the architecture:
- **Performance:** Accelerates DNS query responses by caching frequently requested content, reducing load on internal servers.
- **Security:** Provides a centralized inspection point for all internal user requests, enabling Behavioral Analysis of User (BAU) activities. This allows the security team to detect anomalous patterns — such as unusual data access volumes or off-hours activity — and flag potential insider threats or compromised accounts early.

### 3. Security Incident and Event Management (SIEM)

The SIEM serves as the centralized log aggregation and analysis platform for the entire network. It collects logs from:
- Windows and Linux servers
- User workstations
- Firewalls and network appliances
- File servers and data warehouses

By correlating events across these sources, the SIEM enables the security team to detect multi-stage attacks, identify lateral movement, and generate actionable incident reports with full event timelines.

### 4. Intrusion Detection/Prevention System (IDS/IPS)

Positioned behind the core switch and VLAN switches, the IDS/IPS monitors network packets using a dedicated sniffing interface. It enforces policies covering:
- **Compliance:** Flags traffic that violates organizational security policies.
- **Malware Detection:** Identifies known malware signatures and communication patterns.
- **Emerging Threats:** Uses updated rulesets to detect newly discovered attack techniques.
- **Blacklist Enforcement:** Blocks communication with known malicious IPs, C2 servers, and spam sources.

## Defense-in-Depth Architecture Summary

| Layer | Control | Function |
|-------|---------|----------|
| Perimeter | WAF | Filters malicious web traffic before it enters the network |
| Application | Reverse Proxy | Caches content and inspects user behavior |
| Network | IDS/IPS | Monitors and blocks malicious network traffic |
| Monitoring | SIEM | Aggregates logs and correlates security events across all layers |

## Conclusion

The enhanced network security architecture implements a multi-layered defense strategy where each component addresses a different attack surface. The WAF protects against web-based attacks, the reverse proxy adds behavioral analysis and caching, the IDS/IPS monitors network-level threats, and the SIEM ties everything together with centralized visibility. This layered approach ensures that even if one control is bypassed, subsequent layers provide additional detection and prevention opportunities.
