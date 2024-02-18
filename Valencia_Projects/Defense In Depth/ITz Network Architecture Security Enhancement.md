# ITz Network Architecture Security Enhancement

## Overview

This document reviews and enhances the security components integrated into ITz's network architecture. The goal is to create a robust security framework that not only protects against known threats but also offers proactive defenses against emerging vulnerabilities.

## Security Devices Added

### 1. Web Application Firewall (WAF)

The WAF operates as a specialized layer of protection for HTTP servers, monitoring and filtering incoming web traffic. Its primary function is to discern and neutralize potential web-based threats that could compromise the internal LAN. By examining the traffic flow from the external servers to the LAN, the WAF plays a critical role in preventing data breaches.

### 2. Reverse Proxy

The reverse proxy serves dual purposes: it accelerates DNS query responses by acting as a cached information repository, and it provides an inspection point for all internal user requests. This is instrumental in Behavioral Analysis of User (BAU) activities, allowing for the early detection and mitigation of malicious actions within the network.

### 3. Security Incident and Event Management (SIEM) Tool

The SIEM tool is a centralized system that collects and analyzes logs from various network nodes. It aggregates logs from Windows and Linux servers, user computers, firewalls, file servers, and data warehouses, allowing for a comprehensive correlation, analysis, and reporting of security incidents across the network.

### 4. Intrusion Detection/Prevention System (IDS/IPS)

Positioned strategically behind the core switch or VLAN switches, the IDS/IPS monitors network packets using a dedicated sniffing interface. It captures traffic to enforce policies regarding compliance, malware, emerging threats, and the use of discouraged technology. The IDS/IPS is essential for identifying and addressing communication with blacklisted IPs, spammers, and internal malware distribution.

## Conclusion

The enhanced network security architecture now includes a multi-layered defense strategy, incorporating advanced security devices and tools designed to offer a deepened level of protection. These enhancements are critical for maintaining the integrity, confidentiality, and availability of ITz's network resources.
