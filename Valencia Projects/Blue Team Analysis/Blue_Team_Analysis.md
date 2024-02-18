# Blue Team Network Security Analysis

## Executive Summary

The Blue Team is dedicated to reinforcing network security and providing essential insights. This document outlines a methodical approach for assessing the existing network framework, identifying vulnerabilities, and executing a comprehensive hardening strategy across different layers.

## Network Analysis

The network infrastructure is relatively straightforward, consisting of a wireless gateway router, a switch, two client computers, a DHCP server, a DNS/ADDS server, a printer, and an IIS web server. A star topology connects each device to the switch, ensuring dedicated links between servers and client computers. Notably, all endpoint devices implement password protection, unlike the router and switch, which lack password security.

## Identified Vulnerabilities

Our assessment reveals several critical vulnerabilities within the network:

### 1. Topology and Structure
The current topology and structure are susceptible to internal threats. Servers and endpoint devices share the same network layer, making the servers vulnerable to malware from endpoint devices, which could compromise the confidentiality, integrity, and availability of services like ADDS, DHCP, DNS, and IIS servers.
![Network Topology](https://drive.google.com/file/d/1z8Gbi-ysNuh2ZyJr4i5WwHGSU_zQTgLX/view?usp=sharing "Network Topology")


### 2. Password Policy
The network's password policy is weak. Certain passwords for clients and the DHCP server are overly simple and predictable. Additionally, the absence of password encryption, combined with the router, switch, and printer being unprotected, creates opportunities for unauthorized access.

### 3. Firewall and Security Measures
The lack of firewall protection means the network cannot filter inbound and outbound traffic, leaving it vulnerable to various cyber threats, including malicious attacks and DoS incidents.

## Hardening Procedures

To enhance network security, we propose the following hardening measures:

### 1. Network Restructuring
Introduce a new network configuration that incorporates a hardware firewall, segregating servers from the rest of the network. This prevents direct packet exchanges through a shared switch, enhancing server security against unauthorized access.

### 2. Security Enhancements
- **Hardware Firewall**: Implement a hardware firewall with IDS, IPS, and traffic management capabilities to protect against malicious, DoS, and Trojan attacks.
- **Endpoint Security**: Install endpoint security solutions to shield endpoint devices from malware and prevent its spread across the network.

### 3. Password Policy Overhaul
- Enforce a new password policy requiring all endpoint devices to use 9-digit alphanumeric passwords.
- Apply AES encryption for router and switch passwords.
- Implement additional security features, including malware detection, packet inspection, timer settings, and security for vacant ports on all network nodes.

## Conclusion

The suggested network hardening measures aim to mitigate identified vulnerabilities, significantly improving the network's security stance. By adopting these strategies, the network will be better equipped to defend against potential cyber threats, ensuring the protection of its resources and services.
