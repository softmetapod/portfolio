# Unmasking Roaming Mantis: The Mobile Malware Menace You Need to Know

**By Jacob Phillips | March 22, 2023**

## Overview

Roaming Mantis, also known as Shaoye, is a DNS hijacking malware first identified in Japan by cybersecurity firm Kaspersky in 2018, following reports of DNS settings being hijacked on consumer routers. Initially a banking Trojan aimed at stealing financial credentials, it has since broadened its attacks beyond Asia to Europe, notably France and Germany.

According to Kaspersky's statistics from September to December 2022, France, Japan, and the U.S. saw significant percentages of Roaming Mantis attacks, attributed to large mobile device user bases and strategic geographic locations facilitating malware spread.

## Attack Methodology

### DNS Hijacking — The Initial Foothold

The malware operates by downloading a malicious app onto the victim's device, then altering DNS server settings to redirect all traffic to attacker-controlled servers.

### Secondary Payload Delivery

This redirection facilitates further malware installation on the victim's device — keyloggers, spyware, and additional Trojans — to steal sensitive information and establish persistence.

### Phishing Email Campaigns

**Behind the Bait:** Attackers craft phishing emails mimicking legitimate sources, embedding links to fake login pages designed to deceive victims into submitting their credentials.

**Click, Click, Infected:** Unsuspecting victims are directed to these counterfeit pages, where entering login information leads to immediate data compromise.

**Hooked and Hacked:** The harvested credentials enable attackers to access and exploit personal and financial information from the victims' accounts.

### Remote Device Takeover

**Uninvited Guest:** Roaming Mantis gains remote access through DNS hijacking, establishing a covert C2 (command and control) connection between the victim's device and the attacker's server.

**Seizing Control:** With remote access, attackers can commandeer devices, steal information, install additional malware, or pivot to launch further attacks against other targets on the same network.

## Mitigation Strategies

### Preventive Defenses

- **Antivirus Software**: Regular scans with reputable antivirus can detect and remove malware threats before they establish persistence.
- **Layered Security**: Employ a combination of antivirus, secure DNS services, and VPNs to create overlapping layers of protection.
- **Secure DNS Services**: Services like DNSFilter can block malicious DNS requests at the resolver level, thwarting DNS hijacking attempts before traffic is redirected.
- **VPN Use**: Encrypting internet traffic with a VPN protects against man-in-the-middle data interception.
- **Regular Updates**: Keeping devices, apps, and router firmware updated closes the security gaps that Roaming Mantis exploits.

### Incident Response — Steps to Recover

1. **Disconnect**: Immediately disconnect infected devices from all networks to prevent lateral spread.
2. **Remove Malicious Apps**: Use device settings or antivirus software to identify and uninstall unauthorized applications.
3. **Change Credentials**: Reset all passwords and login information that may have been compromised.

## DNS-Based Defense with DNSFilter

DNSFilter serves as a critical defense layer against Roaming Mantis by blocking access to the malicious domains and IP addresses the malware uses for C2 communication. Its capabilities include:

- **Threat Intelligence Feeds**: Incorporates continuously updated intelligence to identify and block malicious domains in real time.
- **DNS-Level Blocking**: Prevents access to harmful domains at the DNS query level, stopping connections before they reach the attacker's infrastructure.
- **Machine Learning Detection**: Employs advanced algorithms to detect and classify emerging threats, adapting to new malware tactics and domain generation algorithms.

Leveraging DNS-based security alongside endpoint protection and network monitoring provides a robust defense against Roaming Mantis and similar evolving mobile threats.
