# Azure Cloud Security Lab - Questions & Answers

These questions and answers cover the core Azure security concepts explored in the [Azure Cloud Security Lab](Azure%20Cloud%20Security%20Setup.md).

---

**How does Azure Active Directory enhance security within the Azure environment?**

Azure Active Directory enhances security by serving as an identity and access management service that supports conditional access policies and Multi-Factor Authentication (MFA). This effectively prevents unauthorized access to Azure resources by requiring identity verification before granting access to any service.

---

**What role does Azure Firewall play in securing Azure virtual networks?**

Azure Firewall acts as a centralized gatekeeper between your Azure VNet and the internet. It scrutinizes all inbound and outbound traffic against defined rules to shield against unauthorized access and attacks, allowing only verified traffic through.

---

**How does enabling encryption on Azure Storage Accounts protect data?**

Encrypting Azure Storage Accounts protects data at rest using either Azure-managed or customer-managed keys stored in Azure Key Vault. This ensures sensitive data remains unreadable to unauthorized parties, even if they gain access to the underlying storage infrastructure.

---

**What benefits does Azure Key Vault offer in terms of security?**

Azure Key Vault provides secure, centralized storage for secrets, cryptographic keys, and certificates. Its access policies ensure that only authorized applications and users can retrieve sensitive material, drastically reducing the risk of credential exposure.

---

**How does Azure Security Center help maintain a secure Azure environment?**

Azure Security Center provides continuous security monitoring, threat detection, and actionable remediation recommendations. It proactively identifies misconfigurations and vulnerabilities across your Azure resources and offers real-time advanced threat protection.

---

**How does Azure Policy contribute to cloud security?**

Azure Policy enforces organizational standards and compliance requirements across Azure resources. It ensures that all deployed resources adhere to corporate security guidelines and service level agreements, preventing configuration drift.

---

**What is the purpose of Azure Network Security Groups (NSGs)?**

Network Security Groups filter network traffic to and from Azure resources within a VNet. By defining inbound and outbound security rules based on source, destination, port, and protocol, NSGs provide granular control over traffic flow and reduce attack surface.

---

**How does Azure's Role-Based Access Control (RBAC) enhance security?**

RBAC enforces the principle of least privilege by assigning specific roles to users, groups, and applications. Each role grants only the permissions necessary for the assigned responsibilities, preventing excessive access that could be exploited.

---

**What is Azure Defender, and how does it protect your cloud resources?**

Azure Defender is a cloud workload protection platform that provides advanced threat protection across Azure services. It leverages AI and behavioral analytics to detect and neutralize sophisticated threats, and provides actionable guidance for risk mitigation.

---

**How do Azure Application Gateways contribute to application security?**

Azure Application Gateways provide application-level routing and load balancing with integrated Web Application Firewall (WAF) capabilities. The WAF inspects inbound HTTP/HTTPS traffic and blocks common web exploits including SQL injection and cross-site scripting (XSS) attacks.
