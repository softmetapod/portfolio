# Azure Cloud Security Lab

## Objective

To design and implement a secure Azure environment by applying cloud security best practices across identity management, network segmentation, data protection, and continuous monitoring.

## Tools & Technologies

- Microsoft Azure Portal
- Azure Active Directory (AAD)
- Azure Virtual Networks (VNet) & Network Security Groups (NSGs)
- Azure Firewall
- Azure Storage Account
- Azure Key Vault
- Azure Security Center

## Lab Architecture

| Component | Purpose |
|-----------|---------|
| Azure Active Directory | Identity and access management with MFA and role-based access control |
| Virtual Network (VNet) | Network isolation and subnet segmentation |
| Azure Firewall | Centralized traffic inspection and filtering |
| Azure Storage Account | Encrypted data storage with access policies |
| Azure Key Vault | Secrets, keys, and certificate management |
| Azure Security Center | Security posture monitoring and threat protection |

## Implementation Steps

### 1. Setup Azure Active Directory
1. Create a new AAD tenant.
2. Define user roles and permissions using Role-Based Access Control (RBAC).
3. Enable Multi-Factor Authentication (MFA) for all accounts.

### 2. Configure Virtual Network
1. Create a VNet with subnet segmentation to isolate workloads.
2. Set up Network Security Groups (NSGs) for each subnet to control ingress and egress traffic.

### 3. Deploy Azure Firewall
1. Implement Azure Firewall within the VNet as the centralized traffic inspection point.
2. Define application rules and network rules to filter traffic based on IP, port, and protocol.

### 4. Create an Azure Storage Account
1. Enable storage account encryption with Azure-managed keys.
2. Implement access policies and enforce secure transfer (HTTPS only).

### 5. Utilize Azure Key Vault
1. Store and manage cryptographic keys, secrets, and certificates.
2. Configure access policies to restrict retrieval to authorized applications and users only.

### 6. Monitor with Azure Security Center
1. Enable Azure Security Center Standard tier for advanced threat protection.
2. Review security recommendations and implement necessary controls.

## Key Takeaways

- Azure AAD with MFA and RBAC provides a strong identity perimeter, enforcing least-privilege access across all resources.
- VNet segmentation with NSGs limits lateral movement and reduces the blast radius of potential breaches.
- Azure Firewall centralizes traffic filtering, providing visibility and control over both inbound and outbound connections.
- Encryption at rest via Storage Accounts and secrets management through Key Vault protect sensitive data throughout its lifecycle.
- Azure Security Center provides continuous posture assessment and actionable remediation guidance.

## Related

- [Azure Lab Q&A](Q%20%26%20A.md) — Detailed questions and answers covering Azure security concepts explored in this lab.
