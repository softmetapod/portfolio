# Azure Cloud Security Lab Setup

## Objective
To understand and apply Azure security best practices for protecting resources and data.

## Lab Components
- **Azure Active Directory (AAD):** For managing identities and access controls.
- **Virtual Networks (VNet):** To simulate network isolation and segmentation.
- **Azure Firewall:** For inspecting and filtering network traffic.
- **Azure Storage Account:** To explore data encryption, access policies, and secure transfer options.
- **Azure Key Vault:** For managing secrets, keys, and certificates.
- **Azure Security Center:** To monitor security posture and assess vulnerabilities.

## Steps

### Setup Azure Active Directory
1. Create a new AAD tenant.
2. Define user roles and permissions.
3. Enable Multi-Factor Authentication (MFA) for added security.

### Configure Virtual Network
1. Create a VNet with subnet segmentation.
2. Set up Network Security Groups (NSGs) for each subnet to control ingress and egress traffic.

### Deploy Azure Firewall
1. Implement Azure Firewall in your VNet.
2. Define application rules and network rules to filter traffic based on IP, port, and protocol.

### Create an Azure Storage Account
1. Enable storage account encryption with Azure-managed keys.
2. Implement access policies and secure transfer requirements.

### Utilize Azure Key Vault
1. Store and manage cryptographic keys and secrets.
2. Configure access policies to restrict who can access Key Vault.

### Monitor with Azure Security Center
1. Enable Azure Security Center Standard tier for advanced threat protection features.
2. Review security recommendations and implement necessary controls.
