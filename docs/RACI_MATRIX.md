# RACI Matrix

This document defines the roles and responsibilities for the key activities in the AIUC-1 SOC 2 Azure Foundry Compliance Lab project, in accordance with AIUC-1 control E004.

## Roles

- **Pete**: The project owner and sole human user.
- **SOC 2 Auditor**: The AI agent responsible for assessing evidence against SOC 2 criteria.
- **Evidence Collector**: The AI agent responsible for gathering evidence from Azure.
- **Policy Writer**: The AI agent responsible for generating governance documents.
- **IaC Deployer**: The AI agent responsible for deploying Azure infrastructure via Terraform.

## Matrix

| Activity | Pete | SOC 2 Auditor | Evidence Collector | Policy Writer | IaC Deployer |
|---|---|---|---|---|---|
| **Define SOC 2 Scope** | **A** | R | I | I | I |
| **Define AIUC-1 Controls** | **A** | R | I | I | I |
| **Collect Azure Evidence** | I | R | **A** | I | I |
| **Assess Evidence for Compliance** | I | **A** | C | I | I |
| **Generate Governance Documents** | I | I | I | **A** | I |
| **Deploy Infrastructure (Plan)** | I | I | I | I | **R** |
| **Deploy Infrastructure (Apply)** | **A** | I | I | I | **R** |
| **Monitor for Misconfigurations** | I | C | **A** | I | I |
| **Remediate Misconfigurations** | **A** | I | I | I | **R** |
| **Review Agent Performance** | **A** | C | C | C | C |

### RACI Key

- **R**: Responsible - Does the work.
- **A**: Accountable - Owns the work. There can only be one Accountable party for each activity.
- **C**: Consulted - Provides input.
- **I**: Informed - Kept up-to-date.
