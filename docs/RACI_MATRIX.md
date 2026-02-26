# RACI Matrix

This document defines the roles and responsibilities for the key activities in the AIUC-1 SOC 2 Azure Foundry Compliance Lab project, in accordance with AIUC-1 control E004.

## Roles

- **Pete**: The project owner, sole human user, and accountable party for all decisions.
- **SOC 2 Learning Agent**: The single AI agent responsible for all GRC activities — assessing evidence, gathering data, generating documents, and planning remediations.

## Matrix

| Activity | Pete | SOC 2 Learning Agent |
|---|---|---|
| **Define SOC 2 Scope** | **A** | C |
| **Define AIUC-1 Controls** | **A** | C |
| **Collect Azure Evidence** | I | **R** |
| **Assess Evidence for Compliance** | **A** | **R** |
| **Generate Governance Documents** | **A** | **R** |
| **Deploy Infrastructure (Plan)** | I | **R** |
| **Deploy Infrastructure (Apply)** | **A** | **R** |
| **Monitor for Misconfigurations** | **A** | **R** |
| **Remediate Misconfigurations** | **A** | **R** |
| **Review Agent Performance** | **A** | C |

### RACI Key

- **R**: Responsible - Does the work.
- **A**: Accountable - Owns the work. There can only be one Accountable party for each activity.
- **C**: Consulted - Provides input.
- **I**: Informed - Kept up-to-date.
