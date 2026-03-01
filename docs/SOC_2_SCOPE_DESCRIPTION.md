# SOC 2 Scope Description

This document outlines the scope of the System and Organization Controls (SOC) 2 assessment for the AIUC-1 SOC 2 Azure Foundry Compliance Lab project.

## Trust Services Criteria

The assessment will cover the following Trust Services Criteria (TSC):

- **CC1: Control Environment**
- **CC2: Communication and Information**
- **CC3: Risk Assessment**
- **CC4: Monitoring Activities**
- **CC5: Control Activities**
- **CC6: Logical and Physical Access Controls**
- **CC7: System Operations**
- **CC8: Change Management**
- **CC9: Risk Mitigation**

## System Boundary

The system boundary for this assessment includes the following components:

| Component | Description |
|---|---|
| **Azure AI Foundry Agent Service** | The platform for orchestrating the SOC 2 Learning Agent. |
| **Azure Functions** | The serverless compute service used to provide raw Azure state data to the agents. |
| **Target Azure Infrastructure** | The intentionally misconfigured Azure resources that serve as the assessment targets. |
| **GitHub Repository** | The repository for storing all project code, documentation, and results. |

## Assessment Scope

The scope of the assessment is to evaluate the design and operating effectiveness of a subset of the AIUC-1 controls, implemented through a single SOC 2 Learning Agent. The agent assesses intentionally misconfigured Azure resources against the SOC 2 Trust Services Criteria using a "tools provide data, agents provide judgment" model, where 12 Azure Functions provide the raw data and the AI agent provides the compliance judgment. Known gaps against the full AIUC-1 standard are documented in the project README.
