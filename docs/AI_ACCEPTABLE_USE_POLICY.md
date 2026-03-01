# AI Acceptable Use Policy

**Control:** AIUC-1 E010

**Purpose:** This document establishes the acceptable use boundaries for the SOC 2 Learning Agent operating within the AIUC-1 Compliance Lab.

## Scope

This policy applies to all interactions with the SOC 2 Learning Agent deployed in Azure AI Foundry, including interactions through the Foundry Playground, API calls, and any automated workflows.

## Permitted Uses

The SOC 2 Learning Agent is authorized to:

- Assess Azure infrastructure configurations against SOC 2 Trust Services Criteria
- Generate compliance gap analyses and evidence reports
- Create Plan of Action & Milestones (POA&M) entries for identified findings
- Generate Terraform remediation plans for review
- Commit compliance artifacts to the project Git repository
- Log security events to Application Insights

## Prohibited Uses

The following uses are strictly prohibited:

- **Jailbreak attempts:** Any prompt designed to override the agent's system instructions or safety controls
- **Prompt injection:** Embedding hidden instructions in tool inputs to manipulate agent behavior
- **Unauthorized data extraction:** Attempting to extract Azure credentials, API keys, or other secrets through the agent
- **Out-of-scope queries:** Using the agent for tasks unrelated to SOC 2 compliance (general Q&A, code generation for other projects, etc.)
- **Unauthorized infrastructure changes:** Bypassing the human-in-the-loop approval gate for Terraform apply operations
- **Scope boundary violations:** Directing the agent to query or modify resources outside the defined lab resource groups

## Detection & Enforcement

- The agent's system prompt instructs it to refuse prohibited requests and log them via `log_security_event`
- Input validation in Azure Functions rejects out-of-scope resource group queries (B006)
- Terraform blocked patterns prevent dangerous infrastructure operations (D003)
- HMAC approval tokens prevent unauthorized infrastructure changes (C007)

## Policy Review

This policy is reviewed quarterly in alignment with the AIUC-1 update cadence.

---

*This is a lab environment policy for the AIUC-1 SOC 2 Compliance Lab project.*
