# AIUC-1 SOC 2 Azure Foundry Compliance Lab

> **Four autonomous AI agents that assess live Azure infrastructure against SOC 2 Trust Services Criteria, governed by 51 AIUC-1 responsible AI controls — built on Azure AI Foundry Agent Service, Azure Functions, and Terraform.**

---

## Overview

This project demonstrates the application of autonomous AI agents to the domain of Governance, Risk, and Compliance (GRC). The system deploys four specialized agents on **Azure AI Foundry Agent Service** that continuously assess intentionally misconfigured Azure infrastructure against the **SOC 2 Trust Services Criteria (CC1-CC9)**.

Every agent action is governed by the **AIUC-1 standard**, a custom responsible AI control framework with 51 controls across 6 domains (Data & Privacy, Security, Safety, Reliability, Accountability, and Society).

The project follows a **"tools provide data, agents provide judgment"** pattern: Azure Functions return raw Azure state, and the AI agents reason about compliance.

---

## Architecture

```
User (Pete)
    │
    ▼
Azure AI Foundry Agent Service
    │
    ├── SOC 2 Auditor (gpt-4.1-mini)
    ├── Evidence Collector (gpt-4.1-nano)
    ├── Policy Writer (gpt-4.1-mini)
    └── IaC Deployer (gpt-4.1-mini) ──► [Requires Human Approval]
            │
            ▼
        Azure Functions (GRC Tool Library)
            │
            ▼
        Target Azure Infrastructure
        (rg-production / rg-development)
            │
            ▼
        GitHub Repository (Results & Reports)
```

---

## The Four Agents

| Agent | Model | Role |
| :--- | :--- | :--- |
| **SOC 2 Auditor** | `gpt-4.1-mini` | Assesses collected evidence against SOC 2 criteria and generates compliance findings. |
| **Evidence Collector** | `gpt-4.1-nano` | Invokes Azure Functions to gather raw configuration data from target Azure resources. |
| **Policy Writer** | `gpt-4.1-mini` | Generates and maintains governance documents, policies, and runbooks. |
| **IaC Deployer** | `gpt-4.1-mini` | Generates and applies Terraform remediation plans. Requires explicit human approval before `terraform apply`. |

---

## SOC 2 Assessment Targets

The project uses intentional Azure misconfigurations as assessment targets:

| Resource | Finding | SOC 2 Control |
| :--- | :--- | :--- |
| `aiuc1prodstorage` | Public blob access enabled | CC5 |
| `prod-open-nsg` | RDP open to `*` (0.0.0.0/0) | CC6 |
| `dev-open-nsg` | SSH open to `*` (0.0.0.0/0) | CC6 |
| `grclab-sql-02` | SQL Server auditing disabled | CC7 |

---

## Project Structure

```
aiuc1-soc2-compliance-lab/
├── .env.example          # Environment variable template (copy to .env)
├── .gitignore
├── README.md
├── docs/
│   ├── SOC_2_SCOPE_DESCRIPTION.md
│   ├── RISK_TAXONOMY.md
│   ├── RACI_MATRIX.md
│   ├── DATA_FLOW_DIAGRAM.md
│   ├── TRANSPARENCY_STATEMENT.md
│   ├── VENDOR_ASSESSMENTS.md
│   ├── FRAMEWORK_CROSSWALK.md
│   ├── EVIDENCE_MAP.md
│   ├── adrs/
│   │   ├── ADR-001-azure-foundry-selection.md
│   │   ├── ADR-002-soc2-vs-fedramp.md
│   │   └── ADR-003-single-tenant-architecture.md
│   └── runbooks/
│       ├── SECURITY_BREACH_RUNBOOK.md
│       ├── HARMFUL_OUTPUT_RUNBOOK.md
│       └── HALLUCINATION_RUNBOOK.md
├── policies/
│   └── ACCEPTABLE_USE_POLICY.md
├── functions/            # Azure Functions (Phase 3)
├── agents/               # Agent definitions & instructions (Phase 4)
├── terraform/            # IaC for remediation (Phase 4)
├── tests/                # Test suite (Phase 5)
└── reports/              # Generated compliance reports
```

---

## Phase Status

| Phase | Status |
| :--- | :--- |
| Phase 1 — Azure Setup | **Complete** |
| Phase 2 — Governance Docs | **Complete** |
| Phase 3 — Azure Functions | In Progress |
| Phase 4 — Agents | Not Started |
| Phase 5-7 — Testing/CI/CD/Dashboard | Not Started |

---

## Setup

1.  Clone the repository.
2.  Copy `.env.example` to `.env` and fill in your Azure credentials.
3.  Install dependencies (see `requirements.txt` in `functions/` and `agents/`).
4.  Follow the phase-specific setup guides in each subdirectory.

> **Security Note**: Never commit your `.env` file. All secrets must be managed via environment variables or Azure Key Vault.

---

## AIUC-1 Responsible AI Governance

This project is governed by 51 AIUC-1 controls across 6 domains. See `docs/RISK_TAXONOMY.md` and the full control list in the project's skill documentation for details.

---

## LinkedIn Narrative

> *"I built 4 autonomous AI agents that assess Azure infrastructure against SOC 2 compliance standards, governed by AIUC-1 responsible AI controls — using Azure AI Foundry Agent Service, Azure Functions, and Terraform."*
