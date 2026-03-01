# Azure Functions — GRC Tool Library

> **"Tools provide data, agents provide judgment."**

This directory contains the 12 Azure Functions that form the GRC (Governance, Risk & Compliance) tool library for the AIUC-1 SOC 2 Compliance Lab. The SOC 2 Learning Agent calls these functions to gather Azure infrastructure state, execute remediation actions, and maintain audit trails.

> **Note:** All 12 functions are defined in the single `function_app.py` file using queue triggers
> for integration with Azure AI Foundry Agent Service. There are no per-function subdirectories —
> the queue-based architecture replaces the need for individual HTTP-triggered function apps.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Azure AI Foundry Agent Service           │
│               ┌──────────────────────┐                   │
│               │  SOC 2 Learning      │                   │
│               │  Agent (gpt-4.1-mini)│                   │
│               └──────────┬───────────┘                   │
│                          │                               │
│  ────────────────────────┼────────────────────────────── │
│                          ▼                               │
│  ┌──────────────────────────────────────────────────┐   │
│  │          Azure Functions (this directory)         │   │
│  │                                                    │   │
│  │  Data Providers    Actions       Safety           │   │
│  │  ┌─────────────┐  ┌──────────┐  ┌─────────────┐  │   │
│  │  │gap_analyzer │  │poam_entry│  │sanitize_out │  │   │
│  │  │scan_cc      │  │tf_plan   │  │log_security │  │   │
│  │  │evidence_val │  │tf_apply  │  └─────────────┘  │   │
│  │  │access_ctrl  │  │git_push  │                    │   │
│  │  │defender_scr │  └──────────┘                    │   │
│  │  │policy_comp  │                                  │   │
│  │  └─────────────┘                                  │   │
│  └──────────────────────────────────────────────────┘   │
│       │                                                   │
│  ─────┼────────────────────────────────────────────────  │
│       ▼                                                   │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Azure Management APIs                │   │
│  │  Storage │ Network │ SQL │ Security │ Policy      │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Functions

### Data Providers (agent calls these, returns raw data)

| Function | CC Mapping | Description |
|----------|-----------|-------------|
| `gap_analyzer` | CC5, CC6, CC7 | Heuristic gap analysis for a CC category |
| `scan_cc_criteria` | CC1–CC9 | Raw Azure resource state for a CC category |
| `evidence_validator` | All | Validates existence/metadata of evidence artifacts |
| `query_access_controls` | CC6 | RBAC assignments and NSG inbound rules |
| `query_defender_score` | CC3, CC9 | Secure Score and security recommendations |
| `query_policy_compliance` | CC1, CC8 | Azure Policy compliance state |

### Action Functions

| Function | Purpose | Safety Gate |
|----------|---------|-------------|
| `generate_poam_entry` | Risk-based POA&M entry generation | Input validation |
| `run_terraform_plan` | Plan + validation + approval token | Blocked patterns + JSON validation |
| `run_terraform_apply` | Execute approved plan | HMAC approval token required |
| `git_commit_push` | Commit artifacts to repo | Pre-commit secret scanning |

### Safety Functions

| Function | Purpose | AIUC-1 Controls |
|----------|---------|-----------------|
| `sanitize_output` | Strip secrets from text/data | B009, A006 |
| `log_security_event` | Structured App Insights logging | E015 |

## Local Development

```bash
# 1. Install dependencies
cd functions/
pip install -r requirements.txt

# 2. Copy environment template
cp .env.example .env
# Edit .env with your real values

# 3. Copy local settings template
cp local.settings.json.example local.settings.json
# Edit local.settings.json with your real values

# 4. Start the Functions runtime
func start
```

## AIUC-1 Controls Enforced

Every function enforces multiple AIUC-1 controls. The most critical:

| Real AIUC-1 ID | Control Name | How Enforced |
|---|---|---|
| **B006** | Prevent unauthorized AI agent actions | Functions only query allowed resource groups via `validate_resource_group()` |
| **C007** | Flag high-risk outputs | `run_terraform_apply` requires HMAC approval token from `run_terraform_plan` |
| **A003** | Limit AI agent data collection | Only compliance-relevant fields returned from Azure API queries |
| **C002** | Conduct pre-deployment testing | All inputs validated before processing |
| **B009** | Limit output over-exposure | All outputs sanitised via `shared/sanitizer.py` |
| **E015** | Log model activity | Every function call logged to Application Insights with structured metadata |
| **A004** | Protect IP & trade secrets | No hardcoded secrets; env vars only; `sanitizer.py` redacts credentials |
| **E004** | Assign accountability | Terraform apply creates auditable change records |
| **E017** | Document system transparency policy | Response envelopes include provenance metadata |

## Enforcement Layer

The `enforcement/` directory contains the **deterministic enforcement middleware** that architecturally enforces AIUC-1 controls regardless of LLM behavior. This closes the "Prompt-Based vs. Architectural Enforcement" gap identified in the project README.

Instead of relying on the LLM to remember to call `sanitize_output`, the enforcement layer guarantees sanitisation, scope boundaries, disclosure injection, and audit logging at the infrastructure level.

| Module | Purpose | AIUC-1 Controls |
|--------|---------|------------------|
| `enforcement/policy_engine.py` | Declarative policy definitions (10 policies, all mandatory) | E015, E017 |
| `enforcement/gateway.py` | Mandatory output sanitisation on every response | A006, B009, A004 |
| `enforcement/scope_enforcer.py` | Resource group boundary enforcement on every input | B006, D003 |
| `enforcement/tool_restrictions.py` | Rate limiting, injection scanning, HMAC approval validation | D003, C007, B004 |
| `enforcement/disclosure.py` | AI disclosure footer injection on every response | E016, E017 |
| `enforcement/audit_chain.py` | Cryptographic hash chain of all enforcement decisions | E015, E004 |
| `enforcement/middleware.py` | Orchestrates all components into a single pipeline | All |
| `enforcement/integration.py` | Drop-in replacements for `write_output()` and input checking | All |

See [`enforcement/README.md`](./enforcement/README.md) for full architecture documentation, policy definitions, and usage examples.

## Shared Modules

| Module | Purpose | AIUC-1 Controls |
|--------|---------|------------------|
| `config.py` | Centralised settings from environment variables | A004 |
| `azure_clients.py` | Azure SDK client factory with caching | A004, B006 |
| `sanitizer.py` | Secret redaction | B009, A006 |
| `logger.py` | Structured logging to App Insights | E015 |
| `response.py` | Standardised HTTP/queue response builder | B009, E015 |
| `validators.py` | Input validation and CC category mapping | B006, C002 |
