# Azure Functions — GRC Tool Library

> **"Tools provide data, agents provide judgment."**

This directory contains the 12 Azure Functions that form the GRC (Governance, Risk & Compliance) tool library for the AIUC-1 SOC 2 Compliance Lab. The AI agents call these functions to gather Azure infrastructure state, execute remediation actions, and maintain audit trails.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Azure AI Foundry Agents                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │SOC 2     │ │Evidence  │ │Policy    │ │IaC       │  │
│  │Auditor   │ │Collector │ │Writer    │ │Deployer  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
│       │             │            │             │        │
│  ─────┼─────────────┼────────────┼─────────────┼────── │
│       ▼             ▼            ▼             ▼        │
│  ┌──────────────────────────────────────────────────┐  │
│  │          Azure Functions (this directory)         │  │
│  │                                                    │  │
│  │  Data Providers    Actions       Safety           │  │
│  │  ┌─────────────┐  ┌──────────┐  ┌─────────────┐  │  │
│  │  │gap_analyzer │  │poam_entry│  │sanitize_out │  │  │
│  │  │scan_cc      │  │tf_plan   │  │log_security │  │  │
│  │  │evidence_val │  │tf_apply  │  └─────────────┘  │  │
│  │  │access_ctrl  │  │git_push  │                    │  │
│  │  │defender_scr │  └──────────┘                    │  │
│  │  │policy_comp  │                                  │  │
│  │  └─────────────┘                                  │  │
│  └──────────────────────────────────────────────────┘  │
│       │                                                 │
│  ─────┼────────────────────────────────────────────── │
│       ▼                                                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Azure Management APIs                │  │
│  │  Storage │ Network │ SQL │ Security │ Policy      │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Functions

### Data Providers (agents call these, return raw data)

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

### Safety Functions (all agents use)

| Function | Purpose | AIUC-1 Controls |
|----------|---------|-----------------|
| `sanitize_output` | Strip secrets from text/data | AIUC-1-19, AIUC-1-34 |
| `log_security_event` | Structured App Insights logging | AIUC-1-22, AIUC-1-23 |

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

- **AIUC-1-09** Scope Boundaries — functions only query allowed resource groups
- **AIUC-1-11** Human Oversight — terraform apply requires approval token
- **AIUC-1-17** Data Minimization — only compliance-relevant fields returned
- **AIUC-1-18** Input Validation — all inputs validated before processing
- **AIUC-1-19** Output Filtering — all outputs sanitised via `shared/sanitizer.py`
- **AIUC-1-22** Logging — every call logged to Application Insights
- **AIUC-1-34** Credential Management — no hardcoded secrets; env vars only

## Shared Modules

The `shared/` directory contains utility modules used by all functions:

| Module | Purpose |
|--------|---------|
| `config.py` | Centralised settings from environment variables |
| `azure_clients.py` | Azure SDK client factory with caching |
| `sanitizer.py` | Secret redaction (Audit Fix #4) |
| `logger.py` | Structured logging to App Insights |
| `response.py` | Standardised HTTP response builder |
| `validators.py` | Input validation and CC category mapping |
