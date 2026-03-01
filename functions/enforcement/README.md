# Enforcement Layer

> **Deterministic middleware that architecturally enforces AIUC-1 controls regardless of LLM behavior.**

This directory contains the enforcement layer — the architectural fix for the "Prompt-Based vs. Architectural Enforcement" gap identified in the project README. Instead of relying on the LLM to remember to call `sanitize_output` or respect scope boundaries, the enforcement layer guarantees these behaviors at the infrastructure level.

## Why This Exists

The original architecture relied on the system prompt to enforce several critical controls:

- **A006/B009 (Output Sanitisation):** The agent was *instructed* to call `sanitize_output`, but an LLM instruction is not deterministic — the agent could skip it.
- **B006 (Scope Boundaries):** Each function had to explicitly call `validate_resource_group()`, but nothing prevented a function from being called with an out-of-scope resource group if the validation was missed.
- **E016 (AI Disclosure):** The agent was instructed to append a disclosure footer, but could forget.

The enforcement layer moves these controls from the prompt layer to the infrastructure layer. The LLM cannot bypass them because they execute before and after every function call, regardless of what the LLM attempts.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Queue Message Arrives                       │
│                           │                                    │
│                    ┌──────▼──────┐                             │
│                    │  INPUT PHASE │                             │
│                    │              │                             │
│                    │ 1. Scope     │  ← ScopeEnforcer (B006)    │
│                    │    Boundary  │                             │
│                    │ 2. Injection │  ← ToolRestrictions (D003) │
│                    │    Scanning  │                             │
│                    │ 3. Rate      │  ← ToolRestrictions (B004) │
│                    │    Limiting  │                             │
│                    │ 4. Approval  │  ← ToolRestrictions (C007) │
│                    │    Token     │                             │
│                    └──────┬──────┘                             │
│                           │                                    │
│                    ┌──────▼──────┐                             │
│                    │  FUNCTION   │                             │
│                    │  EXECUTION  │  ← Original function logic  │
│                    └──────┬──────┘                             │
│                           │                                    │
│                    ┌──────▼──────┐                             │
│                    │ OUTPUT PHASE │                             │
│                    │              │                             │
│                    │ 5. Sanitise  │  ← OutputGateway (A006)    │
│                    │ 6. Disclose  │  ← DisclosureInjector(E016)│
│                    │ 7. Metadata  │  ← Enforcement metadata    │
│                    │ 8. Audit     │  ← AuditChain (E015)       │
│                    └──────┬──────┘                             │
│                           │                                    │
│                    ┌──────▼──────┐                             │
│                    │ Output Queue │                             │
│                    └─────────────┘                             │
└──────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Purpose | AIUC-1 Controls |
|--------|---------|-----------------|
| `policy_engine.py` | Declarative policy definitions mapping controls to enforcement rules | E015, E017 |
| `gateway.py` | Mandatory output sanitisation on every response | A006, B009, A004 |
| `scope_enforcer.py` | Resource group boundary enforcement on every input | B006, D003, A003 |
| `tool_restrictions.py` | Rate limiting, injection scanning, HMAC approval validation | D003, C007, B004, C006 |
| `disclosure.py` | AI disclosure footer injection on every response | E016, E017 |
| `audit_chain.py` | Cryptographic hash chain of all enforcement decisions | E015, E017, E004 |
| `middleware.py` | Orchestrates all components into a single pipeline | All |
| `integration.py` | Drop-in replacements for `write_output()` and input checking | All |

## Policies

The enforcement layer defines 10 policies, each mapping to specific AIUC-1 controls:

| Policy ID | Name | Action | Scope | Mandatory |
|-----------|------|--------|-------|-----------|
| ENF-001 | Mandatory Output Sanitisation | Sanitise | Output | Yes |
| ENF-002 | Resource Group Scope Boundary | Block | Input | Yes |
| ENF-003 | Destructive Operation Block | Block | Input | Yes |
| ENF-004 | Terraform Apply Approval Gate | Require Approval | Input | Yes |
| ENF-005 | AI Disclosure Footer Injection | Inject | Output | Yes |
| ENF-006 | Enforcement Audit Trail | Log | Both | Yes |
| ENF-007 | Tool Call Rate Limiting | Rate Limit | Input | Yes |
| ENF-008 | Input Payload Sanitisation | Sanitise | Input | Yes |
| ENF-009 | Pre-Commit Secret Scanning | Block | Input | Yes |
| ENF-010 | Git Commit Path Restriction | Block | Input | Yes |

All 10 policies are mandatory. They are defined as frozen (immutable) dataclasses — the LLM cannot modify them at runtime.

## Risk Classification

Every function is classified by risk level, which determines the enforcement intensity:

| Risk Level | Functions | Enforcement |
|------------|-----------|-------------|
| **LOW** | gap_analyzer, scan_cc_criteria, evidence_validator, query_access_controls, query_defender_score, query_policy_compliance, sanitize_output, log_security_event | Standard pipeline |
| **MEDIUM** | generate_poam_entry, git_commit_push | Standard + path restrictions |
| **HIGH** | run_terraform_plan | Standard + destructive pattern blocking |
| **CRITICAL** | run_terraform_apply | Standard + HMAC approval token required |

## Usage

The enforcement layer is integrated into `function_app.py` via two functions:

```python
from enforcement.integration import enforced_write_output, check_input_enforcement

# Input enforcement (at the top of every function)
blocked, decisions = check_input_enforcement("gap_analyzer", body)
if blocked:
    enforced_write_output(output, build_error_envelope(...), ...)
    return

# Output enforcement (replaces write_output)
enforced_write_output(
    output, envelope,
    correlation_id=correlation_id,
    function_name="gap_analyzer",
    input_payload=body,
)
```

## Test Suite

The enforcement layer has a comprehensive test suite with **134 tests** at **95% code coverage**:

```bash
# Run all enforcement tests
python -m pytest tests/test_enforcement/ -v

# Run with coverage
python -m pytest tests/test_enforcement/ --cov=functions.enforcement --cov-report=term-missing
```

| Test File | Tests | Coverage Area |
|-----------|-------|---------------|
| `test_policy_engine.py` | 21 | Policy loading, indexing, evaluation, manifest |
| `test_gateway.py` | 13 | Output sanitisation, redaction patterns, stats |
| `test_scope_enforcer.py` | 16 | Resource group boundaries, ARM ID parsing |
| `test_tool_restrictions.py` | 23 | Rate limiting, injection detection, HMAC validation |
| `test_disclosure_and_audit.py` | 20 | AI disclosure injection, audit chain integrity |
| `test_middleware.py` | 19 | Full pipeline, input/output enforcement, context |
| `test_control_coverage.py` | 22 | AIUC-1 control-to-enforcement mapping proof |
