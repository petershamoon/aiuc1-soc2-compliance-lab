# AIUC-1 SOC 2 Compliance Lab — Live Test Results Summary

**Date:** 2026-03-01  
**Environment:** Azure Subscription `<REDACTED-SUBSCRIPTION-ID>`  
**Tester:** Automated (Manus Agent)

---

## 1. Azure Environment Validation

**Script:** `scripts/validate_deployment.sh`  
**Result:** **19/19 PASS, 0 FAIL, 0 WARN**

| Check | Status |
|-------|--------|
| Resource Group: rg-aiuc1-foundry | PASS |
| Resource Group: rg-production | PASS |
| Resource Group: rg-development | PASS |
| Function App: aiuc1-soc2-tools (Running) | PASS |
| Function App: Python 3.11 runtime | PASS |
| Function App: Managed Identity enabled | PASS |
| Storage Queues: 24 queues (12 input + 12 output) | PASS |
| NSG: prod-open-nsg (RDP 3389 open) | PASS |
| NSG: dev-open-nsg (SSH 22 open) | PASS |
| Storage: aiuc1prodstorage (public blob access) | PASS |
| SQL: aiuc1-sql-server (public endpoint) | PASS |
| RBAC: Reader role on subscription | PASS |
| RBAC: Storage Queue Data Contributor | PASS |

### Bug Found & Fixed
- `validate_deployment.sh`: The `(( PASS++ ))` arithmetic expression fails under `set -euo pipefail` when `PASS=0` (returns exit code 1). Fixed by using `PASS=$((PASS + 1))` syntax.
- RBAC check for Storage Queue Data Contributor only checked subscription scope; fixed to also check storage account scope.

---

## 2. Function App Deployment

**Endpoint:** `https://aiuc1-soc2-tools.azurewebsites.net`  
**Result:** **12/12 functions deployed and verified**

| # | Function Name | Status |
|---|--------------|--------|
| 1 | gap_analyzer | Deployed |
| 2 | scan_cc_criteria | Deployed |
| 3 | evidence_validator | Deployed |
| 4 | query_access_controls | Deployed |
| 5 | query_defender_score | Deployed |
| 6 | query_policy_compliance | Deployed |
| 7 | generate_poam_entry | Deployed |
| 8 | run_terraform_plan | Deployed |
| 9 | run_terraform_apply | Deployed |
| 10 | git_commit_push | Deployed |
| 11 | sanitize_output | Deployed |
| 12 | log_security_event | Deployed |

---

## 3. Agent Registration

**Agent ID:** `asst_QvYudqOUHgi1JgGGQNo1LSyy`  
**Agent Name:** `aiuc1-soc2-compliance-agent`  
**Model:** `gpt-41-mini`  
**Tools:** 12 Azure Function tools registered

### Bug Found & Fixed
- `register_agent_tools.py`: The script tried to print `tool.name` on `AzureFunctionTool` objects which don't have a `.name` attribute. Fixed to use `tool.definition["function"]["name"]`.

### RBAC Fix Applied
- Assigned **Azure AI Developer** role to the Service Principal on the AI Hub resource to enable agent creation.

---

## 4. Terraform Initialization & Plan

**Terraform Version:** v1.14.6  
**Provider:** hashicorp/azurerm v3.117.1  
**Result:** **Plan: 5 to add, 0 to change, 0 to destroy**

| Resource | Action | Description |
|----------|--------|-------------|
| `module.nsg_remediation_prod.azurerm_network_security_rule.restrict_rdp` | Create | Restrict RDP on prod-open-nsg to 10.0.0.0/8 |
| `module.nsg_remediation_prod.azurerm_network_security_rule.restrict_ssh` | Create | Restrict SSH on prod-open-nsg to 10.0.0.0/8 |
| `module.nsg_remediation_dev.azurerm_network_security_rule.restrict_rdp` | Create | Restrict RDP on dev-open-nsg to 10.0.0.0/8 |
| `module.nsg_remediation_dev.azurerm_network_security_rule.restrict_ssh` | Create | Restrict SSH on dev-open-nsg to 10.0.0.0/8 |
| `module.storage_remediation.azurerm_storage_account.remediated` | Create | Disable public blob access on aiuc1prodstorage |

### Bug Found & Fixed
- `terraform/main.tf`: The `nsg_remediation` module passed both NSG names to a single module instance scoped to `rg-production`, but `dev-open-nsg` is in `rg-development`. Fixed by splitting into `nsg_remediation_prod` and `nsg_remediation_dev` modules with correct resource group references.
- `terraform/outputs.tf`: Updated to reference the split module names.

---

## 5. Automated Test Suite

**Framework:** pytest 9.0.2  
**Result:** **343/343 PASSED in 0.67s**  
**Code Coverage:** **78% overall**

### Test Breakdown by File

| Test File | Tests | Passed | Description |
|-----------|-------|--------|-------------|
| test_enforcement.py | 133 | 133 | AIUC-1 enforcement layer (policy engine, gateway, scope, audit chain, disclosure) |
| test_hallucination_prevention.py | 17 | 17 | D001/D002 grounding, structural grounding, system prompt grounding |
| test_integration.py | 55 | 55 | All 12 functions (gap_analyzer through log_security_event) |
| test_aiuc1_controls.py | 138 | 138 | Full AIUC-1 control framework coverage |

### Coverage by Module

| Module | Coverage |
|--------|----------|
| enforcement/ | 97-100% |
| shared/config.py | 100% |
| shared/sanitizer.py | 100% |
| shared/validators.py | 100% |
| function_app.py | 66% |
| **TOTAL** | **78%** |

### Bugs Found & Fixed
- `test_integration.py::TestRunTerraformPlan::test_missing_working_dir`: Test did not mock `os.path.isdir`, so when run on a machine with the repo cloned, the terraform directory existed and the function succeeded instead of erroring. Fixed by adding `patch("os.path.isdir", return_value=False)`.
- `test_integration.py::TestRunTerraformApply::test_valid_approval_token`: Same root cause — the terraform directory existed on the test machine. Fixed with the same `os.path.isdir` mock.

---

## 6. Summary of All Bugs Found & Fixed

| # | File | Bug | Fix | Severity |
|---|------|-----|-----|----------|
| 1 | `scripts/validate_deployment.sh` | `(( PASS++ ))` fails under `set -euo pipefail` when PASS=0 | Changed to `PASS=$((PASS + 1))` | Medium |
| 2 | `scripts/validate_deployment.sh` | RBAC check only at subscription scope | Added storage account scope check | Low |
| 3 | `scripts/register_agent_tools.py` | `tool.name` AttributeError on AzureFunctionTool | Use `tool.definition["function"]["name"]` | Low |
| 4 | `terraform/main.tf` | dev-open-nsg looked up in rg-production | Split into prod/dev module instances | High |
| 5 | `terraform/outputs.tf` | Referenced old module name | Updated to new split module names | High |
| 6 | `tests/test_integration.py` | 2 tests missing `os.path.isdir` mock | Added mock for filesystem isolation | Medium |

---

## 7. Evidence Files

| File | Description |
|------|-------------|
| `evidence/validation_output.txt` | Full validate_deployment.sh output |
| `evidence/terraform_plan_output.txt` | Full terraform plan output |
| `evidence/pytest_output.txt` | Full pytest verbose output (343 tests) |
| `evidence/pytest_coverage_output.txt` | pytest with coverage report |
| `evidence/test_results_summary.md` | This summary document |
