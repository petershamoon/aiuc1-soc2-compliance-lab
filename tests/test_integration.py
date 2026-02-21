#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5: Integration Tests (DB-enabled)
# ---------------------------------------------------------------------------
# Validates all 12 Azure Functions with real HTTP calls.
# Results are written to Azure Table Storage (TestResults table) via the
# result_recorder fixture defined in conftest.py.
#
# Correct payloads confirmed via live curl testing on 2026-02-21.
# ---------------------------------------------------------------------------
import pytest
import json
from conftest import FunctionClient

# --- Helpers ---
def assert_success_schema(result: dict, function_name: str):
    assert result.get("status") == "success", \
        f"{function_name} returned non-success: {result}"
    assert result.get("function") == function_name, \
        f"Function name mismatch. Expected {function_name!r}, got {result.get('function')!r}"
    assert "data" in result, f"{function_name} response missing 'data' key"

def assert_error_schema(result: dict, expected_code: str = None):
    assert result.get("status") == "error", \
        f"Expected error status. Got: {result.get('status')}. Full: {result}"
    assert "error" in result, "Error response missing 'error' key"
    if expected_code:
        assert result["error"].get("code") == expected_code, \
            f"Expected error code {expected_code!r}. Got: {result['error'].get('code')!r}"

# ===========================================================================
# 1. scan_cc_criteria
# ===========================================================================
class TestScanCcCriteria:
    @pytest.mark.parametrize("cc_category", ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"])
    def test_valid_cc_category(self, functions, result_recorder, cc_category):
        result = functions.call("scan_cc_criteria", {"cc_category": cc_category})
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail=f"Scan for {cc_category}",
            function_name="scan_cc_criteria",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "scan_cc_criteria")

    def test_invalid_cc_category(self, functions, result_recorder):
        result = functions.call("scan_cc_criteria", {"cc_category": "CC99"})
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Invalid CC category rejected",
            function_name="scan_cc_criteria",
            response_body=json.dumps(result)
        )
        assert_error_schema(result, "INVALID_CC_CATEGORY")

# ===========================================================================
# 2. gap_analyzer
# ===========================================================================
class TestGapAnalyzer:
    @pytest.mark.parametrize("cc_category", ["CC5", "CC6", "CC7"])
    def test_valid_cc_category(self, functions, result_recorder, cc_category):
        result = functions.call("gap_analyzer", {"cc_category": cc_category})
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail=f"Gap analysis for {cc_category}",
            function_name="gap_analyzer",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "gap_analyzer")

# ===========================================================================
# 3. query_access_controls
# ===========================================================================
class TestQueryAccessControls:
    def test_subscription_wide_query(self, functions, result_recorder):
        result = functions.call("query_access_controls", {})
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail="Subscription-wide RBAC query",
            function_name="query_access_controls",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "query_access_controls")

    def test_out_of_scope_rejection(self, functions, result_recorder):
        result = functions.call("query_access_controls", {"scope": "rg-external-production"})
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Out-of-scope RG rejected",
            function_name="query_access_controls",
            response_body=json.dumps(result),
            control_ids=["B006"]
        )
        assert_error_schema(result, "SCOPE_VIOLATION")

# ===========================================================================
# 4. query_defender_score
# ===========================================================================
class TestQueryDefenderScore:
    def test_returns_secure_score(self, functions, result_recorder):
        result = functions.call("query_defender_score", {})
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail="Query Defender score",
            function_name="query_defender_score",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "query_defender_score")

# ===========================================================================
# 5. query_policy_compliance
# ===========================================================================
class TestQueryPolicyCompliance:
    def test_returns_compliance_summary(self, functions, result_recorder):
        result = functions.call("query_policy_compliance", {})
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail="Query policy compliance",
            function_name="query_policy_compliance",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "query_policy_compliance")

# ===========================================================================
# 6. evidence_validator
# ===========================================================================
class TestEvidenceValidator:
    def test_valid_azure_resource_evidence(self, functions, result_recorder):
        result = functions.call("evidence_validator", {
            "evidence_type": "azure_resource",
            "target": "/subscriptions/REDACTED/resourceGroups/rg-production/providers/Microsoft.Network/networkSecurityGroups/prod-open-nsg",
            "cc_category": "CC6"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail="Valid evidence validation",
            function_name="evidence_validator",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "evidence_validator")

# ===========================================================================
# 7. generate_poam_entry
# ===========================================================================
class TestGeneratePoamEntry:
    def test_valid_payload_returns_poam(self, functions, result_recorder):
        result = functions.call("generate_poam_entry", {
            "cc_category": "CC6",
            "resource": "prod-open-nsg",
            "gap_description": "RDP open to 0.0.0.0/0 violates CC6.1",
            "severity": "high"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail="Generate POA&M entry",
            function_name="generate_poam_entry",
            response_body=json.dumps(result)
        )
        assert_success_schema(result, "generate_poam_entry")

# ===========================================================================
# 8. git_commit_push
# Allowed directories: policies, evidence, reports, docs, terraform
# Commit message must follow: type(scope): description (10-200 chars)
# ===========================================================================
class TestGitCommitPush:
    def test_out_of_scope_path_rejected(self, functions, result_recorder):
        """Files outside allowed dirs (policies/evidence/reports/docs/terraform) must be rejected."""
        result = functions.call("git_commit_push", {
            "files": ["functions/function_app.py"],
            "message": "feat(iac): modify core function app code"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Out-of-scope path rejected (PATH_VIOLATION)",
            function_name="git_commit_push",
            response_body=json.dumps(result),
            control_ids=["B006"]
        )
        assert_error_schema(result, "PATH_VIOLATION")

    def test_invalid_commit_message_rejected(self, functions, result_recorder):
        """Commit messages not following conventional format must be rejected."""
        result = functions.call("git_commit_push", {
            "files": ["reports/test.md"],
            "message": "fixed stuff"  # Too short, no type(scope): prefix
        })
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Invalid commit message rejected (INVALID_COMMIT_MESSAGE)",
            function_name="git_commit_push",
            response_body=json.dumps(result),
            control_ids=["B006"]
        )
        assert_error_schema(result, "INVALID_COMMIT_MESSAGE")

# ===========================================================================
# 9. run_terraform_plan
# ===========================================================================
class TestRunTerraformPlan:
    def test_invalid_working_dir(self, functions, result_recorder):
        result = functions.call("run_terraform_plan", {})
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Missing working_dir handled with INVALID_WORKING_DIR",
            function_name="run_terraform_plan",
            response_body=json.dumps(result)
        )
        assert_error_schema(result, "INVALID_WORKING_DIR")

# ===========================================================================
# 10. run_terraform_apply
# ===========================================================================
class TestRunTerraformApply:
    def test_invalid_approval_token_rejected(self, functions, result_recorder):
        result = functions.call("run_terraform_apply", {
            "plan_hash": "deadbeef",
            "approval_token": "forged"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Invalid approval token rejected (INVALID_APPROVAL_TOKEN)",
            function_name="run_terraform_apply",
            response_body=json.dumps(result),
            control_ids=["D003"]
        )
        assert_error_schema(result, "INVALID_APPROVAL_TOKEN")

# ===========================================================================
# 11. sanitize_output
# ===========================================================================
class TestSanitizeOutput:
    def test_subscription_id_redacted(self, functions, result_recorder):
        result = functions.call("sanitize_output", {
            "text": "/subscriptions/5a9c39a7-65a6-4e2d-9a2b-25d1ac08ff08/rg"
        })
        sanitised = result.get("data", {}).get("sanitised_output", "")
        passed = "[REDACTED" in sanitised and "5a9c39a7" not in sanitised
        result_recorder(
            outcome="passed" if passed else "failed",
            detail="Subscription ID redacted from output",
            function_name="sanitize_output",
            response_body=json.dumps(result),
            control_ids=["A004", "A006"]
        )
        assert_success_schema(result, "sanitize_output")
        assert "5a9c39a7" not in sanitised, \
            f"Subscription ID not redacted. Output: {sanitised}"

# ===========================================================================
# 12. log_security_event
# Valid categories: access_event, anomalous_behavior, approval_denied,
#   compliance_finding, remediation_action, scope_violation,
#   secret_exposure, validation_failure
# Required fields: category, agent_id, description
# ===========================================================================
class TestLogSecurityEvent:
    @pytest.mark.parametrize("category", [
        "access_event", "anomalous_behavior", "approval_denied",
        "compliance_finding", "remediation_action", "scope_violation",
        "secret_exposure", "validation_failure"
    ])
    def test_valid_category_logged(self, functions, result_recorder, category):
        result = functions.call("log_security_event", {
            "category": category,
            "agent_id": "phase5-test-runner",
            "description": f"Phase 5 integration test: {category} event fired"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "success" else "failed",
            detail=f"log_security_event category={category}",
            function_name="log_security_event",
            response_body=json.dumps(result),
            control_ids=["E015"]
        )
        assert_success_schema(result, "log_security_event")

    def test_invalid_category_rejected(self, functions, result_recorder):
        result = functions.call("log_security_event", {
            "category": "invalid_category",
            "agent_id": "phase5-test-runner",
            "description": "This should be rejected"
        })
        result_recorder(
            outcome="passed" if result.get("status") == "error" else "failed",
            detail="Invalid category rejected (INVALID_CATEGORY)",
            function_name="log_security_event",
            response_body=json.dumps(result),
            control_ids=["E015"]
        )
        assert_error_schema(result, "INVALID_CATEGORY")
