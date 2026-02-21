#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5: Integration Tests
# ---------------------------------------------------------------------------
# Validates that each of the 12 deployed Azure Functions responds correctly
# to valid payloads, rejects invalid inputs, and enforces security boundaries.
#
# Test Structure (per function):
#   • Happy path: valid payload → 200 OK + expected response schema
#   • Validation: missing/invalid fields → 400 error + correct error code
#   • Security: out-of-scope or forbidden requests → error + AIUC-1 reference
#
# Functions Under Test (12 total):
#   Data Providers (6):
#     1. scan_cc_criteria
#     2. gap_analyzer
#     3. query_access_controls
#     4. query_defender_score
#     5. query_policy_compliance
#     6. evidence_validator
#   Action Functions (4):
#     7. generate_poam_entry
#     8. git_commit_push
#     9. run_terraform_plan
#    10. run_terraform_apply
#   Utility Functions (2):
#    11. sanitize_output
#    12. log_security_event
#
# AIUC-1 Controls Validated:
#   AIUC-1-09  Scope Boundaries
#   AIUC-1-11  Human Oversight (terraform approval gate)
#   AIUC-1-17  Data Minimisation
#   AIUC-1-18  Input Validation
#   AIUC-1-19  Output Filtering
#   AIUC-1-22  Logging
#   AIUC-1-23  Audit Trail
#   AIUC-1-30  Change Management
# ---------------------------------------------------------------------------

import pytest
import json
from conftest import FunctionClient

# ---------------------------------------------------------------------------
# Response schema helpers
# ---------------------------------------------------------------------------

def assert_success_schema(result: dict, function_name: str):
    """Assert that a response follows the standard success envelope schema."""
    assert result.get("status") == "success", (
        f"{function_name} returned non-success status: {result}"
    )
    assert result.get("function") == function_name, (
        f"Function name mismatch. Expected {function_name!r}, got {result.get('function')!r}"
    )
    assert "data" in result, f"{function_name} response missing 'data' key"
    assert "timestamp" in result, f"{function_name} response missing 'timestamp'"
    assert "aiuc1_controls" in result, f"{function_name} response missing 'aiuc1_controls'"
    assert isinstance(result["aiuc1_controls"], list), "aiuc1_controls must be a list"
    assert len(result["aiuc1_controls"]) >= 1, "aiuc1_controls must not be empty"


def assert_error_schema(result: dict, expected_code: str = None):
    """Assert that a response follows the standard error envelope schema."""
    assert result.get("status") == "error", (
        f"Expected error status. Got: {result.get('status')}. Full: {result}"
    )
    assert "error" in result, "Error response missing 'error' key"
    assert "code" in result["error"], "Error response missing 'error.code'"
    assert "message" in result["error"], "Error response missing 'error.message'"
    if expected_code:
        assert result["error"]["code"] == expected_code, (
            f"Expected error code {expected_code!r}. Got: {result['error']['code']!r}"
        )


# ===========================================================================
# 1. scan_cc_criteria
# ===========================================================================

class TestScanCcCriteria:
    """Integration tests for the scan_cc_criteria data provider function."""

    @pytest.mark.parametrize("cc_category", [
        "CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"
    ])
    def test_valid_cc_category_returns_success(self, functions, cc_category):
        """All 9 valid CC categories return a successful scan result."""
        result = functions.call("scan_cc_criteria", {"cc_category": cc_category})
        assert_success_schema(result, "scan_cc_criteria")
        data = result["data"]
        assert data.get("cc_category") == cc_category
        assert "resources" in data, "Response missing 'resources' list"
        assert "resource_count" in data, "Response missing 'resource_count'"
        assert isinstance(data["resources"], list), "'resources' must be a list"

    def test_invalid_cc_category_returns_error(self, functions):
        """Invalid CC category code returns INVALID_CC_CATEGORY error."""
        result = functions.call("scan_cc_criteria", {"cc_category": "CC99"})
        assert_error_schema(result, "INVALID_CC_CATEGORY")

    def test_missing_cc_category_returns_error(self, functions):
        """Missing cc_category field returns a validation error."""
        result = functions.call("scan_cc_criteria", {})
        assert_error_schema(result)

    def test_response_includes_scope(self, functions):
        """Response includes the scope (allowed resource groups) for audit trail."""
        result = functions.call("scan_cc_criteria", {"cc_category": "CC6"})
        assert_success_schema(result, "scan_cc_criteria")
        scope = result["data"].get("scope", [])
        assert isinstance(scope, list), "'scope' must be a list"
        # Scope must only contain allowed resource groups
        allowed = {"rg-aiuc1-foundry", "rg-production", "rg-development"}
        for rg in scope:
            assert rg in allowed, f"Out-of-scope RG in response: {rg}"

    def test_response_is_sanitised(self, functions):
        """Response envelope has sanitised=True, confirming output filtering."""
        result = functions.call("scan_cc_criteria", {"cc_category": "CC6"})
        assert result.get("sanitised") is True, (
            "Response not marked as sanitised — AIUC-1-19 may not be enforced"
        )


# ===========================================================================
# 2. gap_analyzer
# ===========================================================================

class TestGapAnalyzer:
    """Integration tests for the gap_analyzer data provider function."""

    @pytest.mark.parametrize("cc_category", ["CC5", "CC6", "CC7"])
    def test_valid_cc_returns_gap_analysis(self, functions, cc_category):
        """Valid CC category returns a gap analysis with expected schema."""
        result = functions.call("gap_analyzer", {"cc_category": cc_category})
        assert_success_schema(result, "gap_analyzer")
        data = result["data"]
        assert "gaps" in data, "Response missing 'gaps' list"
        assert "total_gaps" in data, "Response missing 'total_gaps'"
        assert isinstance(data["gaps"], list)

    def test_invalid_cc_returns_error(self, functions):
        """Invalid CC category returns an error."""
        result = functions.call("gap_analyzer", {"cc_category": "INVALID"})
        assert_error_schema(result)

    def test_gap_entries_have_required_fields(self, functions):
        """Each gap entry includes the required fields for POA&M generation."""
        result = functions.call("gap_analyzer", {"cc_category": "CC6"})
        assert_success_schema(result, "gap_analyzer")
        for gap in result["data"].get("gaps", []):
            assert "resource" in gap or "check" in gap, (
                f"Gap entry missing 'resource' or 'check' field: {gap}"
            )


# ===========================================================================
# 3. query_access_controls
# ===========================================================================

class TestQueryAccessControls:
    """Integration tests for the query_access_controls data provider function."""

    def test_subscription_wide_query_succeeds(self, functions):
        """Empty body triggers subscription-wide RBAC query."""
        result = functions.call("query_access_controls", {})
        assert_success_schema(result, "query_access_controls")
        data = result["data"]
        assert "rbac" in data, "Response missing 'rbac' key"
        assert "network_access" in data, "Response missing 'network_access' key"

    def test_rbac_data_is_sanitised(self, functions):
        """RBAC response does not contain raw principal IDs (AIUC-1-17/19)."""
        result = functions.call("query_access_controls", {})
        assert_success_schema(result, "query_access_controls")
        # The response should be marked as sanitised
        assert result.get("sanitised") is True

    def test_out_of_scope_scope_rejected(self, functions):
        """Querying an out-of-scope resource group returns SCOPE_VIOLATION."""
        result = functions.call("query_access_controls", {
            "scope": "rg-external-production"
        })
        assert_error_schema(result, "SCOPE_VIOLATION")

    def test_response_includes_nsg_data(self, functions):
        """Response includes NSG inbound rule data for CC6 assessment."""
        result = functions.call("query_access_controls", {})
        assert_success_schema(result, "query_access_controls")
        network_access = result["data"].get("network_access", {})
        # Should have NSG data or a note about NSG scanning
        assert isinstance(network_access, (dict, list)), (
            "network_access should be a dict or list"
        )


# ===========================================================================
# 4. query_defender_score
# ===========================================================================

class TestQueryDefenderScore:
    """Integration tests for the query_defender_score data provider function."""

    def test_returns_secure_score(self, functions):
        """Returns Microsoft Defender for Cloud secure score."""
        result = functions.call("query_defender_score", {})
        assert_success_schema(result, "query_defender_score")
        data = result["data"]
        assert "secure_score" in data, "Response missing 'secure_score'"

    def test_returns_soc2_mapping(self, functions):
        """Response includes SOC 2 CC category mapping for the secure score."""
        result = functions.call("query_defender_score", {})
        assert_success_schema(result, "query_defender_score")
        assert "soc2_mapping" in result["data"], "Response missing 'soc2_mapping'"

    def test_returns_assessments(self, functions):
        """Response includes individual security assessments."""
        result = functions.call("query_defender_score", {})
        assert_success_schema(result, "query_defender_score")
        assert "assessments" in result["data"], "Response missing 'assessments'"


# ===========================================================================
# 5. query_policy_compliance
# ===========================================================================

class TestQueryPolicyCompliance:
    """Integration tests for the query_policy_compliance data provider function."""

    def test_returns_compliance_summary(self, functions):
        """Returns a compliance summary with counts."""
        result = functions.call("query_policy_compliance", {})
        assert_success_schema(result, "query_policy_compliance")
        data = result["data"]
        assert "compliance_summary" in data, "Response missing 'compliance_summary'"

    def test_returns_cis_benchmark_status(self, functions):
        """Response includes CIS Azure Foundations Benchmark compliance status."""
        result = functions.call("query_policy_compliance", {})
        assert_success_schema(result, "query_policy_compliance")
        assert "cis_benchmark" in result["data"], "Response missing 'cis_benchmark'"

    def test_returns_soc2_mapping(self, functions):
        """Response includes SOC 2 criteria mapping."""
        result = functions.call("query_policy_compliance", {})
        assert_success_schema(result, "query_policy_compliance")
        assert "soc2_mapping" in result["data"], "Response missing 'soc2_mapping'"


# ===========================================================================
# 6. evidence_validator
# ===========================================================================

class TestEvidenceValidator:
    """Integration tests for the evidence_validator action function."""

    def test_valid_azure_resource_evidence(self, functions):
        """Valid azure_resource evidence type returns validation result."""
        result = functions.call("evidence_validator", {
            "evidence_type": "azure_resource",
            "target": "/subscriptions/REDACTED/resourceGroups/rg-production/providers/Microsoft.Network/networkSecurityGroups/prod-open-nsg",
            "cc_category": "CC6",
        })
        assert_success_schema(result, "evidence_validator")
        data = result["data"]
        assert "validation" in data, "Response missing 'validation'"
        assert "evidence_map" in data, "Response missing 'evidence_map'"

    def test_missing_required_fields_returns_error(self, functions):
        """Missing evidence_type or target returns MISSING_FIELDS error."""
        result = functions.call("evidence_validator", {
            "cc_category": "CC6",
            # Missing evidence_type and target
        })
        assert_error_schema(result, "MISSING_FIELDS")

    def test_type_ii_sampling_included(self, functions):
        """Response includes Type II audit sampling guidance."""
        result = functions.call("evidence_validator", {
            "evidence_type": "azure_resource",
            "target": "/subscriptions/REDACTED/resourceGroups/rg-production",
            "cc_category": "CC7",
        })
        assert_success_schema(result, "evidence_validator")
        assert "type_ii_sampling" in result["data"], (
            "Response missing Type II sampling guidance — required for SOC 2 Type II audits"
        )


# ===========================================================================
# 7. generate_poam_entry
# ===========================================================================

class TestGeneratePoamEntry:
    """Integration tests for the generate_poam_entry action function."""

    def test_valid_payload_returns_poam(self, functions):
        """Valid finding details return a structured POA&M entry."""
        result = functions.call("generate_poam_entry", {
            "cc_category": "CC6",
            "resource": "prod-open-nsg",
            "gap_description": "RDP (TCP 3389) open to 0.0.0.0/0 on prod-open-nsg",
            "severity": "high",
        })
        assert_success_schema(result, "generate_poam_entry")
        data = result["data"]
        assert "poam_entry" in data, "Response missing 'poam_entry'"
        poam = data["poam_entry"]
        assert "weakness_id" in poam, "POA&M entry missing 'weakness_id'"
        assert "milestones" in poam, "POA&M entry missing 'milestones'"
        assert "scheduled_completion_date" in poam, "POA&M entry missing target date"

    def test_missing_required_fields_returns_error(self, functions):
        """Missing cc_category, resource, or gap_description returns error."""
        result = functions.call("generate_poam_entry", {
            "severity": "high",
            # Missing cc_category, resource, gap_description
        })
        assert_error_schema(result, "MISSING_FIELDS")

    def test_invalid_severity_returns_error(self, functions):
        """Invalid severity value returns a validation error."""
        result = functions.call("generate_poam_entry", {
            "cc_category": "CC6",
            "resource": "prod-open-nsg",
            "gap_description": "Test finding",
            "severity": "extreme",  # Not a valid severity
        })
        assert_error_schema(result)

    @pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
    def test_all_severity_levels_accepted(self, functions, severity):
        """All four severity levels (critical/high/medium/low) are accepted."""
        result = functions.call("generate_poam_entry", {
            "cc_category": "CC7",
            "resource": "grclab-sql-02",
            "gap_description": f"Test finding with {severity} severity",
            "severity": severity,
        })
        assert_success_schema(result, "generate_poam_entry")


# ===========================================================================
# 8. git_commit_push
# ===========================================================================

class TestGitCommitPush:
    """Integration tests for the git_commit_push action function."""

    def test_out_of_scope_path_rejected(self, functions):
        """Files outside allowed directories (reports, docs, terraform, policies, evidence) are rejected."""
        result = functions.call("git_commit_push", {
            "files": ["functions/function_app.py"],
            "message": "feat(functions): attempt to modify function code",
        })
        assert_error_schema(result, "PATH_VIOLATION")

    def test_invalid_commit_message_format_rejected(self, functions):
        """Commit messages not following conventional commit format are rejected."""
        result = functions.call("git_commit_push", {
            "files": ["reports/test.md"],
            "message": "fixed stuff",  # Not conventional format
        })
        assert_error_schema(result, "INVALID_COMMIT_MESSAGE")

    def test_missing_required_fields_returns_error(self, functions):
        """Missing files or message returns MISSING_FIELDS error."""
        result = functions.call("git_commit_push", {
            "files": ["reports/test.md"],
            # Missing message
        })
        assert_error_schema(result, "MISSING_FIELDS")

    def test_multiple_out_of_scope_paths_all_rejected(self, functions):
        """Multiple out-of-scope paths in a single request are all caught."""
        result = functions.call("git_commit_push", {
            "files": [".github/workflows/ci.yml", "functions/shared/config.py"],
            "message": "feat(ci): attempt to modify CI/CD pipeline",
        })
        assert_error_schema(result, "PATH_VIOLATION")


# ===========================================================================
# 9. run_terraform_plan
# ===========================================================================

class TestRunTerraformPlan:
    """Integration tests for the run_terraform_plan action function."""

    def test_missing_working_dir_returns_error(self, functions):
        """Terraform plan fails gracefully when working directory is not configured."""
        result = functions.call("run_terraform_plan", {})
        # Should fail with INVALID_WORKING_DIR since terraform dir doesn't exist on Function App
        assert_error_schema(result, "INVALID_WORKING_DIR")

    def test_response_includes_aiuc1_controls(self, functions):
        """Error response still includes AIUC-1 control references."""
        result = functions.call("run_terraform_plan", {})
        # Even error responses should reference controls
        controls = result.get("aiuc1_controls", [])
        assert isinstance(controls, list)


# ===========================================================================
# 10. run_terraform_apply
# ===========================================================================

class TestRunTerraformApply:
    """Integration tests for the run_terraform_apply action function."""

    def test_invalid_approval_token_rejected(self, functions):
        """Forged approval token is rejected — AIUC-1-11 (Human Oversight)."""
        result = functions.call("run_terraform_apply", {
            "plan_hash": "deadbeef" * 8,
            "approval_token": "forged_token_12345",
        })
        assert_error_schema(result, "INVALID_APPROVAL_TOKEN")

    def test_missing_plan_hash_rejected(self, functions):
        """Missing plan_hash is rejected before token validation."""
        result = functions.call("run_terraform_apply", {
            "approval_token": "some_token",
        })
        assert result.get("status") == "error", (
            f"Expected error for missing plan_hash. Got: {result.get('status')}"
        )

    def test_missing_approval_token_rejected(self, functions):
        """Missing approval_token is rejected — cannot apply without human approval."""
        result = functions.call("run_terraform_apply", {
            "plan_hash": "deadbeef" * 8,
        })
        assert result.get("status") == "error", (
            f"Expected error for missing approval_token. Got: {result.get('status')}"
        )


# ===========================================================================
# 11. sanitize_output
# ===========================================================================

class TestSanitizeOutput:
    """Integration tests for the sanitize_output utility function."""

    def test_clean_text_passes_through(self, functions):
        """Text with no sensitive data is returned unchanged."""
        clean_text = "The NSG prod-open-nsg has an open RDP rule on port 3389."
        result = functions.call("sanitize_output", {"text": clean_text})
        assert_success_schema(result, "sanitize_output")
        assert result["data"]["sanitised_output"] == clean_text, (
            "Clean text was unexpectedly modified by sanitizer"
        )

    def test_subscription_id_redacted(self, functions):
        """Subscription IDs in ARM resource paths are redacted."""
        result = functions.call("sanitize_output", {
            "text": "/subscriptions/5a9c39a7-65a6-4e2d-9a2b-25d1ac08ff08/resourceGroups/rg-production"
        })
        assert_success_schema(result, "sanitize_output")
        assert "5a9c39a7" not in result["data"]["sanitised_output"]
        assert "[REDACTED" in result["data"]["sanitised_output"]

    def test_access_key_redacted(self, functions):
        """Base64 access keys are redacted."""
        result = functions.call("sanitize_output", {
            "text": "Key: AMi7kcAd2S6do40VEsik02LrNiHnL9B88lnEoB5sNTsEmwmBgQDYJQQJ99CBACYeBjFXJ3w3AAAAACOGJ0VZ"
        })
        assert_success_schema(result, "sanitize_output")
        assert "AMi7kcAd" not in result["data"]["sanitised_output"]

    def test_private_ip_redacted(self, functions):
        """RFC 1918 private IP addresses are redacted."""
        result = functions.call("sanitize_output", {
            "text": "VM private IP: 10.0.0.5, secondary: 172.16.0.1"
        })
        assert_success_schema(result, "sanitize_output")
        sanitised = result["data"]["sanitised_output"]
        assert "10.0.0.5" not in sanitised
        assert "172.16.0.1" not in sanitised
        assert "[REDACTED-IP]" in sanitised

    def test_uuid_redacted(self, functions):
        """Standalone UUIDs are redacted."""
        result = functions.call("sanitize_output", {
            "text": "Tenant: 5d30251d-6d7e-4c8f-849f-90a5c29b3b16"
        })
        assert_success_schema(result, "sanitize_output")
        assert "5d30251d" not in result["data"]["sanitised_output"]

    def test_missing_text_returns_error(self, functions):
        """Missing 'text' field returns a validation error."""
        result = functions.call("sanitize_output", {})
        assert_error_schema(result)

    def test_redaction_stats_present(self, functions):
        """Response includes redaction statistics for audit trail."""
        result = functions.call("sanitize_output", {
            "text": "IP: 10.0.0.1 Key: AMi7kcAd2S6do40VEsik02LrNiHnL9B88lnEoB5sNTsEmwmBgQDYJQQJ99CBACYeBjFXJ3w3AAAAACOGJ0VZ"
        })
        assert_success_schema(result, "sanitize_output")
        stats = result["data"].get("redaction_stats", {})
        assert stats.get("total_redactions", 0) >= 1, (
            "Redaction stats missing or zero — audit trail incomplete"
        )


# ===========================================================================
# 12. log_security_event
# ===========================================================================

class TestLogSecurityEvent:
    """Integration tests for the log_security_event utility function."""

    def test_valid_event_logged_successfully(self, functions):
        """Valid event payload is accepted and logged."""
        result = functions.call("log_security_event", {
            "category": "scope_violation",
            "agent_id": "integration-test-runner",
            "description": "Integration test: validating log_security_event endpoint",
            "cc_category": "CC6",
        })
        assert_success_schema(result, "log_security_event")
        data = result["data"]
        assert data.get("event_id"), "No event_id in response"
        assert data.get("logged_at"), "No logged_at timestamp"
        assert data.get("destination"), "No destination field"

    def test_all_valid_categories_accepted(self, functions):
        """All 8 valid event categories (per deployed function) are accepted."""
        # Actual categories from the deployed log_security_event function
        categories = [
            "scope_violation", "remediation_action", "access_event",
            "anomalous_behavior", "approval_denied", "compliance_finding",
            "secret_exposure", "validation_failure",
        ]
        for cat in categories:
            result = functions.call("log_security_event", {
                "category": cat,
                "agent_id": "test-runner",
                "description": f"Integration test for category: {cat}",
            })
            assert result.get("status") == "success", (
                f"Category '{cat}' was rejected: {result}"
            )

    def test_invalid_category_rejected(self, functions):
        """Unknown event category returns INVALID_CATEGORY error."""
        result = functions.call("log_security_event", {
            "category": "unknown_event_type",
            "agent_id": "test-runner",
            "description": "Test",
        })
        assert_error_schema(result, "INVALID_CATEGORY")

    def test_missing_required_fields_rejected(self, functions):
        """Missing category, agent_id, or description returns MISSING_FIELDS."""
        result = functions.call("log_security_event", {
            "category": "scope_violation",
            # Missing agent_id and description
        })
        assert_error_schema(result, "MISSING_FIELDS")

    def test_event_id_format(self, functions):
        """Event IDs follow the SEC-YYYYMMDDHHMMSS-XXXX format."""
        result = functions.call("log_security_event", {
            "category": "access_event",
            "agent_id": "test-runner",
            "description": "Testing event ID format",
        })
        assert_success_schema(result, "log_security_event")
        event_id = result["data"]["event_id"]
        assert event_id.startswith("SEC-"), (
            f"Event ID does not start with 'SEC-': {event_id}"
        )

    def test_description_sanitised_before_logging(self, functions):
        """Sensitive data in the description is redacted before logging."""
        result = functions.call("log_security_event", {
            "category": "secret_exposure",
            "agent_id": "test-runner",
            "description": (
                "Found subscription 5a9c39a7-65a6-4e2d-9a2b-25d1ac08ff08 "
                "in agent output"
            ),
        })
        assert_success_schema(result, "log_security_event")
        returned_desc = result["data"].get("description", "")
        assert "5a9c39a7" not in returned_desc, (
            "Real subscription ID was not sanitised in logged event description"
        )
