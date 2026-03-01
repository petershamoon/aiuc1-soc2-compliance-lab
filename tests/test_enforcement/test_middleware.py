# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Middleware Integration Tests
# ---------------------------------------------------------------------------
# End-to-end tests for the enforcement middleware that wires together
# all enforcement components into a single pipeline.
#
# Coverage:
#   - Full pipeline (input + output enforcement)
#   - Input-only enforcement
#   - Output-only enforcement
#   - Blocked request handling
#   - Enforcement metadata attachment
#   - AI disclosure injection in pipeline
#   - Enforcement context retrieval
#   - Cross-component integration
# ---------------------------------------------------------------------------

import pytest
from functions.enforcement.middleware import (
    enforce,
    enforce_input_only,
    enforce_output_only,
    get_enforcement_context,
    _init_enforcement,
)


class TestFullPipeline:
    """Test the full enforce() pipeline (input + output)."""

    def test_clean_request_passes(self):
        """A clean request with no violations must pass through."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {"cc_category": "CC5", "gaps": ["Gap 1"]},
        }
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={"cc_category": "CC5"},
            output_envelope=envelope,
            correlation_id="test-123",
        )
        assert blocked is False
        assert len(decisions) > 0  # At least sanitise + disclosure

    def test_output_is_sanitised(self):
        """Output must be sanitised even for clean requests."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {
                "secret": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc"
            },
        }
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope=envelope,
        )
        assert blocked is False
        assert "DefaultEndpointsProtocol" not in str(result["data"])

    def test_ai_disclosure_injected(self):
        """AI disclosure must be injected into every response."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {"value": "test"},
        }
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope=envelope,
        )
        assert "ai_disclosure" in result
        assert result["ai_disclosure"]["ai_generated"] is True

    def test_enforcement_metadata_attached(self):
        """Enforcement metadata must be attached to every response."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {},
        }
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope=envelope,
        )
        assert "enforcement_metadata" in result
        meta = result["enforcement_metadata"]
        assert "enforcement_layer_version" in meta
        assert meta["function_name"] == "gap_analyzer"
        assert "risk_level" in meta
        assert "policies_evaluated" in meta
        assert "gateway" in meta
        assert "audit_chain" in meta
        assert "aiuc1_controls_enforced" in meta

    def test_scope_violation_blocks_request(self):
        """Out-of-scope resource group in input must block the request."""
        envelope = {
            "status": "success",
            "function": "query_access_controls",
            "data": {},
        }
        result, blocked, decisions = enforce(
            function_name="query_access_controls",
            input_payload={"resource_group": "rg-attacker-controlled"},
            output_envelope=envelope,
        )
        assert blocked is True
        block_decisions = [d for d in decisions if d.get("action") == "block"]
        assert len(block_decisions) > 0

    def test_injection_blocks_request(self):
        """Injection patterns in input must block the request."""
        envelope = {
            "status": "success",
            "function": "generate_poam_entry",
            "data": {},
        }
        result, blocked, decisions = enforce(
            function_name="generate_poam_entry",
            input_payload={"description": "<script>alert('xss')</script>"},
            output_envelope=envelope,
        )
        assert blocked is True

    def test_blocked_response_is_still_sanitised(self):
        """Even blocked responses must be sanitised."""
        envelope = {
            "status": "success",
            "function": "query_access_controls",
            "data": {},
        }
        result, blocked, decisions = enforce(
            function_name="query_access_controls",
            input_payload={"resource_group": "rg-attacker-controlled"},
            output_envelope=envelope,
        )
        assert blocked is True
        assert result.get("sanitised") is True

    def test_decisions_list_populated(self):
        """The decisions list must contain at least sanitise and disclosure."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {},
        }
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope=envelope,
        )
        policy_ids = [d.get("policy_id") for d in decisions]
        assert "ENF-001" in policy_ids  # Sanitisation
        assert "ENF-005" in policy_ids  # Disclosure


class TestInputOnlyEnforcement:
    """Test the enforce_input_only() function."""

    def test_clean_input_passes(self):
        """Clean input must not be blocked."""
        blocked, decisions = enforce_input_only(
            "gap_analyzer",
            {"cc_category": "CC5"},
        )
        assert blocked is False

    def test_scope_violation_detected(self):
        """Out-of-scope resource groups must be detected."""
        blocked, decisions = enforce_input_only(
            "query_access_controls",
            {"resource_group": "rg-unauthorized"},
        )
        assert blocked is True
        assert len(decisions) > 0

    def test_injection_detected(self):
        """Injection patterns must be detected."""
        blocked, decisions = enforce_input_only(
            "generate_poam_entry",
            {"description": "__import__('os').system('rm -rf /')"},
        )
        assert blocked is True


class TestOutputOnlyEnforcement:
    """Test the enforce_output_only() function."""

    def test_output_sanitised(self):
        """Output must be sanitised."""
        envelope = {
            "status": "success",
            "data": {
                "secret": "DefaultEndpointsProtocol=https;AccountName=test"
            },
        }
        result = enforce_output_only("gap_analyzer", envelope)
        assert "DefaultEndpointsProtocol" not in str(result["data"])

    def test_disclosure_injected(self):
        """AI disclosure must be injected."""
        envelope = {"status": "success", "data": {}}
        result = enforce_output_only("gap_analyzer", envelope)
        assert "ai_disclosure" in result

    def test_enforcement_metadata_attached(self):
        """Enforcement metadata must be attached."""
        envelope = {"status": "success", "data": {}}
        result = enforce_output_only("gap_analyzer", envelope)
        assert "enforcement_metadata" in result


class TestEnforcementContext:
    """Test the get_enforcement_context() function."""

    def test_context_contains_policy_manifest(self):
        """Context must include the policy manifest."""
        ctx = get_enforcement_context()
        assert "policy_manifest" in ctx
        assert len(ctx["policy_manifest"]) > 0

    def test_context_contains_risk_map(self):
        """Context must include the risk map."""
        ctx = get_enforcement_context()
        assert "risk_map" in ctx
        assert "run_terraform_apply" in ctx["risk_map"]

    def test_context_contains_scope_boundaries(self):
        """Context must include scope boundaries."""
        ctx = get_enforcement_context()
        assert "scope_boundaries" in ctx
        assert "rg-aiuc1-foundry" in ctx["scope_boundaries"]

    def test_context_contains_audit_summary(self):
        """Context must include audit summary."""
        ctx = get_enforcement_context()
        assert "audit_summary" in ctx

    def test_context_contains_gateway_stats(self):
        """Context must include gateway stats."""
        ctx = get_enforcement_context()
        assert "gateway_stats" in ctx
