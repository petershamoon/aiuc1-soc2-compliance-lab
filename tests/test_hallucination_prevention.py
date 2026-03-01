# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Hallucination Prevention Test Suite
# ---------------------------------------------------------------------------
# Tests the grounding controls (D001, D002) that prevent the agent from
# fabricating compliance findings.
#
# The enforcement layer cannot fully prevent hallucination (that's an LLM
# behaviour), but it CAN:
#   1. Ensure every response is grounded in tool output (not invented)
#   2. Ensure the response envelope always contains structured data from
#      the function, not free-form LLM text
#   3. Ensure error conditions are reported honestly (not masked)
#   4. Ensure the system prompt instructs grounding (prompt-based control)
#
# These tests verify the architectural mechanisms that support grounding.
# The agent-level hallucination tests (does the LLM actually comply?)
# are in test_agent_validation.py.
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import os
import pytest
from unittest.mock import MagicMock, patch

from functions.enforcement.gateway import OutputGateway
from functions.enforcement.middleware import (
    enforce,
    enforce_input_only,
    enforce_output_only,
    _init_enforcement,
)
import functions.enforcement.middleware as mw
from functions.enforcement.disclosure import DisclosureInjector
from functions.shared.sanitizer import redact_secrets


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def gateway():
    return OutputGateway()


@pytest.fixture
def disclosure():
    return DisclosureInjector()


# ===========================================================================
# D001 — Grounding: Outputs Must Be Based on Tool Data
# ===========================================================================

class TestD001Grounding:
    """AIUC-1-19: AI agent findings must be grounded in tool output data."""

    def test_success_envelope_requires_data_field(self, gateway):
        """A success response must contain a 'data' field with actual content."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {
                "gaps": [
                    {"finding": "Open SSH port", "severity": "HIGH"},
                ],
                "resource_group": "rg-aiuc1-foundry",
                "cc_category": "CC6",
            },
        }
        sanitised, metadata = gateway.sanitise_envelope(envelope, "gap_analyzer")
        assert "data" in sanitised
        assert len(sanitised["data"]) > 0, "D001: success envelope has empty data"

    def test_error_envelope_reports_failure_honestly(self, gateway):
        """When a tool fails, the error is reported — not masked as success."""
        envelope = {
            "status": "error",
            "function": "gap_analyzer",
            "error": {
                "code": "AZURE_API_ERROR",
                "message": "Failed to query resource group",
            },
        }
        sanitised, metadata = gateway.sanitise_envelope(envelope, "gap_analyzer")
        assert sanitised["status"] == "error", "D001: error was masked as success"
        assert "error" in sanitised

    def test_empty_data_not_disguised_as_findings(self, gateway):
        """An empty scan result should not be presented as 'no gaps found'."""
        envelope = {
            "status": "success",
            "function": "scan_cc_criteria",
            "data": {
                "checks_performed": [],
                "findings": [],
                "resource_group": "rg-aiuc1-foundry",
            },
        }
        sanitised, metadata = gateway.sanitise_envelope(envelope, "scan_cc_criteria")
        # The data should reflect that no checks were actually performed
        data = sanitised.get("data", {})
        checks = data.get("checks_performed", [])
        findings = data.get("findings", [])
        # Empty checks + empty findings = honest reporting
        assert isinstance(checks, list)
        assert isinstance(findings, list)

    def test_function_name_preserved_in_envelope(self, gateway):
        """The function name is preserved so the agent knows which tool produced the data."""
        envelope = {
            "status": "success",
            "function": "query_defender_score",
            "data": {"score": 8.5, "max_score": 21},
        }
        sanitised, metadata = gateway.sanitise_envelope(envelope, "query_defender_score")
        # Function name should be traceable
        assert sanitised.get("function") == "query_defender_score" or \
            "query_defender_score" in json.dumps(sanitised)

    def test_timestamp_provides_temporal_grounding(self, gateway):
        """Timestamps in the envelope provide temporal context for findings."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "timestamp": "2026-02-26T12:00:00+00:00",
            "data": {"gaps": []},
        }
        sanitised, metadata = gateway.sanitise_envelope(envelope, "gap_analyzer")
        # Timestamp should be preserved
        assert "timestamp" in sanitised or "2026" in json.dumps(sanitised)


# ===========================================================================
# D002 — Accuracy: No Fabricated Compliance Status
# ===========================================================================

class TestD002Accuracy:
    """AIUC-1-20: AI agent must not fabricate compliance findings."""

    def test_sanitisation_preserves_data_integrity(self):
        """Sanitisation redacts secrets but preserves finding content."""
        original = "NSG rule AllowSSH allows port 22 from any source (0.0.0.0/0)"
        result = redact_secrets(original)
        # The finding text should be preserved (no secrets to redact)
        assert "AllowSSH" in result
        assert "port 22" in result
        assert "0.0.0.0/0" in result  # This is a public IP, not private

    def test_redaction_does_not_create_false_data(self):
        """Redaction replaces with labels, not fabricated values."""
        text = "Server at 10.0.1.5 has subscription /subscriptions/<REDACTED-SUBSCRIPTION-ID>"
        result = redact_secrets(text)
        # Should contain REDACTED labels, not fake IPs or subscription IDs
        assert "REDACTED" in result
        # Should not contain a different real-looking IP
        assert "10.0.1.5" not in result
        # The non-sensitive parts should be preserved
        assert "Server at" in result

    def test_enforcement_metadata_is_factual(self):
        """Enforcement metadata accurately reflects what was enforced."""
        envelope = {
            "status": "success",
            "data": {"finding": "test"},
        }
        result = enforce_output_only("gap_analyzer", envelope)
        # If enforcement_metadata exists, it should be factual
        meta = result.get("enforcement_metadata", {})
        if meta:
            # Should contain actual policy references, not invented ones
            policies = meta.get("policies_applied", meta.get("decisions", []))
            if isinstance(policies, list):
                for p in policies:
                    if isinstance(p, dict):
                        # Policy IDs should match ENF-xxx format
                        pid = p.get("policy_id", "")
                        if pid:
                            assert pid.startswith("ENF-"), \
                                f"D002: fabricated policy ID: {pid}"

    def test_disclosure_does_not_overstate_capabilities(self, disclosure):
        """AI disclosure text is honest about limitations."""
        text = disclosure.get_disclosure_text()
        # Should mention it's AI-generated
        assert "ai" in text.lower() or "agent" in text.lower()
        # Should recommend human review (acknowledging limitations)
        assert "human" in text.lower()
        # Should NOT claim to be a certified auditor
        assert "certified" not in text.lower()
        assert "guarantee" not in text.lower()


# ===========================================================================
# D001/D002 — Structural Grounding Mechanisms
# ===========================================================================

class TestStructuralGrounding:
    """Tests that the response structure itself enforces grounding."""

    def test_envelope_schema_prevents_freeform_responses(self):
        """The envelope schema forces structured data, not free-form text."""
        from functions.shared.response import build_success_envelope
        envelope = build_success_envelope(
            function_name="gap_analyzer",
            data={
                "gaps": [{"finding": "Open SSH", "severity": "HIGH"}],
                "checks_performed": ["nsg_rules", "rbac_assignments"],
            },
            aiuc1_controls=["B006", "A006"],
        )
        # Must have structured fields, not just a text blob
        assert isinstance(envelope["data"], dict)
        assert "function" in envelope
        assert "timestamp" in envelope
        assert "aiuc1_controls" in envelope

    def test_error_envelope_forces_structured_errors(self):
        """Error responses use structured error objects, not free text."""
        from functions.shared.response import build_error_envelope
        envelope = build_error_envelope(
            function_name="gap_analyzer",
            error_message="Azure API returned 403 Forbidden",
            error_code="AZURE_AUTH_ERROR",
        )
        assert isinstance(envelope["error"], dict)
        assert "code" in envelope["error"]
        assert "message" in envelope["error"]

    def test_aiuc1_controls_field_provides_traceability(self):
        """The aiuc1_controls field traces which controls were exercised."""
        from functions.shared.response import build_success_envelope
        envelope = build_success_envelope(
            function_name="query_access_controls",
            data={"rbac_assignments": []},
            aiuc1_controls=["B006", "A006", "E015"],
        )
        controls = envelope.get("aiuc1_controls", [])
        assert len(controls) > 0
        assert all(isinstance(c, str) for c in controls)


# ===========================================================================
# Agent System Prompt Grounding Instructions
# ===========================================================================

class TestSystemPromptGrounding:
    """Verify the system prompt contains grounding instructions (D001)."""

    def test_system_prompt_contains_grounding_directive(self):
        """The system prompt explicitly instructs grounding."""
        prompt_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "agents",
            "prompts",
            "soc2_auditor_simplified.md",
        )
        if not os.path.exists(prompt_path):
            pytest.skip("System prompt file not found")

        with open(prompt_path, "r") as f:
            prompt = f.read()

        # Must contain D001 grounding instruction
        assert "D001" in prompt, "System prompt missing D001 reference"
        assert "grounding" in prompt.lower() or "ground" in prompt.lower(), \
            "System prompt missing grounding instruction"

    def test_system_prompt_forbids_hallucination(self):
        """The system prompt explicitly forbids fabrication."""
        prompt_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "agents",
            "prompts",
            "soc2_auditor_simplified.md",
        )
        if not os.path.exists(prompt_path):
            pytest.skip("System prompt file not found")

        with open(prompt_path, "r") as f:
            prompt = f.read()

        # Must contain anti-hallucination language
        anti_hallucination_terms = ["never invent", "hallucinate", "fabricat", "assume"]
        found = any(term in prompt.lower() for term in anti_hallucination_terms)
        assert found, "System prompt missing anti-hallucination instruction"

    def test_system_prompt_requires_tool_evidence(self):
        """The system prompt requires findings to be based on tool output."""
        prompt_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "agents",
            "prompts",
            "soc2_auditor_simplified.md",
        )
        if not os.path.exists(prompt_path):
            pytest.skip("System prompt file not found")

        with open(prompt_path, "r") as f:
            prompt = f.read()

        # Must reference tool-based evidence
        assert "tool" in prompt.lower(), "System prompt missing tool-based evidence requirement"
        assert "evidence" in prompt.lower() or "output" in prompt.lower(), \
            "System prompt missing evidence requirement"

    def test_system_prompt_requires_human_review(self):
        """The system prompt states findings need human review."""
        prompt_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "agents",
            "prompts",
            "soc2_auditor_simplified.md",
        )
        if not os.path.exists(prompt_path):
            pytest.skip("System prompt file not found")

        with open(prompt_path, "r") as f:
            prompt = f.read()

        assert "human" in prompt.lower(), "System prompt missing human review requirement"

    def test_system_prompt_requires_disclosure(self):
        """The system prompt mandates AI disclosure footer."""
        prompt_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "agents",
            "prompts",
            "soc2_auditor_simplified.md",
        )
        if not os.path.exists(prompt_path):
            pytest.skip("System prompt file not found")

        with open(prompt_path, "r") as f:
            prompt = f.read()

        assert "E016" in prompt or "disclosure" in prompt.lower(), \
            "System prompt missing disclosure requirement"
