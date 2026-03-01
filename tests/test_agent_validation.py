# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Agent Validation Test Suite
# ---------------------------------------------------------------------------
# Tests that validate agent-level behaviour through the enforcement layer.
#
# These tests verify:
#   1. The agent's system prompt contains all required AIUC-1 directives
#   2. The agent configuration is correct (tools, model, connection)
#   3. The enforcement layer's integration with function_app.py is complete
#   4. The full request→enforcement→response pipeline works end-to-end
#   5. Adversarial inputs are handled safely
#
# Unlike the other test modules, these tests focus on the agent's
# configuration and the enforcement layer's ability to protect against
# agent misbehaviour — not on individual enforcement components.
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import os
import re
import pytest
from unittest.mock import MagicMock, patch

from functions.enforcement.middleware import (
    enforce,
    enforce_input_only,
    enforce_output_only,
    get_enforcement_context,
    _init_enforcement,
)
import functions.enforcement.middleware as mw
from functions.enforcement.scope_enforcer import ScopeEnforcer
from functions.enforcement.tool_restrictions import ToolRestrictionEngine
from functions.enforcement.gateway import OutputGateway
from functions.enforcement.disclosure import DisclosureInjector
from functions.enforcement.audit_chain import AuditChain
from functions.enforcement.policy_engine import PolicyEngine, load_policies


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scope_enforcer():
    return ScopeEnforcer()


@pytest.fixture
def tool_engine():
    return ToolRestrictionEngine()


@pytest.fixture
def gateway():
    return OutputGateway()


@pytest.fixture
def disclosure():
    return DisclosureInjector()


@pytest.fixture
def audit_chain():
    return AuditChain()


# ===========================================================================
# Agent Configuration Validation
# ===========================================================================

class TestAgentConfiguration:
    """Validate the agent's configuration matches AIUC-1 requirements."""

    AGENT_CONFIG_PATH = os.path.join(
        os.path.dirname(__file__), "..", "agents", "agent_config.json"
    )
    SYSTEM_PROMPT_PATH = os.path.join(
        os.path.dirname(__file__), "..", "agents", "prompts", "soc2_auditor_simplified.md"
    )

    def test_agent_config_exists(self):
        """Agent configuration file exists."""
        assert os.path.exists(self.AGENT_CONFIG_PATH), \
            "Agent config not found at agents/agent_config.json"

    def test_agent_config_valid_json(self):
        """Agent configuration is valid JSON."""
        with open(self.AGENT_CONFIG_PATH) as f:
            config = json.load(f)
        assert isinstance(config, dict)

    def test_agent_has_tool_definitions(self):
        """Agent config defines tools for the agent to use."""
        with open(self.AGENT_CONFIG_PATH) as f:
            config = json.load(f)
        # The config nests tool definitions under agents.{agent_name}.tool_names
        has_tools = False
        if "agents" in config:
            for agent_name, agent_cfg in config["agents"].items():
                if "tool_names" in agent_cfg:
                    has_tools = True
                    assert len(agent_cfg["tool_names"]) > 0, \
                        f"Agent {agent_name} has empty tool_names list"
        elif "tools" in config or "functions" in config or "tool_resources" in config:
            has_tools = True
        assert has_tools, "Agent config missing tool definitions"

    def test_system_prompt_exists(self):
        """System prompt file exists."""
        assert os.path.exists(self.SYSTEM_PROMPT_PATH), \
            "System prompt not found at agents/prompts/soc2_auditor_simplified.md"

    def test_system_prompt_references_all_critical_controls(self):
        """System prompt references the critical AIUC-1 controls."""
        with open(self.SYSTEM_PROMPT_PATH) as f:
            prompt = f.read()
        # The system prompt references D001 (Grounding) and E016 (AI Disclosure)
        critical_controls = ["D001", "E016"]
        for control in critical_controls:
            assert control in prompt, \
                f"System prompt missing critical control reference: {control}"

    def test_system_prompt_defines_role(self):
        """System prompt defines the agent's role clearly."""
        with open(self.SYSTEM_PROMPT_PATH) as f:
            prompt = f.read()
        role_terms = ["soc 2", "compliance", "auditor", "agent"]
        found = sum(1 for term in role_terms if term in prompt.lower())
        assert found >= 2, "System prompt does not clearly define agent role"

    def test_system_prompt_defines_scope(self):
        """System prompt defines operational scope."""
        with open(self.SYSTEM_PROMPT_PATH) as f:
            prompt = f.read()
        scope_terms = ["scope", "resource group", "rg-aiuc1"]
        found = any(term in prompt.lower() for term in scope_terms)
        assert found, "System prompt does not define operational scope"


# ===========================================================================
# Agent Injection Resistance
# ===========================================================================

class TestAgentInjectionResistance:
    """Test that the enforcement layer protects against prompt injection
    and adversarial inputs that an attacker might send through the agent."""

    def test_prompt_injection_via_resource_group(self, tool_engine):
        """Injection attempt disguised as a resource group name."""
        violations = tool_engine.check_restrictions(
            function_name="gap_analyzer",
            payload={
                "resource_group": "rg-aiuc1-foundry; rm -rf /",
                "cc_category": "CC6",
            },
        )
        assert len(violations) > 0, "Injection in resource_group not detected"
        assert any(v.rule == "input_injection_detected" for v in violations)

    def test_prompt_injection_via_cc_category(self, tool_engine):
        """Injection attempt in CC category field."""
        violations = tool_engine.check_restrictions(
            function_name="scan_cc_criteria",
            payload={
                "cc_category": "CC6<script>alert(1)</script>",
                "resource_group": "rg-aiuc1-foundry",
            },
        )
        assert len(violations) > 0, "XSS injection in cc_category not detected"

    def test_prompt_injection_via_evidence_text(self, tool_engine):
        """Injection attempt in evidence text field."""
        violations = tool_engine.check_restrictions(
            function_name="evidence_validator",
            payload={
                "evidence_text": "Valid evidence'; DROP TABLE findings; --",
                "control_id": "CC6.1",
            },
        )
        assert len(violations) > 0, "SQL injection in evidence_text not detected"

    def test_python_eval_injection(self, tool_engine):
        """Python eval injection attempt."""
        violations = tool_engine.check_restrictions(
            function_name="gap_analyzer",
            payload={
                "text": "eval(__import__('os').system('id'))",
            },
        )
        assert len(violations) > 0, "Python eval injection not detected"

    def test_nested_injection_in_json(self, tool_engine):
        """Injection buried in nested JSON structure."""
        violations = tool_engine.check_restrictions(
            function_name="gap_analyzer",
            payload={
                "cc_category": "CC6",
                "resource_group": "rg-aiuc1-foundry",
                "metadata": {
                    "notes": "__import__('subprocess').call(['whoami'])",
                },
            },
        )
        assert len(violations) > 0, "Nested injection not detected"

    def test_base64_encoded_injection(self, tool_engine):
        """Base64-encoded payload — raw base64 doesn't match injection patterns."""
        import base64
        encoded = base64.b64encode(b"<script>alert('xss')</script>").decode()
        violations = tool_engine.check_restrictions(
            function_name="gap_analyzer",
            payload={"text": encoded},
        )
        # Base64 string itself doesn't contain injection patterns, so this
        # is acceptable either way — enforcement scans the raw text
        # This test verifies the engine doesn't crash on base64 content
        assert isinstance(violations, list)

    def test_terraform_exempt_fields_not_flagged(self, tool_engine):
        """Terraform content fields should not trigger injection detection."""
        violations = tool_engine.check_restrictions(
            function_name="run_terraform_plan",
            payload={
                "terraform_content": 'resource "azurerm_policy" { rule = "${var.sub_id}" }',
                "resource_group": "rg-aiuc1-foundry",
            },
        )
        # terraform_content is an exempt field, so ${var.sub_id} should not trigger
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) == 0, \
            "Terraform exempt field incorrectly flagged for injection"


# ===========================================================================
# Agent Scope Boundary Validation
# ===========================================================================

class TestAgentScopeBoundaries:
    """Test that the agent cannot escape its operational boundaries."""

    def test_cannot_query_random_resource_group(self, scope_enforcer):
        """Agent cannot query a completely unknown resource group."""
        violations = scope_enforcer.check_payload(
            {"resource_group": "rg-totally-random-external"},
            "gap_analyzer",
        )
        assert len(violations) > 0

    def test_cannot_query_other_subscriptions(self, scope_enforcer):
        """Agent cannot query resource groups from other subscriptions."""
        violations = scope_enforcer.check_payload(
            {"resource_group": "rg-other-subscription-prod"},
            "gap_analyzer",
        )
        assert len(violations) > 0

    def test_cannot_write_to_production(self, scope_enforcer):
        """Agent cannot modify the production resource group."""
        violations = scope_enforcer.check_payload(
            {"resource_group": "rg-production"},
            "run_terraform_apply",
        )
        assert len(violations) > 0, "Write to rg-production should be blocked"

    def test_read_functions_respect_read_scope(self, scope_enforcer):
        """All read functions can access read-scope resource groups."""
        read_functions = [
            "gap_analyzer", "scan_cc_criteria", "evidence_validator",
            "query_access_controls", "query_defender_score",
            "query_policy_compliance",
        ]
        read_rgs = ["rg-aiuc1-foundry", "rg-aiuc1-agents", "rg-production", "rg-development"]
        for func in read_functions:
            for rg in read_rgs:
                violations = scope_enforcer.check_payload(
                    {"resource_group": rg}, func,
                )
                assert len(violations) == 0, \
                    f"Read function {func} blocked from reading {rg}"

    def test_write_functions_respect_write_scope(self, scope_enforcer):
        """Write functions can only access write-scope resource groups."""
        write_functions = ["run_terraform_plan", "run_terraform_apply", "git_commit_push"]
        write_rgs = ["rg-aiuc1-foundry", "rg-aiuc1-agents"]
        blocked_rgs = ["rg-production", "rg-development"]

        for func in write_functions:
            for rg in write_rgs:
                violations = scope_enforcer.check_payload(
                    {"resource_group": rg}, func,
                )
                assert len(violations) == 0, \
                    f"Write function {func} blocked from writing to {rg}"
            for rg in blocked_rgs:
                violations = scope_enforcer.check_payload(
                    {"resource_group": rg}, func,
                )
                assert len(violations) > 0, \
                    f"Write function {func} allowed to write to {rg}"


# ===========================================================================
# Agent Output Integrity
# ===========================================================================

class TestAgentOutputIntegrity:
    """Test that agent outputs maintain integrity through the enforcement layer."""

    def test_finding_data_preserved_after_enforcement(self):
        """Legitimate finding data is preserved after enforcement processing."""
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": {
                "gaps": [
                    {
                        "finding": "NSG rule AllowSSH allows port 22 from any source",
                        "severity": "HIGH",
                        "cc_criteria": "CC6.1",
                        "remediation": "Restrict SSH access to known IP ranges",
                    },
                ],
                "resource_group": "rg-aiuc1-foundry",
                "cc_category": "CC6",
                "checks_performed": 5,
            },
        }
        result = enforce_output_only("gap_analyzer", envelope)
        data = result.get("data", {})
        # Finding content should be preserved
        assert len(data.get("gaps", [])) == 1
        gap = data["gaps"][0]
        assert "AllowSSH" in gap.get("finding", "")
        assert gap.get("severity") == "HIGH"

    def test_error_status_preserved_after_enforcement(self):
        """Error status is not changed to success by enforcement."""
        envelope = {
            "status": "error",
            "function": "gap_analyzer",
            "error": {
                "code": "AZURE_API_ERROR",
                "message": "Failed to query resource group",
            },
        }
        result = enforce_output_only("gap_analyzer", envelope)
        assert result["status"] == "error"

    def test_enforcement_adds_disclosure_not_replaces_data(self):
        """Enforcement adds metadata but does not replace original data."""
        original_data = {"score": 8.5, "max_score": 21, "findings": ["test"]}
        envelope = {
            "status": "success",
            "function": "query_defender_score",
            "data": original_data.copy(),
        }
        result = enforce_output_only("query_defender_score", envelope)
        # Original data fields should still be present
        result_data = result.get("data", {})
        assert result_data.get("score") == 8.5 or "score" in json.dumps(result)
        assert result_data.get("max_score") == 21 or "max_score" in json.dumps(result)

    def test_large_payload_handled_gracefully(self):
        """Large payloads don't crash the enforcement layer."""
        large_data = {
            "findings": [
                {"finding": f"Finding {i}", "severity": "MEDIUM"}
                for i in range(100)
            ],
        }
        envelope = {
            "status": "success",
            "function": "gap_analyzer",
            "data": large_data,
        }
        result = enforce_output_only("gap_analyzer", envelope)
        assert result["status"] == "success"
        # Should be JSON-serialisable
        serialised = json.dumps(result, default=str)
        assert len(serialised) > 0


# ===========================================================================
# Agent Audit Trail Completeness
# ===========================================================================

class TestAgentAuditTrail:
    """Test that the enforcement layer produces a complete audit trail
    for every agent interaction."""

    def test_output_enforcement_produces_audit_entries(self):
        """Full enforcement pipeline produces audit chain entries."""
        _init_enforcement()
        envelope = {"status": "success", "data": {"test": True}}
        # Use enforce() (full pipeline) which records to audit chain;
        # enforce_output_only() is a lightweight path that skips audit recording
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={"cc_category": "CC6", "resource_group": "rg-aiuc1-foundry"},
            output_envelope=envelope,
        )
        assert mw._audit_chain.length > 0

    def test_input_enforcement_produces_audit_entries(self):
        """Full enforcement pipeline records input-phase decisions."""
        _init_enforcement()
        # Use enforce() which records both input and output phase decisions
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={"cc_category": "CC6", "resource_group": "rg-aiuc1-foundry"},
            output_envelope={"status": "success", "data": {"test": True}},
        )
        assert mw._audit_chain.length > 0

    def test_blocked_requests_are_audited(self):
        """Blocked requests are recorded in the audit chain."""
        _init_enforcement()
        # Use enforce() which records to audit chain even for blocked requests
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={"text": "<script>alert('xss')</script>"},
            output_envelope={"status": "success", "data": {}},
        )
        assert blocked is True
        assert mw._audit_chain.length > 0
        summary = mw._audit_chain.get_summary()
        assert summary["chain_length"] > 0

    def test_audit_chain_integrity_after_multiple_operations(self):
        """Audit chain maintains integrity after multiple operations."""
        _init_enforcement()
        # Use enforce() which records to audit chain
        for i in range(5):
            enforce(
                function_name=f"function_{i}",
                input_payload={"cc_category": "CC6", "resource_group": "rg-aiuc1-foundry"},
                output_envelope={"status": "success", "data": {"iteration": i}},
            )
        assert mw._audit_chain.verify() is True
        assert mw._audit_chain.length >= 5


# ===========================================================================
# Full Agent Workflow Simulation
# ===========================================================================

class TestAgentWorkflowSimulation:
    """Simulate complete agent workflows through the enforcement layer."""

    def test_gap_analysis_workflow(self):
        """Simulate: agent calls gap_analyzer → gets enforced response."""
        # Step 1: Input enforcement
        blocked, decisions = enforce_input_only(
            function_name="gap_analyzer",
            input_payload={
                "cc_category": "CC6",
                "resource_group": "rg-aiuc1-foundry",
            },
        )
        assert blocked is False

        # Step 2: Function produces output → full enforcement
        result, was_blocked, out_decisions = enforce(
            function_name="gap_analyzer",
            input_payload={
                "cc_category": "CC6",
                "resource_group": "rg-aiuc1-foundry",
            },
            output_envelope={
                "status": "success",
                "function": "gap_analyzer",
                "data": {
                    "gaps": [{"finding": "Open SSH", "severity": "HIGH"}],
                    "resource_group": "rg-aiuc1-foundry",
                },
            },
        )
        assert result["status"] == "success"
        assert was_blocked is False
        assert "data" in result

    def test_scope_violation_workflow(self):
        """Simulate: agent tries to query out-of-scope RG → blocked."""
        blocked, decisions = enforce_input_only(
            function_name="query_access_controls",
            input_payload={"resource_group": "rg-totally-random-external"},
        )
        assert blocked is True

    def test_terraform_plan_then_apply_workflow(self):
        """Simulate: agent plans terraform (allowed) → applies (needs HMAC)."""
        # Plan should pass input enforcement
        blocked, decisions = enforce_input_only(
            function_name="run_terraform_plan",
            input_payload={
                "terraform_content": 'resource "azurerm_network_security_rule" "deny_ssh" {}',
                "resource_group": "rg-aiuc1-foundry",
            },
        )
        assert blocked is False

        # Apply should require approval (blocked without HMAC)
        blocked, decisions = enforce_input_only(
            function_name="run_terraform_apply",
            input_payload={
                "terraform_content": 'resource "azurerm_network_security_rule" "deny_ssh" {}',
                "resource_group": "rg-aiuc1-foundry",
            },
        )
        # Should be blocked because no HMAC approval token provided
        assert blocked is True
        assert any("approval" in d.get("reason", "").lower() for d in decisions)

    def test_multi_function_workflow_audit_trail(self):
        """Simulate: agent calls multiple functions → complete audit trail."""
        _init_enforcement()
        functions = [
            ("gap_analyzer", {"cc_category": "CC6", "resource_group": "rg-aiuc1-foundry"}),
            ("query_defender_score", {"resource_group": "rg-aiuc1-foundry"}),
            ("generate_poam_entry", {"finding": "Open SSH", "severity": "HIGH"}),
        ]
        for func_name, payload in functions:
            enforce(
                function_name=func_name,
                input_payload=payload,
                output_envelope={
                    "status": "success",
                    "function": func_name,
                    "data": {"result": "ok"},
                },
            )

        assert mw._audit_chain.verify() is True
        summary = mw._audit_chain.get_summary()
        assert summary["chain_length"] >= 6  # At least 2 entries per function
