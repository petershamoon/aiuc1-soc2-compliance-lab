# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Control Coverage Tests
# ---------------------------------------------------------------------------
# These tests verify that the enforcement layer provides architectural
# coverage for the AIUC-1 controls it claims to enforce.
#
# Each test maps a specific AIUC-1 control to the enforcement mechanism
# that implements it, and verifies the mechanism works.
#
# This is the "proof" that the enforcement layer is not just documentation —
# it actually enforces the controls at the infrastructure layer.
# ---------------------------------------------------------------------------

import hashlib
import hmac
import os

import pytest
from functions.enforcement.policy_engine import load_policies
from functions.enforcement.middleware import enforce, enforce_input_only, get_enforcement_context
from functions.enforcement.gateway import OutputGateway
from functions.enforcement.scope_enforcer import ScopeEnforcer
from functions.enforcement.tool_restrictions import ToolRestrictionEngine, RiskLevel
from functions.enforcement.disclosure import DisclosureInjector
from functions.enforcement.audit_chain import AuditChain


class TestA006_PreventPIILeakage:
    """AIUC-1 A006: Prevent PII leakage — mandatory output redaction."""

    def test_subscription_ids_redacted_architecturally(self):
        """Subscription IDs must be redacted by the gateway, not the LLM."""
        gw = OutputGateway()
        envelope = {
            "data": {
                "resource": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-test"
            }
        }
        sanitised, meta = gw.sanitise_envelope(envelope, "gap_analyzer")
        assert "12345678-1234-1234-1234-123456789012" not in str(sanitised)
        assert meta["gateway_applied"] is True

    def test_a006_in_policy_manifest(self):
        """A006 must appear in at least one enforcement policy."""
        policies = load_policies()
        a006_policies = [p for p in policies if "A006" in p.aiuc1_controls]
        assert len(a006_policies) > 0


class TestB006_PreventUnauthorizedActions:
    """AIUC-1 B006: Prevent unauthorized AI agent actions — scope boundaries."""

    def test_out_of_scope_rg_blocked_architecturally(self):
        """Out-of-scope resource groups must be blocked at the infrastructure layer."""
        enforcer = ScopeEnforcer()
        violations = enforcer.check_payload(
            {"resource_group": "rg-production-secrets"}, "query_access_controls"
        )
        assert len(violations) > 0

    def test_allowed_rg_passes(self):
        """Allowed resource groups must pass."""
        enforcer = ScopeEnforcer()
        violations = enforcer.check_payload(
            {"resource_group": "rg-aiuc1-foundry"}, "query_access_controls"
        )
        assert len(violations) == 0

    def test_production_allowed_for_read_but_blocked_for_write(self):
        """rg-production is in read scope but not write scope."""
        enforcer = ScopeEnforcer()
        # Read: allowed
        read_violations = enforcer.check_payload(
            {"resource_group": "rg-production"}, "query_access_controls"
        )
        assert len(read_violations) == 0
        # Write: blocked
        write_violations = enforcer.check_payload(
            {"resource_group": "rg-production"}, "run_terraform_plan"
        )
        assert len(write_violations) > 0

    def test_scope_enforcement_in_full_pipeline(self):
        """Scope enforcement must work in the full pipeline."""
        _, blocked, _ = enforce(
            function_name="query_access_controls",
            input_payload={"resource_group": "rg-unauthorized"},
            output_envelope={"status": "success", "data": {}},
        )
        assert blocked is True


class TestB009_LimitOutputOverExposure:
    """AIUC-1 B009: Limit output over-exposure — strip secrets."""

    def test_connection_strings_stripped(self):
        """Connection strings must be stripped from output."""
        gw = OutputGateway()
        envelope = {
            "data": {
                "config": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=secret123"
            }
        }
        sanitised, _ = gw.sanitise_envelope(envelope, "test_fn")
        assert "AccountKey" not in str(sanitised)

    def test_bearer_tokens_stripped(self):
        """Bearer tokens must be stripped from output."""
        gw = OutputGateway()
        envelope = {
            "data": {"auth": "Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"}
        }
        sanitised, _ = gw.sanitise_envelope(envelope, "test_fn")
        assert "eyJhbGciOiJSUzI1NiJ9" not in str(sanitised)


class TestC007_HumanInTheLoop:
    """AIUC-1 C007: Flag high-risk outputs — human-in-the-loop gate."""

    def test_terraform_apply_requires_hmac_token(self):
        """run_terraform_apply must require a valid HMAC approval token."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=1000, max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        violations = engine.check_restrictions(
            "run_terraform_apply",
            {"plan_hash": "test", "approval_token": "invalid"},
        )
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) > 0

    def test_valid_hmac_passes(self):
        """Valid HMAC token must pass the approval gate."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=1000, max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        plan_hash = "test-plan-hash"
        secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
        token = hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()
        violations = engine.check_restrictions(
            "run_terraform_apply",
            {"plan_hash": plan_hash, "approval_token": token},
        )
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) == 0

    def test_terraform_apply_is_critical_risk(self):
        """run_terraform_apply must be classified as CRITICAL risk."""
        assert ToolRestrictionEngine.get_risk_level("run_terraform_apply") == RiskLevel.CRITICAL


class TestD003_RestrictUnsafeToolCalls:
    """AIUC-1 D003: Restrict unsafe tool calls — injection blocking."""

    def test_shell_injection_blocked(self):
        """Shell injection patterns must be blocked."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=1000, max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        violations = engine.check_restrictions(
            "run_terraform_plan",
            {"working_dir": "/tmp; rm -rf /"},
        )
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_sql_injection_blocked(self):
        """SQL injection patterns must be blocked."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=1000, max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        violations = engine.check_restrictions(
            "evidence_validator",
            {"target": "' OR 1=1 --"},
        )
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0


class TestE015_AuditTrail:
    """AIUC-1 E015: Log model activity — cryptographic audit chain."""

    def test_audit_chain_integrity(self):
        """Audit chain must maintain cryptographic integrity."""
        chain = AuditChain()
        for i in range(5):
            chain.record(
                function_name=f"fn_{i}", action="sanitise",
                policy_id=f"P-{i}", applied=True, reason=f"Entry {i}",
                aiuc1_controls=("E015",),
            )
        assert chain.verify() is True

    def test_audit_chain_tamper_detection(self):
        """Tampering with the audit chain must be detectable."""
        chain = AuditChain()
        chain.record(function_name="fn1", action="sanitise",
                     policy_id="P1", applied=True, reason="First")
        chain.record(function_name="fn2", action="block",
                     policy_id="P2", applied=True, reason="Second")
        assert chain.verify() is True

        # Tamper with the chain
        from functions.enforcement.audit_chain import AuditEntry
        original = chain._entries[0]
        tampered = AuditEntry(
            sequence=original.sequence, timestamp=original.timestamp,
            function_name="TAMPERED", action=original.action,
            policy_id=original.policy_id, applied=original.applied,
            reason=original.reason, aiuc1_controls=original.aiuc1_controls,
            details=original.details, previous_hash=original.previous_hash,
            entry_hash=original.entry_hash,
        )
        chain._entries[0] = tampered
        assert chain.verify() is False

    def test_enforcement_pipeline_records_audit(self):
        """The full enforcement pipeline must record audit entries."""
        result, blocked, decisions = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope={"status": "success", "data": {}},
        )
        # The audit chain summary should be in the enforcement metadata
        assert "audit_chain" in result.get("enforcement_metadata", {})


class TestE016_AIDisclosure:
    """AIUC-1 E016: Implement AI disclosure mechanisms."""

    def test_disclosure_injected_architecturally(self):
        """AI disclosure must be injected by the enforcement layer, not the LLM."""
        injector = DisclosureInjector()
        envelope = {"status": "success", "data": {}}
        result = injector.inject(envelope, "gap_analyzer")
        assert result["ai_disclosure"]["ai_generated"] is True
        assert "AI" in result["ai_disclosure"]["disclosure_text"]

    def test_disclosure_in_full_pipeline(self):
        """AI disclosure must appear in the full pipeline output."""
        result, _, _ = enforce(
            function_name="gap_analyzer",
            input_payload={},
            output_envelope={"status": "success", "data": {}},
        )
        assert "ai_disclosure" in result
        assert result["ai_disclosure"]["ai_generated"] is True

    def test_disclosure_cannot_be_overridden(self):
        """Even if the LLM sets ai_disclosure to False, the enforcement layer must override it."""
        injector = DisclosureInjector()
        envelope = {
            "status": "success",
            "data": {},
            "ai_disclosure": {"ai_generated": False},
        }
        result = injector.inject(envelope, "test_fn")
        assert result["ai_disclosure"]["ai_generated"] is True


class TestE017_SystemTransparency:
    """AIUC-1 E017: Document system transparency policy."""

    def test_policy_manifest_available(self):
        """The full policy manifest must be available for inspection."""
        ctx = get_enforcement_context()
        manifest = ctx["policy_manifest"]
        assert len(manifest) >= 8
        for entry in manifest:
            assert "policy_id" in entry
            assert "name" in entry
            assert "description" in entry
            assert "aiuc1_controls" in entry
            assert "fingerprint" in entry

    def test_risk_map_available(self):
        """The risk classification map must be available for inspection."""
        ctx = get_enforcement_context()
        assert "risk_map" in ctx
        assert len(ctx["risk_map"]) == 12

    def test_scope_boundaries_available(self):
        """Scope boundaries must be available for inspection."""
        ctx = get_enforcement_context()
        assert "scope_boundaries" in ctx
        assert "rg-aiuc1-foundry" in ctx["scope_boundaries"]
