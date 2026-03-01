# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Tool Restriction Engine Tests
# ---------------------------------------------------------------------------
# Tests for the tool-call restriction engine (rate limiting, injection
# scanning, approval validation, risk classification).
#
# Coverage:
#   - Rate limiting (cooldown, per-minute, per-hour)
#   - Input injection detection (XSS, SQL, shell, Python)
#   - HMAC approval token validation
#   - Risk level classification
#   - Clean payloads pass all checks
# ---------------------------------------------------------------------------

import hashlib
import hmac
import os
import time

import pytest
from functions.enforcement.tool_restrictions import (
    RestrictionViolation,
    RiskLevel,
    ToolRestrictionEngine,
)


class TestRiskClassification:
    """Test the static risk classification of tool calls."""

    def test_data_providers_are_low_risk(self):
        """Data provider functions must be classified as LOW risk."""
        low_risk = [
            "gap_analyzer", "scan_cc_criteria", "evidence_validator",
            "query_access_controls", "query_defender_score",
            "query_policy_compliance",
        ]
        for fn in low_risk:
            assert ToolRestrictionEngine.get_risk_level(fn) == RiskLevel.LOW, (
                f"{fn} should be LOW risk"
            )

    def test_action_functions_are_medium_or_higher(self):
        """Action functions must be MEDIUM or higher risk."""
        assert ToolRestrictionEngine.get_risk_level("generate_poam_entry") == RiskLevel.MEDIUM
        assert ToolRestrictionEngine.get_risk_level("git_commit_push") == RiskLevel.MEDIUM

    def test_terraform_plan_is_high_risk(self):
        """run_terraform_plan must be HIGH risk."""
        assert ToolRestrictionEngine.get_risk_level("run_terraform_plan") == RiskLevel.HIGH

    def test_terraform_apply_is_critical_risk(self):
        """run_terraform_apply must be CRITICAL risk."""
        assert ToolRestrictionEngine.get_risk_level("run_terraform_apply") == RiskLevel.CRITICAL

    def test_unknown_function_defaults_to_medium(self):
        """Unknown functions must default to MEDIUM risk."""
        assert ToolRestrictionEngine.get_risk_level("unknown_fn") == RiskLevel.MEDIUM

    def test_risk_map_contains_all_functions(self):
        """The risk map must contain all 12 functions."""
        risk_map = ToolRestrictionEngine.get_risk_map()
        assert len(risk_map) == 12


class TestInjectionDetection:
    """Test the input injection scanning."""

    @pytest.fixture
    def engine(self):
        # Use high limits to avoid rate limiting interference
        return ToolRestrictionEngine(
            max_calls_per_minute=1000,
            max_calls_per_hour=10000,
            cooldown_seconds=0,
        )

    def test_clean_payload_passes(self, engine):
        """Clean payloads must pass all injection checks."""
        payload = {"cc_category": "CC5", "include_details": True}
        violations = engine.check_restrictions("gap_analyzer", payload)
        assert len(violations) == 0

    def test_xss_script_tag_blocked(self, engine):
        """<script> tags must be detected and blocked."""
        payload = {"description": "<script>alert('xss')</script>"}
        violations = engine.check_restrictions("generate_poam_entry", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_javascript_uri_blocked(self, engine):
        """javascript: URIs must be detected and blocked."""
        payload = {"target": "javascript:alert(1)"}
        violations = engine.check_restrictions("evidence_validator", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_shell_injection_blocked(self, engine):
        """Shell command injection must be detected."""
        payload = {"working_dir": "/tmp; rm -rf /"}
        violations = engine.check_restrictions("run_terraform_plan", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_sql_injection_blocked(self, engine):
        """SQL injection patterns must be detected."""
        payload = {"target": "' OR 1=1 --"}
        violations = engine.check_restrictions("evidence_validator", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_python_eval_blocked(self, engine):
        """Python eval() injection must be detected."""
        payload = {"description": "eval(compile('import os', '', 'exec'))"}
        violations = engine.check_restrictions("generate_poam_entry", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_python_import_blocked(self, engine):
        """Python __import__ injection must be detected."""
        payload = {"description": "__import__('os').system('whoami')"}
        violations = engine.check_restrictions("generate_poam_entry", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_template_injection_blocked(self, engine):
        """Template injection (${...}) must be detected."""
        payload = {"target": "${7*7}"}
        violations = engine.check_restrictions("evidence_validator", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_nested_injection_detected(self, engine):
        """Injection patterns in nested payloads must be detected."""
        payload = {
            "config": {
                "nested": {
                    "value": "<script>alert('deep')</script>"
                }
            }
        }
        violations = engine.check_restrictions("test_fn", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_injection_violation_has_severity(self, engine):
        """Injection violations must have CRITICAL severity."""
        payload = {"description": "<script>alert('xss')</script>"}
        violations = engine.check_restrictions("test_fn", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert injection_violations[0].severity == "CRITICAL"

    def test_terraform_content_exempt_from_injection_scan(self, engine):
        """Terraform HCL with ${var.x} should NOT trigger injection on exempt fields."""
        payload = {
            "terraform_content": 'resource "azurerm_policy" { scope = "${var.subscription_id}" }',
        }
        violations = engine.check_restrictions("run_terraform_plan", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) == 0

    def test_non_exempt_function_still_catches_template_injection(self, engine):
        """Non-exempt functions should still catch ${...} patterns."""
        payload = {"target": "${7*7}"}
        violations = engine.check_restrictions("evidence_validator", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0

    def test_git_commit_file_content_exempt(self, engine):
        """Git commit file_content field should be exempt from injection scanning."""
        payload = {
            "file_content": '__import__("os").system("ls")',
        }
        violations = engine.check_restrictions("git_commit_push", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) == 0

    def test_poam_non_exempt_field_still_scanned(self, engine):
        """Non-exempt fields on relaxed functions should still be scanned."""
        payload = {
            "title": "<script>alert('xss')</script>",
        }
        violations = engine.check_restrictions("generate_poam_entry", payload)
        injection_violations = [v for v in violations if v.rule == "input_injection_detected"]
        assert len(injection_violations) > 0


class TestRateLimiting:
    """Test the rate limiting enforcement."""

    def test_cooldown_enforcement(self):
        """Calls within the cooldown period must be rate-limited."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=1000,
            max_calls_per_hour=10000,
            cooldown_seconds=5.0,
        )
        # First call should pass
        v1 = engine.check_restrictions("gap_analyzer", {})
        rate_violations = [v for v in v1 if "rate_limit" in v.rule]
        assert len(rate_violations) == 0

        # Immediate second call should be rate-limited
        v2 = engine.check_restrictions("gap_analyzer", {})
        rate_violations = [v for v in v2 if "rate_limit" in v.rule]
        assert len(rate_violations) > 0

    def test_per_minute_limit(self):
        """Exceeding per-minute limit must trigger rate limiting."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=3,
            max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        for _ in range(3):
            engine.check_restrictions("gap_analyzer", {})

        # 4th call should exceed the limit
        violations = engine.check_restrictions("gap_analyzer", {})
        rate_violations = [v for v in violations if "rate_limit" in v.rule]
        assert len(rate_violations) > 0

    def test_different_functions_have_separate_limits(self):
        """Rate limits must be tracked per-function."""
        engine = ToolRestrictionEngine(
            max_calls_per_minute=2,
            max_calls_per_hour=10000,
            cooldown_seconds=0,
        )
        # Call function A twice
        engine.check_restrictions("gap_analyzer", {})
        engine.check_restrictions("gap_analyzer", {})

        # Function B should still have its own limit
        violations = engine.check_restrictions("scan_cc_criteria", {})
        rate_violations = [v for v in violations if "rate_limit" in v.rule]
        assert len(rate_violations) == 0


class TestApprovalTokenValidation:
    """Test the HMAC approval token validation for critical functions."""

    @pytest.fixture
    def engine(self):
        return ToolRestrictionEngine(
            max_calls_per_minute=1000,
            max_calls_per_hour=10000,
            cooldown_seconds=0,
        )

    def _generate_valid_token(self, plan_hash: str) -> str:
        """Generate a valid HMAC token for testing."""
        secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
        return hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()

    def test_missing_approval_token_blocked(self, engine):
        """run_terraform_apply without approval token must be blocked."""
        payload = {"plan_hash": "abc123"}
        violations = engine.check_restrictions("run_terraform_apply", payload)
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) > 0

    def test_missing_plan_hash_blocked(self, engine):
        """run_terraform_apply without plan_hash must be blocked."""
        payload = {"approval_token": "abc123"}
        violations = engine.check_restrictions("run_terraform_apply", payload)
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) > 0

    def test_invalid_token_blocked(self, engine):
        """run_terraform_apply with invalid token must be blocked."""
        payload = {
            "plan_hash": "abc123",
            "approval_token": "definitely-not-valid",
        }
        violations = engine.check_restrictions("run_terraform_apply", payload)
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) > 0

    def test_valid_token_passes(self, engine):
        """run_terraform_apply with valid HMAC token must pass."""
        plan_hash = "test-plan-hash-12345"
        token = self._generate_valid_token(plan_hash)
        payload = {
            "plan_hash": plan_hash,
            "approval_token": token,
        }
        violations = engine.check_restrictions("run_terraform_apply", payload)
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) == 0

    def test_non_critical_functions_skip_approval(self, engine):
        """Non-critical functions must not require approval tokens."""
        payload = {"cc_category": "CC5"}
        violations = engine.check_restrictions("gap_analyzer", payload)
        approval_violations = [v for v in violations if "approval" in v.rule]
        assert len(approval_violations) == 0
