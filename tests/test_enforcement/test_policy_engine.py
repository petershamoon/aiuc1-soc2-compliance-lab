# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Policy Engine Tests
# ---------------------------------------------------------------------------
# Tests for the declarative policy engine that maps AIUC-1 controls to
# enforcement rules.
#
# Coverage:
#   - Policy loading and validation
#   - Policy indexing (universal vs. function-specific)
#   - Policy evaluation (mandatory vs. optional)
#   - Policy manifest generation (E017 transparency)
#   - Enforcement decision hashing (E015 audit trail)
#   - Immutability guarantees (frozen dataclasses)
# ---------------------------------------------------------------------------

import pytest
from functions.enforcement.policy_engine import (
    EnforcementAction,
    EnforcementDecision,
    EnforcementPolicy,
    PolicyEngine,
    PolicyScope,
    load_policies,
)


class TestEnforcementPolicy:
    """Test the EnforcementPolicy frozen dataclass."""

    def test_policy_is_frozen(self):
        """Policies must be immutable — the LLM cannot modify them at runtime."""
        policy = EnforcementPolicy(
            policy_id="TEST-001",
            name="Test Policy",
            description="A test policy",
            aiuc1_controls=("A006",),
            action=EnforcementAction.SANITISE,
            scope=PolicyScope.OUTPUT,
        )
        with pytest.raises(AttributeError):
            policy.name = "Modified"  # type: ignore

    def test_policy_fingerprint_is_deterministic(self):
        """Same policy definition must always produce the same fingerprint."""
        policy = EnforcementPolicy(
            policy_id="TEST-001",
            name="Test Policy",
            description="A test policy",
            aiuc1_controls=("A006",),
            action=EnforcementAction.SANITISE,
            scope=PolicyScope.OUTPUT,
        )
        assert policy.fingerprint == policy.fingerprint
        assert len(policy.fingerprint) == 16

    def test_different_policies_have_different_fingerprints(self):
        """Different policies must produce different fingerprints."""
        p1 = EnforcementPolicy(
            policy_id="TEST-001", name="Policy A", description="A",
            aiuc1_controls=("A006",), action=EnforcementAction.SANITISE,
            scope=PolicyScope.OUTPUT,
        )
        p2 = EnforcementPolicy(
            policy_id="TEST-002", name="Policy B", description="B",
            aiuc1_controls=("B006",), action=EnforcementAction.BLOCK,
            scope=PolicyScope.INPUT,
        )
        assert p1.fingerprint != p2.fingerprint


class TestEnforcementDecision:
    """Test the EnforcementDecision frozen dataclass."""

    def test_decision_hash_is_deterministic(self):
        """Same decision must always produce the same hash."""
        decision = EnforcementDecision(
            policy_id="ENF-001",
            policy_name="Test",
            action=EnforcementAction.SANITISE,
            applied=True,
            reason="Test reason",
            timestamp="2026-02-26T00:00:00+00:00",
            aiuc1_controls=("A006",),
        )
        assert decision.decision_hash == decision.decision_hash
        assert len(decision.decision_hash) == 64  # SHA-256 hex

    def test_different_decisions_have_different_hashes(self):
        """Different decisions must produce different hashes."""
        d1 = EnforcementDecision(
            policy_id="ENF-001", policy_name="A",
            action=EnforcementAction.SANITISE, applied=True,
            reason="Reason A", timestamp="2026-02-26T00:00:00+00:00",
            aiuc1_controls=("A006",),
        )
        d2 = EnforcementDecision(
            policy_id="ENF-002", policy_name="B",
            action=EnforcementAction.BLOCK, applied=True,
            reason="Reason B", timestamp="2026-02-26T00:00:01+00:00",
            aiuc1_controls=("B006",),
        )
        assert d1.decision_hash != d2.decision_hash


class TestPolicyEngine:
    """Test the PolicyEngine evaluation logic."""

    @pytest.fixture
    def engine(self):
        """Create an engine with a mix of universal and function-specific policies."""
        policies = [
            # Universal mandatory policy
            EnforcementPolicy(
                policy_id="U-001", name="Universal Sanitise",
                description="Sanitise all output",
                aiuc1_controls=("A006", "B009"),
                action=EnforcementAction.SANITISE,
                scope=PolicyScope.OUTPUT, mandatory=True,
            ),
            # Universal mandatory input policy
            EnforcementPolicy(
                policy_id="U-002", name="Universal Audit",
                description="Audit all calls",
                aiuc1_controls=("E015",),
                action=EnforcementAction.LOG,
                scope=PolicyScope.BOTH, mandatory=True,
            ),
            # Function-specific policy
            EnforcementPolicy(
                policy_id="F-001", name="Terraform Block",
                description="Block destructive terraform",
                aiuc1_controls=("D003",),
                action=EnforcementAction.BLOCK,
                scope=PolicyScope.INPUT, mandatory=True,
                applies_to=("run_terraform_plan",),
            ),
            # Optional policy
            EnforcementPolicy(
                policy_id="O-001", name="Optional Rate Limit",
                description="Rate limit",
                aiuc1_controls=("B004",),
                action=EnforcementAction.RATE_LIMIT,
                scope=PolicyScope.INPUT, mandatory=False,
            ),
        ]
        return PolicyEngine(policies)

    def test_universal_policies_apply_to_all_functions(self, engine):
        """Universal policies (empty applies_to) must apply to every function."""
        policies = engine.get_applicable_policies("gap_analyzer", PolicyScope.OUTPUT)
        policy_ids = [p.policy_id for p in policies]
        assert "U-001" in policy_ids  # Universal output policy
        assert "U-002" in policy_ids  # Universal BOTH policy

    def test_function_specific_policies_only_apply_to_target(self, engine):
        """Function-specific policies must only apply to their target function."""
        tf_policies = engine.get_applicable_policies("run_terraform_plan", PolicyScope.INPUT)
        gap_policies = engine.get_applicable_policies("gap_analyzer", PolicyScope.INPUT)

        tf_ids = [p.policy_id for p in tf_policies]
        gap_ids = [p.policy_id for p in gap_policies]

        assert "F-001" in tf_ids
        assert "F-001" not in gap_ids

    def test_mandatory_policies_sorted_first(self, engine):
        """Mandatory policies must be evaluated before optional ones."""
        policies = engine.get_applicable_policies("gap_analyzer", PolicyScope.INPUT)
        mandatory_seen = False
        optional_seen = False
        for p in policies:
            if p.mandatory:
                assert not optional_seen, "Mandatory policy found after optional"
                mandatory_seen = True
            else:
                optional_seen = True

    def test_scope_filtering(self, engine):
        """Policies must only apply in their declared scope."""
        output_policies = engine.get_applicable_policies("gap_analyzer", PolicyScope.OUTPUT)
        output_ids = [p.policy_id for p in output_policies]
        # F-001 is INPUT only — should not appear in OUTPUT
        assert "F-001" not in output_ids
        # U-002 is BOTH — should appear in OUTPUT
        assert "U-002" in output_ids

    def test_evaluate_returns_decisions(self, engine):
        """evaluate() must return a list of EnforcementDecision objects."""
        decisions = engine.evaluate("gap_analyzer", PolicyScope.OUTPUT, {})
        assert len(decisions) > 0
        for d in decisions:
            assert isinstance(d, EnforcementDecision)
            assert d.applied is True
            assert d.timestamp  # Non-empty

    def test_evaluate_mandatory_always_applied(self, engine):
        """Mandatory policies must always produce applied=True decisions."""
        decisions = engine.evaluate("gap_analyzer", PolicyScope.OUTPUT, {})
        for d in decisions:
            if d.policy_id in ("U-001", "U-002"):
                assert d.applied is True

    def test_policy_manifest_contains_all_policies(self, engine):
        """policy_manifest must list every loaded policy (E017 transparency)."""
        manifest = engine.policy_manifest
        assert len(manifest) == 4
        ids = [p["policy_id"] for p in manifest]
        assert "U-001" in ids
        assert "U-002" in ids
        assert "F-001" in ids
        assert "O-001" in ids

    def test_policy_manifest_includes_fingerprints(self, engine):
        """Each manifest entry must include a fingerprint for audit."""
        for entry in engine.policy_manifest:
            assert "fingerprint" in entry
            assert len(entry["fingerprint"]) == 16


class TestLoadPolicies:
    """Test the default policy set loaded by load_policies()."""

    def test_load_policies_returns_non_empty(self):
        """load_policies() must return at least the core enforcement policies."""
        policies = load_policies()
        assert len(policies) >= 8  # We defined 10 policies

    def test_all_policies_have_aiuc1_controls(self):
        """Every policy must reference at least one AIUC-1 control."""
        for policy in load_policies():
            assert len(policy.aiuc1_controls) > 0, (
                f"Policy {policy.policy_id} has no AIUC-1 controls"
            )

    def test_mandatory_output_sanitisation_exists(self):
        """ENF-001 (mandatory output sanitisation) must be present."""
        policies = {p.policy_id: p for p in load_policies()}
        assert "ENF-001" in policies
        p = policies["ENF-001"]
        assert p.mandatory is True
        assert p.action == EnforcementAction.SANITISE
        assert p.scope == PolicyScope.OUTPUT

    def test_scope_boundary_enforcement_exists(self):
        """ENF-002 (scope boundary) must be present."""
        policies = {p.policy_id: p for p in load_policies()}
        assert "ENF-002" in policies
        p = policies["ENF-002"]
        assert p.mandatory is True
        assert p.action == EnforcementAction.BLOCK
        assert p.scope == PolicyScope.INPUT

    def test_ai_disclosure_injection_exists(self):
        """ENF-005 (AI disclosure) must be present."""
        policies = {p.policy_id: p for p in load_policies()}
        assert "ENF-005" in policies
        p = policies["ENF-005"]
        assert p.mandatory is True
        assert "E016" in p.aiuc1_controls

    def test_terraform_apply_requires_approval(self):
        """ENF-004 must require approval for run_terraform_apply."""
        policies = {p.policy_id: p for p in load_policies()}
        assert "ENF-004" in policies
        p = policies["ENF-004"]
        assert p.action == EnforcementAction.REQUIRE_APPROVAL
        assert "run_terraform_apply" in p.applies_to

    def test_rate_limiting_policy_exists(self):
        """ENF-007 (rate limiting) must be present."""
        policies = {p.policy_id: p for p in load_policies()}
        assert "ENF-007" in policies
        p = policies["ENF-007"]
        assert p.action == EnforcementAction.RATE_LIMIT
        assert "B004" in p.aiuc1_controls

    def test_all_policy_ids_unique(self):
        """All policy IDs must be unique."""
        policies = load_policies()
        ids = [p.policy_id for p in policies]
        assert len(ids) == len(set(ids)), "Duplicate policy IDs found"
