# ---------------------------------------------------------------------------
# Tests — Scope Enforcer (Two-Tier Scope Model)
# ---------------------------------------------------------------------------

import pytest
from functions.enforcement.scope_enforcer import ScopeEnforcer, ScopeViolation


@pytest.fixture
def enforcer():
    return ScopeEnforcer()


@pytest.fixture
def strict_enforcer():
    """Enforcer with minimal scope for testing violations."""
    return ScopeEnforcer(
        read_scope=frozenset({"rg-allowed-read"}),
        write_scope=frozenset({"rg-allowed-write"}),
    )


# ---- Read Scope Tests ----

class TestReadScope:
    """Tests for read-only functions (query, scan, analyze)."""

    def test_allowed_read_rg_foundry(self, enforcer):
        payload = {"resource_group": "rg-aiuc1-foundry"}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_allowed_read_rg_production(self, enforcer):
        """Agent should be able to audit production."""
        payload = {"resource_group": "rg-production"}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_allowed_read_rg_development(self, enforcer):
        """Agent should be able to audit development."""
        payload = {"resource_group": "rg-development"}
        violations = enforcer.check_payload(payload, "query_defender_score")
        assert violations == []

    def test_blocked_read_unknown_rg(self, enforcer):
        """Random resource groups should be blocked."""
        payload = {"resource_group": "rg-customer-data"}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1
        assert "rg-customer-data" in violations[0].reason

    def test_blocked_read_empty_rg_passes(self, enforcer):
        payload = {"resource_group": ""}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_gap_analyzer_reads_production(self, enforcer):
        payload = {"resource_group": "rg-production", "criteria": "CC6"}
        violations = enforcer.check_payload(payload, "gap_analyzer")
        assert violations == []

    def test_scan_cc_reads_development(self, enforcer):
        payload = {"resource_group": "rg-development", "criteria": "CC1"}
        violations = enforcer.check_payload(payload, "scan_cc_criteria")
        assert violations == []


# ---- Write Scope Tests ----

class TestWriteScope:
    """Tests for write functions (terraform, git) — tighter scope."""

    def test_terraform_plan_allowed_in_foundry(self, enforcer):
        payload = {"resource_group": "rg-aiuc1-foundry"}
        violations = enforcer.check_payload(payload, "run_terraform_plan")
        assert violations == []

    def test_terraform_plan_blocked_in_production(self, enforcer):
        """Terraform should NOT be able to modify production."""
        payload = {"resource_group": "rg-production"}
        violations = enforcer.check_payload(payload, "run_terraform_plan")
        assert len(violations) == 1
        assert "write scope" in violations[0].reason

    def test_terraform_apply_blocked_in_development(self, enforcer):
        payload = {"resource_group": "rg-development"}
        violations = enforcer.check_payload(payload, "run_terraform_apply")
        assert len(violations) == 1

    def test_git_commit_allowed_in_foundry(self, enforcer):
        payload = {"resource_group": "rg-aiuc1-foundry"}
        violations = enforcer.check_payload(payload, "git_commit_push")
        assert violations == []

    def test_git_commit_blocked_in_production(self, enforcer):
        payload = {"resource_group": "rg-production"}
        violations = enforcer.check_payload(payload, "git_commit_push")
        assert len(violations) == 1


# ---- Content Exemption Tests ----

class TestContentExemption:
    """Terraform/git payloads with RG references in content should NOT be blocked."""

    def test_terraform_content_with_external_rg_reference(self, enforcer):
        """Terraform HCL that references rg-production in policy should pass."""
        payload = {
            "resource_group": "rg-aiuc1-foundry",
            "terraform_content": 'scope = "/subscriptions/xxx/resourceGroups/rg-production"',
        }
        violations = enforcer.check_payload(payload, "run_terraform_plan")
        assert violations == []

    def test_poam_with_external_rg_reference(self, enforcer):
        """POA&M entries that mention rg-production should pass."""
        payload = {
            "finding": "Open SSH in /resourceGroups/rg-production/nsg",
            "severity": "high",
        }
        violations = enforcer.check_payload(payload, "generate_poam_entry")
        assert violations == []

    def test_git_commit_with_policy_content(self, enforcer):
        """Git commits containing policy JSON with RG refs should pass."""
        payload = {
            "resource_group": "rg-aiuc1-foundry",
            "file_content": '{"scope": "/resourceGroups/rg-customer-data"}',
        }
        violations = enforcer.check_payload(payload, "git_commit_push")
        assert violations == []

    def test_non_exempt_function_blocks_arm_id(self, enforcer):
        """Non-exempt functions should still block ARM ID references."""
        payload = {
            "query": "/subscriptions/xxx/resourceGroups/rg-customer-data/providers/foo",
        }
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1
        assert "rg-customer-data" in violations[0].reason


# ---- ARM Resource ID Tests ----

class TestARMResourceIDs:
    """Tests for ARM resource ID pattern scanning."""

    def test_arm_id_allowed_rg(self, enforcer):
        payload = {
            "query": "/subscriptions/xxx/resourceGroups/rg-aiuc1-foundry/providers/foo",
        }
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_arm_id_allowed_production_for_read(self, enforcer):
        payload = {
            "query": "/subscriptions/xxx/resourceGroups/rg-production/providers/foo",
        }
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_arm_id_blocked_unknown_rg(self, enforcer):
        payload = {
            "query": "/subscriptions/xxx/resourceGroups/rg-secret/providers/foo",
        }
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1


# ---- Nested Payload Tests ----

class TestNestedPayloads:
    """Tests for deeply nested payloads."""

    def test_nested_rg_field(self, enforcer):
        payload = {"config": {"resource_group": "rg-customer-data"}}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1

    def test_nested_allowed_rg(self, enforcer):
        payload = {"config": {"resource_group": "rg-production"}}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_list_of_rgs(self, enforcer):
        payload = {"resource_group": ["rg-production", "rg-unknown"]}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1
        assert "rg-unknown" in violations[0].reason

    def test_empty_payload(self, enforcer):
        violations = enforcer.check_payload({}, "test_fn")
        assert violations == []

    def test_payload_without_rg_fields(self, enforcer):
        payload = {"cc_category": "CC5", "include_details": True}
        violations = enforcer.check_payload(payload, "test_fn")
        assert violations == []

    def test_whitespace_rg(self, enforcer):
        payload = {"resource_group": "   "}
        violations = enforcer.check_payload(payload, "test_fn")
        assert violations == []


# ---- Custom Scope Tests ----

class TestCustomScope:
    """Tests with custom scope configuration."""

    def test_strict_enforcer_blocks_default_rgs(self, strict_enforcer):
        payload = {"resource_group": "rg-aiuc1-foundry"}
        violations = strict_enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1

    def test_strict_enforcer_allows_custom_read(self, strict_enforcer):
        payload = {"resource_group": "rg-allowed-read"}
        violations = strict_enforcer.check_payload(payload, "query_access_controls")
        assert violations == []

    def test_strict_enforcer_write_scope(self, strict_enforcer):
        payload = {"resource_group": "rg-allowed-write"}
        violations = strict_enforcer.check_payload(payload, "run_terraform_plan")
        assert violations == []

    def test_strict_enforcer_read_rg_blocked_for_write(self, strict_enforcer):
        """Read-scope RG should be blocked for write functions."""
        payload = {"resource_group": "rg-allowed-read"}
        violations = strict_enforcer.check_payload(payload, "run_terraform_plan")
        assert len(violations) == 1


# ---- Properties ----

class TestProperties:
    def test_allowed_resource_groups_returns_read_scope(self, enforcer):
        rgs = enforcer.allowed_resource_groups
        assert "rg-production" in rgs
        assert "rg-aiuc1-foundry" in rgs

    def test_write_scope_property(self, enforcer):
        ws = enforcer.write_scope
        assert "rg-aiuc1-foundry" in ws
        assert "rg-production" not in ws


# ---- ScopeViolation ----

class TestScopeViolation:
    def test_violation_to_dict(self, enforcer):
        payload = {"resource_group": "rg-bad"}
        violations = enforcer.check_payload(payload, "query_access_controls")
        assert len(violations) == 1
        d = violations[0].to_dict()
        assert "field" in d
        assert "value" in d
        assert "resource_group" in d
        assert "reason" in d
        assert d["resource_group"] == "rg-bad"
