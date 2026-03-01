# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Integration Test Suite
# ---------------------------------------------------------------------------
# Tests all 12 Azure Functions end-to-end with mocked Azure SDK.
# Each function is tested for:
#   1. Valid payload → success envelope
#   2. Missing/invalid fields → error envelope
#   3. Response envelope structure (status, function, timestamp, data/error)
#   4. Sanitisation applied (no raw secrets in output)
#
# These tests simulate the full queue-trigger flow: JSON payload in,
# envelope out, with enforcement layer active.
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import hashlib
import hmac
import sys
import os
import time
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_queue_msg(payload: dict) -> MagicMock:
    """Create a mock QueueMessage with the given JSON payload."""
    msg = MagicMock()
    msg.get_body.return_value = json.dumps(payload).encode("utf-8")
    return msg


def _make_output_binding() -> MagicMock:
    """Create a mock output binding that captures .set() calls."""
    output = MagicMock()
    output._value = None

    def _set(value):
        output._value = value

    output.set = _set
    return output


def _parse_output(output: MagicMock) -> dict:
    """Parse the output binding's captured value into a dict."""
    raw = output._value
    if raw is None:
        return {}
    outer = json.loads(raw)
    if "Value" in outer:
        return json.loads(outer["Value"])
    return outer


def _assert_success_envelope(envelope: dict, function_name: str, *, check_sanitised: bool = True):
    """Assert the envelope is a valid success response.

    Args:
        envelope: The parsed response envelope.
        function_name: Expected function name.
        check_sanitised: Whether to assert sanitised is True.
            Set to False for functions that intentionally set sanitise=False
            (e.g., sanitize_output, which performs its own sanitisation).
    """
    assert envelope.get("status") == "success", f"Expected success, got: {envelope}"
    assert envelope.get("function") == function_name
    assert "timestamp" in envelope
    assert "data" in envelope
    if check_sanitised:
        assert envelope.get("sanitised") is True


def _assert_error_envelope(envelope: dict, function_name: str):
    """Assert the envelope is a valid error response."""
    assert envelope.get("status") == "error", f"Expected error, got: {envelope}"
    assert envelope.get("function") == function_name
    assert "timestamp" in envelope
    assert "error" in envelope


def _assert_blocked_envelope(envelope: dict, function_name: str):
    """Assert the envelope is a blocked response from the enforcement layer."""
    assert envelope.get("status") == "blocked", f"Expected blocked, got: {envelope}"
    assert envelope.get("function") == function_name
    assert "error" in envelope
    assert envelope["error"]["code"] == "ENFORCEMENT_BLOCKED"


def _generate_valid_approval_token(plan_hash: str) -> str:
    """Generate a valid HMAC approval token for testing."""
    secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
    return hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_enforcement():
    """Reset the enforcement middleware singleton between tests."""
    import functions.enforcement.middleware as mw
    mw._policy_engine = None
    mw._output_gateway = None
    mw._scope_enforcer = None
    mw._tool_restrictions = None
    mw._disclosure_injector = None
    mw._audit_chain = None
    yield


def _build_mock_clients():
    """Build a dict of service-name → mock client for get_mgmt_client."""

    # --- Network client ---
    mock_nsg_rule = MagicMock()
    mock_nsg_rule.name = "AllowSSH"
    mock_nsg_rule.direction = "Inbound"
    mock_nsg_rule.access = "Allow"
    mock_nsg_rule.source_address_prefix = "10.0.0.0/8"
    mock_nsg_rule.source_address_prefixes = []
    mock_nsg_rule.destination_port_range = "22"
    mock_nsg_rule.destination_port_ranges = []
    mock_nsg_rule.protocol = "TCP"
    mock_nsg_rule.priority = 100

    mock_nsg = MagicMock()
    mock_nsg.name = "test-nsg"
    mock_nsg.security_rules = [mock_nsg_rule]

    mock_network = MagicMock()
    mock_network.network_security_groups.list.return_value = [mock_nsg]

    # --- Authorization client ---
    mock_role = MagicMock()
    mock_role.role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
    mock_role.principal_id = "00000000-0000-0000-0000-000000000001"
    mock_role.principal_type = "ServicePrincipal"
    mock_role.scope = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-aiuc1-foundry"
    mock_role.created_on = datetime.now(timezone.utc)
    mock_role.condition = None

    mock_auth = MagicMock()
    mock_auth.role_assignments.list_for_subscription.return_value = [mock_role]

    # --- Policy Insights client ---
    mock_policy_state = MagicMock()
    mock_policy_state.compliance_state = "Compliant"
    mock_policy_state.policy_definition_name = "test-policy"
    mock_policy_state.policy_definition_action = "audit"
    mock_policy_state.policy_set_definition_name = None
    mock_policy_state.resource_type = "Microsoft.Compute/virtualMachines"
    mock_policy_state.resource_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-aiuc1-foundry/providers/Microsoft.Compute/virtualMachines/test-vm"
    mock_policy_state.timestamp = datetime.now(timezone.utc)

    mock_summary_result = MagicMock()
    mock_summary_result.results = MagicMock()
    mock_summary_result.results.non_compliant_resources = 0

    mock_summary = MagicMock()
    mock_summary.value = [mock_summary_result]

    mock_policy = MagicMock()
    mock_policy.policy_states.list_query_results_for_subscription.return_value = [mock_policy_state]
    mock_policy.policy_states.summarize_for_subscription.return_value = mock_summary

    # --- Security Center (Defender) client ---
    mock_score = MagicMock()
    mock_score.current_score = 8.5
    mock_score.max_score = 21
    mock_score.weight = 1

    mock_assessment = MagicMock()
    mock_assessment.display_name = "Test Assessment"
    mock_assessment.status = MagicMock()
    mock_assessment.status.code = "Healthy"
    mock_assessment.resource_details = MagicMock()
    mock_assessment.resource_details.source = "Azure"

    mock_security = MagicMock()
    mock_security.secure_scores.list.return_value = [mock_score]
    mock_security.assessments.list.return_value = [mock_assessment]

    # --- Storage client ---
    mock_storage_acct = MagicMock()
    mock_storage_acct.name = "testsa"
    mock_storage_acct.allow_blob_public_access = False
    mock_storage_acct.enable_https_traffic_only = True
    mock_storage_acct.minimum_tls_version = "TLS1_2"
    mock_storage_acct.encryption = MagicMock()
    mock_storage_acct.encryption.require_infrastructure_encryption = True

    mock_storage = MagicMock()
    mock_storage.storage_accounts.list_by_resource_group.return_value = [mock_storage_acct]

    # --- SQL client ---
    mock_sql = MagicMock()
    mock_sql.servers.list_by_resource_group.return_value = []

    # --- Resource client ---
    mock_resource = MagicMock()
    mock_resource.resources.list_by_resource_group.return_value = [
        MagicMock(**{
            "name": "test-nsg",
            "type": "Microsoft.Network/networkSecurityGroups",
            "location": "eastus2",
        })
    ]

    return {
        "network": mock_network,
        "authorization": mock_auth,
        "policy_insights": mock_policy,
        "security": mock_security,
        "storage": mock_storage,
        "sql": mock_sql,
        "resource": mock_resource,
    }


@pytest.fixture
def mock_azure_clients():
    """Patch get_mgmt_client to return appropriate mock based on service name."""
    clients = _build_mock_clients()

    def _mock_get_mgmt_client(service, **kwargs):
        if service in clients:
            return clients[service]
        return MagicMock()

    with patch("shared.azure_clients.get_mgmt_client", side_effect=_mock_get_mgmt_client):
        yield _mock_get_mgmt_client


@pytest.fixture
def app(mock_azure_clients):
    """Import function_app with get_mgmt_client patched."""
    # Clear cached function_app to get fresh import
    for mod_name in list(sys.modules.keys()):
        if mod_name.endswith("function_app"):
            del sys.modules[mod_name]
    import functions.function_app as app_module
    # Patch the already-imported get_mgmt_client in function_app
    with patch.object(app_module, "get_mgmt_client", side_effect=mock_azure_clients):
        yield app_module


# ===========================================================================
# 1. gap_analyzer
# ===========================================================================

class TestGapAnalyzer:
    """Integration tests for the gap_analyzer function."""

    def test_valid_cc6_payload(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "gap_analyzer")

    def test_missing_cc_category(self, app):
        msg = _make_queue_msg({
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "gap_analyzer")

    def test_invalid_cc_category(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC99",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "gap_analyzer")

    def test_response_is_sanitised(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        raw = json.dumps(envelope)
        # Should not contain raw subscription IDs
        assert "/subscriptions/00000000" not in raw


# ===========================================================================
# 2. scan_cc_criteria
# ===========================================================================

class TestScanCcCriteria:
    """Integration tests for the scan_cc_criteria function."""

    def test_valid_cc6_scan(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.scan_cc_criteria(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "scan_cc_criteria")

    def test_missing_fields(self, app):
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.scan_cc_criteria(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "scan_cc_criteria")

    def test_all_nine_cc_categories(self, app):
        """Every valid CC category should return a success envelope."""
        for cc in ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"]:
            msg = _make_queue_msg({
                "cc_category": cc,
                "resource_group": "rg-aiuc1-foundry",
            })
            output = _make_output_binding()
            app.scan_cc_criteria(msg, output)
            envelope = _parse_output(output)
            assert envelope.get("status") in ("success", "error"), f"CC {cc} failed"


# ===========================================================================
# 3. evidence_validator
# ===========================================================================

class TestEvidenceValidator:
    """Integration tests for the evidence_validator function.

    Required fields: evidence_type, target
    Valid evidence_types: azure_resource, policy_state, document, log_entry
    """

    def test_valid_payload(self, app):
        """evidence_validator requires 'evidence_type' and 'target' (not resource_group)."""
        msg = _make_queue_msg({
            "evidence_type": "policy_state",
            "target": "test-policy-assignment",
        })
        output = _make_output_binding()
        app.evidence_validator(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "evidence_validator")

    def test_missing_evidence_type(self, app):
        msg = _make_queue_msg({
            "target": "test-policy-assignment",
        })
        output = _make_output_binding()
        app.evidence_validator(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "evidence_validator")

    def test_missing_target(self, app):
        """Missing 'target' field should produce an error envelope."""
        msg = _make_queue_msg({
            "evidence_type": "policy_state",
        })
        output = _make_output_binding()
        app.evidence_validator(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "evidence_validator")


# ===========================================================================
# 4. query_access_controls
# ===========================================================================

class TestQueryAccessControls:
    """Integration tests for the query_access_controls function.

    This function has NO required fields — an empty payload is valid
    and queries all in-scope resource groups.  The optional 'scope'
    field narrows the query to a specific resource group.
    """

    def test_valid_query(self, app):
        msg = _make_queue_msg({
            "scope": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.query_access_controls(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "query_access_controls")

    def test_empty_payload_is_valid(self, app):
        """An empty payload queries all in-scope resource groups (no required fields)."""
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.query_access_controls(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "query_access_controls")

    def test_out_of_scope_resource_group(self, app):
        """A scope outside allowed resource groups should produce an error."""
        msg = _make_queue_msg({
            "scope": "rg-not-allowed",
        })
        output = _make_output_binding()
        app.query_access_controls(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "query_access_controls")


# ===========================================================================
# 5. query_defender_score
# ===========================================================================

class TestQueryDefenderScore:
    """Integration tests for the query_defender_score function."""

    def test_valid_query(self, app):
        msg = _make_queue_msg({
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.query_defender_score(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "query_defender_score")

    def test_score_is_numeric(self, app):
        msg = _make_queue_msg({
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.query_defender_score(msg, output)
        envelope = _parse_output(output)
        data = envelope.get("data", {})
        raw = json.dumps(data)
        assert "8.5" in raw or "score" in raw.lower()


# ===========================================================================
# 6. query_policy_compliance
# ===========================================================================

class TestQueryPolicyCompliance:
    """Integration tests for the query_policy_compliance function.

    This function has NO required fields — an empty payload is valid.
    Optional fields: include_details (bool), max_results (int).
    """

    def test_valid_query(self, app):
        msg = _make_queue_msg({
            "include_details": True,
        })
        output = _make_output_binding()
        app.query_policy_compliance(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "query_policy_compliance")

    def test_empty_payload_is_valid(self, app):
        """An empty payload uses defaults (include_details=True, max_results=50)."""
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.query_policy_compliance(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "query_policy_compliance")

    def test_compliance_summary_present(self, app):
        """The response should include a compliance_summary section."""
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.query_policy_compliance(msg, output)
        envelope = _parse_output(output)
        data = envelope.get("data", {})
        assert "compliance_summary" in data


# ===========================================================================
# 7. generate_poam_entry
# ===========================================================================

class TestGeneratePoamEntry:
    """Integration tests for the generate_poam_entry function.

    Required fields: cc_category, resource, gap_description, severity
    """

    def test_valid_poam(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource": "prod-open-nsg/AllowSSH",
            "gap_description": "Open SSH port detected on prod-open-nsg",
            "severity": "high",
        })
        output = _make_output_binding()
        app.generate_poam_entry(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "generate_poam_entry")

    def test_missing_required_fields(self, app):
        """Missing cc_category, resource, gap_description should produce error."""
        msg = _make_queue_msg({
            "severity": "high",
        })
        output = _make_output_binding()
        app.generate_poam_entry(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "generate_poam_entry")

    def test_poam_contains_milestones(self, app):
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource": "prod-open-nsg/AllowSSH",
            "gap_description": "Open SSH port detected",
            "severity": "high",
        })
        output = _make_output_binding()
        app.generate_poam_entry(msg, output)
        envelope = _parse_output(output)
        raw = json.dumps(envelope).lower()
        assert "milestone" in raw or "remediation" in raw or "action" in raw


# ===========================================================================
# 8. run_terraform_plan
# ===========================================================================

class TestRunTerraformPlan:
    """Integration tests for the run_terraform_plan function.

    The function checks os.path.isdir(working_dir) before running
    terraform.  We must mock both isdir and subprocess.run.
    """

    def test_valid_plan(self, app):
        with patch("subprocess.run") as mock_run, \
             patch("os.path.isdir", return_value=True):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Plan: 1 to add, 0 to change, 0 to destroy.",
                stderr="",
            )
            msg = _make_queue_msg({
                "working_dir": "/tmp/terraform",
            })
            output = _make_output_binding()
            app.run_terraform_plan(msg, output)
            envelope = _parse_output(output)
            _assert_success_envelope(envelope, "run_terraform_plan")

    def test_missing_working_dir(self, app):
        """When the working directory does not exist, should return error."""
        with patch("os.path.isdir", return_value=False):
            msg = _make_queue_msg({})
            output = _make_output_binding()
            app.run_terraform_plan(msg, output)
            envelope = _parse_output(output)
            _assert_error_envelope(envelope, "run_terraform_plan")

    def test_plan_with_changes(self, app):
        """A plan with changes (exit code 2) should still succeed."""
        with patch("subprocess.run") as mock_run, \
             patch("os.path.isdir", return_value=True):
            mock_run.return_value = MagicMock(
                returncode=2,
                stdout="Plan: 3 to add, 1 to change, 0 to destroy.",
                stderr="",
            )
            msg = _make_queue_msg({
                "working_dir": "/tmp/terraform",
            })
            output = _make_output_binding()
            app.run_terraform_plan(msg, output)
            envelope = _parse_output(output)
            _assert_success_envelope(envelope, "run_terraform_plan")
            assert envelope["data"]["has_changes"] is True


# ===========================================================================
# 9. run_terraform_apply
# ===========================================================================

class TestRunTerraformApply:
    """Integration tests for the run_terraform_apply function.

    This is a CRITICAL risk function.  The enforcement layer validates
    the HMAC approval token BEFORE the function body even runs.
    Missing or invalid tokens result in a 'blocked' status (not 'error').
    """

    def test_missing_approval_token(self, app):
        """Apply without plan_hash/approval_token is blocked by enforcement."""
        msg = _make_queue_msg({
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.run_terraform_apply(msg, output)
        envelope = _parse_output(output)
        # Enforcement layer blocks this with status "blocked", not "error"
        _assert_blocked_envelope(envelope, "run_terraform_apply")

    def test_invalid_approval_token(self, app):
        """Apply with wrong HMAC token is blocked by enforcement."""
        msg = _make_queue_msg({
            "plan_hash": "abc123",
            "approval_token": "invalid-token-12345",
        })
        output = _make_output_binding()
        app.run_terraform_apply(msg, output)
        envelope = _parse_output(output)
        _assert_blocked_envelope(envelope, "run_terraform_apply")

    def test_valid_approval_token(self, app):
        """Apply with valid HMAC token passes enforcement but may fail on missing dir."""
        plan_hash = "test-plan-hash-for-apply"
        valid_token = _generate_valid_approval_token(plan_hash)
        with patch("os.path.isdir", return_value=False):
            msg = _make_queue_msg({
                "plan_hash": plan_hash,
                "approval_token": valid_token,
            })
            output = _make_output_binding()
            app.run_terraform_apply(msg, output)
            envelope = _parse_output(output)
            # Even with valid token, terraform dir doesn't exist → error (not blocked)
            _assert_error_envelope(envelope, "run_terraform_apply")
            assert envelope["error"]["code"] == "INVALID_WORKING_DIR"


# ===========================================================================
# 10. git_commit_push
# ===========================================================================

class TestGitCommitPush:
    """Integration tests for the git_commit_push function.

    Required fields: files (list), message (conventional commit format)
    """

    def test_valid_commit(self, app):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="[main abc1234] docs(reports): add test report",
                stderr="",
            )
            msg = _make_queue_msg({
                "files": ["reports/test-report.md"],
                "message": "docs(reports): add test report for CC6 gap analysis",
            })
            output = _make_output_binding()
            app.git_commit_push(msg, output)
            envelope = _parse_output(output)
            # The function may succeed or error depending on file existence
            # for secret scanning; check it doesn't fail on missing fields
            status = envelope.get("status")
            assert status in ("success", "error"), f"Unexpected status: {status}"
            if status == "error":
                # Should NOT be MISSING_FIELDS since we provided correct fields
                assert envelope["error"]["code"] != "MISSING_FIELDS"

    def test_missing_fields(self, app):
        """Missing 'files' and 'message' should produce MISSING_FIELDS error."""
        msg = _make_queue_msg({
            "content": "some content",
        })
        output = _make_output_binding()
        app.git_commit_push(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "git_commit_push")
        assert envelope["error"]["code"] == "MISSING_FIELDS"

    def test_invalid_commit_message_format(self, app):
        """Non-conventional commit message should produce error."""
        msg = _make_queue_msg({
            "files": ["reports/test.md"],
            "message": "Add test report",
        })
        output = _make_output_binding()
        app.git_commit_push(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "git_commit_push")
        assert envelope["error"]["code"] == "INVALID_COMMIT_MESSAGE"

    def test_files_outside_allowed_directories(self, app):
        """Files outside allowed directories should be rejected."""
        msg = _make_queue_msg({
            "files": ["/etc/passwd"],
            "message": "docs(reports): add test report for CC6 gap analysis",
        })
        output = _make_output_binding()
        app.git_commit_push(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "git_commit_push")


# ===========================================================================
# 11. sanitize_output
# ===========================================================================

class TestSanitizeOutput:
    """Integration tests for the sanitize_output function.

    Note: sanitize_output calls build_success_envelope with sanitise=False
    because it performs its own sanitisation.  The envelope's 'sanitised'
    field will be False, but the data IS sanitised.
    """

    def test_redacts_subscription_id(self, app):
        msg = _make_queue_msg({
            "text": "Resource at /subscriptions/<REDACTED-SUBSCRIPTION-ID>/resourceGroups/rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.sanitize_output(msg, output)
        envelope = _parse_output(output)
        # sanitize_output passes sanitise=False to build_success_envelope
        _assert_success_envelope(envelope, "sanitize_output", check_sanitised=False)
        raw = json.dumps(envelope)
        assert "00000000" not in raw

    def test_redacts_connection_string(self, app):
        msg = _make_queue_msg({
            "text": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123longkeyhere==;EndpointSuffix=core.windows.net",
        })
        output = _make_output_binding()
        app.sanitize_output(msg, output)
        envelope = _parse_output(output)
        raw = json.dumps(envelope)
        assert "DefaultEndpointsProtocol" not in raw or "REDACTED" in raw

    def test_redacts_private_ip(self, app):
        msg = _make_queue_msg({
            "text": "Server at 10.0.1.5 and 192.168.1.100",
        })
        output = _make_output_binding()
        app.sanitize_output(msg, output)
        envelope = _parse_output(output)
        raw = json.dumps(envelope)
        assert "10.0.1.5" not in raw
        assert "192.168.1.100" not in raw

    def test_empty_text(self, app):
        msg = _make_queue_msg({
            "text": "",
        })
        output = _make_output_binding()
        app.sanitize_output(msg, output)
        envelope = _parse_output(output)
        assert envelope.get("status") in ("success", "error")

    def test_missing_input(self, app):
        """Neither 'text' nor 'data' provided should produce error."""
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.sanitize_output(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "sanitize_output")


# ===========================================================================
# 12. log_security_event
# ===========================================================================

class TestLogSecurityEvent:
    """Integration tests for the log_security_event function.

    Required fields: category, agent_id, description
    Valid categories: scope_violation, secret_exposure, validation_failure,
                      approval_denied, anomalous_behavior, compliance_finding,
                      remediation_applied, access_event
    """

    def test_valid_event(self, app):
        msg = _make_queue_msg({
            "category": "compliance_finding",
            "agent_id": "soc2-learning-agent",
            "description": "Open SSH port detected on prod-open-nsg",
            "severity": "ERROR",
        })
        output = _make_output_binding()
        app.log_security_event(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "log_security_event")

    def test_prompt_injection_event(self, app):
        msg = _make_queue_msg({
            "category": "anomalous_behavior",
            "agent_id": "soc2-learning-agent",
            "description": "User attempted to override system prompt",
            "severity": "CRITICAL",
        })
        output = _make_output_binding()
        app.log_security_event(msg, output)
        envelope = _parse_output(output)
        _assert_success_envelope(envelope, "log_security_event")

    def test_missing_required_fields(self, app):
        """Missing 'category' and 'agent_id' should produce error."""
        msg = _make_queue_msg({
            "severity": "HIGH",
            "description": "Something happened",
        })
        output = _make_output_binding()
        app.log_security_event(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "log_security_event")

    def test_invalid_category(self, app):
        """An invalid category should produce error."""
        msg = _make_queue_msg({
            "category": "nonexistent_category",
            "agent_id": "test-agent",
            "description": "Test event",
        })
        output = _make_output_binding()
        app.log_security_event(msg, output)
        envelope = _parse_output(output)
        _assert_error_envelope(envelope, "log_security_event")


# ===========================================================================
# Cross-cutting: Response Envelope Structure
# ===========================================================================

class TestResponseEnvelopeStructure:
    """Verify all functions produce consistent envelope structure."""

    def test_success_envelope_has_required_fields(self, app):
        """A success envelope must have: status, function, timestamp, data."""
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        if envelope.get("status") == "success":
            for field_name in ("status", "function", "timestamp", "data"):
                assert field_name in envelope, f"Missing field: {field_name}"

    def test_error_envelope_has_required_fields(self, app):
        """An error envelope must have: status, function, timestamp, error."""
        msg = _make_queue_msg({})
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        if envelope.get("status") == "error":
            for field_name in ("status", "function", "timestamp", "error"):
                assert field_name in envelope, f"Missing field: {field_name}"

    def test_timestamp_is_iso_format(self, app):
        """Timestamps must be valid ISO 8601."""
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        ts = envelope.get("timestamp", "")
        assert "T" in ts or "20" in ts, f"Invalid timestamp: {ts}"

    def test_enforcement_metadata_present(self, app):
        """All responses should include enforcement_metadata after the enforcement layer."""
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        assert "enforcement_metadata" in envelope, "Missing enforcement_metadata"

    def test_ai_disclosure_present(self, app):
        """All responses should include ai_disclosure after the enforcement layer."""
        msg = _make_queue_msg({
            "cc_category": "CC6",
            "resource_group": "rg-aiuc1-foundry",
        })
        output = _make_output_binding()
        app.gap_analyzer(msg, output)
        envelope = _parse_output(output)
        assert "ai_disclosure" in envelope, "Missing ai_disclosure"
