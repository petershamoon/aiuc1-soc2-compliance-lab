# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Output Gateway Tests
# ---------------------------------------------------------------------------
# Tests for the mandatory output sanitisation gateway.
#
# Coverage:
#   - Subscription ID redaction
#   - UUID redaction
#   - Connection string redaction
#   - Private IP redaction
#   - SAS token redaction
#   - Bearer token redaction
#   - Nested dict/list sanitisation
#   - Passthrough fields (enforcement_metadata)
#   - Gateway statistics tracking
#   - Redaction count accuracy
# ---------------------------------------------------------------------------

import pytest
from functions.enforcement.gateway import OutputGateway


class TestOutputGateway:
    """Test the OutputGateway sanitisation pipeline."""

    @pytest.fixture
    def gateway(self):
        return OutputGateway()

    def test_sanitise_subscription_id(self, gateway):
        """Subscription IDs in ARM paths must be redacted (A006/B009)."""
        envelope = {
            "status": "success",
            "data": {
                "resource_id": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-test"
            },
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "12345678-1234-1234-1234-123456789012" not in str(sanitised)
        assert "[REDACTED" in str(sanitised)

    def test_sanitise_connection_string(self, gateway):
        """Azure connection strings must be redacted (A004)."""
        envelope = {
            "status": "success",
            "data": {
                "config": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123"
            },
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "DefaultEndpointsProtocol" not in str(sanitised)
        assert "AccountKey" not in str(sanitised)

    def test_sanitise_private_ip(self, gateway):
        """RFC 1918 private IPs must be redacted."""
        envelope = {
            "status": "success",
            "data": {"ip": "10.0.1.42", "public": "8.8.8.8"},
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "10.0.1.42" not in str(sanitised)
        # Public IPs should NOT be redacted
        assert "8.8.8.8" in str(sanitised)

    def test_sanitise_bearer_token(self, gateway):
        """Bearer tokens must be redacted (A004)."""
        envelope = {
            "status": "success",
            "data": {"auth": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"},
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" not in str(sanitised)

    def test_sanitise_sas_token(self, gateway):
        """SAS tokens must be redacted."""
        envelope = {
            "status": "success",
            "data": {"url": "https://storage.blob.core.windows.net/c?sig=abc123&sv=2021-06-08&se=2026-01-01"},
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "sig=abc123" not in str(sanitised)

    def test_sanitise_nested_dicts(self, gateway):
        """Sanitisation must recurse into nested dictionaries."""
        envelope = {
            "status": "success",
            "data": {
                "level1": {
                    "level2": {
                        "secret": "DefaultEndpointsProtocol=https;AccountName=deep"
                    }
                }
            },
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "DefaultEndpointsProtocol" not in str(sanitised)

    def test_sanitise_lists(self, gateway):
        """Sanitisation must recurse into lists."""
        envelope = {
            "status": "success",
            "data": {
                "items": [
                    {"ip": "192.168.1.1"},
                    {"ip": "10.0.0.1"},
                ]
            },
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert "192.168.1.1" not in str(sanitised)
        assert "10.0.0.1" not in str(sanitised)

    def test_passthrough_enforcement_metadata(self, gateway):
        """enforcement_metadata field must NOT be sanitised."""
        envelope = {
            "status": "success",
            "data": {"value": "clean"},
            "enforcement_metadata": {
                "note": "This contains /subscriptions/12345678-1234-1234-1234-123456789012"
            },
        }
        sanitised, meta = gateway.sanitise_envelope(envelope, "test_fn")
        # enforcement_metadata should be passed through as-is
        assert "12345678-1234-1234-1234-123456789012" in str(
            sanitised.get("enforcement_metadata", "")
        )

    def test_metadata_includes_required_fields(self, gateway):
        """Gateway metadata must include all required fields."""
        envelope = {"status": "success", "data": {}}
        _, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert meta["gateway_applied"] is True
        assert "gateway_timestamp" in meta
        assert meta["function_name"] == "test_fn"
        assert "redaction_count" in meta
        assert "patterns_applied" in meta
        assert "aiuc1_controls" in meta

    def test_redaction_count_accuracy(self, gateway):
        """Redaction count must reflect actual redactions applied."""
        envelope = {
            "status": "success",
            "data": {"clean": "no secrets here"},
        }
        _, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert meta["redaction_count"] == 0

    def test_redaction_count_nonzero_for_secrets(self, gateway):
        """Redaction count must be > 0 when secrets are present."""
        envelope = {
            "status": "success",
            "data": {
                "secret": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123"
            },
        }
        _, meta = gateway.sanitise_envelope(envelope, "test_fn")
        assert meta["redaction_count"] > 0

    def test_stats_tracking(self, gateway):
        """Gateway must track total calls and redactions."""
        assert gateway.stats["total_calls"] == 0
        gateway.sanitise_envelope({"data": {"clean": "ok"}}, "fn1")
        assert gateway.stats["total_calls"] == 1
        gateway.sanitise_envelope(
            {"data": {"secret": "DefaultEndpointsProtocol=https;x=y"}}, "fn2"
        )
        assert gateway.stats["total_calls"] == 2
        assert gateway.stats["total_redactions"] >= 1

    def test_non_string_values_preserved(self, gateway):
        """Non-string values (int, bool, None) must be preserved."""
        envelope = {
            "status": "success",
            "data": {
                "count": 42,
                "enabled": True,
                "optional": None,
            },
        }
        sanitised, _ = gateway.sanitise_envelope(envelope, "test_fn")
        assert sanitised["data"]["count"] == 42
        assert sanitised["data"]["enabled"] is True
        assert sanitised["data"]["optional"] is None
