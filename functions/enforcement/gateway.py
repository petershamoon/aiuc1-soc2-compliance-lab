# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Output Gateway
# ---------------------------------------------------------------------------
# The output gateway is the final checkpoint before any function response
# reaches the agent.  It guarantees that every response is sanitised,
# regardless of whether the LLM remembered to call sanitize_output.
#
# This is the architectural fix for the "Prompt-Based vs. Architectural
# Enforcement" gap: sanitisation happens at the infrastructure layer,
# not the prompt layer.
#
# AIUC-1 Controls:
#   A006  Prevent PII leakage          — mandatory output redaction
#   B009  Limit output over-exposure    — strip secrets before agent sees them
#   A004  Protect IP & trade secrets    — credentials never leave the gateway
#   E015  Log model activity            — every sanitisation is logged
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from shared.sanitizer import redact_secrets, redact_dict

logger = logging.getLogger("aiuc1.enforcement.gateway")


class OutputGateway:
    """Deterministic output sanitisation gateway.

    Every function response passes through this gateway before being
    written to the output queue.  The gateway:

    1. Sanitises all string values in the response envelope
    2. Counts the number of redactions applied
    3. Stamps the response with enforcement metadata
    4. Returns the sanitised envelope

    This is not optional.  The middleware calls the gateway automatically
    on every function invocation.  The LLM cannot bypass it.
    """

    # Fields that should NOT be sanitised (they are enforcement metadata)
    _PASSTHROUGH_FIELDS = frozenset({
        "enforcement_metadata",
        "enforcement_decisions",
        "policy_manifest",
    })

    def __init__(self) -> None:
        self._total_redactions = 0
        self._total_calls = 0

    def sanitise_envelope(
        self,
        envelope: dict[str, Any],
        function_name: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Sanitise a response envelope and return enforcement metadata.

        Args:
            envelope: The raw function response envelope.
            function_name: Name of the function that produced the response.

        Returns:
            Tuple of (sanitised envelope, enforcement metadata dict).
        """
        self._total_calls += 1
        now = datetime.now(timezone.utc).isoformat()

        # Deep-copy and sanitise the envelope
        sanitised = self._sanitise_recursive(envelope)

        # Count redactions by comparing serialised forms
        original_json = json.dumps(envelope, default=str)
        sanitised_json = json.dumps(sanitised, default=str)
        redaction_count = sanitised_json.count("[REDACTED")

        self._total_redactions += redaction_count

        metadata = {
            "gateway_applied": True,
            "gateway_timestamp": now,
            "function_name": function_name,
            "redaction_count": redaction_count,
            "patterns_applied": [
                "subscription_ids", "standalone_uuids", "base64_access_keys",
                "connection_strings", "private_ips", "sas_tokens",
                "sp_secrets", "bearer_tokens",
            ],
            "aiuc1_controls": ["A006", "B009", "A004"],
            "enforcement_note": (
                "Output sanitised by enforcement gateway (architectural). "
                "This redaction is mandatory and cannot be bypassed by the LLM."
            ),
        }

        if redaction_count > 0:
            logger.info(
                "OutputGateway sanitised %d value(s) in %s response",
                redaction_count,
                function_name,
            )

        return sanitised, metadata

    def _sanitise_recursive(self, obj: Any) -> Any:
        """Recursively sanitise all string values in a nested structure."""
        if isinstance(obj, str):
            return redact_secrets(obj)
        elif isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key in self._PASSTHROUGH_FIELDS:
                    result[key] = value
                else:
                    result[key] = self._sanitise_recursive(value)
            return result
        elif isinstance(obj, (list, tuple)):
            return [self._sanitise_recursive(item) for item in obj]
        else:
            return obj

    @property
    def stats(self) -> dict[str, int]:
        """Return gateway statistics for monitoring."""
        return {
            "total_calls": self._total_calls,
            "total_redactions": self._total_redactions,
        }
