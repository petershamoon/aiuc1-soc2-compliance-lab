# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Enforcement Integration
# ---------------------------------------------------------------------------
# This module provides the integration hooks that wire the enforcement
# layer into the existing Azure Functions queue-trigger architecture.
#
# The key integration points are:
#
#   1. enforced_write_output() — drop-in replacement for write_output()
#      that runs the full enforcement pipeline before writing to the
#      output queue.
#
#   2. enforce_input() — input-phase enforcement that runs before the
#      function's business logic.
#
# These functions are designed to be minimal-change integrations:
# existing functions only need to replace write_output() calls with
# enforced_write_output() calls, or use the @enforced decorator.
#
# AIUC-1 Controls:
#   All controls enforced by the middleware sub-components
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import logging
from typing import Any

import azure.functions as func

from .middleware import (
    enforce,
    enforce_input_only,
    enforce_output_only,
    _init_enforcement,
)

logger = logging.getLogger("aiuc1.enforcement.integration")


def enforced_write_output(
    output: func.Out[str],
    envelope: dict[str, Any],
    correlation_id: str = "",
    function_name: str = "",
    input_payload: dict[str, Any] | None = None,
) -> None:
    """Enforcement-aware replacement for write_output().

    This function:
    1. Runs the full enforcement pipeline on the envelope
    2. Sanitises all output values (A006/B009)
    3. Injects AI disclosure (E016)
    4. Attaches enforcement metadata (E017)
    5. Records the audit chain (E015)
    6. Writes the enforced envelope to the output queue

    If the enforcement pipeline fails for any reason, falls back to
    writing the raw envelope directly — we never want enforcement
    bugs to break the agent's core functionality.

    Args:
        output: Azure Functions queue output binding.
        envelope: The raw function response envelope.
        correlation_id: Queue message correlation ID.
        function_name: Name of the function (auto-detected from envelope).
        input_payload: The original input payload (for input-phase checks).
    """
    try:
        _init_enforcement()

        # Auto-detect function name from envelope if not provided
        if not function_name:
            function_name = envelope.get("function", "unknown")

        # Run the full enforcement pipeline
        if input_payload is not None:
            enforced_envelope, blocked, decisions = enforce(
                function_name=function_name,
                input_payload=input_payload,
                output_envelope=envelope,
                correlation_id=correlation_id,
            )
        else:
            # Output-only enforcement (no input payload available)
            enforced_envelope = enforce_output_only(
                function_name=function_name,
                output_envelope=envelope,
            )
            blocked = False
            decisions = []

        # Write to output queue using the standard format
        response = {
            "Value": json.dumps(enforced_envelope, default=str),
            "CorrelationId": correlation_id,
        }
        output.set(json.dumps(response, default=str))

        if blocked:
            logger.warning(
                "Enforcement layer BLOCKED response for %s: %d violation(s)",
                function_name,
                len(decisions),
            )
        else:
            logger.info(
                "Enforcement layer processed response for %s",
                function_name,
            )

    except Exception as e:
        logger.error(
            "Enforcement layer failed for %s, falling back to direct output: %s",
            function_name or envelope.get("function", "unknown"),
            e,
        )
        # Fallback: write the envelope directly without enforcement
        response = {
            "Value": json.dumps(envelope, default=str),
            "CorrelationId": correlation_id,
        }
        output.set(json.dumps(response, default=str))


def check_input_enforcement(
    function_name: str,
    input_payload: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]]]:
    """Run input-phase enforcement checks.

    Call this at the top of a function to validate the input before
    doing expensive work (Azure API calls, subprocess execution, etc.).

    If the enforcement layer itself fails, returns (False, []) to allow
    the function to proceed — we never want enforcement bugs to break
    the agent's core functionality.

    Args:
        function_name: Name of the Azure Function.
        input_payload: The parsed input from the queue message.

    Returns:
        Tuple of (blocked: bool, decisions: list).
    """
    try:
        _init_enforcement()
        return enforce_input_only(function_name, input_payload)
    except Exception as e:
        logger.error(
            "Enforcement input check failed for %s, allowing through: %s",
            function_name, e,
        )
        return False, []
