# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Enforcement Middleware
# ---------------------------------------------------------------------------
# The middleware is the integration point that wires together all
# enforcement components (gateway, scope enforcer, tool restrictions,
# disclosure injector, audit chain) into a single decorator that wraps
# every Azure Function.
#
# Usage:
#
#   from enforcement.middleware import enforce, get_enforcement_context
#
#   @app.queue_trigger(...)
#   @app.queue_output(...)
#   def my_function(msg, output):
#       body, correlation_id = parse_queue_msg(msg)
#
#       # The enforcement context is available for the function to use
#       ctx = get_enforcement_context()
#
#       # ... function logic ...
#
#       # The enforce() wrapper handles input validation, output
#       # sanitisation, disclosure injection, and audit logging
#       # automatically.
#
# The middleware executes in this order:
#
#   INPUT PHASE:
#     1. Parse queue message
#     2. Scope boundary check (ScopeEnforcer)
#     3. Tool restriction check (ToolRestrictionEngine)
#     4. If any violations → block and return error envelope
#
#   FUNCTION EXECUTION:
#     5. Call the wrapped function
#
#   OUTPUT PHASE:
#     6. Sanitise response (OutputGateway)
#     7. Inject AI disclosure (DisclosureInjector)
#     8. Attach enforcement metadata
#     9. Record all decisions in audit chain (AuditChain)
#     10. Write to output queue
#
# AIUC-1 Controls:
#   All controls enforced by the sub-components, plus:
#   E015  Audit trail for the full enforcement pipeline
#   E017  Transparency — enforcement metadata in every response
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from .gateway import OutputGateway
from .scope_enforcer import ScopeEnforcer
from .tool_restrictions import ToolRestrictionEngine
from .disclosure import DisclosureInjector
from .audit_chain import AuditChain
from .policy_engine import (
    PolicyEngine,
    EnforcementAction,
    PolicyScope,
    load_policies,
)

logger = logging.getLogger("aiuc1.enforcement.middleware")


# ---------------------------------------------------------------------------
# Singleton instances — initialised once per process lifetime
# ---------------------------------------------------------------------------

_policy_engine: Optional[PolicyEngine] = None
_output_gateway: Optional[OutputGateway] = None
_scope_enforcer: Optional[ScopeEnforcer] = None
_tool_restrictions: Optional[ToolRestrictionEngine] = None
_disclosure_injector: Optional[DisclosureInjector] = None
_audit_chain: Optional[AuditChain] = None


def _init_enforcement() -> None:
    """Initialise all enforcement components (idempotent)."""
    global _policy_engine, _output_gateway, _scope_enforcer
    global _tool_restrictions, _disclosure_injector, _audit_chain

    if _policy_engine is not None:
        return  # Already initialised

    policies = load_policies()
    _policy_engine = PolicyEngine(policies)
    _output_gateway = OutputGateway()
    _scope_enforcer = ScopeEnforcer()
    _tool_restrictions = ToolRestrictionEngine()
    _disclosure_injector = DisclosureInjector()
    _audit_chain = AuditChain()

    logger.info(
        "Enforcement layer initialised: %d policies, %d components",
        len(policies),
        5,
    )


def get_enforcement_context() -> dict[str, Any]:
    """Return the current enforcement context for function use.

    Functions can call this to access enforcement metadata, the policy
    manifest, and audit chain summary.
    """
    _init_enforcement()
    return {
        "policy_manifest": _policy_engine.policy_manifest,
        "audit_summary": _audit_chain.get_summary(),
        "gateway_stats": _output_gateway.stats,
        "risk_map": ToolRestrictionEngine.get_risk_map(),
        "scope_boundaries": sorted(_scope_enforcer.allowed_resource_groups),
    }


def enforce(
    function_name: str,
    input_payload: dict[str, Any],
    output_envelope: dict[str, Any],
    correlation_id: str = "",
) -> tuple[dict[str, Any], bool, list[dict[str, Any]]]:
    """Run the full enforcement pipeline on a function call.

    This is the main entry point for the enforcement layer.  It
    processes both the input and output phases and returns the
    final response envelope.

    Args:
        function_name: Name of the Azure Function.
        input_payload: The parsed input from the queue message.
        output_envelope: The function's raw response envelope.
        correlation_id: Queue message correlation ID.

    Returns:
        Tuple of:
        - Final response envelope (sanitised, with disclosure)
        - Whether the call was blocked (True = blocked)
        - List of enforcement decision dicts for transparency
    """
    _init_enforcement()
    decisions = []
    blocked = False

    # ---- INPUT PHASE ----

    # 1. Scope boundary check
    scope_violations = _scope_enforcer.check_payload(input_payload, function_name)
    for violation in scope_violations:
        _audit_chain.record(
            function_name=function_name,
            action="block",
            policy_id="ENF-002",
            applied=True,
            reason=violation.reason,
            aiuc1_controls=("B006", "D003"),
            details=violation.to_dict(),
        )
        decisions.append({
            "policy_id": "ENF-002",
            "action": "block",
            "reason": violation.reason,
            "type": "scope_violation",
        })
        blocked = True

    # 2. Tool restriction check
    restriction_violations = _tool_restrictions.check_restrictions(
        function_name, input_payload
    )
    for violation in restriction_violations:
        _audit_chain.record(
            function_name=function_name,
            action="block",
            policy_id="ENF-003",
            applied=True,
            reason=violation.description,
            aiuc1_controls=tuple(violation.aiuc1_controls),
            details=violation.details,
        )
        decisions.append({
            "policy_id": violation.rule,
            "action": "block",
            "reason": violation.description,
            "type": "restriction_violation",
            "severity": violation.severity,
        })
        if violation.severity in ("CRITICAL", "ERROR"):
            blocked = True

    # If blocked, return an error envelope
    if blocked:
        error_envelope = _build_blocked_envelope(
            function_name, decisions, correlation_id
        )
        # Still sanitise the error envelope
        sanitised, gateway_meta = _output_gateway.sanitise_envelope(
            error_envelope, function_name
        )
        _audit_chain.record(
            function_name=function_name,
            action="sanitise",
            policy_id="ENF-001",
            applied=True,
            reason="Mandatory output sanitisation (even on blocked responses)",
            aiuc1_controls=("A006", "B009"),
        )
        return sanitised, True, decisions

    # ---- OUTPUT PHASE ----

    # 3. Sanitise the response envelope
    sanitised, gateway_meta = _output_gateway.sanitise_envelope(
        output_envelope, function_name
    )
    _audit_chain.record(
        function_name=function_name,
        action="sanitise",
        policy_id="ENF-001",
        applied=True,
        reason=f"Mandatory output sanitisation: {gateway_meta['redaction_count']} redaction(s)",
        aiuc1_controls=("A006", "B009", "A004"),
        details={"redaction_count": gateway_meta["redaction_count"]},
    )
    decisions.append({
        "policy_id": "ENF-001",
        "action": "sanitise",
        "redaction_count": gateway_meta["redaction_count"],
    })

    # 4. Inject AI disclosure
    enforced_controls = _collect_enforced_controls(decisions)
    sanitised = _disclosure_injector.inject(
        sanitised, function_name, enforced_controls
    )
    _audit_chain.record(
        function_name=function_name,
        action="inject",
        policy_id="ENF-005",
        applied=True,
        reason="AI disclosure footer injected (E016)",
        aiuc1_controls=("E016",),
    )
    decisions.append({
        "policy_id": "ENF-005",
        "action": "inject",
        "type": "ai_disclosure",
    })

    # 5. Attach enforcement metadata
    risk_level = ToolRestrictionEngine.get_risk_level(function_name)
    sanitised["enforcement_metadata"] = {
        "enforcement_layer_version": DisclosureInjector.VERSION,
        "function_name": function_name,
        "risk_level": risk_level.value,
        "policies_evaluated": len(decisions),
        "gateway": gateway_meta,
        "audit_chain": _audit_chain.get_summary(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "aiuc1_controls_enforced": enforced_controls,
    }

    # 6. Record the audit trail entry for the full pipeline
    _audit_chain.record(
        function_name=function_name,
        action="complete",
        policy_id="ENF-006",
        applied=True,
        reason=f"Enforcement pipeline completed for {function_name}",
        aiuc1_controls=("E015", "E017"),
        details={
            "decisions_count": len(decisions),
            "risk_level": risk_level.value,
            "blocked": False,
        },
    )

    return sanitised, False, decisions


def enforce_input_only(
    function_name: str,
    input_payload: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]]]:
    """Run only the input-phase enforcement checks.

    This is useful for functions that need to check input validity
    before doing expensive work.

    Args:
        function_name: Name of the Azure Function.
        input_payload: The parsed input from the queue message.

    Returns:
        Tuple of (blocked: bool, decisions: list).
    """
    _init_enforcement()
    decisions = []
    blocked = False

    # Scope check
    scope_violations = _scope_enforcer.check_payload(input_payload, function_name)
    for v in scope_violations:
        decisions.append({"policy_id": "ENF-002", "action": "block", "reason": v.reason})
        blocked = True

    # Restriction check
    restriction_violations = _tool_restrictions.check_restrictions(
        function_name, input_payload
    )
    for v in restriction_violations:
        decisions.append({
            "policy_id": v.rule,
            "action": "block",
            "reason": v.description,
            "severity": v.severity,
        })
        if v.severity in ("CRITICAL", "ERROR"):
            blocked = True

    return blocked, decisions


def enforce_output_only(
    function_name: str,
    output_envelope: dict[str, Any],
) -> dict[str, Any]:
    """Run only the output-phase enforcement (sanitise + disclose).

    Args:
        function_name: Name of the Azure Function.
        output_envelope: The function's raw response envelope.

    Returns:
        The sanitised envelope with disclosure and metadata.
    """
    _init_enforcement()

    sanitised, gateway_meta = _output_gateway.sanitise_envelope(
        output_envelope, function_name
    )
    sanitised = _disclosure_injector.inject(sanitised, function_name)

    risk_level = ToolRestrictionEngine.get_risk_level(function_name)
    sanitised["enforcement_metadata"] = {
        "enforcement_layer_version": DisclosureInjector.VERSION,
        "function_name": function_name,
        "risk_level": risk_level.value,
        "gateway": gateway_meta,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return sanitised


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_blocked_envelope(
    function_name: str,
    decisions: list[dict[str, Any]],
    correlation_id: str,
) -> dict[str, Any]:
    """Build an error envelope for a blocked request."""
    reasons = [d["reason"] for d in decisions if d.get("action") == "block"]
    return {
        "status": "blocked",
        "function": function_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error": {
            "code": "ENFORCEMENT_BLOCKED",
            "message": (
                f"Request to '{function_name}' was blocked by the AIUC-1 "
                f"enforcement layer.  {len(reasons)} violation(s) detected."
            ),
            "violations": reasons,
        },
        "enforcement_decisions": decisions,
        "aiuc1_controls": _collect_enforced_controls(decisions),
        "sanitised": True,
    }


def _collect_enforced_controls(
    decisions: list[dict[str, Any]],
) -> list[str]:
    """Collect unique AIUC-1 control IDs from enforcement decisions."""
    controls = set()
    # Always include the core enforcement controls
    controls.update(["A006", "B009", "E015", "E016", "E017"])
    for d in decisions:
        if "aiuc1_controls" in d:
            controls.update(d["aiuc1_controls"])
    return sorted(controls)
