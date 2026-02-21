# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — log_security_event
# ---------------------------------------------------------------------------
# Safety Function (2 of 2)
#
# Purpose:
#   Provides a dedicated endpoint for agents to log security-relevant
#   events to Azure Application Insights.  This creates structured,
#   searchable audit records for SOC 2 evidence and incident detection.
#
# Event categories:
#   • scope_violation    — agent tried to access out-of-scope resources
#   • secret_exposure    — potential credential leak detected
#   • validation_failure — input validation rejected a request
#   • approval_denied    — terraform apply rejected (invalid token)
#   • anomalous_behavior — agent behavior outside expected patterns
#   • compliance_finding — new compliance gap discovered
#   • remediation_action — infrastructure change applied
#   • access_event       — RBAC or access control change detected
#
# All events include:
#   • Timestamp (UTC)
#   • Agent ID (which agent triggered the event)
#   • Event category and severity
#   • AIUC-1 controls relevant to the event
#   • Structured details for App Insights custom dimensions
#
# AIUC-1 Controls:
#   AIUC-1-22  Logging & Monitoring — this IS the logging function
#   AIUC-1-23  Audit Trail          — creates immutable records
#   AIUC-1-24  Incident Detection   — security events enable detection
#   AIUC-1-19  Output Filtering     — event details are sanitised
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.sanitizer import redact_secrets, redact_dict
from shared.validators import validate_required_fields

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.log_security_event")


# ---- Valid Event Categories -----------------------------------------------

VALID_CATEGORIES = {
    "scope_violation": {
        "description": "Agent attempted to access resources outside lab scope",
        "default_severity": "ERROR",
        "aiuc1_controls": ["AIUC-1-09", "AIUC-1-22"],
    },
    "secret_exposure": {
        "description": "Potential credential or secret leak detected",
        "default_severity": "CRITICAL",
        "aiuc1_controls": ["AIUC-1-34", "AIUC-1-19", "AIUC-1-22"],
    },
    "validation_failure": {
        "description": "Input validation rejected a request",
        "default_severity": "WARNING",
        "aiuc1_controls": ["AIUC-1-18", "AIUC-1-22"],
    },
    "approval_denied": {
        "description": "Terraform apply rejected due to invalid approval token",
        "default_severity": "ERROR",
        "aiuc1_controls": ["AIUC-1-11", "AIUC-1-22"],
    },
    "anomalous_behavior": {
        "description": "Agent behavior outside expected patterns",
        "default_severity": "WARNING",
        "aiuc1_controls": ["AIUC-1-24", "AIUC-1-22"],
    },
    "compliance_finding": {
        "description": "New compliance gap discovered during assessment",
        "default_severity": "INFO",
        "aiuc1_controls": ["AIUC-1-22", "AIUC-1-23"],
    },
    "remediation_action": {
        "description": "Infrastructure change applied to fix a compliance gap",
        "default_severity": "INFO",
        "aiuc1_controls": ["AIUC-1-30", "AIUC-1-22"],
    },
    "access_event": {
        "description": "RBAC or access control change detected",
        "default_severity": "WARNING",
        "aiuc1_controls": ["AIUC-1-09", "AIUC-1-22"],
    },
}

VALID_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@app.route(route="log_security_event", methods=["POST"])
@log_function_call("log_security_event", aiuc1_controls=["AIUC-1-22", "AIUC-1-23", "AIUC-1-24", "AIUC-1-19"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Log a structured security event to Application Insights.

    Request body (JSON):
        {
            "category": "scope_violation",        // required — event category
            "agent_id": "soc2-auditor",           // required — which agent
            "description": "Attempted to query...",// required — what happened
            "severity": "ERROR",                  // optional — override default
            "cc_category": "CC6",                 // optional — related CC
            "details": {"resource": "..."},       // optional — extra context
            "aiuc1_controls": ["AIUC-1-09"]       // optional — override defaults
        }

    Response:
        Standard envelope confirming the event was logged.
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "log_security_event",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    # ---- Input validation (AIUC-1-18) ------------------------------------
    field_error = validate_required_fields(body, ["category", "agent_id", "description"])
    if field_error:
        return build_error_response(
            "log_security_event", field_error, error_code="MISSING_FIELDS", status_code=400
        )

    category = body["category"].strip().lower()
    agent_id = body["agent_id"].strip()
    description = body["description"].strip()

    if category not in VALID_CATEGORIES:
        return build_error_response(
            "log_security_event",
            f"Invalid category '{category}'. Must be one of: {sorted(VALID_CATEGORIES.keys())}",
            error_code="INVALID_CATEGORY",
            status_code=400,
        )

    # Determine severity (use provided or category default)
    severity = body.get("severity", "").strip().upper()
    if severity and severity not in VALID_SEVERITIES:
        return build_error_response(
            "log_security_event",
            f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}",
            error_code="INVALID_SEVERITY",
            status_code=400,
        )
    if not severity:
        severity = VALID_CATEGORIES[category]["default_severity"]

    # Determine AIUC-1 controls
    aiuc1_controls = body.get(
        "aiuc1_controls",
        VALID_CATEGORIES[category]["aiuc1_controls"],
    )

    # Sanitise the description and details before logging
    sanitised_description = redact_secrets(description)
    details = body.get("details", {})
    sanitised_details = redact_dict(details) if isinstance(details, dict) else {}

    # ---- Log the event ---------------------------------------------------
    event_id = f"SEC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{category[:4].upper()}"

    log_event(
        event_type=f"security_event.{category}",
        function_name="log_security_event",
        agent_id=agent_id,
        cc_category=body.get("cc_category", ""),
        severity=severity,
        details={
            "event_id": event_id,
            "category": category,
            "category_description": VALID_CATEGORIES[category]["description"],
            "description": sanitised_description,
            **sanitised_details,
        },
        aiuc1_controls=aiuc1_controls,
    )

    # ---- Build response --------------------------------------------------
    result = {
        "event_id": event_id,
        "category": category,
        "category_description": VALID_CATEGORIES[category]["description"],
        "severity": severity,
        "agent_id": agent_id,
        "description": sanitised_description,
        "details": sanitised_details,
        "aiuc1_controls": aiuc1_controls,
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "destination": "Azure Application Insights (custom events)",
        "retention_note": (
            "Security events are retained in Application Insights for the "
            "configured retention period (default 90 days). For SOC 2 Type II "
            "audits, ensure retention covers the examination period."
        ),
    }

    return build_success_response(
        "log_security_event",
        result,
        aiuc1_controls=["AIUC-1-22", "AIUC-1-23", "AIUC-1-24", "AIUC-1-19"],
    )
