# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — generate_poam_entry
# ---------------------------------------------------------------------------
# Action Function (1 of 4)
#
# Purpose:
#   Generates a structured Plan of Action & Milestones (POA&M) entry
#   for a compliance gap.  The entry includes risk-based remediation
#   timelines calculated from the severity and impact of the finding.
#
# How it works:
#   1. Accepts gap details (CC category, resource, description)
#   2. Calculates a risk-based remediation timeline
#   3. Generates a structured POA&M entry in standard format
#   4. Returns the entry — the Policy Writer agent may refine the language
#
# POA&M fields follow NIST SP 800-53 conventions:
#   • Weakness ID, Description, Severity, Risk Level
#   • Scheduled Completion Date (based on risk)
#   • Milestones with target dates
#   • Resources Required, Responsible Party
#
# AIUC-1 Controls:
#   AIUC-1-18  Input Validation  — validates required fields
#   AIUC-1-19  Output Filtering  — sanitises output
#   AIUC-1-22  Logging           — logs every POA&M generation
#   AIUC-1-46  Provenance        — tracks who requested the entry
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
import hashlib
from datetime import datetime, timezone, timedelta

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.validators import validate_cc_category, validate_required_fields

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.generate_poam_entry")


# ---- Risk-Based Timeline Calculation -------------------------------------
# Remediation timelines are based on severity × impact scoring.
# These are heuristic defaults — the agent can override them.

SEVERITY_TIMELINES = {
    "critical": {"days": 7, "label": "Immediate (7 days)"},
    "high": {"days": 30, "label": "Urgent (30 days)"},
    "medium": {"days": 90, "label": "Standard (90 days)"},
    "low": {"days": 180, "label": "Planned (180 days)"},
}

# Milestone templates per severity level
MILESTONE_TEMPLATES = {
    "critical": [
        {"phase": "Immediate containment", "offset_days": 1},
        {"phase": "Root cause analysis", "offset_days": 3},
        {"phase": "Remediation implementation", "offset_days": 5},
        {"phase": "Verification and closure", "offset_days": 7},
    ],
    "high": [
        {"phase": "Impact assessment", "offset_days": 3},
        {"phase": "Remediation planning", "offset_days": 7},
        {"phase": "Implementation", "offset_days": 21},
        {"phase": "Testing and verification", "offset_days": 28},
        {"phase": "Closure and documentation", "offset_days": 30},
    ],
    "medium": [
        {"phase": "Gap documentation", "offset_days": 7},
        {"phase": "Remediation design", "offset_days": 21},
        {"phase": "Change request approval", "offset_days": 35},
        {"phase": "Implementation", "offset_days": 70},
        {"phase": "Testing and verification", "offset_days": 84},
        {"phase": "Closure", "offset_days": 90},
    ],
    "low": [
        {"phase": "Backlog prioritisation", "offset_days": 14},
        {"phase": "Design and planning", "offset_days": 60},
        {"phase": "Implementation", "offset_days": 140},
        {"phase": "Verification and closure", "offset_days": 180},
    ],
}


def _generate_weakness_id(cc_category: str, resource: str, gap: str) -> str:
    """Generate a deterministic weakness ID from the gap details.

    The ID is a short hash so the same gap always gets the same ID,
    enabling tracking across multiple POA&M iterations.
    """
    content = f"{cc_category}:{resource}:{gap}".lower()
    return f"POAM-{hashlib.sha256(content.encode()).hexdigest()[:8].upper()}"


def _calculate_milestones(
    severity: str,
    start_date: datetime,
) -> list[dict]:
    """Generate milestone entries with target dates based on severity."""
    templates = MILESTONE_TEMPLATES.get(severity, MILESTONE_TEMPLATES["medium"])
    milestones = []
    for i, template in enumerate(templates, 1):
        target_date = start_date + timedelta(days=template["offset_days"])
        milestones.append({
            "milestone_number": i,
            "description": template["phase"],
            "target_date": target_date.strftime("%Y-%m-%d"),
            "status": "not_started",
        })
    return milestones


@app.route(route="generate_poam_entry", methods=["POST"])
@log_function_call("generate_poam_entry", aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Generate a structured POA&M entry for a compliance gap.

    Request body (JSON):
        {
            "cc_category": "CC6",                       // required
            "resource": "prod-open-nsg",                // required
            "gap_description": "RDP open to Internet",  // required
            "severity": "high",                         // required: critical/high/medium/low
            "responsible_party": "Cloud Security Team", // optional
            "resources_required": "Terraform module",   // optional
            "agent_id": "soc2-auditor"                  // optional — for provenance
        }

    Response:
        Standard envelope with the POA&M entry in data.poam_entry.
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "generate_poam_entry",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    # ---- Input validation (AIUC-1-18) ------------------------------------
    field_error = validate_required_fields(
        body, ["cc_category", "resource", "gap_description", "severity"]
    )
    if field_error:
        return build_error_response(
            "generate_poam_entry", field_error, error_code="MISSING_FIELDS", status_code=400
        )

    cc_category = body["cc_category"].strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response(
            "generate_poam_entry", cc_error, error_code="INVALID_CC_CATEGORY", status_code=400
        )

    severity = body["severity"].strip().lower()
    if severity not in SEVERITY_TIMELINES:
        return build_error_response(
            "generate_poam_entry",
            f"Invalid severity '{severity}'. Must be one of: {list(SEVERITY_TIMELINES.keys())}",
            error_code="INVALID_SEVERITY",
            status_code=400,
        )

    # ---- Generate POA&M entry --------------------------------------------
    now = datetime.now(timezone.utc)
    timeline = SEVERITY_TIMELINES[severity]
    completion_date = now + timedelta(days=timeline["days"])
    weakness_id = _generate_weakness_id(
        cc_category, body["resource"], body["gap_description"]
    )

    poam_entry = {
        "weakness_id": weakness_id,
        "cc_category": cc_category,
        "resource": body["resource"],
        "gap_description": body["gap_description"],
        "severity": severity,
        "risk_level": timeline["label"],
        "date_identified": now.strftime("%Y-%m-%d"),
        "scheduled_completion_date": completion_date.strftime("%Y-%m-%d"),
        "milestones": _calculate_milestones(severity, now),
        "responsible_party": body.get("responsible_party", "Unassigned"),
        "resources_required": body.get("resources_required", "To be determined"),
        "status": "open",
        "provenance": {
            "generated_by": "generate_poam_entry",
            "requested_by_agent": body.get("agent_id", "unknown"),
            "generated_at": now.isoformat(),
            "note": (
                "This POA&M entry was generated by the GRC tool library. "
                "The Policy Writer agent should review and refine the language "
                "before including it in the final POA&M report."
            ),
        },
    }

    result = {
        "poam_entry": poam_entry,
        "timeline_rationale": (
            f"Severity '{severity}' maps to a {timeline['days']}-day remediation "
            f"window per the risk-based timeline policy. The agent may adjust "
            f"this based on contextual factors."
        ),
    }

    return build_success_response(
        "generate_poam_entry",
        result,
        aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"],
    )
