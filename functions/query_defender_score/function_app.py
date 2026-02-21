# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — query_defender_score
# ---------------------------------------------------------------------------
# Data Provider Function (5 of 6)
#
# Purpose:
#   Retrieves the Microsoft Defender for Cloud Secure Score and
#   associated security recommendations for the subscription.
#   Maps to CC9 (Risk Mitigation) and CC3 (Risk Assessment).
#
# How it works:
#   1. Queries the Security Center API for the current Secure Score
#   2. Retrieves active security recommendations (assessments)
#   3. Returns raw scores and recommendation data — the agent
#      interprets the risk implications
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — subscription-scoped only
#   AIUC-1-17  Data Minimization — returns scores, not full assessment bodies
#   AIUC-1-19  Output Filtering  — sanitises resource IDs
#   AIUC-1-22  Logging           — logs every query
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.azure_clients import get_mgmt_client
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.query_defender_score")


def _get_secure_scores(settings) -> dict:
    """Retrieve the Secure Score summary from Microsoft Defender for Cloud.

    The Secure Score is a percentage (0-100) representing the overall
    security posture of the subscription.  It's calculated by Microsoft
    based on security recommendations and their remediation status.
    """
    security_client = get_mgmt_client("security")
    scores = {}

    try:
        # secure_scores.list() returns all score profiles
        for score in security_client.secure_scores.list():
            scores = {
                "score_name": score.display_name or score.name,
                "current_score": score.score.current if score.score else None,
                "max_score": score.score.max if score.score else None,
                "percentage": score.score.percentage if score.score else None,
                "weight": score.weight,
            }
            break  # Usually only one score profile ("ascScore")
    except Exception as e:
        logger.error("Failed to retrieve Secure Score: %s", e)
        scores = {
            "error": str(e),
            "note": "Secure Score retrieval failed. Defender may not be fully enabled.",
        }

    return scores


def _get_security_assessments(settings, max_results: int = 50) -> list[dict]:
    """Retrieve security assessments (recommendations) from Defender.

    Each assessment represents a security recommendation with its current
    status (Healthy, Unhealthy, NotApplicable).  We return only the
    fields relevant to compliance assessment.

    Args:
        settings: Application settings.
        max_results: Maximum number of assessments to return (default 50).

    Returns:
        List of assessment summaries sorted by severity.
    """
    security_client = get_mgmt_client("security")
    assessments = []

    try:
        scope = f"/subscriptions/{settings.azure_subscription_id}"
        count = 0
        for assessment in security_client.assessments.list(scope=scope):
            if count >= max_results:
                break

            status_code = "unknown"
            if assessment.status:
                status_code = assessment.status.code or "unknown"

            # Only include unhealthy or not-applicable assessments
            # (healthy ones are compliant — less interesting for gap analysis)
            if status_code in ("Unhealthy", "NotApplicable", "unknown"):
                assessments.append({
                    "name": assessment.display_name or assessment.name,
                    "status": status_code,
                    "severity": (
                        assessment.metadata.severity
                        if assessment.metadata else "unknown"
                    ),
                    "category": (
                        assessment.metadata.categories[0]
                        if assessment.metadata and assessment.metadata.categories
                        else "uncategorised"
                    ),
                    "description": (
                        assessment.metadata.description
                        if assessment.metadata else ""
                    ),
                    "remediation_description": (
                        assessment.metadata.remediation_description
                        if assessment.metadata else ""
                    ),
                    "resource_type": assessment.resource_details.source if assessment.resource_details else "unknown",
                })
                count += 1
    except Exception as e:
        logger.error("Failed to retrieve security assessments: %s", e)
        assessments.append({
            "error": str(e),
            "note": "Assessment retrieval failed. Check Defender configuration.",
        })

    # Sort by severity: High > Medium > Low
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "unknown": 3}
    assessments.sort(key=lambda a: severity_order.get(a.get("severity", "unknown"), 3))

    return assessments


@app.route(route="query_defender_score", methods=["POST"])
@log_function_call("query_defender_score", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Query Microsoft Defender for Cloud Secure Score and recommendations.

    Request body (JSON):
        {
            "include_assessments": true,  // optional (default true)
            "max_results": 50             // optional (default 50)
        }

    Response:
        Standard envelope with secure_score and assessments in data.
    """
    try:
        body = req.get_json()
    except ValueError:
        body = {}

    include_assessments = body.get("include_assessments", True)
    max_results = min(body.get("max_results", 50), 100)  # Cap at 100

    # ---- Query Defender --------------------------------------------------
    settings = get_settings()

    secure_score = _get_secure_scores(settings)
    assessments = (
        _get_security_assessments(settings, max_results)
        if include_assessments
        else []
    )

    # ---- Summary for the agent -------------------------------------------
    unhealthy_count = sum(1 for a in assessments if a.get("status") == "Unhealthy")
    high_severity_count = sum(
        1 for a in assessments
        if a.get("severity") == "High" and a.get("status") == "Unhealthy"
    )

    result = {
        "secure_score": secure_score,
        "assessments": {
            "total_returned": len(assessments),
            "unhealthy_count": unhealthy_count,
            "high_severity_unhealthy": high_severity_count,
            "items": assessments,
        },
        "soc2_mapping": {
            "primary": "CC9 — Risk Mitigation",
            "secondary": "CC3 — Risk Assessment",
            "note": (
                "Secure Score reflects the subscription's overall security posture. "
                "Individual assessments map to specific CC categories based on their "
                "category (e.g., 'Networking' → CC6, 'Data' → CC5)."
            ),
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return build_success_response(
        "query_defender_score",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"],
    )
