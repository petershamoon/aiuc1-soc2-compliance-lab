# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — query_policy_compliance
# ---------------------------------------------------------------------------
# Data Provider Function (6 of 6)
#
# Purpose:
#   Returns Azure Policy compliance state for the subscription, with
#   special attention to the CIS Azure Foundations Benchmark v2.0.0
#   policy assignment.  Maps to CC1 (Control Environment) and CC8
#   (Change Management).
#
# How it works:
#   1. Queries Policy Insights API for compliance summary
#   2. Retrieves non-compliant resources per policy definition
#   3. Highlights CIS Benchmark results specifically
#   4. Returns raw compliance data — agent interprets implications
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — subscription-scoped
#   AIUC-1-17  Data Minimization — summary counts, not full resource details
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

logger = logging.getLogger("aiuc1.query_policy_compliance")

# CIS Azure Foundations Benchmark v2.0.0 policy set definition ID
# (Lesson Learned #6: v2.0.0 is the correct one, not v1.1.0)
CIS_BENCHMARK_POLICY_ID = "06f19060-9e68-4070-92ca-f15cc126059e"


def _get_compliance_summary(settings) -> dict:
    """Get the overall policy compliance summary for the subscription.

    Returns aggregate counts of compliant, non-compliant, and exempt
    resources across all policy assignments.
    """
    policy_client = get_mgmt_client("policy_insights")
    summary = {
        "compliant": 0,
        "non_compliant": 0,
        "exempt": 0,
        "conflicting": 0,
        "not_started": 0,
    }

    try:
        # Query policy states summary at subscription scope
        sub_id = settings.azure_subscription_id
        results = policy_client.policy_states.summarize_for_subscription(
            subscription_id=sub_id,
            policy_states_resource="latest",
        )

        if results and results.value:
            for result in results.value:
                if result.results:
                    for detail in (result.results.non_compliant_resources or []):
                        pass  # Handled below
                    # Use the summary totals
                    summary["non_compliant"] = (
                        result.results.non_compliant_resources
                        if isinstance(result.results.non_compliant_resources, int)
                        else 0
                    )
    except Exception as e:
        logger.error("Failed to get compliance summary: %s", e)
        summary["error"] = str(e)

    return summary


def _get_non_compliant_policies(settings, max_results: int = 50) -> list[dict]:
    """Retrieve policies with non-compliant resources.

    Returns a list of policy definitions that have at least one
    non-compliant resource, along with the count and category.
    """
    policy_client = get_mgmt_client("policy_insights")
    non_compliant = []

    try:
        sub_id = settings.azure_subscription_id
        results = policy_client.policy_states.list_query_results_for_subscription(
            subscription_id=sub_id,
            policy_states_resource="latest",
            query_options=None,
        )

        seen_policies = {}
        count = 0
        for state in results:
            if count >= max_results:
                break
            if state.compliance_state == "NonCompliant":
                policy_key = state.policy_definition_name or "unknown"
                if policy_key not in seen_policies:
                    seen_policies[policy_key] = {
                        "policy_name": state.policy_definition_name,
                        "policy_definition_action": state.policy_definition_action,
                        "policy_set_definition_name": state.policy_set_definition_name,
                        "resource_type": state.resource_type,
                        "compliance_state": state.compliance_state,
                        "is_cis_benchmark": (
                            state.policy_set_definition_name == CIS_BENCHMARK_POLICY_ID
                            if state.policy_set_definition_name else False
                        ),
                        "non_compliant_count": 1,
                    }
                    count += 1
                else:
                    seen_policies[policy_key]["non_compliant_count"] += 1

        non_compliant = list(seen_policies.values())
        # Sort: CIS benchmark findings first, then by count
        non_compliant.sort(
            key=lambda p: (not p.get("is_cis_benchmark"), -p.get("non_compliant_count", 0))
        )
    except Exception as e:
        logger.error("Failed to query non-compliant policies: %s", e)
        non_compliant.append({
            "error": str(e),
            "note": "Policy compliance query failed.",
        })

    return non_compliant


@app.route(route="query_policy_compliance", methods=["POST"])
@log_function_call("query_policy_compliance", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Query Azure Policy compliance state for the subscription.

    Request body (JSON):
        {
            "include_details": true,  // optional (default true)
            "max_results": 50         // optional (default 50)
        }

    Response:
        Standard envelope with compliance summary and non-compliant policies.
    """
    try:
        body = req.get_json()
    except ValueError:
        body = {}

    include_details = body.get("include_details", True)
    max_results = min(body.get("max_results", 50), 100)

    # ---- Query policy compliance -----------------------------------------
    settings = get_settings()

    compliance_summary = _get_compliance_summary(settings)
    non_compliant_policies = (
        _get_non_compliant_policies(settings, max_results)
        if include_details
        else []
    )

    # ---- CIS Benchmark highlight -----------------------------------------
    cis_findings = [p for p in non_compliant_policies if p.get("is_cis_benchmark")]

    result = {
        "compliance_summary": compliance_summary,
        "non_compliant_policies": {
            "total": len(non_compliant_policies),
            "items": non_compliant_policies,
        },
        "cis_benchmark": {
            "policy_id": CIS_BENCHMARK_POLICY_ID,
            "version": "v2.0.0",
            "findings_count": len(cis_findings),
            "findings": cis_findings,
            "note": (
                "CIS Azure Foundations Benchmark v2.0.0 is the primary policy "
                "framework for this lab. Non-compliant findings here directly "
                "map to SOC 2 control gaps."
            ),
        },
        "soc2_mapping": {
            "primary": "CC1 — Control Environment",
            "secondary": "CC8 — Change Management",
            "note": (
                "Azure Policy enforces the control environment (CC1) and "
                "validates that changes comply with defined standards (CC8)."
            ),
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return build_success_response(
        "query_policy_compliance",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"],
    )
