# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — gap_analyzer
# ---------------------------------------------------------------------------
# Data Provider Function (1 of 6)
#
# Purpose:
#   Accepts a SOC 2 CC category, retrieves the relevant Azure resource
#   state, and returns a heuristic gap analysis comparing the current
#   state against expected controls.
#
# How it works:
#   1. Validates the CC category input (AIUC-1-18)
#   2. Calls scan_cc_criteria logic to get raw Azure state
#   3. Applies heuristic rules to identify potential gaps
#   4. Returns structured gap data — the *agent* decides severity
#
# Design principle:
#   "Tools provide data, agents provide judgment."
#   This function identifies *what* is missing; the SOC 2 Auditor agent
#   decides *how bad* it is and what to recommend.
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — only queries allowed resource groups
#   AIUC-1-17  Data Minimization — returns only compliance-relevant fields
#   AIUC-1-18  Input Validation  — validates CC category
#   AIUC-1-19  Output Filtering  — sanitises response
#   AIUC-1-22  Logging           — logs every invocation
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
from datetime import datetime, timezone

# Import shared utilities
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.azure_clients import get_mgmt_client
from shared.sanitizer import redact_dict
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.validators import (
    validate_cc_category,
    validate_resource_group,
    CC_RESOURCE_MAP,
)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.gap_analyzer")


# ---- Heuristic Gap Rules --------------------------------------------------
# Each rule maps a CC category to a check function that returns a list of
# gap findings.  Rules are intentionally simple heuristics — the AI agent
# applies nuanced judgment on top.

def _check_cc5_storage_gaps(settings) -> list[dict]:
    """CC5 — Control Activities: check storage account configurations."""
    gaps = []
    try:
        storage_client = get_mgmt_client("storage")
        for rg in settings.allowed_resource_groups:
            try:
                accounts = storage_client.storage_accounts.list_by_resource_group(rg)
                for acct in accounts:
                    # Check: public blob access should be disabled
                    if acct.allow_blob_public_access:
                        gaps.append({
                            "resource": acct.name,
                            "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": "Public blob access is enabled",
                            "expected": "allow_blob_public_access = false",
                            "actual": "allow_blob_public_access = true",
                            "risk": "Data exposure — blobs may be publicly readable",
                        })
                    # Check: HTTPS-only traffic
                    if not acct.enable_https_traffic_only:
                        gaps.append({
                            "resource": acct.name,
                            "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": "HTTPS-only traffic not enforced",
                            "expected": "enable_https_traffic_only = true",
                            "actual": "enable_https_traffic_only = false",
                            "risk": "Data in transit may be unencrypted",
                        })
                    # Check: minimum TLS version
                    if acct.minimum_tls_version and acct.minimum_tls_version != "TLS1_2":
                        gaps.append({
                            "resource": acct.name,
                            "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": f"TLS version is {acct.minimum_tls_version}",
                            "expected": "minimum_tls_version = TLS1_2",
                            "actual": f"minimum_tls_version = {acct.minimum_tls_version}",
                            "risk": "Weak TLS may allow downgrade attacks",
                        })
            except Exception as e:
                logger.warning("Error scanning storage in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create storage client: %s", e)
    return gaps


def _check_cc6_network_gaps(settings) -> list[dict]:
    """CC6 — Logical Access Controls: check NSG rules for overly permissive access."""
    gaps = []
    try:
        network_client = get_mgmt_client("network")
        for rg in settings.allowed_resource_groups:
            try:
                nsgs = network_client.network_security_groups.list(rg)
                for nsg in nsgs:
                    for rule in (nsg.security_rules or []):
                        # Flag rules that allow inbound from Any source
                        if (
                            rule.direction == "Inbound"
                            and rule.access == "Allow"
                            and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")
                        ):
                            gaps.append({
                                "resource": nsg.name,
                                "resource_group": rg,
                                "cc_category": "CC6",
                                "gap": f"Inbound rule '{rule.name}' allows traffic from {rule.source_address_prefix}",
                                "expected": "Source restricted to known CIDR ranges",
                                "actual": f"source={rule.source_address_prefix}, port={rule.destination_port_range}, protocol={rule.protocol}",
                                "risk": "Unrestricted inbound access (potential RDP/SSH exposure)",
                            })
            except Exception as e:
                logger.warning("Error scanning NSGs in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create network client: %s", e)
    return gaps


def _check_cc7_sql_gaps(settings) -> list[dict]:
    """CC7 — System Operations: check SQL Server auditing and TDE."""
    gaps = []
    try:
        sql_client = get_mgmt_client("sql")
        for rg in settings.allowed_resource_groups:
            try:
                servers = sql_client.servers.list_by_resource_group(rg)
                for server in servers:
                    # Check auditing status
                    try:
                        audit = sql_client.server_blob_auditing_policies.get(
                            rg, server.name
                        )
                        if audit.state != "Enabled":
                            gaps.append({
                                "resource": server.name,
                                "resource_group": rg,
                                "cc_category": "CC7",
                                "gap": "SQL Server auditing is not enabled",
                                "expected": "blob_auditing_policy.state = Enabled",
                                "actual": f"blob_auditing_policy.state = {audit.state}",
                                "risk": "No audit trail for database operations",
                            })
                    except Exception:
                        gaps.append({
                            "resource": server.name,
                            "resource_group": rg,
                            "cc_category": "CC7",
                            "gap": "Unable to retrieve SQL auditing policy",
                            "expected": "Auditing policy accessible and enabled",
                            "actual": "Policy retrieval failed",
                            "risk": "Auditing status unknown",
                        })
            except Exception as e:
                logger.warning("Error scanning SQL in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create SQL client: %s", e)
    return gaps


# Map CC categories to their gap-check functions
_GAP_CHECKERS = {
    "CC5": _check_cc5_storage_gaps,
    "CC6": _check_cc6_network_gaps,
    "CC7": _check_cc7_sql_gaps,
}


@app.route(route="gap_analyzer", methods=["POST"])
@log_function_call("gap_analyzer", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Analyse compliance gaps for a given SOC 2 CC category.

    Request body (JSON):
        {
            "cc_category": "CC6",          // required — SOC 2 CC code
            "resource_group": "rg-production"  // optional — limit scope
        }

    Response:
        Standard envelope with gap findings in data.gaps[].
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "gap_analyzer",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    cc_category = body.get("cc_category", "").strip().upper()
    resource_group = body.get("resource_group", "")

    # ---- Input validation (AIUC-1-18) ------------------------------------
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response(
            "gap_analyzer", cc_error, error_code="INVALID_CC_CATEGORY", status_code=400
        )

    if resource_group:
        rg_error = validate_resource_group(resource_group)
        if rg_error:
            return build_error_response(
                "gap_analyzer", rg_error, error_code="SCOPE_VIOLATION", status_code=403
            )

    # ---- Run gap analysis ------------------------------------------------
    settings = get_settings()
    checker = _GAP_CHECKERS.get(cc_category)

    if checker:
        gaps = checker(settings)
    else:
        # For CC categories without specific checkers, return metadata
        # indicating that the check is not yet implemented.
        gaps = []
        logger.info(
            "No heuristic checker for %s — returning empty gaps (agent will assess manually)",
            cc_category,
        )

    # Optionally filter by resource group
    if resource_group:
        gaps = [g for g in gaps if g.get("resource_group") == resource_group]

    # ---- Build response --------------------------------------------------
    result = {
        "cc_category": cc_category,
        "cc_description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "total_gaps": len(gaps),
        "gaps": gaps,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Gaps are heuristic findings. The SOC 2 Auditor agent determines severity and recommendations.",
    }

    return build_success_response(
        "gap_analyzer",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"],
    )
