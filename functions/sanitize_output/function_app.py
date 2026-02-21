# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — sanitize_output
# ---------------------------------------------------------------------------
# Safety Function (1 of 2)
#
# Purpose:
#   Standalone HTTP endpoint that agents can call to sanitise arbitrary
#   text before presenting it to users or writing it to reports.
#   Implements the explicit redaction rules from ChatGPT Audit Fix #4.
#
# Why a separate function?
#   While all functions sanitise their own output via the shared
#   sanitizer module, agents sometimes need to sanitise text they've
#   composed themselves (e.g., report narratives that reference Azure
#   resource IDs).  This function provides that capability as a service.
#
# Redaction rules (explicit per Audit Fix #4):
#   • Subscription IDs in ARM paths
#   • Standalone UUIDs (tenant, object, client IDs)
#   • Base64 access keys (> 40 chars)
#   • Connection strings (DefaultEndpointsProtocol=...)
#   • Private IP addresses (RFC 1918 ranges)
#   • SAS tokens (sig=, sv=, se=, etc.)
#   • Service principal secrets
#   • Bearer tokens
#
# What is NOT redacted (allowed to remain):
#   • Resource names (e.g., "aiuc1prodstorage")
#   • SKU names (e.g., "Standard_LRS")
#   • Azure regions (e.g., "eastus2")
#   • Policy compliance states (e.g., "NonCompliant")
#   • RBAC role names (e.g., "Contributor")
#   • CC category codes (e.g., "CC6")
#
# AIUC-1 Controls:
#   AIUC-1-19  Output Filtering  — this IS the output filter
#   AIUC-1-17  Data Minimization — strips unnecessary sensitive data
#   AIUC-1-22  Logging           — logs sanitisation requests
#   AIUC-1-34  Credential Mgmt  — prevents credential leakage
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.sanitizer import redact_secrets, redact_dict
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.sanitize_output")


@app.route(route="sanitize_output", methods=["POST"])
@log_function_call("sanitize_output", aiuc1_controls=["AIUC-1-17", "AIUC-1-19", "AIUC-1-22", "AIUC-1-34"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Sanitise text or structured data by redacting sensitive values.

    Accepts either plain text or a JSON object.  Returns the sanitised
    version with a report of how many redactions were made.

    Request body (JSON):
        {
            "text": "some text with /subscriptions/abc-123...",  // option A
            "data": {"key": "value with secrets"},               // option B
            "agent_id": "soc2-auditor"                           // optional
        }

    Exactly one of "text" or "data" must be provided.

    Response:
        Standard envelope with sanitised content and redaction stats.
        Note: sanitise=False on the response to avoid double-redaction.
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "sanitize_output",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    text_input = body.get("text")
    data_input = body.get("data")
    agent_id = body.get("agent_id", "unknown")

    if text_input is None and data_input is None:
        return build_error_response(
            "sanitize_output",
            "Provide either 'text' (string) or 'data' (object) to sanitise",
            error_code="MISSING_INPUT",
            status_code=400,
        )

    if text_input is not None and data_input is not None:
        return build_error_response(
            "sanitize_output",
            "Provide only one of 'text' or 'data', not both",
            error_code="AMBIGUOUS_INPUT",
            status_code=400,
        )

    # ---- Perform sanitisation --------------------------------------------
    redaction_count = 0

    if text_input is not None:
        if not isinstance(text_input, str):
            return build_error_response(
                "sanitize_output",
                "'text' must be a string",
                error_code="INVALID_TYPE",
                status_code=400,
            )

        sanitised = redact_secrets(text_input)

        # Count redactions by comparing before/after
        redaction_count = sanitised.count("[REDACTED")
        output_type = "text"
        output = sanitised

    else:
        if not isinstance(data_input, dict):
            return build_error_response(
                "sanitize_output",
                "'data' must be a JSON object",
                error_code="INVALID_TYPE",
                status_code=400,
            )

        sanitised = redact_dict(data_input)

        # Count redactions in the serialised output
        serialised = json.dumps(sanitised)
        redaction_count = serialised.count("[REDACTED")
        output_type = "data"
        output = sanitised

    # ---- Log the sanitisation event --------------------------------------
    log_event(
        "sanitisation_performed",
        function_name="sanitize_output",
        agent_id=agent_id,
        details={
            "input_type": output_type,
            "redaction_count": redaction_count,
        },
        aiuc1_controls=["AIUC-1-19"],
    )

    # ---- Build response --------------------------------------------------
    # IMPORTANT: sanitise=False here to avoid double-redaction.
    # The content has already been sanitised by this function.
    result = {
        "output_type": output_type,
        "sanitised_output": output,
        "redaction_stats": {
            "total_redactions": redaction_count,
            "patterns_applied": [
                "subscription_ids",
                "standalone_uuids",
                "base64_access_keys",
                "connection_strings",
                "private_ips",
                "sas_tokens",
                "sp_secrets",
                "bearer_tokens",
            ],
        },
        "allowed_to_remain": [
            "resource_names",
            "sku_names",
            "azure_regions",
            "policy_states",
            "rbac_role_names",
            "cc_category_codes",
        ],
        "sanitised_at": datetime.now(timezone.utc).isoformat(),
    }

    return build_success_response(
        "sanitize_output",
        result,
        sanitise=False,  # Already sanitised — prevent double-redaction
        aiuc1_controls=["AIUC-1-17", "AIUC-1-19", "AIUC-1-22", "AIUC-1-34"],
    )
