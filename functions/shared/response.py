# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Standardised HTTP Response Builder
# ---------------------------------------------------------------------------
# All 12 Azure Functions return responses through these helpers to ensure
# a consistent JSON envelope.  The envelope includes metadata that agents
# use for provenance tracking and audit trails.
#
# Response envelope schema:
#   {
#     "status": "success" | "error",
#     "function": "<function_name>",
#     "timestamp": "<ISO 8601>",
#     "data": { ... },            // present on success
#     "error": { ... },           // present on error
#     "aiuc1_controls": ["..."],  // controls exercised
#     "sanitised": true           // confirms output was redacted
#   }
#
# AIUC-1 Controls:
#   AIUC-1-19  Output Filtering  — every response is sanitised
#   AIUC-1-22  Logging           — response metadata supports audit
#   AIUC-1-46  Provenance        — timestamp + function name for tracing
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import azure.functions as func

from .sanitizer import redact_dict


def build_success_response(
    function_name: str,
    data: dict[str, Any],
    *,
    aiuc1_controls: Optional[list[str]] = None,
    status_code: int = 200,
    sanitise: bool = True,
) -> func.HttpResponse:
    """Build a standardised success response.

    Args:
        function_name: Name of the Azure Function returning the response.
        data: The payload dictionary to include under the "data" key.
        aiuc1_controls: AIUC-1 control IDs exercised during this call.
        status_code: HTTP status code (default 200).
        sanitise: Whether to run redact_dict on *data* (default True).
            Set to False only for the sanitize_output function itself
            to avoid double-redaction.

    Returns:
        An azure.functions.HttpResponse with JSON body.
    """
    clean_data = redact_dict(data) if sanitise else data

    envelope = {
        "status": "success",
        "function": function_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": clean_data,
        "aiuc1_controls": aiuc1_controls or [],
        "sanitised": sanitise,
    }

    return func.HttpResponse(
        body=json.dumps(envelope, indent=2, default=str),
        status_code=status_code,
        mimetype="application/json",
    )


def build_error_response(
    function_name: str,
    error_message: str,
    *,
    error_code: str = "INTERNAL_ERROR",
    status_code: int = 500,
    details: Optional[dict[str, Any]] = None,
    aiuc1_controls: Optional[list[str]] = None,
) -> func.HttpResponse:
    """Build a standardised error response.

    Error messages are also sanitised to prevent accidental secret leakage
    in stack traces or Azure SDK error messages.

    Args:
        function_name: Name of the Azure Function returning the error.
        error_message: Human-readable error description.
        error_code: Machine-readable error code for programmatic handling.
        status_code: HTTP status code (default 500).
        details: Additional error context (will be sanitised).
        aiuc1_controls: AIUC-1 control IDs exercised during this call.

    Returns:
        An azure.functions.HttpResponse with JSON error body.
    """
    from .sanitizer import redact_secrets

    envelope = {
        "status": "error",
        "function": function_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error": {
            "code": error_code,
            "message": redact_secrets(error_message),
            "details": redact_dict(details) if details else {},
        },
        "aiuc1_controls": aiuc1_controls or [],
        "sanitised": True,
    }

    return func.HttpResponse(
        body=json.dumps(envelope, indent=2, default=str),
        status_code=status_code,
        mimetype="application/json",
    )
