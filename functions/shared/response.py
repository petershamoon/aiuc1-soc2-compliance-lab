# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Standardised Response Builder
# ---------------------------------------------------------------------------
# Supports both HTTP responses and Queue output bindings.
# When used with Queue triggers, returns a dict (JSON-serialisable).
# When used with HTTP triggers, returns an azure.functions.HttpResponse.
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
#   B009  Output Filtering  — every response is sanitised
#   E015  Logging           — response metadata supports audit
#   E017  Provenance        — timestamp + function name for tracing
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from .sanitizer import redact_dict


def build_success_envelope(
    function_name: str,
    data: dict[str, Any],
    *,
    aiuc1_controls: Optional[list[str]] = None,
    sanitise: bool = True,
) -> dict:
    """Build a standardised success envelope as a dict."""
    clean_data = redact_dict(data) if sanitise else data
    return {
        "status": "success",
        "function": function_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": clean_data,
        "aiuc1_controls": aiuc1_controls or [],
        "sanitised": sanitise,
    }


def build_error_envelope(
    function_name: str,
    error_message: str,
    *,
    error_code: str = "INTERNAL_ERROR",
    details: Optional[dict[str, Any]] = None,
    aiuc1_controls: Optional[list[str]] = None,
) -> dict:
    """Build a standardised error envelope as a dict."""
    from .sanitizer import redact_secrets
    return {
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


# --- Legacy HTTP wrappers (kept for backward compatibility) ---

def build_success_response(
    function_name: str,
    data: dict[str, Any],
    *,
    aiuc1_controls: Optional[list[str]] = None,
    status_code: int = 200,
    sanitise: bool = True,
):
    """Build a standardised success HTTP response."""
    import azure.functions as func
    envelope = build_success_envelope(function_name, data,
                                      aiuc1_controls=aiuc1_controls,
                                      sanitise=sanitise)
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
):
    """Build a standardised error HTTP response."""
    import azure.functions as func
    envelope = build_error_envelope(function_name, error_message,
                                    error_code=error_code,
                                    details=details,
                                    aiuc1_controls=aiuc1_controls)
    return func.HttpResponse(
        body=json.dumps(envelope, indent=2, default=str),
        status_code=status_code,
        mimetype="application/json",
    )
