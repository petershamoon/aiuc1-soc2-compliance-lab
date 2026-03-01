# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Shared Utilities Package
# ---------------------------------------------------------------------------
# This package contains utility modules shared across all 12 Azure Functions
# in the GRC (Governance, Risk & Compliance) tool library.
#
# Architecture note:
#   "Tools provide data, agents provide judgment."
#   Functions return raw Azure state; the AI agents reason about compliance.
#
# AIUC-1 Controls enforced here:
#   A003  Data Minimization — only return fields agents need
#   B009  Output Filtering  — sanitize_output strips secrets
#   E015  Logging           — every call logged to App Insights
#   A004  Credential Mgmt   — no hardcoded secrets; env vars only
# ---------------------------------------------------------------------------

from .config import get_settings, Settings
from .azure_clients import get_credential, get_mgmt_client
from .sanitizer import redact_secrets
from .logger import log_event, log_function_call
from .response import build_success_response, build_error_response, build_success_envelope, build_error_envelope
from .validators import validate_cc_category, validate_resource_group

__all__ = [
    "get_settings",
    "Settings",
    "get_credential",
    "get_mgmt_client",
    "redact_secrets",
    "log_event",
    "log_function_call",
    "build_success_response",
    "build_error_response",
    "build_success_envelope",
    "build_error_envelope",
    "validate_cc_category",
    "validate_resource_group",
]
