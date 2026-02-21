# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Output Sanitizer
# ---------------------------------------------------------------------------
# Implements the explicit redaction rules required by ChatGPT Audit Fix #4.
# Every function response passes through redact_secrets() before being
# returned to the calling agent.
#
# Redaction targets (from Phase 3 reference):
#   • Subscription IDs    /subscriptions/[a-f0-9-]{36}/
#   • Tenant / Object IDs [a-f0-9]{8}-...-[a-f0-9]{12}  (UUID pattern)
#   • Access keys          base64 strings > 40 chars
#   • Connection strings   DefaultEndpointsProtocol=...
#   • Private IP addresses 10.x, 172.16-31.x, 192.168.x
#   • SAS tokens           sig=... / sv=... / se=...
#   • Service principal secrets
#
# Allowed to remain: resource names, SKUs, regions, policy states, role names.
#
# AIUC-1 Controls:
#   AIUC-1-19  Output Filtering — primary control
#   AIUC-1-17  Data Minimization — strip what agents don't need
#   AIUC-1-34  Credential Management — never surface creds
# ---------------------------------------------------------------------------

from __future__ import annotations

import re
from typing import Any


# ---- Compiled regex patterns (compiled once at module load) ---------------

# Subscription ID embedded in ARM resource IDs
_RE_SUBSCRIPTION_PATH = re.compile(
    r"/subscriptions/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    re.IGNORECASE,
)

# Standalone UUIDs (tenant IDs, object IDs, client IDs, etc.)
_RE_UUID = re.compile(
    r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
    re.IGNORECASE,
)

# Base64-encoded access keys (storage keys, Foundry keys, etc.)
# Matches strings of 40+ base64 characters that look like keys.
_RE_ACCESS_KEY = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
)

# Azure Storage / Service Bus connection strings
_RE_CONNECTION_STRING = re.compile(
    r"DefaultEndpointsProtocol=[^;\"'\s]+(?:;[^;\"'\s]+)*",
    re.IGNORECASE,
)

# Private IP addresses (RFC 1918)
_RE_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# SAS tokens — match the signature and surrounding query params
_RE_SAS_TOKEN = re.compile(
    r"(?:sig|sv|se|sp|spr|st|srt|ss)=[^&\s\"']+",
    re.IGNORECASE,
)

# Service principal / client secrets (common patterns)
_RE_SP_SECRET = re.compile(
    r"(?:client_secret|password|secret)\s*[=:]\s*[\"']?[^\s\"',}{]{8,}",
    re.IGNORECASE,
)

# Bearer tokens
_RE_BEARER = re.compile(
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    re.IGNORECASE,
)

# ---- Replacement labels ---------------------------------------------------

_REDACTED = "[REDACTED]"
_REDACTED_SUB = "/subscriptions/[REDACTED]"
_REDACTED_UUID = "[REDACTED-UUID]"
_REDACTED_IP = "[REDACTED-IP]"


# ---- Public API -----------------------------------------------------------

def redact_secrets(text: str) -> str:
    """Strip sensitive data from *text* and return the sanitised version.

    The function applies patterns in a specific order so that more-specific
    patterns (e.g. subscription paths) are matched before the generic UUID
    pattern.  This avoids double-redaction artefacts.

    Args:
        text: Raw string that may contain secrets.

    Returns:
        A copy of *text* with all sensitive values replaced by redaction
        labels.
    """
    if not text:
        return text

    # 1. Connection strings (most specific compound pattern)
    text = _RE_CONNECTION_STRING.sub(_REDACTED, text)

    # 2. SAS tokens
    text = _RE_SAS_TOKEN.sub(f"sig={_REDACTED}", text)

    # 3. Bearer tokens
    text = _RE_BEARER.sub(f"Bearer {_REDACTED}", text)

    # 4. Subscription paths in ARM IDs
    text = _RE_SUBSCRIPTION_PATH.sub(_REDACTED_SUB, text)

    # 5. Service principal secrets
    text = _RE_SP_SECRET.sub(f"secret={_REDACTED}", text)

    # 6. Access keys (base64 blobs)
    text = _RE_ACCESS_KEY.sub(_REDACTED, text)

    # 7. Standalone UUIDs (tenant, object, client IDs)
    text = _RE_UUID.sub(_REDACTED_UUID, text)

    # 8. Private IPs
    text = _RE_PRIVATE_IP.sub(_REDACTED_IP, text)

    return text


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact all string values in a nested dictionary.

    Non-string leaf values (int, bool, None) are left untouched.
    Lists are iterated and each element is processed.

    Args:
        data: Dictionary that may contain sensitive string values.

    Returns:
        A new dictionary with all string values sanitised.
    """
    sanitised: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitised[key] = redact_secrets(value)
        elif isinstance(value, dict):
            sanitised[key] = redact_dict(value)
        elif isinstance(value, list):
            sanitised[key] = [
                redact_dict(item) if isinstance(item, dict)
                else redact_secrets(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitised[key] = value
    return sanitised
