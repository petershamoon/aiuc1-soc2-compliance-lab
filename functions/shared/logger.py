# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Structured Logging
# ---------------------------------------------------------------------------
# Provides structured logging to Azure Application Insights via the
# OpenCensus exporter, plus a convenience decorator for function-level
# call tracing.
#
# Every GRC tool function call is logged with:
#   • function_name   — which tool was invoked
#   • agent_id        — which AI agent made the call
#   • cc_category     — SOC 2 criteria being assessed (if applicable)
#   • duration_ms     — execution time
#   • status          — success / error
#   • aiuc1_controls  — list of AIUC-1 controls exercised
#
# AIUC-1 Controls:
#   E015  Logging & Monitoring — primary control
#   E015  Audit Trail          — immutable App Insights records
#   E015  Incident Detection   — anomalous patterns surface here
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger("aiuc1.grc_tools")

# Attempt to import the App Insights exporter.  If unavailable (e.g. in
# unit tests or local dev without the SDK), we fall back to standard
# Python logging — the structured payload is still emitted as JSON.
_APPINSIGHTS_AVAILABLE = False
try:
    from opencensus.ext.azure.log_exporter import AzureLogHandler
    from .config import get_settings

    _settings = get_settings()
    if _settings.appinsights_connection_string:
        _handler = AzureLogHandler(
            connection_string=_settings.appinsights_connection_string
        )
        logger.addHandler(_handler)
        _APPINSIGHTS_AVAILABLE = True
except ImportError:
    pass  # Graceful degradation — logs go to stdout only


def log_event(
    event_type: str,
    *,
    function_name: str = "",
    agent_id: str = "",
    cc_category: str = "",
    details: Optional[dict[str, Any]] = None,
    severity: str = "INFO",
    aiuc1_controls: Optional[list[str]] = None,
) -> None:
    """Emit a structured log event to App Insights and stdout.

    Args:
        event_type: High-level event category (e.g. "function_call",
            "security_event", "validation_error").
        function_name: Name of the Azure Function that generated the event.
        agent_id: Identifier of the AI agent that triggered the call.
        cc_category: SOC 2 CC category (e.g. "CC6") if applicable.
        details: Arbitrary key-value pairs for additional context.
        severity: One of "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL".
        aiuc1_controls: List of AIUC-1 control IDs exercised by this event.
    """
    payload = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "function_name": function_name,
        "agent_id": agent_id,
        "cc_category": cc_category,
        "severity": severity,
        "aiuc1_controls": aiuc1_controls or [],
        "details": details or {},
    }

    # Map string severity to logging level
    level = getattr(logging, severity.upper(), logging.INFO)

    # Emit as structured JSON so App Insights custom dimensions pick it up
    logger.log(level, json.dumps(payload))


def log_function_call(
    function_name: str,
    aiuc1_controls: Optional[list[str]] = None,
) -> Callable:
    """Decorator that logs entry, exit, duration, and errors for a function.

    Usage::

        @log_function_call("gap_analyzer", aiuc1_controls=["E015"])
        async def main(req: func.HttpRequest) -> func.HttpResponse:
            ...

    The decorator:
      1. Logs a "function_call_start" event on entry
      2. Times the execution
      3. Logs "function_call_success" or "function_call_error" on exit
      4. Re-raises any exception after logging
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            agent_id = ""

            # Try to extract agent_id from the HTTP request headers
            # (Azure AI Foundry passes this as X-Agent-Id)
            for arg in args:
                if hasattr(arg, "headers"):
                    agent_id = arg.headers.get("X-Agent-Id", "")
                    break

            log_event(
                "function_call_start",
                function_name=function_name,
                agent_id=agent_id,
                aiuc1_controls=aiuc1_controls,
            )

            try:
                result = await fn(*args, **kwargs)
                duration_ms = (time.monotonic() - start) * 1000
                log_event(
                    "function_call_success",
                    function_name=function_name,
                    agent_id=agent_id,
                    details={"duration_ms": round(duration_ms, 2)},
                    aiuc1_controls=aiuc1_controls,
                )
                return result

            except Exception as exc:
                duration_ms = (time.monotonic() - start) * 1000
                log_event(
                    "function_call_error",
                    function_name=function_name,
                    agent_id=agent_id,
                    severity="ERROR",
                    details={
                        "duration_ms": round(duration_ms, 2),
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                    aiuc1_controls=aiuc1_controls,
                )
                raise

        @wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            agent_id = ""
            for arg in args:
                if hasattr(arg, "headers"):
                    agent_id = arg.headers.get("X-Agent-Id", "")
                    break

            log_event(
                "function_call_start",
                function_name=function_name,
                agent_id=agent_id,
                aiuc1_controls=aiuc1_controls,
            )
            try:
                result = fn(*args, **kwargs)
                duration_ms = (time.monotonic() - start) * 1000
                log_event(
                    "function_call_success",
                    function_name=function_name,
                    agent_id=agent_id,
                    details={"duration_ms": round(duration_ms, 2)},
                    aiuc1_controls=aiuc1_controls,
                )
                return result
            except Exception as exc:
                duration_ms = (time.monotonic() - start) * 1000
                log_event(
                    "function_call_error",
                    function_name=function_name,
                    agent_id=agent_id,
                    severity="ERROR",
                    details={
                        "duration_ms": round(duration_ms, 2),
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                    aiuc1_controls=aiuc1_controls,
                )
                raise

        # Return the appropriate wrapper based on whether fn is async
        import asyncio
        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator
