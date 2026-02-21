#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5 Test Suite
# Shared Fixtures (conftest.py)
# ---------------------------------------------------------------------------
# Provides pytest fixtures shared across all test modules.  Fixtures
# establish live connections to the Azure AI Foundry Agent Service and the
# deployed Function App, enabling end-to-end validation of the full stack.
#
# Architecture:
#   • FoundryClient  — wraps the OpenAI Assistants API on Azure AI Services
#   • FunctionClient — wraps the Azure Functions HTTP API
#   • AgentRunner    — creates threads, sends messages, polls for completion,
#                      and handles tool call submission loops
#
# AIUC-1 Controls Tested:
#   All 51 controls are exercised indirectly through the agents and functions.
#   The test suite specifically validates controls referenced in the test plan:
#   A004, A006, B006, C007, D001, D003, E015, E016.
# ---------------------------------------------------------------------------

import pytest
import json
import os
import time
import urllib.request
import urllib.error
from typing import Dict, Optional, List, Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AGENT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "agents", "agent_config.json"
)

# Azure AI Services (eastus2) — hosts the 4 agents
AGENT_SERVICE_ENDPOINT = "https://aiuc1-hub-eastus2.cognitiveservices.azure.com/"
AGENT_SERVICE_API_KEY = "D4c8ciZk5jgGpIPyods5GLzhkT920o3n0tdjTlpRM5I8eJp7JiJtJQQJ99CBACHYHv6XJ3w3AAAAACOG9IUf"
AGENT_API_VERSION = "2024-07-01-preview"

# Azure Functions — the 12-function GRC tool library
FUNCTIONS_BASE_URL = "https://aiuc1-soc2-tools.azurewebsites.net/api"
FUNCTIONS_HOST_KEY = "uFXSSPtLbfWT-l688529PDN4TlTlPeu09EByuxv0uFkyAzFuIoalzg=="

# Polling configuration for agent runs
RUN_POLL_INTERVAL_SECONDS = 3
RUN_MAX_WAIT_SECONDS = 120  # 2-minute timeout per agent run

# ---------------------------------------------------------------------------
# Low-level HTTP helper
# ---------------------------------------------------------------------------

def http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict:
    """Execute an HTTP request and return the parsed JSON response.

    On HTTP errors, returns a dict with ``_error_code`` and ``_error_body``
    keys so callers can inspect the failure without raising.
    """
    data = json.dumps(body).encode("utf-8") if body is not None else b"{}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            # Azure Functions return JSON bodies even on 4xx/5xx — parse them
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_error_code": exc.code, "_error_body": raw[:1000]}
    except Exception as exc:
        return {"_error_code": -1, "_error_body": str(exc)}


# ---------------------------------------------------------------------------
# Foundry / Agent Service Client
# ---------------------------------------------------------------------------

class FoundryClient:
    """Thin wrapper around the Azure AI Foundry OpenAI Assistants API."""

    def __init__(self, endpoint: str, api_key: str, api_version: str):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self._headers = {
            "api-key": api_key,
            "Content-Type": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.endpoint}/{path}?api-version={self.api_version}"

    def _call(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        return http_request(method, self._url(path), self._headers, body)

    # --- Thread management ------------------------------------------------

    def create_thread(self) -> Dict:
        return self._call("POST", "openai/threads")

    def add_message(self, thread_id: str, content: str) -> Dict:
        return self._call(
            "POST",
            f"openai/threads/{thread_id}/messages",
            {"role": "user", "content": content},
        )

    def create_run(self, thread_id: str, assistant_id: str) -> Dict:
        return self._call(
            "POST",
            f"openai/threads/{thread_id}/runs",
            {"assistant_id": assistant_id},
        )

    def get_run(self, thread_id: str, run_id: str) -> Dict:
        return self._call("GET", f"openai/threads/{thread_id}/runs/{run_id}")

    def list_messages(self, thread_id: str) -> Dict:
        return self._call("GET", f"openai/threads/{thread_id}/messages")

    def submit_tool_outputs(
        self, thread_id: str, run_id: str, tool_outputs: List[Dict]
    ) -> Dict:
        return self._call(
            "POST",
            f"openai/threads/{thread_id}/runs/{run_id}/submit_tool_outputs",
            {"tool_outputs": tool_outputs},
        )

    def list_run_steps(self, thread_id: str, run_id: str) -> Dict:
        return self._call("GET", f"openai/threads/{thread_id}/runs/{run_id}/steps")


# ---------------------------------------------------------------------------
# Function App Client
# ---------------------------------------------------------------------------

class FunctionClient:
    """Thin wrapper around the Azure Functions HTTP API."""

    def __init__(self, base_url: str, host_key: str):
        self.base_url = base_url.rstrip("/")
        self.host_key = host_key
        self._headers = {"Content-Type": "application/json"}

    def call(self, function_name: str, payload: Dict, timeout: int = 30) -> Dict:
        """Call a named Azure Function with the given payload."""
        url = f"{self.base_url}/{function_name}?code={self.host_key}"
        return http_request("POST", url, self._headers, payload, timeout=timeout)


# ---------------------------------------------------------------------------
# Agent Runner — orchestrates a full agent run with tool call handling
# ---------------------------------------------------------------------------

class AgentRunner:
    """Runs an agent through a complete request-response cycle.

    Handles the ``requires_action`` state by forwarding tool calls to the
    live Azure Functions and submitting the results back to the run.

    Returns an ``AgentRunResult`` with the final message text, all tool
    calls made, and the final run status.
    """

    def __init__(self, foundry: FoundryClient, functions: FunctionClient):
        self.foundry = foundry
        self.functions = functions

    def run(
        self,
        assistant_id: str,
        prompt: str,
        max_wait: int = RUN_MAX_WAIT_SECONDS,
    ) -> "AgentRunResult":
        """Execute a full agent run and return the result."""
        # Create thread and add user message
        thread = self.foundry.create_thread()
        if "_error_code" in thread:
            return AgentRunResult(
                status="error",
                error=f"Thread creation failed: {thread['_error_body']}",
            )
        thread_id = thread["id"]

        msg = self.foundry.add_message(thread_id, prompt)
        if "_error_code" in msg:
            return AgentRunResult(
                status="error",
                error=f"Message creation failed: {msg['_error_body']}",
                thread_id=thread_id,
            )

        # Start the run
        run = self.foundry.create_run(thread_id, assistant_id)
        if "_error_code" in run:
            return AgentRunResult(
                status="error",
                error=f"Run creation failed: {run['_error_body']}",
                thread_id=thread_id,
            )
        run_id = run["id"]

        # Poll until terminal state
        tool_calls_made: List[Dict] = []
        deadline = time.time() + max_wait

        while time.time() < deadline:
            time.sleep(RUN_POLL_INTERVAL_SECONDS)
            run_status = self.foundry.get_run(thread_id, run_id)
            status = run_status.get("status", "unknown")

            if status == "requires_action":
                # Handle tool calls
                required_action = run_status.get("required_action", {})
                tool_calls = (
                    required_action.get("submit_tool_outputs", {}).get("tool_calls", [])
                )
                tool_outputs = []
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    fn_args_raw = tc["function"].get("arguments", "{}")
                    try:
                        fn_args = json.loads(fn_args_raw)
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Call the live Azure Function
                    fn_result = self.functions.call(fn_name, fn_args, timeout=45)
                    tool_calls_made.append(
                        {
                            "tool_call_id": tc["id"],
                            "function_name": fn_name,
                            "arguments": fn_args,
                            "result": fn_result,
                        }
                    )
                    tool_outputs.append(
                        {
                            "tool_call_id": tc["id"],
                            "output": json.dumps(fn_result),
                        }
                    )

                # Submit tool outputs
                self.foundry.submit_tool_outputs(thread_id, run_id, tool_outputs)
                continue

            if status in ("completed", "failed", "cancelled", "expired"):
                # Retrieve the final assistant message
                messages = self.foundry.list_messages(thread_id)
                final_text = ""
                for m in messages.get("data", []):
                    if m.get("role") == "assistant":
                        for block in m.get("content", []):
                            if block.get("type") == "text":
                                final_text = block["text"]["value"]
                                break
                        if final_text:
                            break

                return AgentRunResult(
                    status=status,
                    thread_id=thread_id,
                    run_id=run_id,
                    final_message=final_text,
                    tool_calls=tool_calls_made,
                    run_details=run_status,
                )

        return AgentRunResult(
            status="timeout",
            thread_id=thread_id,
            run_id=run_id,
            tool_calls=tool_calls_made,
            error=f"Run did not complete within {max_wait}s",
        )


class AgentRunResult:
    """Holds the outcome of a single agent run."""

    def __init__(
        self,
        status: str,
        thread_id: str = "",
        run_id: str = "",
        final_message: str = "",
        tool_calls: Optional[List[Dict]] = None,
        run_details: Optional[Dict] = None,
        error: str = "",
    ):
        self.status = status
        self.thread_id = thread_id
        self.run_id = run_id
        self.final_message = final_message
        self.tool_calls = tool_calls or []
        self.run_details = run_details or {}
        self.error = error

    @property
    def tool_names(self) -> List[str]:
        """Returns the list of function names called during this run."""
        return [tc["function_name"] for tc in self.tool_calls]

    @property
    def succeeded(self) -> bool:
        return self.status == "completed"

    def called_tool(self, name: str) -> bool:
        return name in self.tool_names

    def __repr__(self) -> str:
        return (
            f"AgentRunResult(status={self.status!r}, "
            f"tools={self.tool_names}, "
            f"message_len={len(self.final_message)})"
        )


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def agent_config() -> Dict:
    """Load the agent_config.json file produced by deploy_agents.py."""
    if not os.path.exists(AGENT_CONFIG_PATH):
        pytest.fail(f"Agent config not found: {AGENT_CONFIG_PATH}")
    with open(AGENT_CONFIG_PATH) as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def foundry(agent_config) -> FoundryClient:
    """Authenticated Foundry client (session-scoped — shared across all tests)."""
    return FoundryClient(
        endpoint=AGENT_SERVICE_ENDPOINT,
        api_key=AGENT_SERVICE_API_KEY,
        api_version=AGENT_API_VERSION,
    )


@pytest.fixture(scope="session")
def functions(agent_config) -> FunctionClient:
    """Function App client (session-scoped)."""
    return FunctionClient(
        base_url=FUNCTIONS_BASE_URL,
        host_key=FUNCTIONS_HOST_KEY,
    )


@pytest.fixture(scope="session")
def runner(foundry, functions) -> AgentRunner:
    """AgentRunner that wires the Foundry client to the Function App."""
    return AgentRunner(foundry, functions)


@pytest.fixture(scope="session")
def agent_ids(agent_config) -> Dict[str, str]:
    """Map of agent display-name → assistant ID."""
    return {
        v["display_name"]: v["id"]
        for v in agent_config.get("agents", {}).values()
    }
