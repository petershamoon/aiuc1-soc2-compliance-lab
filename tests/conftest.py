#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5: Test Suite Fixtures
# ---------------------------------------------------------------------------
import pytest
import json
import os
import time
import urllib.request
import urllib.error
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any
from azure.data.tables import TableServiceClient, UpdateMode

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AGENT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "agents", "agent_config.json")
AGENT_SERVICE_ENDPOINT = "https://aiuc1-hub-eastus2.cognitiveservices.azure.com/"
AGENT_SERVICE_API_KEY = "D4c8ciZk5jgGpIPyods5GLzhkT920o3n0tdjTlpRM5I8eJp7JiJtJQQJ99CBACHYHv6XJ3w3AAAAACOG9IUf"
AGENT_API_VERSION = "2024-07-01-preview"
FUNCTIONS_BASE_URL = "https://aiuc1-soc2-tools.azurewebsites.net/api"
FUNCTIONS_HOST_KEY = os.getenv("AZURE_FUNC_HOST_KEY", "uFXSSPtLbfWT-l688529PDN4TlTlPeu09EByuxv0uFkyAzFuIoalzg==")
RUN_POLL_INTERVAL_SECONDS = 3
RUN_MAX_WAIT_SECONDS = 120

# ---------------------------------------------------------------------------
# Low-level HTTP helper
# ---------------------------------------------------------------------------
def http_request(method: str, url: str, headers: Dict[str, str], body: Optional[Dict] = None, timeout: int = 30) -> Dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_error_code": exc.code, "_error_body": raw[:1000]}
    except Exception as exc:
        return {"_error_code": -1, "_error_body": str(exc)}

# ---------------------------------------------------------------------------
# Foundry / Agent Service Client
# ---------------------------------------------------------------------------
class FoundryClient:
    def __init__(self, endpoint: str, api_key: str, api_version: str):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self._headers = {"api-key": api_key, "Content-Type": "application/json"}

    def _url(self, path: str) -> str:
        return f"{self.endpoint}/{path}?api-version={self.api_version}"

    def _call(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        return http_request(method, self._url(path), self._headers, body)

    def create_thread(self) -> Dict: return self._call("POST", "openai/threads", {})
    def add_message(self, thread_id: str, content: str) -> Dict: return self._call("POST", f"openai/threads/{thread_id}/messages", {"role": "user", "content": content})
    def create_run(self, thread_id: str, assistant_id: str) -> Dict: return self._call("POST", f"openai/threads/{thread_id}/runs", {"assistant_id": assistant_id})
    def get_run(self, thread_id: str, run_id: str) -> Dict: return self._call("GET", f"openai/threads/{thread_id}/runs/{run_id}")
    def list_messages(self, thread_id: str) -> Dict: return self._call("GET", f"openai/threads/{thread_id}/messages")
    def submit_tool_outputs(self, thread_id: str, run_id: str, tool_outputs: List[Dict]) -> Dict: return self._call("POST", f"openai/threads/{thread_id}/runs/{run_id}/submit_tool_outputs", {"tool_outputs": tool_outputs})

# ---------------------------------------------------------------------------
# Function App Client
# ---------------------------------------------------------------------------
class FunctionClient:
    def __init__(self, base_url: str, host_key: str):
        self.base_url = base_url.rstrip("/")
        self.host_key = host_key
        self._headers = {"Content-Type": "application/json"}

    def call(self, function_name: str, payload: Dict, timeout: int = 30) -> Dict:
        url = f"{self.base_url}/{function_name}?code={self.host_key}"
        return http_request("POST", url, self._headers, payload, timeout=timeout)

# ---------------------------------------------------------------------------
# Agent Runner & Result Classes
# ---------------------------------------------------------------------------
class AgentRunner:
    def __init__(self, foundry: FoundryClient, functions: FunctionClient):
        self.foundry = foundry
        self.functions = functions

    def run(self, assistant_id: str, prompt: str, max_wait: int = RUN_MAX_WAIT_SECONDS) -> "AgentRunResult":
        thread = self.foundry.create_thread()
        if "_error_code" in thread: return AgentRunResult(status="error", error=f"Thread creation failed: {thread['_error_body']}")
        thread_id = thread["id"]

        msg = self.foundry.add_message(thread_id, prompt)
        if "_error_code" in msg: return AgentRunResult(status="error", error=f"Message creation failed: {msg['_error_body']}", thread_id=thread_id)

        run = self.foundry.create_run(thread_id, assistant_id)
        if "_error_code" in run: return AgentRunResult(status="error", error=f"Run creation failed: {run['_error_body']}", thread_id=thread_id)
        run_id = run["id"]

        tool_calls_made: List[Dict] = []
        deadline = time.time() + max_wait
        while time.time() < deadline:
            time.sleep(RUN_POLL_INTERVAL_SECONDS)
            run_status = self.foundry.get_run(thread_id, run_id)
            status = run_status.get("status", "unknown")

            if status == "requires_action":
                tool_calls = run_status.get("required_action", {}).get("submit_tool_outputs", {}).get("tool_calls", [])
                tool_outputs = []
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    fn_args = json.loads(tc["function"].get("arguments", "{}"))
                    fn_result = self.functions.call(fn_name, fn_args, timeout=45)
                    tool_calls_made.append({"tool_call_id": tc["id"], "function_name": fn_name, "arguments": fn_args, "result": fn_result})
                    tool_outputs.append({"tool_call_id": tc["id"], "output": json.dumps(fn_result)})
                self.foundry.submit_tool_outputs(thread_id, run_id, tool_outputs)
                continue

            if status in ("completed", "failed", "cancelled", "expired"):
                messages = self.foundry.list_messages(thread_id)
                final_text = next((block["text"]["value"] for m in messages.get("data", []) if m.get("role") == "assistant" for block in m.get("content", []) if block.get("type") == "text"), "")
                return AgentRunResult(status=status, thread_id=thread_id, run_id=run_id, final_message=final_text, tool_calls=tool_calls_made, run_details=run_status)

        return AgentRunResult(status="timeout", thread_id=thread_id, run_id=run_id, tool_calls=tool_calls_made, error=f"Run did not complete within {max_wait}s")

class AgentRunResult:
    def __init__(self, status: str, thread_id: str = "", run_id: str = "", final_message: str = "", tool_calls: Optional[List[Dict]] = None, run_details: Optional[Dict] = None, error: str = ""):
        self.status, self.thread_id, self.run_id, self.final_message, self.tool_calls, self.run_details, self.error = status, thread_id, run_id, final_message, tool_calls or [], run_details or {}, error
    @property
    def tool_names(self) -> List[str]: return [tc["function_name"] for tc in self.tool_calls]
    @property
    def succeeded(self) -> bool: return self.status == "completed"

# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def test_run_id() -> str: return str(uuid.uuid4())

@pytest.fixture(scope="session")
def table_service_client() -> TableServiceClient:
    conn_str = os.getenv("AIUC1_TEST_RESULTS_CONN")
    if not conn_str: pytest.skip("AIUC1_TEST_RESULTS_CONN not set. Skipping DB logging.")
    return TableServiceClient.from_connection_string(conn_str)

@pytest.fixture(scope="session", autouse=True)
def test_run_recorder(test_run_id, table_service_client):
    run_table = table_service_client.get_table_client("TestRuns")
    run_entity = {"PartitionKey": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "RowKey": test_run_id, "StartTimeUTC": datetime.now(timezone.utc).isoformat(), "Status": "InProgress"}
    run_table.upsert_entity(run_entity)
    yield
    run_entity["EndTimeUTC"] = datetime.now(timezone.utc).isoformat()
    run_entity["Status"] = "Completed"
    run_table.update_entity(run_entity, mode=UpdateMode.REPLACE)

@pytest.fixture
def result_recorder(table_service_client, test_run_id, request):
    results_table = table_service_client.get_table_client("TestResults")
    def _record(outcome: str, detail: str, control_ids: list = None, function_name: str = None, response_body: str = None):
        response_hash = hashlib.sha256(response_body.encode()).hexdigest() if response_body else None
        entity = {
            "PartitionKey": test_run_id,
            "RowKey": request.node.nodeid.replace("::", "_").replace("/", "_").replace("\\", "_").replace("#", "_").replace("?", "_")[:255],
            "TimestampUTC": datetime.now(timezone.utc).isoformat(),
            "Suite": os.path.basename(str(request.node.fspath)),
            "TestName": request.node.name,
            "Outcome": outcome,
            "Detail": str(detail)[:32768],
            "ControlIDs": ",".join(control_ids) if control_ids else None,
            "FunctionName": function_name,
            "ResponseHash": response_hash,
        }
        results_table.upsert_entity(entity)
    return _record

@pytest.fixture(scope="session")
def agent_config() -> Dict:
    if not os.path.exists(AGENT_CONFIG_PATH): pytest.fail(f"Agent config not found: {AGENT_CONFIG_PATH}")
    with open(AGENT_CONFIG_PATH) as fh: return json.load(fh)

@pytest.fixture(scope="session")
def foundry(agent_config) -> FoundryClient: return FoundryClient(endpoint=AGENT_SERVICE_ENDPOINT, api_key=AGENT_SERVICE_API_KEY, api_version=AGENT_API_VERSION)

@pytest.fixture(scope="session")
def functions(agent_config) -> FunctionClient: return FunctionClient(base_url=FUNCTIONS_BASE_URL, host_key=FUNCTIONS_HOST_KEY)

@pytest.fixture(scope="session")
def runner(foundry, functions) -> AgentRunner: return AgentRunner(foundry, functions)

@pytest.fixture(scope="session")
def agent_ids(agent_config) -> Dict[str, str]: return {v["display_name"]: v["id"] for v in agent_config.get("agents", {}).values()}
