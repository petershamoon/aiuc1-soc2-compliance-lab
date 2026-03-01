# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Test Configuration
# ---------------------------------------------------------------------------
# Configures sys.path and mocks Azure SDK dependencies so that all tests
# can run without the Azure SDK installed.
#
# Key challenge: azure.functions.FunctionApp uses decorators like
# @app.queue_trigger() that wrap functions. If we mock FunctionApp as
# a plain MagicMock, the decorators swallow the real functions and
# replace them with MagicMocks. We need the decorators to be pass-through.
# ---------------------------------------------------------------------------

import os
import sys
from unittest.mock import MagicMock
from types import ModuleType

# ---- Build a smart azure.functions mock ------------------------------------


class _PassthroughDecorator:
    """A decorator factory that returns the original function unchanged."""
    def __call__(self, *args, **kwargs):
        def _decorator(fn):
            return fn
        return _decorator


class _MockFunctionApp:
    """Mock FunctionApp where queue_trigger/queue_output are pass-through."""
    def __init__(self, *args, **kwargs):
        self._passthrough = _PassthroughDecorator()

    def __getattr__(self, name):
        return self._passthrough


class _MockOut:
    """Mock azure.functions.Out[str] for output bindings."""
    def __init__(self):
        self._value = None

    def set(self, value):
        self._value = value

    def get(self):
        return self._value

    def __class_getitem__(cls, item):
        """Support Out[str] syntax."""
        return cls


class _MockQueueMessage:
    """Mock azure.functions.QueueMessage."""
    def __init__(self, body: bytes = b"{}"):
        self._body = body

    def get_body(self):
        return self._body


# ---- Mock Azure SDK modules ------------------------------------------------
# IMPORTANT: We must set up the hierarchy correctly.
# `azure` is a MagicMock, and `azure.functions` must point to our smart mock.
# If we set sys.modules["azure"] = MagicMock() first, then accessing
# azure.functions returns a MagicMock attribute, NOT our custom module.
# Solution: set sys.modules["azure.functions"] AFTER azure, and also
# set the attribute on the azure mock.

_AZURE_MGMT_MODULES = [
    "azure.mgmt",
    "azure.mgmt.resource",
    "azure.mgmt.network",
    "azure.mgmt.storage",
    "azure.mgmt.sql",
    "azure.mgmt.security",
    "azure.mgmt.authorization",
    "azure.mgmt.policyinsights",
]

# Build the azure.functions mock module
_mock_func_module = ModuleType("azure.functions")
_mock_func_module.FunctionApp = _MockFunctionApp
_mock_func_module.QueueMessage = _MockQueueMessage
_mock_func_module.Out = _MockOut

# Create the azure namespace mock
_mock_azure = MagicMock()
# Override the functions attribute to point to our smart mock
_mock_azure.functions = _mock_func_module

# Set all azure modules
sys.modules["azure"] = _mock_azure
sys.modules["azure.identity"] = MagicMock()
sys.modules["azure.functions"] = _mock_func_module  # Our smart mock

for mod_name in _AZURE_MGMT_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# ---- Path setup ------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
_FUNCTIONS_DIR = os.path.join(_REPO_ROOT, "functions")
for _path in (_REPO_ROOT, _FUNCTIONS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# ---- Environment variables -------------------------------------------------
os.environ.setdefault("AZURE_SUBSCRIPTION_ID", "test-subscription-id")
os.environ.setdefault("AZURE_RESOURCE_GROUP", "rg-aiuc1-foundry")
os.environ.setdefault("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")


# ---- Reset middleware singletons between tests ------------------------------
import pytest


@pytest.fixture(autouse=True, scope="function")
def _reset_enforcement_singletons():
    """Reset the middleware singletons before each test."""
    import functions.enforcement.middleware as mw
    mw._policy_engine = None
    mw._output_gateway = None
    mw._scope_enforcer = None
    mw._tool_restrictions = None
    mw._disclosure_injector = None
    mw._audit_chain = None
    yield
