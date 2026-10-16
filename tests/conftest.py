import sys
import os
import socket
import pytest

# Ensure root directory is in sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Configure offline environment
os.environ["SAFEGUARD_OFFLINE"] = "1"
os.environ["SAFEGUARD_DB"] = "off"
os.environ["SAFEGUARD_NETWORK"] = "off"
os.environ["PYTHONIOENCODING"] = "utf-8"

# Safety net: blank every real API key BEFORE any codebase import. python-dotenv does not
# override variables that already exist, so a developer's .env can never re-enable live LLM /
# threat-intel calls during tests (gRPC bypasses the Python socket patches below).
for _key in ("GEMINI_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "VIRUSTOTAL_API_KEY",
             "GOOGLE_SAFE_BROWSING_KEY", "URLSCAN_API_KEY"):
    os.environ[_key] = ""

from codebase.config import get_settings
get_settings(refresh=True)


@pytest.fixture(autouse=True)
def _force_offline_settings():
    """Tests that monkeypatch SAFEGUARD_* and call get_settings(refresh=True) must not leak
    a non-offline settings cache into later tests (it used to make later tests call Gemini)."""
    os.environ["SAFEGUARD_OFFLINE"] = "1"
    get_settings(refresh=True)
    yield
    os.environ["SAFEGUARD_OFFLINE"] = "1"
    os.environ["SAFEGUARD_DB"] = "off"
    os.environ["SAFEGUARD_NETWORK"] = "off"
    os.environ.pop("SAFEGUARD_LLM_MODE", None)
    get_settings(refresh=True)
    assert get_settings().offline, "offline settings were not restored after test"


class NetworkBlockedError(RuntimeError):
    pass


_orig_connect = socket.socket.connect
_orig_create_connection = socket.create_connection
_orig_getaddrinfo = socket.getaddrinfo


def _is_loopback(host):
    return str(host).lower() in ("127.0.0.1", "localhost", "::1")


def _blocked_connect(self, address, *args, **kwargs):
    host = address[0] if isinstance(address, tuple) and len(address) > 0 else address
    if _is_loopback(host):
        return _orig_connect(self, address, *args, **kwargs)
    raise NetworkBlockedError("Network access blocked: socket.connect is forbidden during offline tests")


def _blocked_create_connection(address, *args, **kwargs):
    host = address[0] if isinstance(address, tuple) and len(address) > 0 else address
    if _is_loopback(host):
        return _orig_create_connection(address, *args, **kwargs)
    raise NetworkBlockedError("Network access blocked: socket.create_connection is forbidden during offline tests")


def _blocked_getaddrinfo(host, port, *args, **kwargs):
    if _is_loopback(host):
        return _orig_getaddrinfo(host, port, *args, **kwargs)
    raise NetworkBlockedError("Network access blocked: socket.getaddrinfo is forbidden during offline tests")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked_getaddrinfo)



@pytest.fixture(scope="session")
def _shared_orchestrator():
    """
    Session-scoped orchestrator instance to avoid expensive repeated re-initializations (~7.5s each).
    """
    from codebase.orchestrator import SafeGuardOrchestrator
    orc = SafeGuardOrchestrator()
    orc._orig_db_manager = orc.db_manager
    orc.memory_agent._orig_load_history = orc.memory_agent.load_history_from_db
    return orc


@pytest.fixture
def orchestrator(_shared_orchestrator):
    """
    Function-scoped fixture providing the shared orchestrator with isolated state:
    memory history is reset and any mocked attributes restored before and after each test.
    """
    _shared_orchestrator.memory_agent.reset()
    _shared_orchestrator.db_manager = _shared_orchestrator._orig_db_manager
    _shared_orchestrator.memory_agent.load_history_from_db = _shared_orchestrator.memory_agent._orig_load_history
    yield _shared_orchestrator
    _shared_orchestrator.memory_agent.reset()
    _shared_orchestrator.db_manager = _shared_orchestrator._orig_db_manager
    _shared_orchestrator.memory_agent.load_history_from_db = _shared_orchestrator.memory_agent._orig_load_history

