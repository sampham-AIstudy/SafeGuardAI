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

from codebase.config import get_settings
get_settings(refresh=True)


class NetworkBlockedError(RuntimeError):
    pass


def _blocked_connect(*args, **kwargs):
    raise NetworkBlockedError("Network access blocked: socket.connect is forbidden during offline tests")


def _blocked_create_connection(*args, **kwargs):
    raise NetworkBlockedError("Network access blocked: socket.create_connection is forbidden during offline tests")


def _blocked_getaddrinfo(*args, **kwargs):
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
    _shared_orchestrator.memory_agent.history.clear()
    _shared_orchestrator.db_manager = _shared_orchestrator._orig_db_manager
    _shared_orchestrator.memory_agent.load_history_from_db = _shared_orchestrator.memory_agent._orig_load_history
    yield _shared_orchestrator
    _shared_orchestrator.memory_agent.history.clear()
    _shared_orchestrator.db_manager = _shared_orchestrator._orig_db_manager
    _shared_orchestrator.memory_agent.load_history_from_db = _shared_orchestrator.memory_agent._orig_load_history

