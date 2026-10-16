import pytest
import socket
from codebase.orchestrator import SafeGuardOrchestrator
from tests.conftest import NetworkBlockedError


def test_no_network_fixture():
    with pytest.raises(RuntimeError, match="Network access blocked"):
        socket.create_connection(("example.com", 80))

    with pytest.raises(RuntimeError, match="Network access blocked"):
        socket.getaddrinfo("example.com", 80)


def test_orchestrator_smoke_offline(orchestrator):
    res = orchestrator.process_request("chào bạn", session_id="test_smoke", persist=False)

    assert "decision" in res
    assert "risk_score" in res
    assert "confidence" in res
    assert "explainable" in res
    assert "emergency" in res
    assert "tool_calls_made" in res
    assert "latency_ms" in res
    assert "execution_path" in res

    assert res["decision"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(res["risk_score"], int)
    assert res["execution_path"] == "sequential_fallback"
