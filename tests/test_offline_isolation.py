from unittest.mock import MagicMock
import pytest
from codebase.knowledge_base.db_connect import MySQLManager
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.config import get_settings


def test_mysql_manager_offline_no_connection(monkeypatch):
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_DB", "off")
    get_settings(refresh=True)

    mgr = MySQLManager(host="127.0.0.1", port=3306)
    assert mgr.is_connected is False
    assert mgr.conn is None


def test_process_request_persist_false_no_db_calls(orchestrator):
    # Emulate active database connection on the db_manager
    mock_db = MagicMock()
    mock_db.is_connected = True
    orchestrator.db_manager = mock_db

    # Emulate memory agent db hydration method
    orchestrator.memory_agent.load_history_from_db = MagicMock()

    res = orchestrator.process_request(
        "Chào bạn, kiểm tra giúp tôi tin nhắn này",
        session_id="test_mock_persist",
        persist=False
    )

    # Verify neither load_history_from_db nor log_user_analysis was invoked
    orchestrator.memory_agent.load_history_from_db.assert_not_called()
    mock_db.log_user_analysis.assert_not_called()
    assert res is not None
    assert "decision" in res
