import os
import sys
import json
import uuid
import re
import threading
import http.client
from datetime import datetime
import pytest

from codebase.server import create_server, orchestrator, CLIENT_ID_PATTERN, SESSION_ID_PATTERN
from codebase.agents.memory_agent import MemoryAgent
from codebase.orchestrator import SafeGuardOrchestrator


class FakeInMemoryDB:
    """
    Thread-safe In-Memory DB mimicking MySQLManager interface for isolation testing.
    """
    def __init__(self):
        self.is_connected = True
        self._lock = threading.Lock()
        # list of dicts
        self.logs = []

    def log_user_analysis(
        self,
        user_text,
        risk_score,
        risk_level,
        confidence_score,
        matched_flags,
        latency_ms,
        session_id="session_default",
        bot_response="",
        image_base64=None,
        client_id=None
    ):
        with self._lock:
            self.logs.append({
                "id": len(self.logs) + 1,
                "session_id": session_id,
                "client_id": client_id,
                "user_text": user_text,
                "image_base64": image_base64,
                "has_image": bool(image_base64),
                "bot_response": bot_response,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "confidence_score": confidence_score,
                "matched_flags": matched_flags,
                "latency_ms": latency_ms,
                "created_at": datetime.now().isoformat()
            })
            return True

    def get_chat_history(self, session_id, client_id=None):
        with self._lock:
            results = []
            for item in self.logs:
                if item["session_id"] == session_id:
                    if client_id is not None and item.get("client_id") != client_id:
                        continue
                    results.append({
                        "user_text": item["user_text"],
                        "image_base64": item["image_base64"] or "",
                        "has_image": item["has_image"],
                        "bot_response": item["bot_response"],
                        "risk_score": item["risk_score"],
                        "risk_level": item["risk_level"],
                        "created_at": item["created_at"]
                    })
            return results

    def get_all_sessions(self, client_id=None):
        with self._lock:
            # Group by session_id
            sessions = {}
            for item in self.logs:
                if client_id is not None and item.get("client_id") != client_id:
                    continue
                sid = item["session_id"]
                if sid.startswith("eval_") or sid.startswith("session_test"):
                    continue
                if sid not in sessions:
                    sessions[sid] = {
                        "session_id": sid,
                        "title": item["user_text"],
                        "last_active": item["created_at"],
                        "msg_count": 0
                    }
                sessions[sid]["msg_count"] += 1
                sessions[sid]["last_active"] = max(sessions[sid]["last_active"], item["created_at"])
            return list(sessions.values())

    def close(self):
        pass


@pytest.fixture
def isolation_server(monkeypatch):
    """Sets up live server with isolated FakeInMemoryDB on ephemeral port."""
    fake_db = FakeInMemoryDB()
    monkeypatch.setattr(orchestrator, "db_manager", fake_db)

    server = create_server(host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    server_thread.start()
    host, port = server.server_address[:2]
    yield host, port, server, fake_db
    server.shutdown()
    server.server_close()


def make_request(host, port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = headers or {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp_body = resp.read()
    hdr_dict = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, resp_body, hdr_dict


# ─────────────────────────────────────────────────────────────────────────────
# S5: Client Isolation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_or_invalid_client_id_header_returns_400(isolation_server):
    """GET /api/sessions and /api/history must reject missing or invalid X-Client-Id with 400."""
    host, port, _, _ = isolation_server

    # 1. Missing header on /api/sessions
    status, body, _ = make_request(host, port, "GET", "/api/sessions")
    assert status == 400
    assert b"Missing or invalid X-Client-Id header" in body

    # 2. Invalid header (too short < 16 chars)
    status, body, _ = make_request(host, port, "GET", "/api/sessions", headers={"X-Client-Id": "short_id"})
    assert status == 400
    assert b"Missing or invalid X-Client-Id header" in body

    # 3. Invalid header (special characters / injection)
    status, body, _ = make_request(host, port, "GET", "/api/sessions", headers={"X-Client-Id": "client'; DROP TABLE;"})
    assert status == 400
    assert b"Missing or invalid X-Client-Id header" in body

    # 4. Missing header on /api/history
    status, body, _ = make_request(host, port, "GET", "/api/history?session_id=valid_sess_123")
    assert status == 400
    assert b"Missing or invalid X-Client-Id header" in body

    # 5. Invalid header on /api/history
    status, body, _ = make_request(host, port, "GET", "/api/history?session_id=valid_sess_123", headers={"X-Client-Id": "bad*chars!"})
    assert status == 400


def test_client_sessions_isolation(isolation_server):
    """Client A creates 3 sessions; Client B calling /api/sessions sees ONLY B's sessions."""
    host, port, _, fake_db = isolation_server
    client_a = "client_AAAA_1234567890abcdef"
    client_b = "client_BBBB_1234567890abcdef"

    # Populate 3 sessions for Client A
    fake_db.log_user_analysis("User A msg 1", 10, "LOW", 90, [], 10.0, session_id="sess_A1", client_id=client_a)
    fake_db.log_user_analysis("User A msg 2", 10, "LOW", 90, [], 10.0, session_id="sess_A2", client_id=client_a)
    fake_db.log_user_analysis("User A msg 3", 10, "LOW", 90, [], 10.0, session_id="sess_A3", client_id=client_a)

    # Populate 1 session for Client B
    fake_db.log_user_analysis("User B msg 1", 20, "LOW", 95, [], 15.0, session_id="sess_B1", client_id=client_b)

    # Client B queries /api/sessions
    status, body, _ = make_request(host, port, "GET", "/api/sessions", headers={"X-Client-Id": client_b})
    assert status == 200
    sessions_b = json.loads(body.decode("utf-8"))
    assert len(sessions_b) == 1, f"Expected 1 session for Client B, got {len(sessions_b)}"
    assert sessions_b[0]["session_id"] == "sess_B1"

    # Client A queries /api/sessions
    status, body, _ = make_request(host, port, "GET", "/api/sessions", headers={"X-Client-Id": client_a})
    assert status == 200
    sessions_a = json.loads(body.decode("utf-8"))
    assert len(sessions_a) == 3, f"Expected 3 sessions for Client A, got {len(sessions_a)}"
    a_sids = {s["session_id"] for s in sessions_a}
    assert a_sids == {"sess_A1", "sess_A2", "sess_A3"}


def test_client_history_cross_access_returns_empty(isolation_server):
    """When Client B queries Client A's session_id, server returns empty list [] (not 403) to prevent enumeration."""
    host, port, _, fake_db = isolation_server
    client_a = "client_AAAA_1234567890abcdef"
    client_b = "client_BBBB_1234567890abcdef"

    # Log secret message for Client A in session_secret_A
    fake_db.log_user_analysis(
        "Số tài khoản bí mật của tôi: 1903338888",
        10, "LOW", 99, [], 5.0,
        session_id="session_secret_A",
        client_id=client_a
    )

    # Client B guesses or queries Client A's session_id
    status, body, _ = make_request(
        host, port, "GET",
        "/api/history?session_id=session_secret_A",
        headers={"X-Client-Id": client_b}
    )
    assert status == 200, f"Expected status 200 with empty list, got {status}"
    history = json.loads(body.decode("utf-8"))
    assert history == [], "Client B must NOT receive any history of Client A's session"
    assert b"1903338888" not in body


def test_memory_agent_isolation_same_session_id():
    """
    Two different clients using the SAME session_id ('session_default') must not share escalation state.
    Client A recruitment prompt must NOT cause Client B tuition deposit to trigger scam escalation.
    """
    mem = MemoryAgent()
    client_a = "client_AAAA_1234567890abcdef"
    client_b = "client_BBBB_1234567890abcdef"
    shared_session_id = "session_same_id_100"

    # Client A: records recruitment interaction
    mem.add_interaction(
        user_text="Em tìm việc làm tuyển dụng CTV xem video 500k/ngày",
        risk_level="LOW",
        matched_flags=["tuyển dụng"],
        session_id=shared_session_id,
        client_id=client_a
    )

    # Client B: checks escalation for tuition fee in the same session_id
    res_b = mem.analyze_escalation(
        current_text="Tôi chuyển 500k tiền học phí cho con nhé",
        session_id=shared_session_id,
        client_id=client_b
    )
    assert not res_b["escalation_detected"], "Client B must NOT trigger escalation from Client A's recruitment memory"
    assert res_b["history_count"] == 0, "Client B must have 0 history count in their isolated namespace"

    # Client A: checks escalation with transfer -> triggers escalation
    res_a = mem.analyze_escalation(
        current_text="Họ yêu cầu nạp tiền 500k quỹ cọc",
        session_id=shared_session_id,
        client_id=client_a
    )
    assert res_a["escalation_detected"], "Client A must trigger escalation on their own sequential pattern"
    assert res_a["history_count"] == 1


def test_sql_injection_in_client_id_and_session_id_blocked(isolation_server):
    """SQL injection payloads in X-Client-Id or session_id are strictly rejected by regex."""
    host, port, _, _ = isolation_server

    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE user_logs; --",
        "admin'--",
        "1 UNION SELECT * FROM users",
        "<script>alert(1)</script>",
        "../../../etc/passwd"
    ]

    for payload in sqli_payloads:
        # In X-Client-Id header
        st, b, _ = make_request(host, port, "GET", "/api/sessions", headers={"X-Client-Id": payload})
        assert st == 400, f"Payload '{payload}' in X-Client-Id must return 400, got {st}"

        # In session_id query param
        valid_cid = "client_VALID_1234567890abcdef"
        from urllib.parse import quote
        st_sess, _, _ = make_request(
            host, port, "GET",
            f"/api/history?session_id={quote(payload)}",
            headers={"X-Client-Id": valid_cid}
        )
        assert st_sess == 400, f"Payload '{payload}' in session_id must return 400, got {st_sess}"


def test_new_session_id_is_unpredictable_uuid(isolation_server):
    """POST /api/sessions/new must generate unpredictable UUID (not predictable timestamp)."""
    host, port, _, _ = isolation_server

    ids = set()
    for _ in range(5):
        status, body, _ = make_request(host, port, "POST", "/api/sessions/new")
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        sid = data.get("session_id", "")
        assert sid.startswith("session_")
        raw_uuid = sid.replace("session_", "")
        # Validate that it is a valid UUID
        parsed = uuid.UUID(raw_uuid)
        assert str(parsed) == raw_uuid
        ids.add(sid)

    assert len(ids) == 5, "Session IDs must all be unique"


def test_analyze_missing_client_id_assigns_anonymous_hash(isolation_server, monkeypatch):
    """When X-Client-Id is missing in /api/analyze, server generates anonymous-<hash(IP)> and does not crash."""
    host, port, _, fake_db = isolation_server

    captured_client_ids = []

    def spy_process_request(*args, **kwargs):
        captured_client_ids.append(kwargs.get("client_id"))
        return {"decision": {"headline": "OK", "risk_level": "LOW"}, "risk_score": 0}

    monkeypatch.setattr(orchestrator, "process_request", spy_process_request)

    payload = json.dumps({"user_text": "Tin nhắn ẩn danh"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload))
    }
    # Notice: NO X-Client-Id header sent!
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)
    assert status == 200
    assert len(captured_client_ids) == 1
    cid = captured_client_ids[0]
    assert cid is not None
    assert cid.startswith("anonymous-"), f"Expected anonymous-<hash>, got '{cid}'"
