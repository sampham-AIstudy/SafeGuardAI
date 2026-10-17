import os
import http.client
import json
import threading
import uuid
import pytest
from codebase.server import create_server, SafeGuardAPIHandler, orchestrator


@pytest.fixture
def live_server():
    """Runs real HTTP server in a thread on an ephemeral port (port 0)."""
    server = create_server(host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    server_thread.start()
    host, port = server.server_address[:2]
    yield host, port
    server.shutdown()
    server.server_close()


def make_request(host, port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = headers or {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp_body = resp.read()
    conn.close()
    return resp.status, resp_body, resp.headers


def test_get_root_and_static_200(live_server):
    host, port = live_server
    # GET / should return index.html (200)
    status, body, headers = make_request(host, port, "GET", "/")
    assert status == 200
    assert b"SafeGuard AI" in body or b"<!DOCTYPE html>" in body

    # GET /index.html should return 200
    status, body, headers = make_request(host, port, "GET", "/index.html")
    assert status == 200


def test_path_traversal_blocked(live_server):
    host, port = live_server
    # Direct traversal
    status, _, _ = make_request(host, port, "GET", "/../codebase/server.py")
    assert status == 404

    # Encoded traversal
    status, _, _ = make_request(host, port, "GET", "/%2e%2e/codebase/server.py")
    assert status == 404

    status, _, _ = make_request(host, port, "GET", "/%2e%2e/%2e%2e/requirements.txt")
    assert status == 404


def test_payload_too_large_413(live_server):
    host, port = live_server
    # Declare Content-Length greater than max_body_bytes (8_000_000)
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.putrequest("POST", "/api/analyze")
    conn.putheader("Host", f"{host}:{port}")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "9000000")
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 413
    body = resp.read()
    assert b"Payload Too Large" in body
    conn.close()


def test_bad_request_missing_or_invalid_content_length(live_server):
    host, port = live_server
    conn = http.client.HTTPConnection(host, port, timeout=5)
    # HTTP 1.1 POST without Content-Length
    conn.putrequest("POST", "/api/analyze")
    conn.putheader("Host", f"{host}:{port}")
    conn.putheader("Content-Type", "application/json")
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    body = resp.read()
    conn.close()
    assert status == 400


def test_bad_request_malformed_json(live_server):
    host, port = live_server
    payload = b"{not-a-valid-json"
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload))
    }
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)
    assert status == 400
    assert b"Malformed JSON" in body


def test_bad_request_invalid_types_and_session_id(live_server):
    host, port = live_server

    # 1. user_text not string
    p1 = json.dumps({"user_text": 12345}).encode("utf-8")
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=p1,
                                   headers={"Content-Length": str(len(p1))})
    assert status == 400
    assert b"user_text must be a string" in body

    # 2. session_id with invalid characters (spaces, special chars)
    p2 = json.dumps({"user_text": "test", "session_id": "session with space"}).encode("utf-8")
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=p2,
                                   headers={"Content-Length": str(len(p2))})
    assert status == 400
    assert b"Invalid session_id" in body

    # 3. session_id too long (> 100 chars)
    p3 = json.dumps({"user_text": "test", "session_id": "a" * 105}).encode("utf-8")
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=p3,
                                   headers={"Content-Length": str(len(p3))})
    assert status == 400

    # 4. image_base64 invalid type (e.g. integer)
    p4 = json.dumps({"user_text": "test", "image_base64": 123}).encode("utf-8")
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=p4,
                                   headers={"Content-Length": str(len(p4))})
    assert status == 400
    assert b"image_base64 must be string or null" in body


def test_internal_error_500_masks_secrets_and_returns_error_id(live_server, monkeypatch):
    host, port = live_server

    def fake_process_request(*args, **kwargs):
        raise RuntimeError("SUPER_SECRET_INTERNAL_KEY_DO_NOT_LEAK")

    monkeypatch.setattr(orchestrator, "process_request", fake_process_request)

    payload = json.dumps({"user_text": "test"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload))
    }
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)
    assert status == 500

    # Body must NOT contain the secret error message or Traceback
    assert b"SUPER_SECRET_INTERNAL_KEY_DO_NOT_LEAK" not in body
    assert b"Traceback" not in body

    # Body must be valid JSON with error="internal_error" and a valid uuid4 error_id
    data = json.loads(body.decode("utf-8"))
    assert data.get("error") == "internal_error"
    error_id = data.get("error_id")
    assert error_id is not None
    # Verify it is a valid UUID
    parsed_uuid = uuid.UUID(error_id, version=4)
    assert str(parsed_uuid) == error_id


def test_e1_unc_path_traversal_blocked(live_server):
    """Test UNC, Windows drive letter, null byte, double-slash paths (Task E1 blocker)."""
    host, port = live_server
    malicious_paths = [
        '/%5c%5clocalhost%5cc$%5cWindows%5cwin.ini',
        '/\\localhost\\c$\\x',
        '/%5c%5cattacker%5cx',
        '/C:/Windows/win.ini',
        '/%00',
        '/..%5c..%5c.env',
        '//etc/passwd'
    ]

    for m_path in malicious_paths:
        status, _, _ = make_request(host, port, "GET", m_path)
        assert status == 404, f"Path '{m_path}' must return 404, got {status}"
        # Server must still be alive and serve GET /
        next_status, next_body, _ = make_request(host, port, "GET", "/")
        assert next_status == 200, f"Server failed to serve GET / after '{m_path}' (status: {next_status})"
        assert b"SafeGuard AI" in next_body or b"<!DOCTYPE html>" in next_body


def test_e2_session_id_ascii_fullmatch(live_server):
    """Session_id must strictly match ^[a-zA-Z0-9_-]{1,100}$ (re.ASCII, fullmatch)."""
    host, port = live_server
    invalid_session_ids = [
        "abc\n",
        "session\r\n",
        "session１２３",       # Fullwidth Unicode digits
        "session_١٢٣",       # Arabic-Indic digits
        "session với khoảng trắng",
        "session@tag",
    ]

    for sid in invalid_session_ids:
        # 1. GET /api/history
        from urllib.parse import quote
        get_status, get_body, _ = make_request(
            host, port, "GET", f"/api/history?session_id={quote(sid)}",
            headers={"X-Client-Id": "client-1234567890abcdef"}
        )
        assert get_status == 400, f"GET with session_id '{sid}' must return 400, got {get_status}"
        assert b"Invalid session_id" in get_body

        # 2. POST /api/analyze
        post_payload = json.dumps({"user_text": "test", "session_id": sid}).encode("utf-8")
        post_status, post_body, _ = make_request(
            host, port, "POST", "/api/analyze", body=post_payload,
            headers={"Content-Length": str(len(post_payload)), "Content-Type": "application/json"}
        )
        assert post_status == 400, f"POST with session_id '{sid}' must return 400, got {post_status}"


def test_e2_handler_timeout_partial_body(live_server):
    """Sending Content-Length 100 with only 10 bytes times out in <=12s; next GET / returns 200."""
    import socket
    import time
    host, port = live_server

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    raw_req = (
        f"POST /api/analyze HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 100\r\n\r\n"
        f"0123456789"  # only 10 bytes
    ).encode("utf-8")
    s.sendall(raw_req)

    t0 = time.perf_counter()
    try:
        s.settimeout(12)
        s.recv(1024)
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    finally:
        s.close()

    elapsed = time.perf_counter() - t0
    assert elapsed <= 13.0, f"Handler timeout took {elapsed:.2f}s > 12s"

    # Server must still be responsive
    status, body, _ = make_request(host, port, "GET", "/")
    assert status == 200


def test_e2_base64_error_vietnamese_message(live_server):
    """Invalid base64 returns fixed Vietnamese message without leaking exception details."""
    host, port = live_server
    payload = json.dumps({"user_text": "test", "image_base64": "invalid-base64-content!!!"}).encode("utf-8")
    status, body, _ = make_request(
        host, port, "POST", "/api/analyze", body=payload,
        headers={"Content-Length": str(len(payload)), "Content-Type": "application/json"}
    )
    assert status == 400
    assert "Dữ liệu ảnh base64 không hợp lệ." in body.decode("utf-8")
    assert b"binascii" not in body
    assert b"Error:" not in body


def test_e2_server_header_overridden(live_server):
    """Server header must be overridden with 'SafeGuardAI'."""
    host, port = live_server
    status, body, headers = make_request(host, port, "GET", "/")
    assert status == 200
    server_hdr = headers.get("Server")
    assert server_hdr == "SafeGuardAI", f"Expected 'SafeGuardAI', got '{server_hdr}'"


def test_e8_negative_content_length(live_server):
    """Negative Content-Length must return 400 Bad Request."""
    host, port = live_server
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.putrequest("POST", "/api/analyze")
    conn.putheader("Host", f"{host}:{port}")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "-10")
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    conn.close()
    assert status == 400


def test_e8_orchestrator_session_id_isolation():
    """Orchestrator must isolate sessions so Session B does not inherit Session A's escalation."""
    from codebase.orchestrator import SafeGuardOrchestrator
    orch = SafeGuardOrchestrator()
    # Session A: Recruitment message
    res_a = orch.process_request(
        user_text="tuyển cộng tác viên làm thêm nạp cọc quỹ đảm bảo",
        session_id="session_isolated_user_A"
    )
    # Session B: Independent tuition bill
    res_b = orch.process_request(
        user_text="Anh ơi chuyển 500k bill học phí nhé",
        session_id="session_isolated_user_B"
    )
    assert not res_b.get("memory", {}).get("escalation_detected"), (
        "Session B must not inherit escalation from Session A"
    )


def test_e8_agent_runner_session_id_spy(monkeypatch):
    """Orchestrator must forward request session_id to agent_runner.run."""
    from codebase.orchestrator import SafeGuardOrchestrator
    from codebase.config import get_settings
    orch = SafeGuardOrchestrator()
    captured_session_ids = []

    def spy_run(user_text, pil_image=None, session_id="default", **kwargs):
        captured_session_ids.append(session_id)
        return None  # fall back to sequential

    monkeypatch.setattr(orch.agent_runner, "run", spy_run)
    monkeypatch.setattr(orch.agent_runner, "is_active", True)
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_LLM_MODE", "agentic")
    get_settings(refresh=True)
    test_sid = "test_custom_session_id_999"
    orch.process_request(user_text="Kiểm tra tin nhắn này", session_id=test_sid, llm_mode="agentic")
    assert test_sid in captured_session_ids, f"Expected {test_sid} passed to runner, got {captured_session_ids}"


def test_commonpath_must_not_be_startswith():
    """Mutation (a): Server path containment check must use commonpath/is_relative_to, NOT startswith."""
    import inspect
    from codebase import server
    source = inspect.getsource(server.SafeGuardAPIHandler.do_GET)
    assert ("commonpath" in source or "is_relative_to" in source), "Must use commonpath or is_relative_to"
    assert "target_path).startswith" not in source and "target_path.startswith" not in source, "Must NOT use startswith for target_path containment check"

    public_root = os.path.normpath(os.path.abspath(server.PUBLIC_DIR))
    sibling = os.path.normpath(public_root + "_backup/config.json")
    assert str(sibling).startswith(str(public_root)) is True, "Sanity check: startswith is vulnerable"
    assert (os.path.commonpath([public_root, sibling]) == public_root) is False, "commonpath must reject prefix sibling"


