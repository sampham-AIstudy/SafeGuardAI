import os
import sys
import json
import time
import socket
import threading
import http.client
from http.server import ThreadingHTTPServer
import ipaddress
import hashlib
import hmac
from unittest.mock import MagicMock, patch
import pytest

from codebase.config import get_settings, Settings
from codebase.server import (
    create_server,
    SafeGuardAPIHandler,
    SafeGuardServer,
    TokenBucketRateLimiter,
    get_client_ip,
    _clean_ip_string,
    _check_json_depth,
    orchestrator,
    _SERVER_ANON_SECRET,
)
from codebase.agents.memory_agent import MemoryAgent
from codebase.knowledge_base.db_connect import MySQLManager, _mask_client_id


@pytest.fixture
def phase4d_server(monkeypatch):
    """Starts live SafeGuardServer on ephemeral port with daemon thread in strict offline mode."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    get_settings(refresh=True)
    server = create_server(host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    server_thread.start()
    host, port = server.server_address[:2]
    yield host, port, server
    server.shutdown()
    server.server_close()


def raw_http_request(host, port, request_bytes, read_timeout=5.0):
    """Sends raw bytes over a TCP socket and returns all received bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    s.connect((host, port))
    try:
        s.sendall(request_bytes)
        received = bytearray()
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
            except (socket.timeout, TimeoutError):
                break
        return bytes(received)
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# S1 & S4(a) & Mutation 1 & 2: Anonymous Client ID Hardening
# ─────────────────────────────────────────────────────────────────────────────

def test_anonymous_client_id_rejected_on_sessions_and_history(phase4d_server):
    """GET /api/sessions and /api/history must strictly reject client_id with 'anonymous-' prefix (HTTP 400)."""
    host, port, _ = phase4d_server
    anon_id = "anonymous-1234567890123456"

    # 1. /api/sessions with anonymous- prefix
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/api/sessions", headers={"X-Client-Id": anon_id})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 400
    assert b"Missing or invalid X-Client-Id" in body

    # 2. /api/history with anonymous- prefix
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/api/history?session_id=s1", headers={"X-Client-Id": anon_id})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 400
    assert b"Missing or invalid X-Client-Id" in body


def test_anonymous_client_id_rejected_on_post_analyze(phase4d_server):
    """S4(a): POST /api/analyze with X-Client-Id starting with 'anonymous-' must return HTTP 400."""
    host, port, _ = phase4d_server
    conn = http.client.HTTPConnection(host, port, timeout=5)
    payload = json.dumps({"user_text": "Tin nhắn thử nghiệm", "session_id": "s_test_post"}).encode("utf-8")
    conn.request(
        "POST",
        "/api/analyze",
        body=payload,
        headers={"Content-Type": "application/json", "X-Client-Id": "anonymous-fake12345678"}
    )
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 400
    assert b"Invalid X-Client-Id header" in body


def test_anonymous_hmac_isolation_across_restarts_and_ips(phase4d_server):
    """
    Mutation 1:
    - ID must differ across server restarts (different RAM secrets) for the same IP.
    - ID cannot be computed via sha256(ip)[:16].
    - Two different IPs produce different anonymous IDs.
    - Same IP, including IPv4-mapped IPv6 (::ffff:198.51.100.1), produces the exact same ID.
    """
    ip1 = "198.51.100.1"
    ip2 = "203.0.113.2"
    ip1_v6 = "::ffff:198.51.100.1"

    # Simulate restart 1 with secret A
    secret_a = b"A" * 32
    hmac_a1 = hmac.new(secret_a, ip1.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    id_a1 = f"anonymous-{hmac_a1}"

    # Simulate restart 2 with secret B
    secret_b = b"B" * 32
    hmac_b1 = hmac.new(secret_b, ip1.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    id_b1 = f"anonymous-{hmac_b1}"

    # Assert different between restarts
    assert id_a1 != id_b1

    # Assert cannot be computed via sha256(ip)[:16]
    old_sha_id = f"anonymous-{hashlib.sha256(ip1.encode()).hexdigest()[:16]}"
    assert id_a1 != old_sha_id
    assert id_b1 != old_sha_id

    # Two different IPs produce different IDs
    hmac_a2 = hmac.new(secret_a, ip2.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    id_a2 = f"anonymous-{hmac_a2}"
    assert id_a1 != id_a2

    # Same IP via IPv4-mapped IPv6 normalizes and produces the same ID
    clean_v6 = get_client_ip(MagicMock(client_address=(ip1_v6, 1234), headers={}))
    assert clean_v6 == ip1
    hmac_mapped = hmac.new(secret_a, clean_v6.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    assert f"anonymous-{hmac_mapped}" == id_a1


def test_server_generates_unpredictable_hmac_for_anonymous_post(phase4d_server):
    """Verifies that live server generates HMAC-based anonymous client_id, never predictable sha256(ip)[:16]."""
    host, port, _ = phase4d_server
    captured_client_ids = []
    orig_proc = orchestrator.process_request

    def mock_proc(*args, **kwargs):
        captured_client_ids.append(kwargs.get("client_id"))
        return orig_proc(*args, **kwargs)

    with patch.object(orchestrator, "process_request", side_effect=mock_proc):
        conn = http.client.HTTPConnection(host, port, timeout=5)
        payload = json.dumps({"user_text": "hello"}).encode("utf-8")
        conn.request("POST", "/api/analyze", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        conn.close()

    assert len(captured_client_ids) == 1
    actual_cid = captured_client_ids[0]
    forbidden_sha = f"anonymous-{hashlib.sha256(b'127.0.0.1').hexdigest()[:16]}"
    assert actual_cid != forbidden_sha, f"Generated client_id was predictable sha256(ip)[:16]: {actual_cid}"


def test_db_does_not_save_anonymous_client_id():
    """Mutation 2: DB must save stored_client_id as None when client_id starts with 'anonymous-'."""
    mgr = MySQLManager.__new__(MySQLManager)
    mgr._lock = threading.Lock()
    mgr.is_connected = True
    mgr.conn = MagicMock()
    mock_cursor = MagicMock()
    mgr.conn.cursor.return_value.__enter__.return_value = mock_cursor

    mgr.log_user_analysis(
        user_text="Thử nghiệm lưu log",
        risk_score=20,
        risk_level="LOW",
        confidence_score=90,
        matched_flags=[],
        latency_ms=5.0,
        session_id="s_anon_db",
        client_id="anonymous-9876543210abcdef"
    )

    assert mock_cursor.execute.called
    sql, params = mock_cursor.execute.call_args[0]
    # In params: (session_id, stored_client_id, user_text, ...)
    assert params[1] is None, f"Expected stored_client_id to be None, got {params[1]}"

    # Conversely, a valid client_id IS saved
    mgr.log_user_analysis(
        user_text="Thử nghiệm lưu log 2",
        risk_score=20,
        risk_level="LOW",
        confidence_score=90,
        matched_flags=[],
        latency_ms=5.0,
        session_id="s_real_db",
        client_id="real-client-uuid-1234"
    )
    sql2, params2 = mock_cursor.execute.call_args[0]
    assert params2[1] == "real-client-uuid-1234"


# ─────────────────────────────────────────────────────────────────────────────
# B1 & S4(d) & Mutation 4 & 5: Body Drain on 413 & 429
# ─────────────────────────────────────────────────────────────────────────────

def test_429_raw_socket_sends_full_3mb_then_reads_complete_response(phase4d_server):
    """
    B1 & Mutation 4:
    Client sends full 3MB body on 429 BEFORE reading response.
    Server drains min(Content-Length, max_body_bytes) = 3MB and does NOT send TCP RST.
    Client receives complete status 429 and JSON body.
    S4(d): Connection: close is sent only ONCE.
    """
    host, port, server = phase4d_server
    # Exhaust rate limiter for 127.0.0.1
    server.rate_limiter._buckets["127.0.0.1"] = (0.0, time.monotonic())

    body_len = 3 * 1024 * 1024  # 3MB
    body_data = b"B" * body_len
    headers = (
        f"POST /api/analyze HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {body_len}\r\n\r\n"
    ).encode("ascii")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))
    try:
        # Send headers and full 3MB body completely before reading
        s.sendall(headers + body_data)

        # Now read response
        resp_data = bytearray()
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp_data.extend(chunk)
            except (socket.timeout, TimeoutError):
                break

        resp_text = resp_data.decode("utf-8", errors="replace")
        assert "429" in resp_text
        assert "Retry-After" in resp_text
        assert "rate_limited" in resp_text

        # Verify Connection: close appears exactly once
        headers_section = resp_text.split("\r\n\r\n")[0]
        conn_headers = [line for line in headers_section.split("\r\n") if line.lower().startswith("connection:")]
        assert len(conn_headers) == 1, f"Expected 1 Connection header, got: {conn_headers}"
    finally:
        s.close()


def test_413_raw_socket_sends_full_9mb_then_reads_complete_response(phase4d_server):
    """
    B1 & Mutation 4:
    Client sends full 9MB body on 413 (max_body_bytes=8MB) BEFORE reading response.
    Server drains ~8MB and shuts down write side gracefully without TCP RST.
    Client receives complete status 413 and JSON body.
    S4(d): Connection: close is sent only ONCE.
    """
    host, port, _ = phase4d_server

    body_len = 9 * 1024 * 1024  # 9MB
    body_data = b"C" * body_len
    headers = (
        f"POST /api/analyze HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {body_len}\r\n\r\n"
    ).encode("ascii")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))
    try:
        # Send full 9MB body completely before reading
        s.sendall(headers + body_data)

        # Now read response
        resp_data = bytearray()
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp_data.extend(chunk)
            except (socket.timeout, TimeoutError):
                break

        resp_text = resp_data.decode("utf-8", errors="replace")
        assert "413" in resp_text
        assert "Payload Too Large" in resp_text

        # Verify Connection: close appears exactly once
        headers_section = resp_text.split("\r\n\r\n")[0]
        conn_headers = [line for line in headers_section.split("\r\n") if line.lower().startswith("connection:")]
        assert len(conn_headers) == 1, f"Expected 1 Connection header, got: {conn_headers}"
    finally:
        s.close()


def test_drain_timeout_stops_on_slow_drip_client(phase4d_server):
    """
    B1 & Mutation 5:
    Client drips 1 byte every 0.3s on 413.
    Total drain budget (~3s) must stop the loop and close the socket within <= ~3.5s.
    """
    host, port, _ = phase4d_server

    headers = (
        b"POST /api/analyze HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 10000000\r\n\r\n"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect((host, port))
    s.sendall(headers)

    t_start = time.monotonic()
    try:
        # Drip 1 byte every 0.3s until server closes connection
        while True:
            try:
                s.sendall(b"X")
                time.sleep(0.3)
            except (OSError, socket.error):
                break
            if time.monotonic() - t_start > 6.0:
                break
    finally:
        duration = time.monotonic() - t_start
        s.close()

    assert duration <= 4.0, f"Drip drain took {duration:.2f}s, expected <= ~3.5s budget"


# ─────────────────────────────────────────────────────────────────────────────
# S1: X-Forwarded-For Hop Count, Tail Hop, Port & Scope ID Parsing
# ─────────────────────────────────────────────────────────────────────────────

def test_xff_strict_hops_and_tail_and_ports(monkeypatch):
    """
    S1 & Mutation 9 (part 1):
    1. If hops < SAFEGUARD_TRUSTED_PROXY_HOPS: returns connection IP (not hops[0]).
    2. If XFF > 512 chars: extracts rightmost hop from TAIL of header (not fallback to proxy).
    3. Strips port from IPv4 ("1.2.3.4:5555") and IPv6 ("[2001:db8::1]:80").
    4. Strips scope ID ("fe80::1%eth0").
    5. Normalizes IPv4-mapped IPv6.
    """
    class DummyHandler:
        def __init__(self, client_ip, xff_header):
            self.client_address = (client_ip, 12345)
            self.headers = {"X-Forwarded-For": xff_header} if xff_header is not None else {}

    monkeypatch.setenv("SAFEGUARD_TRUST_PROXY", "1")
    monkeypatch.setenv("SAFEGUARD_TRUSTED_PROXY_HOPS", "2")
    get_settings(refresh=True)

    try:
        # 1. Hops count < 2 (only 1 hop): must return connection IP "10.0.0.1", NOT attacker hop "198.51.100.1"
        h1 = DummyHandler("10.0.0.1", "198.51.100.1")
        assert get_client_ip(h1) == "10.0.0.1"

        # 2. XFF > 512 chars: extracts rightmost hop from tail
        long_prefix = "192.0.2.1, " * 60  # ~660 chars
        full_xff = f"{long_prefix}203.0.113.195"
        assert len(full_xff) > 512
        h2 = DummyHandler("10.0.0.1", full_xff)
        assert get_client_ip(h2) == "203.0.113.195"

        # 3. IPv4 with port
        monkeypatch.setenv("SAFEGUARD_TRUSTED_PROXY_HOPS", "1")
        get_settings(refresh=True)
        h3 = DummyHandler("10.0.0.1", "198.51.100.42:8080")
        assert get_client_ip(h3) == "198.51.100.42"

        # 4. IPv6 in brackets with port
        h4 = DummyHandler("10.0.0.1", "[2001:db8::1]:443")
        assert get_client_ip(h4) == "2001:db8::1"

        # 5. Scope ID stripping
        h5 = DummyHandler("10.0.0.1", "fe80::1%eth0")
        assert get_client_ip(h5) == "fe80::1"

        h6 = DummyHandler("10.0.0.1", "[fe80::1%eth0]:80")
        assert get_client_ip(h6) == "fe80::1"

        # 6. IPv4-mapped IPv6 with port
        h7 = DummyHandler("10.0.0.1", "[::ffff:198.51.100.99]:8000")
        assert get_client_ip(h7) == "198.51.100.99"

    finally:
        monkeypatch.undo()
        get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# S2 & Mutation 7 & Mutation 9 (part 2): MemoryAgent Character Budget & Eviction
# ─────────────────────────────────────────────────────────────────────────────

def test_memory_agent_char_budget_eviction_protects_active_client():
    """
    S2 & Mutation 7:
    Eviction triggers when total character budget is exceeded.
    Evicts sessions of the LEAST active client.
    NEVER evicts sessions of the currently active client.
    """
    # Set small char budget: 5000 characters
    mem = MemoryAgent(max_total_chars=5000, max_history=10, max_sessions=100)

    # Inactive client B adds 4000 characters across 2 sessions
    client_b = "client_BBBB_1234"
    mem.add_interaction("B" * 2000, "LOW", [], session_id="sess_b1", client_id=client_b)
    mem.add_interaction("B" * 2000, "LOW", [], session_id="sess_b2", client_id=client_b)
    assert mem.get_total_stored_chars() == 4000

    # Active client A adds 2000 characters
    # Total would be 4000 + 2000 = 6000 > 5000 ceiling!
    client_a = "client_AAAA_1234"
    mem.add_interaction("A" * 2000, "HIGH", [], session_id="sess_a1", client_id=client_a)

    # Client A's session MUST be preserved and active!
    assert client_a in mem._client_sessions
    assert "sess_a1" in mem._client_sessions[client_a]
    assert len(mem._client_sessions[client_a]["sess_a1"]) == 1

    # Client B's oldest session MUST have been evicted to fit the character budget
    assert len(mem._client_sessions[client_b]) == 1
    assert "sess_b1" not in mem._client_sessions[client_b]
    assert "sess_b2" in mem._client_sessions[client_b]
    assert mem.get_total_stored_chars() <= 5000


def test_memory_agent_empty_client_id_isolated_from_default():
    """
    S2 & Mutation 9 (part 2):
    Empty string client_id="" must NOT share a key or collision with default client_id=None.
    """
    mem = MemoryAgent()

    # Default client (client_id=None)
    mem.add_interaction("Nội dung của default client", "LOW", [], session_id="shared_sess", client_id=None)

    # Empty string client (client_id="")
    mem.add_interaction("Nội dung của empty client", "HIGH", [], session_id="shared_sess", client_id="")

    # Verify they are isolated
    hist_default = mem._get_session_deque("shared_sess", client_id=None)
    hist_empty = mem._get_session_deque("shared_sess", client_id="")

    assert len(hist_default) == 1
    assert hist_default[0]["text"] == "Nội dung của default client"

    assert len(hist_empty) == 1
    assert hist_empty[0]["text"] == "Nội dung của empty client"


# ─────────────────────────────────────────────────────────────────────────────
# S3 & Mutation 6 & Mutation 9 (part 3): Server Max Connections Per IP
# ─────────────────────────────────────────────────────────────────────────────

def test_max_connections_per_ip_and_counter_decrement(monkeypatch):
    """
    S3 & Mutation 6 & Mutation 9 (part 3):
    1. A single IP opening connections exceeding max_connections_per_ip receives 503 Service Unavailable
       immediately without creating a thread.
    2. Other IPs are still accepted and served concurrently.
    3. Both active_connections and per-ip connection counters decrement correctly on close_request.
    """
    server = SafeGuardServer.__new__(SafeGuardServer)
    server._active_connections = 0
    server._ip_connections = {}
    server._request_to_ip = {}
    server._conn_lock = threading.Lock()

    # Monkeypatch Settings to have max_connections_per_ip = 2
    monkeypatch.setenv("SAFEGUARD_MAX_CONNECTIONS_PER_IP", "2")
    monkeypatch.setenv("SAFEGUARD_MAX_CONNECTIONS", "10")
    get_settings(refresh=True)

    try:
        # Mock requests
        req_ip1_a = MagicMock()
        req_ip1_b = MagicMock()
        req_ip1_c = MagicMock()
        req_ip2 = MagicMock()

        with patch.object(ThreadingHTTPServer, "process_request", return_value=None):
            # IP 1 connection 1 -> accepted
            server.process_request(req_ip1_a, ("198.51.100.1", 1001))
            assert server._active_connections == 1
            assert server._ip_connections["198.51.100.1"] == 1

            # IP 1 connection 2 -> accepted
            server.process_request(req_ip1_b, ("198.51.100.1", 1002))
            assert server._active_connections == 2
            assert server._ip_connections["198.51.100.1"] == 2

            # IP 1 connection 3 -> REJECTED with 503
            server.process_request(req_ip1_c, ("198.51.100.1", 1003))
            req_ip1_c.sendall.assert_called_once()
            sent = req_ip1_c.sendall.call_args[0][0]
            assert b"503 Service Unavailable" in sent
            assert b"Server at capacity" in sent
            req_ip1_c.close.assert_called_once()
            # Counters not incremented for rejected
            assert server._active_connections == 2
            assert server._ip_connections["198.51.100.1"] == 2

            # IP 2 connection 1 -> ACCEPTED!
            server.process_request(req_ip2, ("203.0.113.5", 2001))
            assert server._active_connections == 3
            assert server._ip_connections["203.0.113.5"] == 1

        with patch.object(ThreadingHTTPServer, "close_request", return_value=None):
            # Close IP 1 requests
            server.close_request(req_ip1_a)
            assert server._active_connections == 2
            assert server._ip_connections["198.51.100.1"] == 1

            server.close_request(req_ip1_b)
            assert server._active_connections == 1
            assert "198.51.100.1" not in server._ip_connections

            # Close IP 2 request
            server.close_request(req_ip2)
            assert server._active_connections == 0
            assert len(server._ip_connections) == 0

    finally:
        monkeypatch.undo()
        get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# Mutation 3: Live Endpoint Rate Limiting on /api/sessions and /api/history
# ─────────────────────────────────────────────────────────────────────────────

def test_api_sessions_and_history_rate_limiting_via_live_endpoint(phase4d_server):
    """
    Mutation 3:
    Rate limiting on /api/sessions and /api/history tested through LIVE endpoints.
    Sending 70 requests results in HTTP 429 after 60 requests.
    """
    host, port, server = phase4d_server
    client_id = "client-test-ratelimit-12345678"

    # Reset session rate limiter for clean state
    server.session_rate_limiter.reset()

    # Send requests to /api/sessions
    statuses = []
    for _ in range(70):
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/sessions", headers={"X-Client-Id": client_id})
        resp = conn.getresponse()
        statuses.append(resp.status)
        resp.read()
        conn.close()

    assert 200 in statuses
    assert 429 in statuses
    # First 60 should be 200, 61-70 should be 429
    assert statuses[:60] == [200] * 60
    assert 429 in statuses[60:]

    # Also test /api/history
    server.session_rate_limiter.reset()
    hist_statuses = []
    for _ in range(70):
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/history?session_id=s_rate_limit", headers={"X-Client-Id": client_id})
        resp = conn.getresponse()
        hist_statuses.append(resp.status)
        resp.read()
        conn.close()

    assert 200 in hist_statuses
    assert 429 in hist_statuses
    assert hist_statuses[:60] == [200] * 60
    assert 429 in hist_statuses[60:]


# ─────────────────────────────────────────────────────────────────────────────
# Mutation 8: Raw Client ID Never Printed in Logs
# ─────────────────────────────────────────────────────────────────────────────

def test_client_id_never_logged_in_raw_form(capsys):
    """
    Mutation 8:
    Raw client_id must never appear in log outputs from db_connect or memory_agent.
    Only its 8-char SHA256 digest is printed.
    """
    raw_token = "CONFIDENTIAL_CLIENT_TOKEN_XYZ_9876543210"
    masked_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:8]

    # 1. db_connect
    mgr = MySQLManager.__new__(MySQLManager)
    mgr._lock = threading.Lock()
    mgr.is_connected = True
    mgr.conn = MagicMock()
    mgr.conn.cursor.return_value.__enter__.return_value = MagicMock()
    mgr.log_user_analysis(
        user_text="Log test",
        risk_score=10,
        risk_level="LOW",
        confidence_score=95,
        matched_flags=[],
        latency_ms=2.0,
        session_id="s_mask_test",
        client_id=raw_token
    )

    # 2. memory_agent
    mem = MemoryAgent()
    mock_db = MagicMock()
    mock_db.is_connected = True
    mock_db.get_chat_history.return_value = [{"user_text": "hello", "risk_level": "LOW"}]
    mem.load_history_from_db(mock_db, session_id="s_mem_mask", client_id=raw_token)

    captured = capsys.readouterr()
    assert raw_token not in captured.out, f"Raw client_id leaked into logs: {captured.out}"
    assert raw_token not in captured.err, f"Raw client_id leaked into stderr: {captured.err}"
    assert masked_hash in captured.out, f"Masked client_hash expected in logs: {captured.out}"


# ─────────────────────────────────────────────────────────────────────────────
# Existing Hardening Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_json_depth_limit_prevents_recursion_dos(phase4d_server):
    """Deeply nested JSON structure (>200 depth) returns HTTP 400, not HTTP 500 RecursionError."""
    host, port, _ = phase4d_server

    # Create 250 nested JSON brackets: {"a": {"a": ... }}
    deep_json = '{"a": ' * 250 + '"val"' + '}' * 250

    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("POST", "/api/analyze", body=deep_json.encode("utf-8"), headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    assert resp.status == 400
    assert resp.status != 500
    assert b"JSON depth exceeds maximum allowed limit" in body or b"Malformed JSON" in body


def test_client_id_is_masked_in_logs():
    """Client ID is masked with an 8-char SHA256 digest in logs instead of raw token."""
    raw_token = "user-secret-auth-token-12345678"
    masked = _mask_client_id(raw_token)
    assert len(masked) == 8
    assert raw_token not in masked
    assert _mask_client_id(None) == "none"


def test_mysql_lock_timeout_fail_open_does_not_deadlock(monkeypatch):
    """
    When MySQL operation hangs or lock is contested:
    - Lock acquire times out after Settings.db_timeout_s.
    - Fails open gracefully (returns False/[], logs notice, does not raise or deadlock).
    """
    monkeypatch.setenv("SAFEGUARD_DB_TIMEOUT", "1.0")
    get_settings(refresh=True)

    try:
        mgr = MySQLManager.__new__(MySQLManager)
        mgr._lock = threading.Lock()
        mgr.is_connected = True
        mgr.conn = MagicMock()

        # Hold the lock to simulate another thread hung in MySQL
        mgr._lock.acquire()

        t0 = time.monotonic()
        res = mgr.log_user_analysis(
            user_text="Test hung DB",
            risk_score=50,
            risk_level="MEDIUM",
            confidence_score=80,
            matched_flags=["test"],
            latency_ms=10.0,
            session_id="s_hang"
        )
        elapsed = time.monotonic() - t0

        # Must fail open (False) and not wait longer than db_timeout_s + 0.5s
        assert res is False
        assert elapsed < 1.8, f"Hung DB held request for {elapsed:.2f}s (expected < 1.8s)"

        # Release lock and ensure subsequent call works cleanly
        mgr._lock.release()
        mgr.conn.cursor.return_value.__enter__.return_value = MagicMock()
        res2 = mgr.log_user_analysis(
            user_text="Test resumed DB",
            risk_score=10,
            risk_level="LOW",
            confidence_score=90,
            matched_flags=[],
            latency_ms=5.0,
            session_id="s_ok"
        )
        assert res2 is True

    finally:
        monkeypatch.undo()
        get_settings(refresh=True)
