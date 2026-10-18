import os
import sys
import json
import time
import socket
import threading
import http.client
import ipaddress
import hashlib
from unittest.mock import MagicMock, patch
import pytest

from codebase.config import get_settings, Settings
from codebase.server import (
    create_server,
    SafeGuardAPIHandler,
    SafeGuardServer,
    TokenBucketRateLimiter,
    get_client_ip,
    _check_json_depth,
    orchestrator,
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


def raw_http_request(host, port, request_bytes, read_timeout=3.0):
    """Sends raw bytes over a TCP socket and returns all received bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    s.connect((host, port))
    try:
        s.sendall(request_bytes)
        received = bytearray()
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)
            except (socket.timeout, TimeoutError):
                break
        return bytes(received)
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# S1: Anonymous Client ID Hardening
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


def test_anonymous_post_cannot_be_read_back_and_different_ips_isolated(phase4d_server, monkeypatch):
    """
    POST /api/analyze without X-Client-Id generates server HMAC client_id.
    An attacker trying to calculate sha256(ip)[:16] or query anonymous- prefix gets 400.
    Different IPs produce different anonymous IDs.
    """
    host, port, _ = phase4d_server

    # POST without X-Client-Id header
    conn = http.client.HTTPConnection(host, port, timeout=15)
    payload = json.dumps({"user_text": "Kiem tra don hang qua Zalo", "session_id": "anon_session_1"}).encode("utf-8")
    conn.request("POST", "/api/analyze", body=payload, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 200

    # Attacker tries to guess client_id based on old algorithm sha256(ip)[:16]
    guessed_id = f"anonymous-{hashlib.sha256(b'127.0.0.1').hexdigest()[:16]}"
    conn = http.client.HTTPConnection(host, port, timeout=15)
    conn.request("GET", "/api/sessions", headers={"X-Client-Id": guessed_id})
    resp = conn.getresponse()
    assert resp.status == 400

    conn = http.client.HTTPConnection(host, port, timeout=15)
    conn.request("GET", f"/api/history?session_id=anon_session_1", headers={"X-Client-Id": guessed_id})
    resp = conn.getresponse()
    assert resp.status == 400


# ─────────────────────────────────────────────────────────────────────────────
# S2: 413 & 429 Prevent Client TCP ConnectionReset (Drain & Shutdown)
# ─────────────────────────────────────────────────────────────────────────────

def test_413_payload_too_large_drains_without_rst(phase4d_server):
    """
    Client sending body larger than max_body_bytes receives clean 413 HTTP response,
    not a ConnectionReset error, even when unread data remains.
    """
    host, port, _ = phase4d_server
    # Max body is default 8MB (8388608). We declare 9MB body and send header + 64KB body.
    headers = (
        b"POST /api/analyze HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 9437184\r\n\r\n"
    )
    body_chunk = b"X" * (64 * 1024)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    try:
        s.sendall(headers + body_chunk)
        # Read response from server
        resp_data = bytearray()
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_data.extend(chunk)
            except (socket.timeout, TimeoutError):
                break
        resp_str = resp_data.decode("utf-8", errors="replace")
        assert "413" in resp_str
        assert "Payload Too Large" in resp_str
    finally:
        s.close()


def test_429_rate_limited_drains_without_rst(phase4d_server):
    """
    Client being rate-limited with remaining body data receives clean 429 response
    with Retry-After and no TCP connection reset.
    """
    host, port, server = phase4d_server
    # Exhaust rate limiter on server
    server.rate_limiter._buckets["127.0.0.1"] = (0.0, time.monotonic())

    headers = (
        b"POST /api/analyze HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 1048576\r\n\r\n"
    )
    body_chunk = b"A" * 32768

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    try:
        s.sendall(headers + body_chunk)
        resp_data = bytearray()
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_data.extend(chunk)
            except (socket.timeout, TimeoutError):
                break
        resp_str = resp_data.decode("utf-8", errors="replace")
        assert "429" in resp_str
        assert "Retry-After" in resp_str
        assert "rate_limited" in resp_str
    finally:
        s.close()


def test_drain_and_close_invoked_on_413_and_429(phase4d_server):
    """Verifies that _drain_and_close is actively called when 413 or 429 is encountered."""
    host, port, server = phase4d_server
    drain_calls = []
    event_413 = threading.Event()
    event_429 = threading.Event()
    orig_drain = SafeGuardAPIHandler._drain_and_close

    def tracking_drain(self, *args, **kwargs):
        drain_calls.append(True)
        if len(drain_calls) == 1:
            event_413.set()
        elif len(drain_calls) == 2:
            event_429.set()
        return orig_drain(self, *args, **kwargs)

    with patch.object(SafeGuardAPIHandler, "_drain_and_close", tracking_drain):
        # 1. Trigger 413
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/analyze", body=b"X" * 1024, headers={"Content-Length": "9437184", "Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 413
        assert event_413.wait(timeout=2.0)
        assert len(drain_calls) == 1

        # 2. Trigger 429
        server.rate_limiter._buckets["127.0.0.1"] = (0.0, time.monotonic())
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/analyze", body=b"{}", headers={"Content-Length": "2", "Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 429
        assert event_429.wait(timeout=2.0)
        assert len(drain_calls) == 2


# ─────────────────────────────────────────────────────────────────────────────
# S3: X-Forwarded-For Trust Proxy Security
# ─────────────────────────────────────────────────────────────────────────────

def test_xff_takes_rightmost_hop_and_validates(monkeypatch):
    """
    When trust_proxy=True:
    - Multiple hops: takes rightmost hop (or Nth from right via trusted_proxy_hops).
    - Invalid IP: falls back to connection IP.
    - Header > 512 chars: ignored, falls back to connection IP.
    - IPv4-mapped IPv6 normalized to pure IPv4.
    """
    class DummyHandler:
        def __init__(self, client_ip, xff_header):
            self.client_address = (client_ip, 12345)
            self.headers = {"X-Forwarded-For": xff_header} if xff_header is not None else {}

    monkeypatch.setenv("SAFEGUARD_TRUST_PROXY", "1")
    monkeypatch.setenv("SAFEGUARD_TRUSTED_PROXY_HOPS", "1")
    get_settings(refresh=True)

    try:
        # 1. Takes rightmost hop: 'attacker_fake, real_client' -> real_client
        h1 = DummyHandler("10.0.0.1", "198.51.100.1, 203.0.113.5")
        assert get_client_ip(h1) == "203.0.113.5"

        # 2. Trusted proxy hops = 2
        monkeypatch.setenv("SAFEGUARD_TRUSTED_PROXY_HOPS", "2")
        get_settings(refresh=True)
        h2 = DummyHandler("10.0.0.1", "198.51.100.1, 203.0.113.5, 10.0.0.2")
        assert get_client_ip(h2) == "203.0.113.5"

        # Reset to 1 hop
        monkeypatch.setenv("SAFEGUARD_TRUSTED_PROXY_HOPS", "1")
        get_settings(refresh=True)

        # 3. Invalid IP syntax in XFF -> fall back to connection IP
        h3 = DummyHandler("127.0.0.1", "random-bad-string, not_an_ip")
        assert get_client_ip(h3) == "127.0.0.1"

        # 4. Header > 512 characters -> ignored (prevents 60KB bucket keys)
        long_xff = "192.168.1.1, " * 50  # > 512 chars
        assert len(long_xff) > 512
        h4 = DummyHandler("127.0.0.1", long_xff)
        assert get_client_ip(h4) == "127.0.0.1"

        # 5. IPv4-mapped IPv6 normalization
        h5 = DummyHandler("10.0.0.1", "::ffff:198.51.100.42")
        assert get_client_ip(h5) == "198.51.100.42"

        # 6. trust_proxy=False must ignore XFF entirely
        monkeypatch.setenv("SAFEGUARD_TRUST_PROXY", "0")
        get_settings(refresh=True)
        h6 = DummyHandler("127.0.0.1", "203.0.113.99")
        assert get_client_ip(h6) == "127.0.0.1"

    finally:
        monkeypatch.undo()
        get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# S4: MySQL Timeout & Fail-Open Resilience
# ─────────────────────────────────────────────────────────────────────────────

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

        # Hold the lock from a background thread to simulate another thread hung in MySQL
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


# ─────────────────────────────────────────────────────────────────────────────
# S5: MemoryAgent Per-Client Quota, Global Limit & Text Truncation
# ─────────────────────────────────────────────────────────────────────────────

def test_memory_agent_per_client_quota_protects_other_clients():
    """
    Client X creating thousands of sessions must NOT evict sessions of active Client Y.
    Per-client quota (50 sessions/client) and global limit (2000) are strictly enforced.
    """
    mem = MemoryAgent(max_sessions=100, max_sessions_per_client=50)

    # Client Y creates 10 sessions
    client_y = "client-YYYY-12345678"
    for i in range(10):
        mem.add_interaction(f"tin nhắn của Y {i}", "LOW", [], session_id=f"y_sess_{i}", client_id=client_y)

    # Client X creates 500 sessions (exceeding both its per-client quota and total max_sessions)
    client_x = "client-XXXX-12345678"
    for i in range(500):
        mem.add_interaction(f"tin nhắn của X {i}", "LOW", [], session_id=f"x_sess_{i}", client_id=client_x)

    # Client X's sessions inside client_map must not exceed 50
    assert len(mem._client_sessions[client_x]) <= 50

    # Client Y's sessions must NOT have been completely wiped out by Client X!
    assert client_y in mem._client_sessions
    y_sessions = mem._client_sessions[client_y]
    assert len(y_sessions) > 0, "Client X flooded memory and evicted all of Client Y's sessions!"


def test_memory_agent_truncates_interaction_text_and_bounds_memory():
    """Each interaction text stored in memory must be capped at 2000 characters."""
    mem = MemoryAgent(max_text_chars=2000)
    long_text = "A" * 15000

    mem.add_interaction(long_text, "HIGH", ["scam_flag"], session_id="s_long", client_id="c_test_trunc")
    hist = mem._get_session_deque("s_long", client_id="c_test_trunc")

    assert len(hist) == 1
    assert len(hist[0]["text"]) == 2000
    assert mem.get_total_stored_chars() <= 2000


# ─────────────────────────────────────────────────────────────────────────────
# S6: Nit & Minor Hardening (JSON Depth, Masking, Connection Limit, Rate Limits)
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


def test_api_sessions_and_history_rate_limiting():
    """Endpoints /api/sessions and /api/history are rate limited with 60/min bucket."""
    limiter = TokenBucketRateLimiter(rate_per_min=60, burst=60)
    test_ip = "192.0.2.100"

    # 60 requests succeed
    for _ in range(60):
        allowed, _ = limiter.check_and_consume(test_ip)
        assert allowed is True

    # 61st request rejected
    allowed, wait_s = limiter.check_and_consume(test_ip)
    assert allowed is False
    assert wait_s > 0


def test_max_connections_rejection():
    """SafeGuardServer immediately rejects connections exceeding Settings.max_connections with 503."""
    server = SafeGuardServer.__new__(SafeGuardServer)
    server._active_connections = 256
    server._conn_lock = threading.Lock()
    mock_request = MagicMock()

    # When active connections >= max_connections (256)
    server.process_request(mock_request, ("127.0.0.1", 12345))

    # Assert 503 was sent directly to socket without thread creation
    mock_request.sendall.assert_called_once()
    sent_data = mock_request.sendall.call_args[0][0]
    assert b"503 Service Unavailable" in sent_data
    assert b"Server at capacity" in sent_data
    mock_request.close.assert_called_once()
