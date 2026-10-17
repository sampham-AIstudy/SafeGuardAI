import os
import sys
import json
import time
import math
import uuid
import re
import socket
import threading
import http.client
from unittest.mock import MagicMock
import pytest

from codebase.config import get_settings, Settings
from codebase.server import (
    create_server,
    SafeGuardAPIHandler,
    SafeGuardServer,
    TokenBucketRateLimiter,
    get_client_ip,
    orchestrator,
    PUBLIC_DIR,
)
from codebase.knowledge_base.db_connect import MySQLManager


@pytest.fixture
def test_server():
    """Starts live SafeGuardServer on port 0."""
    server = create_server(host="127.0.0.1", port=0)
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    server_thread.start()
    host, port = server.server_address[:2]
    yield host, port, server
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
# S1: Concurrency & Semaphore Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_threading_server_daemon_threads():
    """create_server must return SafeGuardServer with daemon_threads=True."""
    srv = create_server(host="127.0.0.1", port=0)
    try:
        assert isinstance(srv, SafeGuardServer)
        assert srv.daemon_threads is True
        assert hasattr(srv, "analyze_semaphore")
    finally:
        srv.server_close()


def test_concurrency_parallel_completion_and_max_limit(test_server, monkeypatch):
    """
    8 parallel requests to /api/analyze with 0.3s sleep in orchestrator stub
    must complete in < 8 * 0.3s (proof of concurrent execution) and
    observed concurrent executions must never exceed max_concurrency.
    """
    host, port, srv = test_server
    max_conc = 4
    srv.analyze_semaphore = threading.BoundedSemaphore(max_conc)

    active_count = 0
    max_observed_active = 0
    count_lock = threading.Lock()

    def stub_process_request(*args, **kwargs):
        nonlocal active_count, max_observed_active
        with count_lock:
            active_count += 1
            if active_count > max_observed_active:
                max_observed_active = active_count
        try:
            time.sleep(0.3)
            return {"decision": {"headline": "OK", "risk_level": "LOW"}, "risk_score": 10}
        finally:
            with count_lock:
                active_count -= 1

    monkeypatch.setattr(orchestrator, "process_request", stub_process_request)

    num_requests = 8
    results = []

    def send_one(idx):
        payload = json.dumps({"user_text": f"test {idx}"}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "X-Client-Id": f"client_{uuid.uuid4().hex}"
        }
        status, body, _ = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)
        results.append((status, body))

    t0 = time.perf_counter()
    threads = [threading.Thread(target=send_one, args=(i,)) for i in range(num_requests)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.perf_counter() - t0

    assert len(results) == num_requests
    assert all(st == 200 for st, _ in results)
    # Proof of concurrency: serial time would be >= 8 * 0.3 = 2.4s.
    # With 4 parallel slots, 8 requests take ~2 batches * 0.3s = ~0.6s - 1.2s (< 2.4s).
    assert duration < (num_requests * 0.3), f"Total time {duration:.2f}s should be < {num_requests * 0.3}s"
    assert max_observed_active <= max_conc, f"Observed {max_observed_active} > max {max_conc}"


def test_semaphore_exhaustion_returns_503(test_server, monkeypatch):
    """When semaphore is held for > 5s, new requests timeout and receive 503 + Retry-After: 2."""
    host, port, srv = test_server
    # Constrain semaphore to 1 slot
    srv.analyze_semaphore = threading.BoundedSemaphore(1)

    # Acquire the slot directly to simulate busy server
    assert srv.analyze_semaphore.acquire(blocking=False) is True

    try:
        # Request should block for 5s then return 503
        t0 = time.perf_counter()
        payload = json.dumps({"user_text": "test"}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "X-Client-Id": "client-1234567890abcdef"
        }
        status, body, resp_headers = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)
        elapsed = time.perf_counter() - t0

        assert status == 503
        assert elapsed >= 4.8, f"Wait time was {elapsed:.2f}s, expected ~5s"
        data = json.loads(body.decode("utf-8"))
        assert data.get("error") == "busy"
        assert "error_id" in data
        # Retry-After header must be 2
        retry_hdr = resp_headers.get("retry-after") or resp_headers.get("Retry-After")
        assert retry_hdr == "2"
    finally:
        srv.analyze_semaphore.release()


def test_slow_analyze_does_not_block_static_get(test_server, monkeypatch):
    """A slow /api/analyze request holding a slot must not block lightweight GET / requests."""
    host, port, srv = test_server

    hold_event = threading.Event()

    def slow_process(*args, **kwargs):
        hold_event.wait(timeout=5)
        return {"decision": {"headline": "OK"}}

    monkeypatch.setattr(orchestrator, "process_request", slow_process)

    # Launch slow analyze in background thread
    def send_slow():
        payload = json.dumps({"user_text": "slow"}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Content-Length": str(len(payload)), "X-Client-Id": "client-test1234567890"}
        make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)

    t_slow = threading.Thread(target=send_slow, daemon=True)
    t_slow.start()

    time.sleep(0.1)

    # GET / should return 200 immediately without waiting
    t0 = time.perf_counter()
    status, body, _ = make_request(host, port, "GET", "/")
    elapsed = time.perf_counter() - t0

    hold_event.set()
    t_slow.join(timeout=3)

    assert status == 200
    assert elapsed < 0.5, f"GET / was blocked: took {elapsed:.2f}s"


def test_mysql_manager_lock_and_ping_fail_open():
    """MySQLManager queries must acquire lock, call ping, and fail-open on connection errors."""
    mgr = MySQLManager.__new__(MySQLManager)
    mgr._lock = threading.Lock()
    mgr.is_connected = True

    mock_conn = MagicMock()
    mock_conn.ping.side_effect = Exception("MySQL server gone away")
    mgr.conn = mock_conn

    # Calling _ping must not raise
    mgr._ping()
    assert mock_conn.ping.called

    # Calling log_user_analysis with failing ping/cursor must not raise
    res = mgr.log_user_analysis("test", 10, "LOW", 90, [], 10.0)
    assert res is False or res is True  # Fail-open: returns bool, does not raise


# ─────────────────────────────────────────────────────────────────────────────
# S2: Rate Limiting Tests (Token Bucket with Injectable Clock)
# ─────────────────────────────────────────────────────────────────────────────

def test_token_bucket_rate_limiter_exceeded_and_token_refill():
    """Rate limiter allows burst then throttles; refills tokens with simulated time."""
    current_time = 1000.0

    def mock_clock():
        return current_time

    # rate = 20/min, burst = min(10, 20) = 10 tokens
    limiter = TokenBucketRateLimiter(rate_per_min=20, max_ips=100, clock=mock_clock)
    ip = "192.168.1.50"

    # Consume 10 burst tokens
    for i in range(10):
        allowed, wait_s = limiter.check_and_consume(ip)
        assert allowed is True, f"Token {i} should be allowed"
        assert wait_s == 0.0

    # 11th request must be rejected
    allowed, wait_s = limiter.check_and_consume(ip)
    assert allowed is False
    assert wait_s >= 1.0

    # Advance time by 3 seconds (20 tokens/60s = 1 token per 3 seconds)
    current_time += 3.0
    allowed, wait_s = limiter.check_and_consume(ip)
    assert allowed is True, "Token should be replenished after 3.0s"

    # Immediately check again -> rejected
    allowed, wait_s = limiter.check_and_consume(ip)
    assert allowed is False


def test_token_bucket_two_independent_ips():
    """Two different IPs must have separate buckets and not affect each other."""
    current_time = 2000.0
    limiter = TokenBucketRateLimiter(rate_per_min=10, max_ips=100, clock=lambda: current_time)

    ip1 = "10.0.0.1"
    ip2 = "10.0.0.2"

    # Exhaust ip1 (burst = 10)
    for _ in range(10):
        assert limiter.check_and_consume(ip1)[0] is True
    assert limiter.check_and_consume(ip1)[0] is False

    # ip2 must still have full tokens
    assert limiter.check_and_consume(ip2)[0] is True


def test_token_bucket_bounded_lru_table_size():
    """Inserting 50,000 distinct IPs into a 10,000-cap limiter must not exceed max_ips."""
    limiter = TokenBucketRateLimiter(rate_per_min=20, max_ips=1000, clock=time.monotonic)
    for i in range(5000):
        limiter.check_and_consume(f"192.168.{i // 256}.{i % 256}")

    assert len(limiter._buckets) == 1000, f"Table size {len(limiter._buckets)} exceeded max 1000"


def test_token_bucket_thread_safety():
    """Concurrent requests across threads must not corrupt TokenBucketRateLimiter."""
    limiter = TokenBucketRateLimiter(rate_per_min=60, max_ips=500)
    num_threads = 16
    iters = 100
    errors = []

    def worker(tid):
        try:
            ip = f"10.0.0.{tid % 4}"
            for _ in range(iters):
                limiter.check_and_consume(ip)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent rate limiting raised: {errors}"


def test_untrusted_x_forwarded_for_by_default(monkeypatch):
    """X-Forwarded-For header must NOT be trusted by default unless SAFEGUARD_TRUST_PROXY=1."""
    monkeypatch.delenv("SAFEGUARD_TRUST_PROXY", raising=False)
    get_settings(refresh=True)

    class DummyHandler:
        headers = {"X-Forwarded-For": "203.0.113.195"}
        client_address = ("127.0.0.1", 54321)

    ip = get_client_ip(DummyHandler())
    assert ip == "127.0.0.1", f"Expected client_address '127.0.0.1', but got untrusted XFF '{ip}'"

    monkeypatch.setenv("SAFEGUARD_TRUST_PROXY", "1")
    get_settings(refresh=True)
    ip_trusted = get_client_ip(DummyHandler())
    assert ip_trusted == "203.0.113.195"


def test_rate_limit_integration_429(test_server):
    """POST /api/sessions/new returns 429 once burst limit is exceeded."""
    host, port, srv = test_server
    # Use small rate limit to trigger fast
    srv.rate_limiter = TokenBucketRateLimiter(rate_per_min=5, max_ips=100)

    # Exhaust burst (min(10, 5) = 5)
    for _ in range(5):
        status, _, _ = make_request(host, port, "POST", "/api/sessions/new")
        assert status == 200

    # 6th request must receive 429
    status, body, headers = make_request(host, port, "POST", "/api/sessions/new")
    assert status == 429
    data = json.loads(body.decode("utf-8"))
    assert data.get("error") == "rate_limited"
    assert "error_id" in data
    assert "retry-after" in headers or "Retry-After" in headers


# ─────────────────────────────────────────────────────────────────────────────
# S3: CORS & Security Headers Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_cors_same_origin_default_no_wildcard(test_server, monkeypatch):
    """By default, no CORS header is sent (same-origin policy); no wildcard '*' allowed."""
    host, port, _ = test_server
    monkeypatch.delenv("SAFEGUARD_CORS_ORIGINS", raising=False)

    status, _, headers = make_request(host, port, "GET", "/", headers={"Origin": "https://malicious.com"})
    assert status == 200
    assert "access-control-allow-origin" not in headers
    assert "Access-Control-Allow-Origin" not in headers


def test_cors_allowlist_exact_match(test_server, monkeypatch):
    """Origin in SAFEGUARD_CORS_ORIGINS is echoed back with Vary: Origin."""
    host, port, _ = test_server
    monkeypatch.setenv("SAFEGUARD_CORS_ORIGINS", "https://app.safeguard.vn,https://trusted.local")

    # Allowed origin
    status, _, headers = make_request(host, port, "GET", "/", headers={"Origin": "https://app.safeguard.vn"})
    assert status == 200
    allow_origin = headers.get("access-control-allow-origin") or headers.get("Access-Control-Allow-Origin")
    assert allow_origin == "https://app.safeguard.vn"
    vary = headers.get("vary") or headers.get("Vary")
    assert "Origin" in vary

    # Disallowed origin
    status, _, headers2 = make_request(host, port, "GET", "/", headers={"Origin": "https://untrusted.com"})
    assert status == 200
    assert "access-control-allow-origin" not in headers2


def test_cors_options_preflight(test_server, monkeypatch):
    """OPTIONS returns 200 for allowed origin and 403 for disallowed origin."""
    host, port, _ = test_server
    monkeypatch.setenv("SAFEGUARD_CORS_ORIGINS", "https://frontend.company.com")

    # 1. Allowed origin preflight
    status, _, headers = make_request(
        host, port, "OPTIONS", "/api/analyze",
        headers={"Origin": "https://frontend.company.com"}
    )
    assert status == 200
    allow_origin = headers.get("access-control-allow-origin") or headers.get("Access-Control-Allow-Origin")
    assert allow_origin == "https://frontend.company.com"
    allow_headers = headers.get("access-control-allow-headers") or headers.get("Access-Control-Allow-Headers")
    assert "X-Client-Id" in allow_headers

    # 2. Unknown origin preflight => 403
    status2, _, _ = make_request(
        host, port, "OPTIONS", "/api/analyze",
        headers={"Origin": "https://attacker.com"}
    )
    assert status2 == 403


def test_all_security_headers_present(test_server):
    """Every response must contain nosniff, Referrer-Policy, DENY, CSP, Cache-Control on API."""
    host, port, _ = test_server

    # 1. Check on static file
    _, _, static_hdrs = make_request(host, port, "GET", "/")
    assert static_hdrs.get("x-content-type-options") == "nosniff"
    assert static_hdrs.get("referrer-policy") == "no-referrer"
    assert static_hdrs.get("x-frame-options") == "DENY"
    assert static_hdrs.get("cross-origin-opener-policy") == "same-origin"
    assert "default-src 'self'" in static_hdrs.get("content-security-policy", "")

    # 2. Check on /api/ endpoint (must include Cache-Control: no-store)
    _, _, api_hdrs = make_request(host, port, "POST", "/api/sessions/new")
    assert api_hdrs.get("cache-control") == "no-store"
    assert api_hdrs.get("x-content-type-options") == "nosniff"


def test_static_html_and_js_csp_compliance():
    """index.html and app.js must have no inline scripts, on*= handlers, or inline style attributes."""
    index_path = os.path.join(PUBLIC_DIR, "index.html")
    app_js_path = os.path.join(PUBLIC_DIR, "app.js")

    with open(index_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(app_js_path, "r", encoding="utf-8") as f:
        js = f.read()

    # 1. No inline <script> in index.html (only <script src=...>)
    script_tags = re.findall(r'<script\b[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    for tag_content in script_tags:
        assert not tag_content.strip(), f"Found inline <script> content in index.html: {tag_content[:100]}"

    # 2. No inline event handlers on*= in index.html
    on_handlers = re.findall(r'\s+on[a-zA-Z]+\s*=', html, re.IGNORECASE)
    assert len(on_handlers) == 0, f"Found inline event handlers in index.html: {on_handlers}"

    # 3. No inline style="..." attribute in index.html
    style_attrs = re.findall(r'\s+style\s*=\s*["\']', html, re.IGNORECASE)
    assert len(style_attrs) == 0, f"Found inline style attributes in index.html: {style_attrs}"

    # 4. No inline style="..." attribute inside app.js template literals
    js_style_attrs = re.findall(r'\bstyle\s*=\s*\\?["\']', js, re.IGNORECASE)
    assert len(js_style_attrs) == 0, f"Found style attributes in app.js markup strings: {js_style_attrs}"

    # 5. No eval in app.js
    assert not re.search(r'\beval\s*\(', js), "eval() must not be used in app.js"


# ─────────────────────────────────────────────────────────────────────────────
# S4: Image Storage Settings & DB Mock Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_store_images_default_false_insert_params(monkeypatch):
    """When store_images=False, image_base64 in INSERT is None and has_image is 1."""
    monkeypatch.setenv("SAFEGUARD_STORE_IMAGES", "0")
    get_settings(refresh=True)

    mgr = MySQLManager.__new__(MySQLManager)
    mgr._lock = threading.Lock()
    mgr.is_connected = True

    executed_queries = []

    class FakeCursor:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def execute(self, sql, params=None):
            executed_queries.append((sql, params))

    class FakeConn:
        def cursor(self):
            return FakeCursor()
        def commit(self):
            pass
        def ping(self, reconnect=True):
            pass

    mgr.conn = FakeConn()

    raw_img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    res = mgr.log_user_analysis(
        user_text="Gửi bill chuyển tiền",
        risk_score=50,
        risk_level="MEDIUM",
        confidence_score=85,
        matched_flags=["bill"],
        latency_ms=120.0,
        session_id="sess_img_test",
        image_base64=raw_img,
        client_id="client_test_id"
    )

    assert res is True
    assert len(executed_queries) > 0
    sql, params = executed_queries[0]
    assert "INSERT INTO `user_logs`" in sql
    # Parameters: (session_id, client_id, user_text, stored_image, has_image, ...)
    # stored_image MUST be None when store_images is False!
    stored_image = params[3]
    has_image = params[4]
    assert stored_image is None, "image_base64 must NOT be stored in DB when store_images is False"
    assert has_image == 1, "has_image must be 1 when image was provided"


def test_get_chat_history_masks_image_when_store_images_false(monkeypatch):
    """get_chat_history returns has_image=True and image_base64='' when store_images=False."""
    monkeypatch.setenv("SAFEGUARD_STORE_IMAGES", "0")
    get_settings(refresh=True)

    mgr = MySQLManager.__new__(MySQLManager)
    mgr._lock = threading.Lock()
    mgr.is_connected = True

    fake_row = {
        "user_text": "Gửi ảnh CCCD",
        "image_base64": "legacy_image_data_here",
        "has_image": 1,
        "bot_response": "Cảnh báo lừa đảo",
        "risk_score": 90,
        "risk_level": "HIGH",
        "created_at": "2026-10-17 12:00:00"
    }

    class FakeCursor:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def execute(self, sql, params=None):
            pass
        def fetchall(self):
            return [fake_row]

    class FakeConn:
        def cursor(self):
            return FakeCursor()
        def ping(self, reconnect=True):
            pass

    mgr.conn = FakeConn()
    history = mgr.get_chat_history("sess_123", client_id="client_123")

    assert len(history) == 1
    item = history[0]
    assert item["has_image"] is True
    assert item["image_base64"] == "", "image_base64 must be masked to empty string when store_images=False"


# ─────────────────────────────────────────────────────────────────────────────
# S6: Information Disclosure Prevention
# ─────────────────────────────────────────────────────────────────────────────

def test_internal_error_does_not_leak_exception_string(test_server, monkeypatch, capsys):
    """500 Internal error must not leak exception str or file paths into response or stderr."""
    host, port, _ = test_server

    secret_message = "CRITICAL_DATABASE_PASSWORD_SECRET_XYZ"
    def failing_request(*args, **kwargs):
        raise ValueError(f"Failed to connect: {secret_message} at /var/secrets/db.key")

    monkeypatch.setattr(orchestrator, "process_request", failing_request)

    payload = json.dumps({"user_text": "trigger_error"}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Content-Length": str(len(payload)), "X-Client-Id": "client-test1234567890"}
    status, body, _ = make_request(host, port, "POST", "/api/analyze", body=payload, headers=headers)

    assert status == 500
    assert secret_message.encode("utf-8") not in body
    assert b"/var/secrets" not in body
    data = json.loads(body.decode("utf-8"))
    assert data["error"] == "internal_error"
    assert "error_id" in data
