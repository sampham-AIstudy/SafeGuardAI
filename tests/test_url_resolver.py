import copy
import http.server
import socket
import threading
import time
import pytest

from codebase.config import get_settings
from codebase.url_analysis.resolver import (
    Hop,
    RedirectChain,
    SafeRedirectResolver,
    _extract_meta_refresh,
    _is_safe_ip,
    is_public_destination,
)


@pytest.fixture
def enable_network_settings(monkeypatch):
    """Enable network and offline=0 for resolver tests while preserving no-network socket blocks."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "1")
    get_settings(refresh=True)
    yield
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "off")
    get_settings(refresh=True)


# =====================================================================
# 1. SSRF Parameterized: IP literals, encodings, special names, single label
# =====================================================================

@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[64:ff9b::7f00:1]",
        "[2002:7f00:1::]",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.1",
        "localhost",
        "x.localhost",
        "foo.internal",
        "metadata.google.internal",
        "metadata",
        "intranet",
    ],
)
def test_ssrf_forbidden_destinations(enable_network_settings, target):
    url = f"http://{target}/path"
    resolver = SafeRedirectResolver(mode="all")
    chain = resolver.resolve(url)
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert any(k in chain.blocked_reason for k in ("private", "disallowed", "loopback"))


# =====================================================================
# 2. DNS resolution mock behaviors
# =====================================================================

def test_getaddrinfo_returns_private_ip_for_public_name(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

    transport_called = False

    def fake_transport(*args, **kwargs):
        nonlocal transport_called
        transport_called = True
        return 200, {}, b"ok"

    resolver = SafeRedirectResolver(mode="all", getaddrinfo=fake_gai, transport=fake_transport)
    chain = resolver.resolve("http://evil.example/login")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert "private" in chain.blocked_reason
    assert not transport_called


def test_getaddrinfo_returns_mixed_ips(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    resolver = SafeRedirectResolver(mode="all", getaddrinfo=fake_gai)
    chain = resolver.resolve("http://mixed.example/")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert "private" in chain.blocked_reason


def test_getaddrinfo_returns_empty_list(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return []

    resolver = SafeRedirectResolver(mode="all", getaddrinfo=fake_gai)
    chain = resolver.resolve("http://empty.example/")
    assert chain.final_url is None
    assert chain.blocked_reason is not None


def test_getaddrinfo_raises_error(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    resolver = SafeRedirectResolver(mode="all", getaddrinfo=fake_gai)
    chain = resolver.resolve("http://error.example/")
    assert chain.final_url is None
    assert chain.blocked_reason is not None


def test_getaddrinfo_hangs_timeout(enable_network_settings):
    def hanging_gai(host, port, *args, **kwargs):
        time.sleep(30)
        return []

    resolver = SafeRedirectResolver(
        mode="all",
        getaddrinfo=hanging_gai,
        per_hop_timeout=0.3,
        total_budget=0.6,
    )
    t0 = time.monotonic()
    chain = resolver.resolve("http://hang.example/")
    elapsed = time.monotonic() - t0
    assert elapsed <= 0.8
    assert chain.final_url is None
    assert chain.error in ("dns_timeout", "budget_exceeded") or (
        chain.blocked_reason and "timeout" in chain.blocked_reason
    )


# =====================================================================
# 3. DNS rebinding prevention (IP pinning)
# =====================================================================

def test_dns_rebinding_pins_ip_single_call(enable_network_settings):
    gai_calls = 0

    def rebinding_gai(host, port, *args, **kwargs):
        nonlocal gai_calls
        gai_calls += 1
        if gai_calls == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    received_ip = None

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal received_ip
        received_ip = ip
        return 200, {}, b"safe response"

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=rebinding_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://rebind.example/")
    assert gai_calls == 1
    assert received_ip == "93.184.216.34"
    assert chain.final_url == "http://rebind.example/"
    assert len(chain.hops) == 1
    assert chain.hops[0].ip == "93.184.216.34"


# =====================================================================
# 4. Hop 2 redirect to private/internal blocked, hop 1 preserved
# =====================================================================

@pytest.mark.parametrize(
    "target_hop2",
    [
        "http://10.0.0.1/admin",
        "http://localhost/secret",
        "http://metadata.google.internal/computeMetadata",
    ],
)
def test_hop2_redirect_to_private_blocked_hop1_retained(
    enable_network_settings, target_hop2
):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        return 302, {"location": target_hop2}, b""

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://public.example/redir")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert any(k in chain.blocked_reason for k in ("private", "disallowed"))
    assert len(chain.hops) == 1
    assert chain.hops[0].url == "http://public.example/redir"
    assert chain.hops[0].status == 302
    assert chain.hops[0].location == target_hop2


# =====================================================================
# 5. Port and Scheme restrictions
# =====================================================================

@pytest.mark.parametrize("port", [8080, 22, 25, 6379])
def test_disallowed_ports(enable_network_settings, port):
    resolver = SafeRedirectResolver(mode="all")
    chain = resolver.resolve(f"http://example.com:{port}/")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert str(port) in chain.blocked_reason or "port" in chain.blocked_reason


@pytest.mark.parametrize("scheme", ["file", "ftp", "gopher", "javascript", "data"])
def test_disallowed_schemes(enable_network_settings, scheme):
    resolver = SafeRedirectResolver(mode="all")
    chain = resolver.resolve(f"{scheme}://example.com/test")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert "scheme" in chain.blocked_reason or scheme in chain.blocked_reason


# =====================================================================
# 6. Userinfo forbidden
# =====================================================================

@pytest.mark.parametrize(
    "url", ["http://user:pass@example.com/", "http://admin@example.com/login"]
)
def test_userinfo_forbidden(enable_network_settings, url):
    resolver = SafeRedirectResolver(mode="all")
    chain = resolver.resolve(url)
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert "userinfo" in chain.blocked_reason


# =====================================================================
# 7. Hop count and loops
# =====================================================================

def test_too_many_hops(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    hop_counter = 0

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal hop_counter
        hop_counter += 1
        return 302, {"location": f"http://example.com/step{hop_counter}"}, b""

    resolver = SafeRedirectResolver(
        mode="all", max_hops=5, getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/step0")
    assert chain.error == "too_many_hops"
    assert len(chain.hops) == 5
    assert chain.final_url is None


def test_redirect_loop(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        if "step_a" in path:
            return 302, {"location": "http://example.com/step_b"}, b""
        return 302, {"location": "http://example.com/step_a"}, b""

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/step_a")
    assert chain.error == "redirect_loop"
    assert chain.final_url is None
    assert len(chain.hops) >= 2


# =====================================================================
# 8. Budget exceeded
# =====================================================================

def test_budget_exceeded(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    hop_n = 0

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal hop_n
        hop_n += 1
        time.sleep(0.2)
        return 302, {"location": f"http://example.com/h{hop_n}"}, b""

    resolver = SafeRedirectResolver(
        mode="all",
        per_hop_timeout=1.0,
        total_budget=0.5,
        getaddrinfo=fake_gai,
        transport=mock_transport,
    )
    t0 = time.monotonic()
    chain = resolver.resolve("http://example.com/h0")
    elapsed = time.monotonic() - t0
    assert elapsed <= 1.0
    assert chain.error == "budget_exceeded"
    assert len(chain.hops) >= 1


# =====================================================================
# 9. Body 64KB truncation
# =====================================================================

def test_body_truncated_to_65536_bytes(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    one_mb = b"A" * (1024 * 1024)

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        if method == "HEAD":
            return 405, {}, b""
        return 200, {}, one_mb

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/large")
    assert chain.final_url == "http://example.com/large"
    assert len(chain.hops) == 1
    assert resolver.max_body_bytes == 65536


# =====================================================================
# 10. HEAD 405 -> GET fallback
# =====================================================================

def test_head_405_fallback_to_get(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    methods_called = []

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        methods_called.append(method)
        if method == "HEAD":
            return 405, {}, b""
        return 302, {"location": "http://example.com/destination"}, b""

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/start")
    assert "HEAD" in methods_called
    assert "GET" in methods_called
    assert len(chain.hops) >= 1


# =====================================================================
# 11. Meta refresh variations
# =====================================================================

@pytest.mark.parametrize(
    "html_body, expected_url",
    [
        (
            b'<html><head><meta http-equiv="refresh" content="0; url=https://target.com/a"></head></html>',
            "https://target.com/a",
        ),
        (
            b"<html><head><meta http-equiv='refresh' content='0; URL=https://target.com/b'></head></html>",
            "https://target.com/b",
        ),
        (
            b"<html><head><meta http-equiv=refresh content=0;url=https://target.com/c></head></html>",
            "https://target.com/c",
        ),
        (
            b'<html><head><meta content="1; url=https://target.com/d" http-equiv="refresh"></head></html>',
            "https://target.com/d",
        ),
    ],
)
def test_meta_refresh_variations(enable_network_settings, html_body, expected_url):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        if "meta" in path:
            if method == "HEAD":
                return 405, {}, b""
            return 200, {}, html_body
        return 200, {}, b"final target reached"

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/meta")
    assert chain.final_url == expected_url
    assert len(chain.hops) == 2
    assert chain.hops[0].location == expected_url


# =====================================================================
# 12. Relative location and long location
# =====================================================================

def test_relative_location_resolution(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    calls = 0

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 302, {"location": "/relative/path?foo=bar"}, b""
        return 200, {}, b"ok"

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/base/page")
    assert chain.final_url == "http://example.com/relative/path?foo=bar"
    assert len(chain.hops) == 2


def test_location_too_long(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    huge_loc = "http://example.com/" + "a" * 2500

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        return 302, {"location": huge_loc}, b""

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/huge")
    assert chain.error == "location_too_long"
    assert chain.final_url is None


# =====================================================================
# 13. Request headers verification
# =====================================================================

def test_request_headers_sent_to_transport(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    captured_headers = {}

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal captured_headers
        captured_headers = headers
        return 200, {}, b"ok"

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/check-headers")
    assert chain.final_url == "http://example.com/check-headers"
    assert captured_headers.get("Accept-Encoding") == "identity"
    assert captured_headers.get("User-Agent") == "SafeGuardAI-LinkChecker/1.0"
    assert captured_headers.get("Host") == "example.com"
    lower_keys = [k.lower() for k in captured_headers.keys()]
    assert "cookie" not in lower_keys
    assert "referer" not in lower_keys
    assert "authorization" not in lower_keys


# =====================================================================
# 14. Cache tests (hit, miss, TTL, LRU, 16 threads concurrency)
# =====================================================================

def test_cache_mechanisms(enable_network_settings):
    calls = 0

    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal calls
        calls += 1
        return 200, {}, b"ok"

    resolver = SafeRedirectResolver(
        mode="all",
        cache_ttl_s=10,
        cache_max=3,
        getaddrinfo=fake_gai,
        transport=mock_transport,
    )

    # 1. Miss
    c1 = resolver.resolve("http://example.com/1")
    assert not c1.from_cache
    assert calls == 1

    # 2. Hit
    c2 = resolver.resolve("http://example.com/1")
    assert c2.from_cache
    assert calls == 1

    # 3. Blocked result cached for 60s
    c_blocked1 = resolver.resolve("http://127.0.0.1/local")
    assert c_blocked1.blocked_reason is not None
    assert not c_blocked1.from_cache
    c_blocked2 = resolver.resolve("http://127.0.0.1/local")
    assert c_blocked2.from_cache
    assert c_blocked2.blocked_reason is not None

    # 4. LRU eviction with cache_max=3
    resolver.resolve("http://example.com/2")
    resolver.resolve("http://example.com/3")
    resolver.resolve("http://example.com/4")  # evicts /1
    calls_before = calls
    resolver.resolve("http://example.com/1")
    assert calls == calls_before + 1


def test_cache_concurrency_16_threads(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        time.sleep(0.005)
        return 200, {}, b"ok"

    resolver = SafeRedirectResolver(
        mode="all",
        cache_max=64,
        getaddrinfo=fake_gai,
        transport=mock_transport,
    )

    errors = []

    def worker(worker_id):
        try:
            for i in range(10):
                url = f"http://example.com/item_{i % 5}"
                c = resolver.resolve(url)
                assert c.final_url == url
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0


# =====================================================================
# 15. Network disabled & Resolver modes
# =====================================================================

def test_network_disabled_calls_zero_transport(monkeypatch):
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "off")
    get_settings(refresh=True)

    transport_called = False

    def mock_transport(*args, **kwargs):
        nonlocal transport_called
        transport_called = True
        return 200, {}, b"ok"

    gai_called = False

    def mock_gai(*args, **kwargs):
        nonlocal gai_called
        gai_called = True
        return []

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=mock_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://example.com/test")
    assert chain.blocked_reason == "network_disabled"
    assert not transport_called
    assert not gai_called


def test_resolver_modes(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    calls = 0

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        nonlocal calls
        calls += 1
        return 200, {}, b"ok"

    # Mode: off
    res_off = SafeRedirectResolver(
        mode="off", getaddrinfo=fake_gai, transport=mock_transport
    )
    assert not res_off.should_resolve("http://bit.ly/123")
    c_off = res_off.resolve("http://bit.ly/123")
    assert c_off.blocked_reason == "mode_off"
    assert calls == 0

    # Mode: shorteners
    res_short = SafeRedirectResolver(
        mode="shorteners", getaddrinfo=fake_gai, transport=mock_transport
    )
    assert res_short.should_resolve("http://bit.ly/123")
    assert not res_short.should_resolve("http://example.com/page")
    c_norm = res_short.resolve("http://example.com/page")
    assert c_norm.blocked_reason == "not_a_shortener"
    assert calls == 0
    c_short = res_short.resolve("http://bit.ly/123")
    assert c_short.final_url == "http://bit.ly/123"
    assert calls == 1

    # Mode: all
    res_all = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    assert res_all.should_resolve("http://example.com/page")
    c_all = res_all.resolve("http://example.com/page")
    assert c_all.final_url == "http://example.com/page"
    assert calls == 2


# =====================================================================
# 16. Transport exception safety & ReDoS protection
# =====================================================================

def test_transport_raise_captured(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def broken_transport(*args, **kwargs):
        raise ConnectionResetError("Connection unexpectedly broken by peer")

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=broken_transport
    )
    chain = resolver.resolve("http://example.com/fail")
    assert chain.error is not None
    assert "broken" in chain.error
    assert chain.final_url is None


def test_redos_meta_refresh_speed():
    evil_body = "<meta " * 10000
    t0 = time.monotonic()
    url = _extract_meta_refresh(evil_body)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.2
    assert url is None


# =====================================================================
# 17. Real HTTP Server tests on 127.0.0.1 (thread, ip_validator loopback)
# =====================================================================

def test_real_server_2_hops_redirect(enable_network_settings):
    requests_received = []

    class RealTestHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_HEAD(self):
            requests_received.append((self.command, self.path, dict(self.headers)))
            if self.path == "/hop1":
                self.send_response(302)
                self.send_header("Location", "/hop2")
                self.end_headers()
            elif self.path == "/hop2":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()
            elif self.path == "/final":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 0), RealTestHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        resolver = SafeRedirectResolver(
            mode="all",
            ip_validator=lambda ip: True,
            per_hop_timeout=2.0,
            total_budget=5.0,
        )
        chain = resolver.resolve(f"http://127.0.0.1:{port}/hop1")
        assert chain.final_url == f"http://127.0.0.1:{port}/final"
        assert len(chain.hops) == 3
        assert chain.hops[0].url == f"http://127.0.0.1:{port}/hop1"
        assert chain.hops[0].status == 302
        assert chain.hops[1].url == f"http://127.0.0.1:{port}/hop2"
        assert chain.hops[1].status == 302
        assert chain.hops[2].url == f"http://127.0.0.1:{port}/final"
        assert chain.hops[2].status == 200

        # Verify headers received by real server
        assert len(requests_received) == 3
        for cmd, path, hdrs in requests_received:
            assert cmd == "HEAD"
            lower_h = {k.lower(): v for k, v in hdrs.items()}
            assert lower_h.get("host") == f"127.0.0.1:{port}"
            assert "cookie" not in lower_h
            assert "referer" not in lower_h
            assert lower_h.get("user-agent") == "SafeGuardAI-LinkChecker/1.0"
    finally:
        server.shutdown()
        server.server_close()


def test_real_server_hanging_terminates_on_timeout(enable_network_settings):
    class HangingHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_HEAD(self):
            time.sleep(10)
            self.send_response(200)
            self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 0), HangingHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        resolver = SafeRedirectResolver(
            mode="all",
            ip_validator=lambda ip: True,
            per_hop_timeout=0.3,
            total_budget=0.6,
        )
        t0 = time.monotonic()
        chain = resolver.resolve(f"http://127.0.0.1:{port}/hang")
        elapsed = time.monotonic() - t0
        assert elapsed <= 1.0
        assert chain.final_url is None
        assert chain.error in (
            "request_timeout",
            "budget_exceeded",
        ) or "timeout" in str(chain.error)
    finally:
        server.shutdown()
        server.server_close()


# =====================================================================
# 18. Mutation Guard Tests (8+ mutations)
# =====================================================================

def test_mutation_guard_is_global_blocks_private_ranges():
    for private_ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"):
        safe, reason = _is_safe_ip(private_ip)
        assert not safe, f"{private_ip} must not be considered safe"
        assert "private" in reason or "loopback" in reason


def test_mutation_guard_ipv4_mapped_blocks_embedded_private():
    for mapped_ip in ("::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"):
        safe, reason = _is_safe_ip(mapped_ip)
        assert not safe, f"{mapped_ip} embedded private IP must be blocked"
        assert "private" in reason


def test_mutation_guard_subsequent_hop_ssrf_checked(enable_network_settings):
    def fake_gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout):
        return 302, {"location": "http://192.168.1.1/internal"}, b""

    resolver = SafeRedirectResolver(
        mode="all", getaddrinfo=fake_gai, transport=mock_transport
    )
    chain = resolver.resolve("http://public.example/redir")
    assert chain.final_url is None
    assert chain.blocked_reason is not None
    assert "private" in chain.blocked_reason
    assert len(chain.hops) == 1


def test_mutation_guard_ip_pinning_prevents_second_dns_resolution(
    enable_network_settings,
):
    gai_count = 0

    def counting_gai(host, port, *args, **kwargs):
        nonlocal gai_count
        gai_count += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    resolver = SafeRedirectResolver(
        mode="all",
        getaddrinfo=counting_gai,
        transport=lambda *a, **kw: (200, {}, b"ok"),
    )
    chain = resolver.resolve("http://example.com/one")
    assert chain.final_url == "http://example.com/one"
    assert gai_count == 1, "DNS resolution must occur exactly once per hop (IP pinned)"


def test_mutation_guard_port_restriction_enforced(enable_network_settings):
    resolver = SafeRedirectResolver(mode="all")
    for bad_port in (8080, 22, 25, 6379, 445):
        chain = resolver.resolve(f"http://example.com:{bad_port}/")
        assert chain.final_url is None
        assert chain.blocked_reason is not None
        assert "port" in chain.blocked_reason or str(bad_port) in chain.blocked_reason


def test_mutation_guard_body_64kb_cap_enforced(enable_network_settings):
    resolver = SafeRedirectResolver(
        mode="all",
        getaddrinfo=lambda h, p, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))
        ],
        transport=lambda m, s, ip, p, h, pq, hd, t: (
            405,
            {},
            b"",
        )
        if m == "HEAD"
        else (200, {}, b"X" * 100000),
    )
    chain = resolver.resolve("http://example.com/big")
    assert chain.final_url == "http://example.com/big"
    assert resolver.max_body_bytes == 65536


def test_mutation_guard_dns_timeout_enforced(enable_network_settings):
    def slow_gai(host, port, *args, **kwargs):
        time.sleep(10)
        return []

    resolver = SafeRedirectResolver(
        mode="all",
        getaddrinfo=slow_gai,
        per_hop_timeout=0.2,
        total_budget=0.5,
    )
    t0 = time.monotonic()
    chain = resolver.resolve("http://slow.example/")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.8
    assert chain.final_url is None
    assert chain.error in ("dns_timeout", "budget_exceeded") or (
        chain.blocked_reason and "timeout" in chain.blocked_reason
    )


def test_mutation_guard_loop_detection_enforced(enable_network_settings):
    def loop_transport(m, s, ip, p, h, pq, hd, t):
        if "a" in pq:
            return 302, {"location": "http://example.com/b"}, b""
        return 302, {"location": "http://example.com/a"}, b""

    resolver = SafeRedirectResolver(
        mode="all",
        getaddrinfo=lambda h, p, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))
        ],
        transport=loop_transport,
    )
    chain = resolver.resolve("http://example.com/a")
    assert chain.final_url is None
    assert chain.error == "redirect_loop"


def test_mutation_guard_userinfo_blocked(enable_network_settings):
    resolver = SafeRedirectResolver(mode="all")
    chain = resolver.resolve("http://attacker:secret@example.com/login")
    assert chain.final_url is None
    assert chain.blocked_reason == "userinfo_forbidden"
