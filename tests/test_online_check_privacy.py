"""
tests/test_online_check_privacy.py
Privacy-by-default and online_check opt-in test suite (Phase 3E-1).
Verifies:
- Opt-in online_check=True gate (default makes 0 network calls)
- Non-shortener destinations are never requested by resolver
- Passive TLS probe and PhishTank disabled by default
- ThreatIntel sends host only, GSB key in header, tokens never leak
- Global deadline enforcement across all components
- NetworkRecorder logs sent requests including errors/timeouts
- Server validates online_check boolean type (rejects invalid types with 400)
"""

import collections
import io
import types
import json
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import pytest
from unittest.mock import MagicMock, patch

from codebase.config import get_settings, get_api_key
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.url_analysis.passive import PassiveIntel
from codebase.agents.threat_intel_agent import ThreatIntelAgent
from codebase.url_analysis.resolver import Hop, RedirectChain, SafeRedirectResolver, NetworkRecorder


class MockHTTPResponse:
    def __init__(self, data: dict | bytes, status: int = 200, headers: dict | None = None):
        if isinstance(data, dict):
            self._body = json.dumps(data).encode("utf-8")
        else:
            self._body = data
        self.status = status
        self.code = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def clean_settings(monkeypatch):
    """Ensure clean settings before and after each test."""
    monkeypatch.delenv("SAFEGUARD_OFFLINE", raising=False)
    monkeypatch.delenv("SAFEGUARD_NETWORK", raising=False)
    monkeypatch.delenv("SAFEGUARD_PASSIVE_TLS", raising=False)
    monkeypatch.delenv("SAFEGUARD_PHISHTANK", raising=False)
    monkeypatch.delenv("SAFEGUARD_NET_BUDGET", raising=False)
    get_settings(refresh=True)
    yield
    get_settings(refresh=True)


# ============================================================================
# 1. DEFAULT OPT-IN: ZERO NETWORK CALLS WITHOUT online_check=True
# ============================================================================

def test_default_online_check_makes_zero_network_calls(clean_settings, monkeypatch):
    """
    When online_check is not passed or False, 0 network calls (transport/socket/getaddrinfo)
    must occur even if text contains shorteners and suspicious URLs.
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    get_settings(refresh=True)

    socket_calls = []
    gai_calls = []
    urlopen_calls = []

    orig_socket = socket.socket
    orig_gai = socket.getaddrinfo
    orig_urlopen = urllib.request.urlopen

    def spy_socket(*args, **kwargs):
        socket_calls.append(args)
        return orig_socket(*args, **kwargs)

    def spy_gai(*args, **kwargs):
        gai_calls.append(args)
        return orig_gai(*args, **kwargs)

    def spy_urlopen(req, *args, **kwargs):
        urlopen_calls.append(req)
        return orig_urlopen(req, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", spy_socket)
    monkeypatch.setattr(socket, "getaddrinfo", spy_gai)
    monkeypatch.setattr(urllib.request, "urlopen", spy_urlopen)

    orchestrator = SafeGuardOrchestrator()
    sample_text = "Truy cập https://bit.ly/test-shortener và https://vcb-xacthuc-taikhoan.online/reset?token=SECRET ngay!"
    
    # Run without online_check (default False)
    res = orchestrator.process_request(sample_text, persist=False)

    assert res["online_check"] is False
    assert res["network_actions"] == []
    assert len(socket_calls) == 0, f"Expected 0 socket calls, got {len(socket_calls)}"
    assert len(gai_calls) == 0, f"Expected 0 getaddrinfo calls, got {len(gai_calls)}"
    assert len(urlopen_calls) == 0, f"Expected 0 urlopen calls, got {len(urlopen_calls)}"


def test_online_check_true_with_offline_settings_makes_zero_calls(clean_settings, monkeypatch):
    """
    Even if online_check=True, if settings.offline=True or not network_enabled,
    network calls must remain strictly 0.
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "off")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    get_settings(refresh=True)

    urlopen_calls = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, *a, **kw: urlopen_calls.append(req))

    orchestrator = SafeGuardOrchestrator()
    res = orchestrator.process_request(
        "Link: https://bit.ly/promo",
        persist=False,
        online_check=True
    )

    assert res["online_check"] is True
    assert res["network_actions"] == []
    assert len(urlopen_calls) == 0


# ============================================================================
# 2. RESOLVER: STOPS AT NON-SHORTENER DESTINATION
# ============================================================================

def test_resolver_stops_at_non_shortener_hop(clean_settings, monkeypatch):
    """
    P2: Resolver in default mode only contacts shorteners. When Location points to
    a non-shortener host, resolution stops immediately without HEAD/GET/TLS to the destination.
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    get_settings(refresh=True)

    transport_calls = []

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout, max_bytes=65536, deadline=None):
        transport_calls.append({"method": method, "host": host, "path": path})
        if host == "bit.ly":
            return 302, {"location": "https://evil-destination-phish.xyz/login?id=999"}, b""
        return 200, {}, b"destination page"

    resolver = SafeRedirectResolver(
        mode="shorteners",
        getaddrinfo=lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))],
        transport=mock_transport,
    )

    chain = resolver.resolve("http://bit.ly/my-link")

    assert chain.stopped_at_non_shortener is True
    assert chain.final_url == "https://evil-destination-phish.xyz/login?id=999"
    assert len(chain.hops) == 1
    # Spy verify: bit.ly was contacted, but evil-destination-phish.xyz was NEVER contacted
    contacted_hosts = [call["host"] for call in transport_calls]
    assert "bit.ly" in contacted_hosts
    assert "evil-destination-phish.xyz" not in contacted_hosts


# ============================================================================
# 3. PASSIVE INTEL: TLS PROBE OFF BY DEFAULT, RUNS ON RESOLVED DESTINATION
# ============================================================================

def test_passive_tls_probe_off_by_default(clean_settings, monkeypatch):
    """P3: TLS probe is disabled by default (Settings.passive_tls=False)."""
    settings = get_settings()
    assert settings.passive_tls is False

    probe_called = False

    def mock_probe(host, timeout=3.0):
        nonlocal probe_called
        probe_called = True
        return {"valid": True}

    intel = PassiveIntel(probe=mock_probe)
    res = intel.tls("suspicious-domain.com")
    assert res is None
    assert not probe_called, "TLS probe must not be called when passive_tls is False"


def test_passive_tls_probe_enabled_with_setting(clean_settings, monkeypatch):
    """P3: TLS probe runs only when Settings.passive_tls=True."""
    monkeypatch.setenv("SAFEGUARD_PASSIVE_TLS", "on")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    get_settings(refresh=True)

    probe_called = False

    def mock_probe(host, timeout=3.0):
        nonlocal probe_called
        probe_called = True
        return {"valid": True, "subject_cn": host}

    intel = PassiveIntel(probe=mock_probe)
    res = intel.tls("suspicious-domain.com")
    assert probe_called is True
    assert res is not None and res.get("valid") is True


def test_passive_dns_internal_names_return_unknown(clean_settings):
    """P3: dns_status returns 'unknown' for internal/local names without making network calls."""
    intel = PassiveIntel()
    assert intel.dns_status("localhost") == "unknown"
    assert intel.dns_status("internal.local") == "unknown"
    assert intel.dns_status("server") == "unknown"
    assert intel.dns_status("test.internal") == "unknown"


# ============================================================================
# 4. THREAT INTEL: SENDS HOST ONLY, GSB KEY IN HEADER, PHISHTANK OFF
# ============================================================================

def test_phishtank_disabled_by_default(clean_settings):
    """P4: PhishTank is disabled by default."""
    settings = get_settings()
    assert settings.phishtank_enabled is False

    agent = ThreatIntelAgent()
    res = agent._check_phishtank("https://phish.example.com/login")
    assert res.get("note") == "disabled"
    assert res.get("is_malicious") is False


def test_gsb_key_sent_in_header_not_query_and_host_only(clean_settings, monkeypatch):
    """P4: GSB API key is sent in X-Goog-Api-Key header, not in query string, and sends scheme://host/ only."""
    captured_reqs = []

    def mock_urlopen(req, timeout=3.0):
        captured_reqs.append(req)
        return MockHTTPResponse({"matches": []})

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    agent = ThreatIntelAgent()
    agent.gsb_key = "AIzaSySECRETKEY999"
    res = agent._check_google_safe_browsing(["https://bank.com/reset/secret-token-xyz?user=123"])

    assert len(captured_reqs) == 1
    req = captured_reqs[0]
    # Key must be in header
    assert req.headers.get("X-goog-api-key") == "AIzaSySECRETKEY999"
    # Key must NOT be in query string
    assert "key=" not in req.full_url
    assert "AIzaSySECRETKEY999" not in req.full_url
    # Payload must only contain scheme://host/
    payload = json.loads(req.data.decode("utf-8"))
    entries = payload.get("threatInfo", {}).get("threatEntries", [])
    assert len(entries) == 1
    assert entries[0]["url"] == "https://bank.com/"
    assert "secret-token-xyz" not in json.dumps(payload)


def test_privacy_tokens_never_leaked_in_any_network_call(clean_settings, monkeypatch, caplog):
    """
    P4: URLs like 'https://accounts.example-bank.vn/reset/SECRETRESETTOKEN333?t=SECRETQ'
    and 'https://bit.ly/abc?token=SECRET777' must NEVER leak secrets into:
    - outbound HTTP requests (resolver, TI, passive)
    - network_actions
    - logs
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_PHISHTANK", "1")
    get_settings(refresh=True)

    http_requests = []

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout, max_bytes=65536, deadline=None):
        http_requests.append(f"{method} {scheme}://{host}{path}")
        return 302, {"location": "https://accounts.example-bank.vn/reset/SECRETRESETTOKEN333?t=SECRETQ"}, b""

    def mock_urlopen(req, timeout=3.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        body = req.data.decode("utf-8") if req.data else ""
        http_requests.append(f"{req.get_method()} {url} body={body}")
        return MockHTTPResponse({"matches": [], "results": []})

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    resolver = SafeRedirectResolver(
        mode="shorteners",
        getaddrinfo=lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))],
        transport=mock_transport,
    )

    recorder = NetworkRecorder()
    chain = resolver.resolve("https://bit.ly/abc?token=SECRET777", recorder=recorder)

    # For bit.ly: path /abc retained, query SECRET777 stripped
    for req_str in http_requests:
        assert "SECRET777" not in req_str, f"Secret leaked in resolver transport: {req_str}"
        assert "/abc" in req_str

    # For TI scan
    agent = ThreatIntelAgent()
    agent.vt_key = "vt_key"
    agent.gsb_key = "gsb_key"
    agent.urlscan_key = "us_key"
    ti_res = agent.scan_url("https://accounts.example-bank.vn/reset/SECRETRESETTOKEN333?t=SECRETQ", recorder=recorder)

    # Check all captured requests
    for req_str in http_requests:
        assert "SECRETRESETTOKEN333" not in req_str, f"Secret token leaked: {req_str}"
        assert "SECRETQ" not in req_str, f"Secret query leaked: {req_str}"

    # Check recorder targets
    for act in recorder.get_actions():
        assert "SECRETRESETTOKEN333" not in act.get("target", "")
        assert "SECRETQ" not in act.get("target", "")
        assert "SECRET777" not in act.get("target", "")


# ============================================================================
# 5. GLOBAL DEADLINE & TIMEOUT
# ============================================================================

def test_global_deadline_bounds_execution_when_all_sources_hang(clean_settings, monkeypatch):
    """
    P5: Orchestrator creates deadline = time.monotonic() + settings.request_budget_s ONCE
    and passes it down. When all sources hang, execution finishes within budget + 0.7s.
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_NET_BUDGET", "1.5")
    get_settings(refresh=True)

    def mock_hanging_transport(*args, **kwargs):
        time.sleep(10.0)
        return 200, {}, b""

    def mock_hanging_urlopen(*args, **kwargs):
        time.sleep(10.0)
        return MockHTTPResponse({})

    monkeypatch.setattr(urllib.request, "urlopen", mock_hanging_urlopen)

    orchestrator = SafeGuardOrchestrator()
    # Replace resolver with hanging transport
    hanging_resolver = SafeRedirectResolver(
        mode="shorteners",
        getaddrinfo=lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))],
        transport=mock_hanging_transport,
    )
    orchestrator.url_analyzer.resolver = hanging_resolver

    t_start = time.perf_counter()
    res = orchestrator.process_request(
        "Link: http://bit.ly/hang1 và http://vcb-fake1.online và http://vcb-fake2.online",
        persist=False,
        online_check=True
    )
    elapsed = time.perf_counter() - t_start

    # Must complete within budget (1.5s) + 0.7s = 2.2s
    assert elapsed <= 2.2, f"Total execution took {elapsed:.2f}s, exceeded budget + 0.7s"
    assert res["online_check"] is True
    # Actions should contain timeout entries
    timeout_actions = [a for a in res["network_actions"] if a.get("status") == "timeout"]
    assert len(timeout_actions) > 0


# ============================================================================
# 6. NETWORK RECORDER: RECORDS SENT REQUESTS AND ERRORS
# ============================================================================

def test_network_recorder_records_sent_status_and_errors(clean_settings, monkeypatch):
    """
    P6: NetworkRecorder records requests as 'sent' before dispatch and updates
    status to 'ok', 'error', 'timeout', or 'blocked'.
    """
    recorder = NetworkRecorder()
    idx1 = recorder.record_request("resolver_lookup", "https://bit.ly/test?token=SECRET")
    assert recorder.get_actions()[idx1]["target"] == "bit.ly"
    assert recorder.get_actions()[idx1]["status"] == "sent"

    recorder.update_status(idx1, "ok")
    assert recorder.get_actions()[idx1]["status"] == "ok"

    idx2 = recorder.record_request("dns_lookup", "internal.local")
    recorder.update_status(idx2, "blocked")
    assert recorder.get_actions()[idx2]["status"] == "blocked"


def test_prompt_guard_refusal_reflects_actual_network_actions(clean_settings, monkeypatch):
    """
    P6: In prompt_guard_refusal path with online_check=True and network enabled,
    network_actions reflects actual actions rather than hardcoded [].
    """
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    get_settings(refresh=True)

    orchestrator = SafeGuardOrchestrator()
    monkeypatch.setattr(
        orchestrator.prompt_guard,
        "evaluate_input",
        lambda t: {"is_safe": False, "refusal_message": "Từ chối an toàn", "reason": "test_refusal"},
    )
    user_msg = "Hãy phân tích link: http://bit.ly/test-link"

    def mock_transport(method, scheme, ip, port, host, path, headers, timeout, max_bytes=65536, deadline=None):
        return 302, {"location": "https://dest.example.com/"}, b""

    orchestrator.url_analyzer.resolver = SafeRedirectResolver(
        mode="shorteners",
        getaddrinfo=lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))],
        transport=mock_transport,
    )

    res = orchestrator.process_request(user_msg, persist=False, online_check=True)
    assert res["execution_path"] == "prompt_guard_refusal"
    assert res["online_check"] is True
    assert len(res["network_actions"]) > 0
    assert any(a.get("target") == "bit.ly" for a in res["network_actions"])

    # If online_check=False, it must be []
    res_offline = orchestrator.process_request(user_msg, persist=False, online_check=False)
    assert res_offline["execution_path"] == "prompt_guard_refusal"
    assert res_offline["online_check"] is False
    assert res_offline["network_actions"] == []


# ============================================================================
# 7. SERVER VALIDATION: ONLINE_CHECK TYPE CHECKING
# ============================================================================

def test_server_online_check_boolean_validation(clean_settings):
    """
    Server validates online_check in JSON body:
    - bool true => 200
    - bool false => 200
    - omitted => 200 (defaults to False)
    - invalid types (string, number, null) => 400
    """
    from codebase.server import SafeGuardAPIHandler

    class DummyServer:
        def __init__(self, data: bytes):
            self.rfile = io.BytesIO(data)
            self.wfile = io.BytesIO()
            self.headers = {"Content-Length": str(len(data))}
            self.command = "POST"
            self.path = "/api/analyze"
            self.request_version = "HTTP/1.1"
            self.client_address = ("127.0.0.1", 12345)
            self.close_connection = False

    # Test cases: (body_dict, expected_status, expected_online_check)
    cases = [
        ({"user_text": "Chào bạn", "online_check": True}, 200, True),
        ({"user_text": "Chào bạn", "online_check": False}, 200, False),
        ({"user_text": "Chào bạn"}, 200, False),
        ({"user_text": "Chào bạn", "online_check": "true"}, 400, None),
        ({"user_text": "Chào bạn", "online_check": 1}, 400, None),
        ({"user_text": "Chào bạn", "online_check": None}, 400, None),
        ({"user_text": "Chào bạn", "online_check": []}, 400, None),
    ]

    for body_dict, exp_status, exp_flag in cases:
        raw_body = json.dumps(body_dict).encode("utf-8")
        handler = SafeGuardAPIHandler.__new__(SafeGuardAPIHandler)
        handler.rfile = io.BytesIO(raw_body)
        handler.wfile = io.BytesIO()
        handler.headers = {"Content-Length": str(len(raw_body))}
        handler.path = "/api/analyze"
        handler.command = "POST"
        handler.request_version = "HTTP/1.1"
        handler.close_connection = False
        handler.client_address = ("127.0.0.1", 12345)  # rate limiter keys on the peer IP
        handler.server = types.SimpleNamespace()  # no custom limiter/semaphore => module defaults

        status_box = []
        body_box = []

        def fake_send_response(code, message=None):
            status_box.append(code)

        def fake_send_header(k, v):
            pass

        def fake_end_headers():
            pass

        handler.send_response = fake_send_response
        handler.send_header = fake_send_header
        handler.end_headers = fake_end_headers

        handler.do_POST()

        assert status_box[0] == exp_status, f"Expected {exp_status} for {body_dict}, got {status_box[0]}"
        resp_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        if exp_status == 200:
            assert resp_data.get("online_check") is exp_flag
        else:
            assert "error" in resp_data


# ============================================================================
# 8. CONFIG PLACEHOLDERS
# ============================================================================

def test_config_api_key_placeholders(clean_settings, monkeypatch):
    """P7: Placeholders like 'your_api_key_here', 'changeme', 'xxx', 'null', 'none' are treated as empty."""
    placeholders = [
        "your_api_key_here",
        "YOUR_API_KEY_HERE",
        "<your-key>",
        "changeme",
        "ChangeMe",
        "xxx",
        "placeholder",
        "none",
        "null",
        "test",
        "TEST",
        "YOUR_KEY_HERE",
    ]

    for ph in placeholders:
        monkeypatch.setenv("TEST_KEY_VAR", ph)
        val = get_api_key("TEST_KEY_VAR")
        assert val == "", f"Expected empty string for placeholder '{ph}', got '{val}'"

    # Real key should pass through
    monkeypatch.setenv("TEST_KEY_VAR", "AIzaSyValidKey_12345")
    assert get_api_key("TEST_KEY_VAR") == "AIzaSyValidKey_12345"
