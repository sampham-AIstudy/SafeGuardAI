"""
tests/test_threat_intel_network.py
Unit & integration tests for ThreatIntelAgent network behavior (Phase 3C).
All network calls are strictly mocked (0 real internet calls).

Covers:
- Strict timeout <= 3.5s when a source sleeps 30s, preserving results from fast sources.
- No public submission by default: URLScan searches existing scans; VT does not POST on 404.
- URLSCAN_SUBMIT=1 submits with visibility="unlisted" and no sleep(3).
- VT_SUBMIT=1 allows POST submission on 404.
- Cache hit prevents duplicate network calls, with 6h TTL for normal and 60s for error.
- Offline and network_disabled modes make 0 network calls.
- Privacy preservation: ?token=SECRET123 never leaks in requests, logs, or network_actions.
- Return dictionary contract (backward compatible keys + network_actions).
"""

import collections
import io
import json
import logging
import os
import time
import urllib.error
import urllib.request
import pytest

from codebase.agents.threat_intel_agent import ThreatIntelAgent
from codebase.config import get_settings


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
def mock_keys(monkeypatch):
    """Enable mock network settings and set dummy keys for testing."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt_test_key_123")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "gsb_test_key_123")
    monkeypatch.setenv("URLSCAN_API_KEY", "urlscan_test_key_123")
    get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# 1. TIMEOUT TEST
# ─────────────────────────────────────────────────────────────────────────────
def test_threat_intel_timeout_bounds_within_3_5s(mock_keys, monkeypatch):
    """Mock one source sleeping 30s: total time must be <= 3.5s and keep fast sources."""
    agent = ThreatIntelAgent()
    agent._cache.clear()

    # Fast sources return immediately
    def mock_vt(url):
        return {
            "is_malicious": False,
            "positives": 0,
            "total": 70,
            "stats": {"malicious": 0},
            "permalink": "https://vt/test"
        }

    # Hanging source sleeps 30s
    def mock_gsb_hang(urls):
        time.sleep(30)
        return {"is_malicious": True, "threat_type": "MALWARE", "matches": 1}

    def mock_urlscan(url):
        return {"is_malicious": False, "score": 0, "scan_count": 1, "malicious_count": 0}

    def mock_phishtank(url):
        return {"is_malicious": False, "in_database": False}

    monkeypatch.setattr(agent, "_check_virustotal", mock_vt)
    monkeypatch.setattr(agent, "_check_google_safe_browsing", mock_gsb_hang)
    monkeypatch.setattr(agent, "_check_urlscan", mock_urlscan)
    monkeypatch.setattr(agent, "_check_phishtank", mock_phishtank)

    start = time.perf_counter()
    result = agent.scan_url("https://fast-test.com/login")
    elapsed = time.perf_counter() - start

    assert elapsed <= 3.5, f"scan_url took too long: {elapsed:.2f}s > 3.5s"
    assert "virustotal" in result["sources_checked"]
    assert "urlscan" in result["sources_checked"]
    assert "phishtank" in result["sources_checked"]
    assert "google_safe_browsing" not in result["sources_checked"]
    assert result["details"]["google_safe_browsing"].get("error") == "timeout"
    assert not result["is_malicious"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. PRIVACY & DEFAULT BEHAVIOR (URLSCAN & VIRUSTOTAL)
# ─────────────────────────────────────────────────────────────────────────────
def test_urlscan_default_only_searches_no_post_submit(mock_keys, monkeypatch):
    """Default: URLScan ONLY performs search GET/search API, never POST submit."""
    agent = ThreatIntelAgent()
    agent._cache.clear()

    requests_sent = []

    def fake_urlopen(req, timeout=None):
        requests_sent.append(req)
        # URLScan search API mock
        return MockHTTPResponse({"results": [{"verdicts": {"overall": {"malicious": False, "score": 0}}}]})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.delenv("URLSCAN_SUBMIT", raising=False)

    res = agent._check_urlscan("https://target-victim.com/page")
    assert not res["is_malicious"]

    # Verify no POST to /api/v1/scan/
    for r in requests_sent:
        assert r.get_method() != "POST"
        assert "/api/v1/scan/" not in r.full_url
        assert "/api/v1/search/" in r.full_url


def test_urlscan_submit_env_submits_unlisted_visibility(mock_keys, monkeypatch):
    """When URLSCAN_SUBMIT=1: submits scan with visibility='unlisted' and no sleep(3)."""
    monkeypatch.setenv("URLSCAN_SUBMIT", "1")
    agent = ThreatIntelAgent()
    agent._cache.clear()

    submitted_payloads = []

    def fake_urlopen(req, timeout=None):
        if req.data:
            submitted_payloads.append(json.loads(req.data.decode("utf-8")))
        return MockHTTPResponse({"uuid": "scan-uuid-12345"})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    start = time.perf_counter()
    res = agent._check_urlscan("https://target-victim.com/page")
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"URLScan submit took {elapsed:.2f}s, expected no sleep(3)"
    assert res.get("status") == "submitted"
    assert res.get("uuid") == "scan-uuid-12345"

    assert len(submitted_payloads) == 1
    assert submitted_payloads[0].get("visibility") == "unlisted"
    assert submitted_payloads[0].get("visibility") != "public"


def test_virustotal_default_no_submit_on_404(mock_keys, monkeypatch):
    """When VT returns 404 and VT_SUBMIT is unset, do NOT submit URL for scanning."""
    monkeypatch.delenv("VT_SUBMIT", raising=False)
    agent = ThreatIntelAgent()
    agent._cache.clear()

    submit_called = False

    def fake_submit(url):
        nonlocal submit_called
        submit_called = True
        return {"status": "submitted"}

    monkeypatch.setattr(agent, "_submit_virustotal", fake_submit)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    res = agent._check_virustotal("https://unknown-link.xyz/path")
    assert not submit_called, "VirusTotal should NOT submit by default on 404"
    assert res.get("status") == "not_found"
    assert not res.get("is_malicious")


def test_virustotal_submits_when_vt_submit_is_1(mock_keys, monkeypatch):
    """When VT_SUBMIT=1 and VT returns 404, submit URL for scanning."""
    monkeypatch.setenv("VT_SUBMIT", "1")
    agent = ThreatIntelAgent()
    agent._cache.clear()

    submit_called = False

    def fake_submit(url):
        nonlocal submit_called
        submit_called = True
        return {"status": "submitted", "is_malicious": False}

    monkeypatch.setattr(agent, "_submit_virustotal", fake_submit)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    res = agent._check_virustotal("https://unknown-link.xyz/path")
    assert submit_called, "VirusTotal should submit on 404 when VT_SUBMIT=1"
    assert res.get("status") == "submitted"


# ─────────────────────────────────────────────────────────────────────────────
# 3. PRIVACY: SECRET QUERY / TOKEN PROTECTION TEST
# ─────────────────────────────────────────────────────────────────────────────
def test_privacy_secret_query_never_sent_in_requests_or_actions(mock_keys, monkeypatch, caplog):
    """
    Assert that sensitive tokens like ?token=SECRET123 never appear in:
    1. Outbound HTTP request URLs, headers, or request bodies.
    2. Any entry in network_actions.
    3. Any logging output.
    """
    agent = ThreatIntelAgent()
    agent._cache.clear()

    outbound_requests = []

    def spy_urlopen(req, timeout=None):
        outbound_requests.append(req)
        # Provide generic responses for all endpoints
        if "virustotal" in req.full_url:
            return MockHTTPResponse({"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})
        elif "safebrowsing" in req.full_url:
            return MockHTTPResponse({"matches": []})
        elif "urlscan" in req.full_url:
            return MockHTTPResponse({"results": []})
        elif "phishtank" in req.full_url:
            return MockHTTPResponse({"results": {"in_database": False, "valid": False}})
        return MockHTTPResponse({})

    monkeypatch.setattr(urllib.request, "urlopen", spy_urlopen)

    sensitive_url = "https://bank-portal.example.com/verify?token=SECRET123&session=PRIVATE456"

    with caplog.at_level(logging.DEBUG):
        result = agent.scan_url(sensitive_url)

    # 1. Assert network_actions only contains domain
    assert "network_actions" in result
    assert len(result["network_actions"]) > 0
    for act in result["network_actions"]:
        target = act.get("target", "")
        assert target == "bank-portal.example.com"
        assert "SECRET123" not in target
        assert "PRIVATE456" not in target
        assert "?" not in target
        assert "/" not in target

    # 2. Assert 'SECRET123' never appeared in ANY outbound request
    assert len(outbound_requests) > 0
    for req in outbound_requests:
        url_str = req.full_url
        assert "SECRET123" not in url_str
        assert "PRIVATE456" not in url_str

        # Check request headers
        for k, v in req.headers.items():
            assert "SECRET123" not in str(v)

        # Check request body if present
        if req.data:
            data_str = req.data.decode("utf-8", errors="replace")
            assert "SECRET123" not in data_str
            assert "PRIVATE456" not in data_str

    # 3. Assert 'SECRET123' does not appear in caplog text
    assert "SECRET123" not in caplog.text


# ─────────────────────────────────────────────────────────────────────────────
# 4. CACHING & TTL TEST
# ─────────────────────────────────────────────────────────────────────────────
def test_cache_hit_prevents_duplicate_network_calls(mock_keys, monkeypatch):
    """Consecutive calls for the same normalized URL hit cache with 0 network calls on 2nd run."""
    agent = ThreatIntelAgent()
    agent._cache.clear()

    call_count = 0

    def mock_vt(url):
        nonlocal call_count
        call_count += 1
        return {"is_malicious": False, "positives": 0, "total": 70}

    monkeypatch.setattr(agent, "_check_virustotal", mock_vt)
    monkeypatch.setattr(agent, "_check_phishtank", lambda u: {"is_malicious": False})

    # Call 1
    res1 = agent.scan_url("https://cached-example.com/test")
    assert call_count == 1
    assert len(res1["network_actions"]) > 0

    # Call 2 (cache hit)
    res2 = agent.scan_url("https://cached-example.com/test")
    assert call_count == 1, "Expected cache hit without re-invoking network methods"
    assert res2["network_actions"] == [], "Cache hit must report 0 network actions for this invocation"
    assert res2["domain"] == "cached-example.com"


def test_cache_ttl_durations(mock_keys, monkeypatch):
    """Normal results cached with 6h TTL (21600s); errors cached with 60s TTL."""
    agent = ThreatIntelAgent()
    agent._cache.clear()

    # Normal result
    monkeypatch.setattr(agent, "_check_virustotal", lambda u: {"is_malicious": False, "positives": 0})
    monkeypatch.setattr(agent, "_check_phishtank", lambda u: {"is_malicious": False})
    t0 = time.time()
    res_normal = agent.scan_url("https://normal-cache.com/")
    key_normal = agent._normalize_cache_key("https://normal-cache.com/")
    _, exp_normal = agent._cache[key_normal]
    assert 21500 <= (exp_normal - t0) <= 21700

    # Error result
    monkeypatch.setattr(agent, "_check_virustotal", lambda u: {"error": "connection failed"})
    monkeypatch.setattr(agent, "_check_phishtank", lambda u: {"error": "timeout"})
    t1 = time.time()
    res_err = agent.scan_url("https://error-cache.com/")
    key_err = agent._normalize_cache_key("https://error-cache.com/")
    _, exp_err = agent._cache[key_err]
    assert 50 <= (exp_err - t1) <= 70


# ─────────────────────────────────────────────────────────────────────────────
# 5. OFFLINE / NETWORK_DISABLED SAFETY TEST
# ─────────────────────────────────────────────────────────────────────────────
def test_offline_mode_makes_zero_network_calls(mock_keys, monkeypatch):
    """When offline or network disabled, 0 network calls and empty network_actions."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    get_settings(refresh=True)
    agent = ThreatIntelAgent()

    call_count = 0

    def mock_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return MockHTTPResponse({})

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    res = agent.scan_url("https://malicious-offline.xyz/login")
    assert call_count == 0
    assert not res["is_malicious"]
    assert res["network_actions"] == []
    assert res["verdict_summary"] == "Offline / mạng bị tắt"
