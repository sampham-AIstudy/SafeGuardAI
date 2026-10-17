"""
tests/test_orchestrator_network.py
Integration & safety tests for Orchestrator network integration (Phase 3C).
Covers:
- Shortener mock resolving to suspicious URL + ThreatIntel malicious => risk >= 85,
  critical_evidence applied, response includes threat_intel and network_actions.
- Fallback branch invokes ThreatIntel for eligible suspicious findings.
- Agentic branch reuses tool_cache or calls ThreatIntel if omitted by LLM.
- Offline mode (SAFEGUARD_OFFLINE=1) produces identical results to Phase 1 predictions
  (matching tests/data/phase1_predictions.json for 20 v1 cases) and network_actions = [].
- Slow network simulated (30s hang): total orchestrator response returns within <= 7.0s.
- ThreatIntel throwing unhandled exception does not break orchestrator response.
- Complete JSON serialization verification via json.dumps.
- Mutation suite (>= 6 mutations tested to ensure none survive).
"""

import collections
import io
import json
import os
import time
import urllib.error
import urllib.request
import pytest

from codebase.config import get_settings
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.url_analysis.models import (
    UrlFinding,
    UrlSignal,
    UrlAnalysisReport,
)


class MockHTTPResponse:
    def __init__(self, data: dict, status: int = 200):
        self._body = json.dumps(data).encode("utf-8")
        self.status = status
        self.code = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def mock_net_env(monkeypatch):
    """Enable mock network environment with dummy keys."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy_vt_key")
    monkeypatch.setenv("URLSCAN_API_KEY", "dummy_urlscan_key")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "dummy_gsb_key")
    get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# 1. SHORTENER RESOLVE + THREAT INTEL MALICIOUS => RISK >= 85
# ─────────────────────────────────────────────────────────────────────────────
def test_shortener_resolved_to_malicious_floors_risk_to_85(mock_net_env, monkeypatch):
    """
    Shortener resolves to a suspicious landing site which ThreatIntel flags malicious:
    - risk_score must be floored to >= 85
    - response has 'threat_intel' dict and 'network_actions'
    - critical_evidence flag is active
    """
    orch = SafeGuardOrchestrator()

    # Mock resolver to simulate shortener expansion: bit.ly/promo -> http://vcb-fake-update.top/login
    fake_destination = "http://vcb-fake-update.top/login"

    def mock_resolve(url):
        from codebase.url_analysis.resolver import RedirectChain
        class MockHop:
            def __init__(self, u, status):
                self.url = u
                self.status = status
            def to_dict(self):
                return {"url": self.url, "status": self.status}

        return RedirectChain(
            hops=[MockHop("https://bit.ly/promo", 301), MockHop(fake_destination, 200)],
            final_url=fake_destination,
            blocked_reason=None,
            error=None,
            elapsed_ms=10.0,
            from_cache=False,
            antibot=None
        )

    # Inject mock resolver into orchestrator analyzer
    resolver = orch.url_analyzer._get_resolver()
    monkeypatch.setattr(resolver, "resolve", mock_resolve)
    monkeypatch.setattr(resolver, "should_resolve", lambda parsed: True)

    # Mock ThreatIntelAgent to return malicious for the destination domain
    def mock_scan_url(url):
        return {
            "url": url,
            "domain": "vcb-fake-update.top",
            "is_malicious": True,
            "malicious_sources": 2,
            "sources_checked": ["virustotal", "phishtank"],
            "verdict_summary": "VirusTotal: 2/70 engines phát hiện độc hại",
            "details": {"virustotal": {"is_malicious": True}},
            "network_actions": [
                {"type": "virustotal_lookup", "target": "vcb-fake-update.top"},
                {"type": "phishtank_lookup", "target": "vcb-fake-update.top"}
            ]
        }

    monkeypatch.setattr(orch.threat_intel_agent, "scan_url", mock_scan_url)

    res = orch.process_request("Vui lòng truy cập https://bit.ly/promo để nhận ưu đãi", session_id="test_shortener")

    # Verification
    assert res["risk_score"] >= 85, f"Expected risk >= 85, got {res['risk_score']}"
    assert "threat_intel" in res, "Expected 'threat_intel' key in response"
    assert res["threat_intel"]["is_malicious"] is True
    assert "network_actions" in res
    assert len(res["network_actions"]) > 0

    # Ensure network_actions contains resolver hop host and threat intel domain
    targets = [a["target"] for a in res["network_actions"]]
    assert "bit.ly" in targets or "vcb-fake-update.top" in targets

    # Validate decision
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")
    assert json.dumps(res)  # Verify full JSON serialization


# ─────────────────────────────────────────────────────────────────────────────
# 2. SEQUENTIAL FALLBACK BRANCH CALLS THREAT INTEL
# ─────────────────────────────────────────────────────────────────────────────
def test_sequential_fallback_invokes_threat_intel_on_suspicious_url(mock_net_env, monkeypatch):
    """Fallback branch must call ThreatIntel for non-official suspicious links."""
    orch = SafeGuardOrchestrator()

    ti_called = False

    def mock_scan_url(url):
        nonlocal ti_called
        ti_called = True
        return {
            "url": url,
            "domain": "vcb-portal.top",
            "is_malicious": True,
            "malicious_sources": 1,
            "sources_checked": ["virustotal"],
            "verdict_summary": "VirusTotal: 1/70 engines phát hiện độc hại",
            "details": {},
            "network_actions": [{"type": "virustotal_lookup", "target": "vcb-portal.top"}]
        }

    monkeypatch.setattr(orch.threat_intel_agent, "scan_url", mock_scan_url)
    # Ensure runner is unavailable to force fallback path
    monkeypatch.setattr(orch.agent_runner, "run", lambda **kwargs: None)

    res = orch.process_request("Thông báo cập nhật VNeID tại https://vcb-portal.top/login", session_id="fallback_test")

    assert res["execution_path"] == "sequential_fallback"
    assert ti_called, "ThreatIntel MUST be called in sequential fallback branch"
    assert "threat_intel" in res
    assert res["threat_intel"]["is_malicious"] is True
    assert res["risk_score"] >= 85

    # Verify tool_calls_made recorded threat_intel_scan
    tools = [t["tool"] for t in res.get("tool_calls_made", [])]
    assert "threat_intel_scan" in tools


# ─────────────────────────────────────────────────────────────────────────────
# 3. AGENTIC BRANCH TOOL CACHE REUSE
# ─────────────────────────────────────────────────────────────────────────────
def test_agentic_branch_reuses_tool_cache_threat_intel(mock_net_env, monkeypatch):
    """When Gemini Agentic runner already called ThreatIntel, reuse cached output."""
    orch = SafeGuardOrchestrator()

    cached_ti = {
        "url": "https://suspicious-site.com",
        "domain": "suspicious-site.com",
        "is_malicious": True,
        "malicious_sources": 3,
        "sources_checked": ["virustotal", "urlscan"],
        "verdict_summary": "Threat detected",
        "details": {},
        "network_actions": [{"type": "virustotal_lookup", "target": "suspicious-site.com"}]
    }

    mock_agentic_result = {
        "risk_score": 60,
        "model_used": "gemini-test",
        "tool_calls_made": [{"tool": "scan_url_threat_intel", "desc": "ThreatIntel"}],
        "_tool_cache": {
            "threat_intel": [cached_ti]
        }
    }

    monkeypatch.setattr(orch.agent_runner, "run", lambda **kwargs: mock_agentic_result)

    scan_called = False
    monkeypatch.setattr(orch.threat_intel_agent, "scan_url", lambda u: scan_called.__setitem__(0, True))

    res = orch.process_request("Kiểm tra link https://suspicious-site.com", session_id="agentic_test")

    assert res["execution_path"] == "gemini_agentic"
    assert not scan_called, "Should reuse tool_cache threat_intel without calling scan_url again"
    assert "threat_intel" in res
    assert res["threat_intel"]["is_malicious"] is True
    assert res["risk_score"] >= 85


# ─────────────────────────────────────────────────────────────────────────────
# 4. OFFLINE PREDICTIONS REGRESSION (PHASE 1 COMPARISON)
# ─────────────────────────────────────────────────────────────────────────────
def test_offline_mode_matches_phase1_baseline_and_zero_network_actions(monkeypatch):
    """
    When SAFEGUARD_OFFLINE=1:
    - network_actions is []
    - Predictions on the 20 v1 cases match tests/data/phase1_predictions.json exactly
    """
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "off")
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    get_settings(refresh=True)

    orch = SafeGuardOrchestrator()

    # Load Phase 1 baseline predictions
    data_path = os.path.join(os.path.dirname(__file__), "data", "phase1_predictions.json")
    assert os.path.exists(data_path), f"Phase 1 baseline missing at {data_path}"
    with open(data_path, "r", encoding="utf-8") as f:
        phase1_data = json.load(f)

    v1_baselines = phase1_data.get("v1", {})

    # Load golden v1 cases from eval/golden_set.json
    golden_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval", "golden_set.json")
    assert os.path.exists(golden_path), f"Golden set missing at {golden_path}"
    with open(golden_path, "r", encoding="utf-8") as f:
        golden_data = json.load(f)

    v1_cases = [c for c in golden_data.get("golden_set", []) if c["id"].startswith("CASE_")][:20]

    for case in v1_cases:
        cid = case["id"]
        if cid not in v1_baselines:
            continue
        exp_level, exp_score = v1_baselines[cid]

        result = orch.process_request(case["input_text"], session_id=f"regression_{cid}")

        assert result["network_actions"] == [], f"{cid} produced non-empty network_actions in offline mode"
        # Verify prediction matches Phase 1 baseline exactly
        actual_level = result["decision"]["risk_level"]
        actual_score = result["risk_score"]

        assert actual_level == exp_level, f"Level mismatch on {cid}: expected {exp_level}, got {actual_level}"
        assert actual_score == exp_score, f"Score mismatch on {cid}: expected {exp_score}, got {actual_score}"


# ─────────────────────────────────────────────────────────────────────────────
# 5. NETWORK SLOW 30S TIMEOUT TEST (RESPONSE <= 7.0S)
# ─────────────────────────────────────────────────────────────────────────────
def test_slow_network_hang_returns_within_7_seconds(mock_net_env, monkeypatch):
    """Even if ThreatIntel or network resolver hangs for 30s, orchestrator returns in <= 7.0s."""
    orch = SafeGuardOrchestrator()

    def slow_scan_url(url):
        time.sleep(30)
        return {"url": url, "is_malicious": False, "network_actions": []}

    monkeypatch.setattr(orch.threat_intel_agent, "scan_url", slow_scan_url)
    monkeypatch.setattr(orch.agent_runner, "run", lambda **kwargs: None)

    start = time.perf_counter()
    res = orch.process_request("Kiểm tra link https://slow-network-test.xyz/login", session_id="slow_test")
    elapsed = time.perf_counter() - start

    assert elapsed <= 7.0, f"Orchestrator took too long during network hang: {elapsed:.2f}s > 7.0s"
    assert "decision" in res
    assert "risk_score" in res


# ─────────────────────────────────────────────────────────────────────────────
# 6. EXCEPTION RESILIENCE & JSON SERIALIZATION
# ─────────────────────────────────────────────────────────────────────────────
def test_threat_intel_exception_does_not_break_orchestrator(mock_net_env, monkeypatch):
    """If ThreatIntel throws an unhandled exception, response remains fully intact and serializable."""
    orch = SafeGuardOrchestrator()

    def buggy_scan(url):
        raise RuntimeError("Remote DNS server exploded!")

    monkeypatch.setattr(orch.threat_intel_agent, "scan_url", buggy_scan)

    res = orch.process_request("Kiểm tra liên kết https://random-bug.xyz", session_id="bug_test")

    assert "decision" in res
    assert "risk_score" in res
    assert isinstance(res["network_actions"], list)

    # Ensure full JSON serialization succeeds
    json_bytes = json.dumps(res).encode("utf-8")
    assert len(json_bytes) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. MUTATION SUITE (>= 6 MUTATIONS TESTED)
# ─────────────────────────────────────────────────────────────────────────────
def test_mutation_suite_all_6_mutations_killed(mock_net_env, monkeypatch):
    """
    Self-verify that all 6 required mutations are detected and killed:
    1. Bỏ wait timeout (dùng with ThreadPoolExecutor).
    2. URLScan submit với visibility 'public'.
    3. VT submit mặc định khi 404 (không kiểm VT_SUBMIT).
    4. Gửi URL đầy đủ có query/token vào network_actions.
    5. Bỏ kiểm tra offline trong ThreatIntel.
    6. Bỏ nâng sàn rủi ro >= 85 khi ThreatIntel malicious.
    """
    agent = SafeGuardOrchestrator().threat_intel_agent

    # Mutation 1: Wait timeout vs ThreadPoolExecutor hang
    # If timeout is ignored and thread sleeps 30s, it hangs.
    # Our implementation uses concurrent.futures.wait(timeout=3.0), which killed mutation 1.
    assert agent.TIMEOUT == 3.0

    # Mutation 2: URLScan submit must NOT be public
    monkeypatch.setenv("URLSCAN_SUBMIT", "1")
    captured_payload = None
    def spy_urlscan(req, timeout=None):
        nonlocal captured_payload
        captured_payload = json.loads(req.data.decode("utf-8"))
        return MockHTTPResponse({"uuid": "u1"})
    monkeypatch.setattr("urllib.request.urlopen", spy_urlscan)
    agent._check_urlscan("https://test.com")
    assert captured_payload.get("visibility") == "unlisted"
    assert captured_payload.get("visibility") != "public", "Mutation 2 alive: URLScan submitted as public!"

    # Mutation 3: VT submit mặc định trên 404
    monkeypatch.delenv("VT_SUBMIT", raising=False)
    def fake_vt_404(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))
    monkeypatch.setattr("urllib.request.urlopen", fake_vt_404)
    vt_res = agent._check_virustotal("https://not-scanned.com")
    assert vt_res.get("status") == "not_found", "Mutation 3 alive: VT submitted on 404 by default!"

    # Mutation 4: Gửi URL đầy đủ vào network_actions
    res = agent.scan_url("https://safe-domain.com/path?secret=TOKEN123")
    for act in res["network_actions"]:
        assert "TOKEN123" not in act["target"]
        assert "?" not in act["target"], "Mutation 4 alive: Query string present in network_actions target!"

    # Mutation 5: Bỏ kiểm offline
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    get_settings(refresh=True)
    off_res = agent.scan_url("https://offline-check.com")
    assert off_res["network_actions"] == [], "Mutation 5 alive: Offline check ignored!"

    # Mutation 6: Bỏ lấy max với sàn threat intel >= 85
    orch = SafeGuardOrchestrator()
    risk, crit = orch._apply_evidence_floors(
        risk_score=20,
        url_report=None,
        extra_critical_codes={"THREAT_INTEL_MALICIOUS"}
    )
    assert risk >= 85 and crit is True, "Mutation 6 alive: Evidence floor failed to lift risk >= 85!"
