"""
tests/test_rag_url_integration.py
Phase 2D-2 Unit & Integration tests for RAGAgent + url_analysis integration.
Covers:
- R1.1: RAGAgent.search with url_report containing BLACKLIST_HIT findings (and child findings)
- R1.2: RAGAgent.search deduplication and order preservation for BLACKLIST_HIT domains
- R1.3: RAGAgent.search return dictionary structure preservation
- R1.4: RAGAgent.search with url_report=None uses lazy UrlAnalyzer
- R1.5: RAGAgent.search with module disabled (SAFEGUARD_URL_MODULE=off) falls back to legacy substring scan
- R1.6: Performance on 20k characters (< 200ms)
- R1.7: Orchestrator integration passes url_report to rag_agent.search
"""

import time
import pytest

from codebase.agents.rag_agent import RAGAgent
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.config import get_settings
from codebase.url_analysis.models import (
    UrlAnalysisReport,
    UrlFinding,
    UrlSignal,
)


def _make_mock_report(findings):
    return UrlAnalysisReport(
        findings=findings,
        max_url_risk=90 if any(f.signals and any(s.severity == "critical" for s in f.signals) for f in findings) else 0,
        has_only_official_urls=False,
    )


def test_rag_search_with_url_report_blacklist_hit():
    """RAGAgent extracts effective_host from findings having BLACKLIST_HIT signal."""
    agent = RAGAgent()
    sig = UrlSignal(
        code="BLACKLIST_HIT",
        severity="critical",
        weight=60,
        message_vi="Tên miền nằm trong danh sách đen PhishVN",
        evidence="host=evil-test-phish.xyz, level=host",
    )
    f = UrlFinding(
        raw="http://evil-test-phish.xyz/login",
        normalized="http://evil-test-phish.xyz/login",
        final_url="http://evil-test-phish.xyz/login",
        display_host="evil-test-phish.xyz",
        effective_host="evil-test-phish.xyz",
        effective_host_unicode="evil-test-phish.xyz",
        registrable_domain="evil-test-phish.xyz",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[sig],
    )
    report = _make_mock_report([f])
    res = agent.search("Thong bao tai khoan", url_report=report)

    assert "evil-test-phish.xyz" in res["matched_phish_domains"]
    expected_flag = "Tên miền lừa đảo NCSC/ChongLuaDao: evil-test-phish.xyz"
    assert expected_flag in res["matched_flags"]
    assert res["total_patterns_matched"] == len(res["matched_flags"])
    assert "matched_tactics" in res
    assert "mysql_active" in res
    assert "phish_vn_stats" in res
    assert "global_stats" in res


def test_rag_search_with_url_report_child_findings():
    """RAGAgent extracts BLACKLIST_HIT domains recursively from child findings."""
    agent = RAGAgent()
    sig_child = UrlSignal(
        code="BLACKLIST_HIT",
        severity="critical",
        weight=60,
        message_vi="Tên miền nằm trong danh sách đen PhishVN",
        evidence="host=child-phish.top, level=host",
    )
    child = UrlFinding(
        raw="http://child-phish.top",
        normalized="http://child-phish.top",
        final_url="http://child-phish.top",
        display_host="child-phish.top",
        effective_host="child-phish.top",
        effective_host_unicode="child-phish.top",
        registrable_domain="child-phish.top",
        is_official=False,
        brand_match=None,
        source="redirect",
        signals=[sig_child],
    )
    parent = UrlFinding(
        raw="http://tinyurl.com/abc",
        normalized="http://tinyurl.com/abc",
        final_url="http://child-phish.top",
        display_host="tinyurl.com",
        effective_host="tinyurl.com",
        effective_host_unicode="tinyurl.com",
        registrable_domain="tinyurl.com",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[],
        children=[child],
    )
    report = _make_mock_report([parent])
    res = agent.search("Nhan qua ngay", url_report=report)

    assert "child-phish.top" in res["matched_phish_domains"]
    assert any("child-phish.top" in f for f in res["matched_flags"])


def test_rag_search_deduplicates_and_preserves_order():
    """Duplicate findings produce distinct domains in matched_phish_domains preserving order."""
    agent = RAGAgent()
    sig = UrlSignal(
        code="BLACKLIST_HIT",
        severity="critical",
        weight=60,
        message_vi="Blacklist hit",
        evidence="host=alpha-phish.com, level=host",
    )
    f1 = UrlFinding(
        raw="http://alpha-phish.com/1",
        normalized="http://alpha-phish.com/1",
        final_url="http://alpha-phish.com/1",
        display_host="alpha-phish.com",
        effective_host="alpha-phish.com",
        effective_host_unicode="alpha-phish.com",
        registrable_domain="alpha-phish.com",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[sig],
    )
    f2 = UrlFinding(
        raw="http://beta-phish.com/2",
        normalized="http://beta-phish.com/2",
        final_url="http://beta-phish.com/2",
        display_host="beta-phish.com",
        effective_host="beta-phish.com",
        effective_host_unicode="beta-phish.com",
        registrable_domain="beta-phish.com",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[sig],
    )
    f3 = UrlFinding(
        raw="http://alpha-phish.com/3",
        normalized="http://alpha-phish.com/3",
        final_url="http://alpha-phish.com/3",
        display_host="alpha-phish.com",
        effective_host="alpha-phish.com",
        effective_host_unicode="alpha-phish.com",
        registrable_domain="alpha-phish.com",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[sig],
    )
    report = _make_mock_report([f1, f2, f3])
    res = agent.search("Kiem tra", url_report=report)

    assert res["matched_phish_domains"] == ["alpha-phish.com", "beta-phish.com"]
    flags = [f for f in res["matched_flags"] if "alpha-phish.com" in f or "beta-phish.com" in f]
    assert len(flags) == 2


def test_rag_search_lazy_analyzer_when_report_none():
    """When url_report is None, RAGAgent lazily analyzes text using UrlAnalyzer."""
    agent = RAGAgent()
    # vcb-verify.xyz is in DEFAULT_SAMPLE_PHISH_HOSTS
    query = "Quy khach vui long truy cap http://vcb-verify.xyz de xac thuc so du"
    res = agent.search(query, url_report=None)

    assert "vcb-verify.xyz" in res["matched_phish_domains"]
    assert any("vcb-verify.xyz" in f for f in res["matched_flags"])


def test_rag_search_module_disabled_uses_legacy_loop(monkeypatch):
    """When SAFEGUARD_URL_MODULE is off, RAGAgent uses the legacy substring loop."""
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    get_settings(refresh=True)
    try:
        agent = RAGAgent()
        mock_domain = "legacy-custom-phish-domain.com"
        agent.phish_data = {"phishing_domains": {mock_domain}, "total_phishing_records": 1}

        res = agent.search(f"truy cap {mock_domain} ngay")
        assert mock_domain in res["matched_phish_domains"]
    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)


def test_rag_search_performance_20k_chars():
    """RAGAgent.search on 20k characters executes in < 200ms when url_module is enabled."""
    agent = RAGAgent()
    text = "vietcombank thong bao giao dich chuyen khoan " * 450
    text_20k = text[:20000]

    t0 = time.perf_counter()
    res = agent.search(text_20k)
    elapsed = time.perf_counter() - t0

    assert elapsed < 0.200, f"RAGAgent.search took {elapsed:.3f}s (must be < 0.200s)"
    assert isinstance(res["matched_phish_domains"], list)


def test_orchestrator_passes_url_report_to_rag():
    """Orchestrator fallback pipeline passes url_report to rag_agent.search."""
    orch = SafeGuardOrchestrator()
    # Query with a known sample phish host
    res = orch.process_request("Canh bao truy cap link http://vcb-verify.xyz de nhan thuong")
    assert "decision" in res
    assert "url_analysis" in res
    assert res["url_analysis"] is not None
    assert res["risk_score"] >= 75
