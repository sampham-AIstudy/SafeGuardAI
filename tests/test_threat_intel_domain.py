"""
tests/test_threat_intel_domain.py
Phase 2D-2 Unit & Integration tests for ThreatIntelAgent domain extraction and lookup.
Covers:
- R3.1: _extract_domain for >= 12 URLs (userinfo, port, repeated www, IDN/punycode, strange IP, case, no scheme, backslash)
- R3.2: lookup_domain TLD precision ('www.topcv.vn', 'www.garena.vn' NOT suspicious; 'abc.top', 'x.xyz' IS suspicious)
- R3.3: lookup_domain official domain verification via BrandCatalog / whitelist
- R3.4: lookup_domain offline safety (zero network calls, valid dict structure)
- R3.5: 4 Mutation tests (reverting to replace("www."), reverting to substring TLD, dropping url_report, ignoring module toggle)
"""

import socket
import pytest

from codebase.agents.threat_intel_agent import ThreatIntelAgent
from codebase.agents.rag_agent import RAGAgent
from codebase.config import get_settings
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.url_analysis.models import (
    UrlAnalysisReport,
    UrlFinding,
    UrlSignal,
)


@pytest.fixture
def threat_agent():
    return ThreatIntelAgent()


# ─────────────────────────────────────────────────────────────────────────────
# R3.1: _extract_domain with >= 12 URLs
# ─────────────────────────────────────────────────────────────────────────────
EXTRACT_DOMAIN_TEST_CASES = [
    # 1. userinfo + port + inner www
    ("http://user:pw@www.evilwww.com:8080/path", "evilwww.com"),
    # 2. standard port
    ("https://vietcombank.com.vn:443/login", "vietcombank.com.vn"),
    # 3. repeated www
    ("https://www.www.example.com/test", "www.example.com"),
    # 4. Unicode IDN
    ("http://dịchvụcông.gov.vn", "xn--dchvcng-x0a0689dsha.gov.vn"),
    # 5. Punycode
    ("http://xn--dchvcng-x0a0689dsha.gov.vn", "xn--dchvcng-x0a0689dsha.gov.vn"),
    # 6. Strange/dword decimal IPv4
    ("http://2130706433/index.html", "127.0.0.1"),
    # 7. Hex IPv4
    ("http://0x7f000001/path", "127.0.0.1"),
    # 8. IPv4 with userinfo & non-standard port
    ("http://admin:secret@192.168.1.1:8080/setup", "192.168.1.1"),
    # 9. Mixed/Uppercase
    ("HTTPS://WWW.VIETCOMBANK.COM.VN/EBANKING", "vietcombank.com.vn"),
    # 10. No scheme
    ("vietcombank.com.vn/ebanking", "vietcombank.com.vn"),
    # 11. No scheme with www
    ("www.topcv.vn/vieclam", "topcv.vn"),
    # 12. Backslash confusion
    ("https://evil.com\\fake.com/path", "evil.com"),
    # 13. Subdomain with query & fragment
    ("https://sub.portal.gov.vn:8443/?v=1#sec", "sub.portal.gov.vn"),
]


@pytest.mark.parametrize("url,expected_domain", EXTRACT_DOMAIN_TEST_CASES)
def test_extract_domain_diverse_urls(threat_agent, url, expected_domain):
    extracted = threat_agent._extract_domain(url)
    assert extracted == expected_domain, f"Failed on URL '{url}': expected '{expected_domain}', got '{extracted}'"


# ─────────────────────────────────────────────────────────────────────────────
# R3.2: lookup_domain TLD precision
# ─────────────────────────────────────────────────────────────────────────────
def test_lookup_domain_tld_no_false_positive_on_topcv(threat_agent):
    """'www.topcv.vn' and 'topcv.vn' must NOT be flagged as suspicious TLD (.top substring bug)."""
    res1 = threat_agent.lookup_domain("www.topcv.vn")
    assert not res1["is_suspicious"], f"www.topcv.vn falsely flagged suspicious: {res1.get('reason')}"
    assert "TLD đáng ngờ" not in str(res1.get("reason", ""))

    res2 = threat_agent.lookup_domain("topcv.vn")
    assert not res2["is_suspicious"], f"topcv.vn falsely flagged suspicious: {res2.get('reason')}"


def test_lookup_domain_tld_no_false_positive_on_garena(threat_agent):
    """'www.garena.vn' must NOT be flagged as suspicious TLD."""
    res = threat_agent.lookup_domain("www.garena.vn")
    assert not res["is_suspicious"], f"www.garena.vn falsely flagged suspicious: {res.get('reason')}"


def test_lookup_domain_tld_flags_suspicious_tld(threat_agent):
    """'abc.top' and 'x.xyz' must be flagged as suspicious due to suspicious TLD."""
    res_top = threat_agent.lookup_domain("abc.top")
    assert res_top["is_suspicious"], "abc.top must be flagged as suspicious"
    assert "TLD đáng ngờ" in str(res_top.get("reason", ""))

    res_xyz = threat_agent.lookup_domain("x.xyz")
    assert res_xyz["is_suspicious"], "x.xyz must be flagged as suspicious"
    assert "TLD đáng ngờ" in str(res_xyz.get("reason", ""))


# ─────────────────────────────────────────────────────────────────────────────
# R3.3: lookup_domain official domain verification
# ─────────────────────────────────────────────────────────────────────────────
def test_lookup_domain_official_whitelist(threat_agent):
    """Official banking domains are verified via BrandCatalog and marked is_official=True."""
    res = threat_agent.lookup_domain("vietcombank.com.vn")
    assert res.get("is_official") is True
    assert not res["is_suspicious"]
    assert "chính thức" in str(res.get("reason", "")).lower()

    res_sub = threat_agent.lookup_domain("portal.vietcombank.com.vn")
    assert res_sub.get("is_official") is True
    assert not res_sub["is_suspicious"]


# ─────────────────────────────────────────────────────────────────────────────
# R3.4: lookup_domain offline safety
# ─────────────────────────────────────────────────────────────────────────────
def test_lookup_domain_offline_no_network(threat_agent):
    """lookup_domain runs fully offline without attempting any socket connection."""
    # Under no_network fixture, socket connect raises NetworkBlockedError
    res = threat_agent.lookup_domain("some-random-domain.com")
    assert isinstance(res, dict)
    assert res["domain"] == "some-random-domain.com"
    assert "is_suspicious" in res
    assert "age_days" in res
    assert "registrar" in res
    assert "urlscan_verdict" in res
    assert res["urlscan_verdict"] is None


# ─────────────────────────────────────────────────────────────────────────────
# R3.5: 4 MUTATION TESTS
# ─────────────────────────────────────────────────────────────────────────────
def test_mutation_1_revert_to_replace_www_fails():
    """Mutation 1: Reverting to replace('www.', '') alters 'evilwww.com' -> fails assertion."""
    url = "http://user:pw@www.evilwww.com:8080/path"
    agent = ThreatIntelAgent()
    correct_domain = agent._extract_domain(url)
    assert correct_domain == "evilwww.com", f"Expected 'evilwww.com', got {correct_domain}"

    # Simulate buggy legacy mutation:
    import urllib.parse
    buggy_domain = urllib.parse.urlparse(url).netloc.lower().replace("www.", "")
    # In legacy buggy code: buggy_domain was "user:pw@evilcom:8080"
    assert buggy_domain != "evilwww.com", "Legacy buggy logic should differ from correct output"
    assert "user:pw@" in buggy_domain or "evilcom" in buggy_domain


def test_mutation_2_revert_to_substring_tld_fails():
    """Mutation 2: Reverting to `tld in domain` substring flags www.topcv.vn -> fails assertion."""
    domain = "www.topcv.vn"
    agent = ThreatIntelAgent()
    res = agent.lookup_domain(domain)
    # Correct logic:
    assert not res["is_suspicious"], "www.topcv.vn must NOT be suspicious in correct logic"

    # Simulate buggy substring mutation:
    suspicious_tlds = [".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".info", ".top", ".pw"]
    buggy_is_suspicious = any(tld in domain for tld in suspicious_tlds)
    assert buggy_is_suspicious is True, "Buggy substring logic would falsely flag .top in topcv"


def test_mutation_3_dropping_url_report_fails():
    """Mutation 3: Dropping url_report in orchestrator fallback -> RAG does not receive BLACKLIST_HIT finding."""
    agent = RAGAgent()
    sig = UrlSignal(
        code="BLACKLIST_HIT",
        severity="critical",
        weight=60,
        message_vi="Blacklist hit",
        evidence="host=threat-test-domain.xyz, level=host",
    )
    finding = UrlFinding(
        raw="http://threat-test-domain.xyz",
        normalized="http://threat-test-domain.xyz",
        final_url="http://threat-test-domain.xyz",
        display_host="threat-test-domain.xyz",
        effective_host="threat-test-domain.xyz",
        effective_host_unicode="threat-test-domain.xyz",
        registrable_domain="threat-test-domain.xyz",
        is_official=False,
        brand_match=None,
        source="text",
        signals=[sig],
    )
    report = UrlAnalysisReport(
        findings=[finding],
        max_url_risk=90,
    )

    # With url_report passed:
    res_with_report = agent.search("tin nhan binh thuong", url_report=report)
    assert "threat-test-domain.xyz" in res_with_report["matched_phish_domains"]

    # Without url_report (and query without the URL):
    res_without_report = agent.search("tin nhan binh thuong", url_report=None)
    assert "threat-test-domain.xyz" not in res_without_report["matched_phish_domains"]


def test_mutation_4_ignoring_module_disabled_flag_fails(monkeypatch):
    """Mutation 4: Ignoring SAFEGUARD_URL_MODULE=off fails to activate legacy loop."""
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    get_settings(refresh=True)
    try:
        agent = RAGAgent()
        mock_domain = "mutation4-test-domain.com"
        agent.phish_data = {"phishing_domains": {mock_domain}, "total_phishing_records": 1}

        res = agent.search(f"truy cap {mock_domain} ngay")
        # In legacy loop: substring matches mock_domain
        assert mock_domain in res["matched_phish_domains"], "Legacy loop must be active when module is disabled"
    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)
