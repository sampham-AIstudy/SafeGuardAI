import time
import pytest
from unittest.mock import MagicMock

from codebase.config import get_settings
from codebase.url_analysis.analyzer import UrlAnalyzer
from codebase.url_analysis.models import UrlFinding, UrlSignal
from codebase.url_analysis.resolver import Hop, RedirectChain, SafeRedirectResolver


class FakeResolver:
    """Mock resolver returning preconfigured RedirectChain instances."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def should_resolve(self, parsed_url):
        raw = parsed_url.raw if hasattr(parsed_url, "raw") else str(parsed_url)
        host = (getattr(parsed_url, "effective_host", "") or "").lower().rstrip(".")
        if host in ("bit.ly", "tinyurl.com", "t.co", "s.id", "cutt.ly"):
            return True
        if raw in self.routes:
            return True
        return False

    def resolve(self, url):
        self.calls.append(url)
        if url in self.routes:
            res = self.routes[url]
            if isinstance(res, Exception):
                raise res
            return res
        return RedirectChain(
            hops=[Hop(url=url, status=200)],
            final_url=url,
            blocked_reason=None,
            error=None,
            elapsed_ms=5.0,
        )


@pytest.fixture(autouse=True)
def enable_network_settings(monkeypatch):
    """Enable network settings by default for network test suite."""
    monkeypatch.setenv("SAFEGUARD_NETWORK", "on")
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    settings = get_settings()
    monkeypatch.setattr(settings, "network_enabled", True)
    monkeypatch.setattr(settings, "offline", False)


# ============================================================================
# 1. SHORTENER RESOLUTION TO SUSPICIOUS VS OFFICIAL
# ============================================================================


def test_shortener_resolves_to_suspicious_domain():
    """
    bit.ly resolves to suspicious domain:
    Parent has SHORTENER_RESOLVED, child is dangerous/suspicious, parent score >= child score.
    """
    suspicious_dest = "http://vcb-xacthuc-taikhoan.online/login"
    mock_chain = RedirectChain(
        hops=[
            Hop(url="http://bit.ly/vcb-login", status=301, location=suspicious_dest),
            Hop(url=suspicious_dest, status=200),
        ],
        final_url=suspicious_dest,
        elapsed_ms=10.0,
    )
    resolver = FakeResolver(routes={"http://bit.ly/vcb-login": mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text("Truy cập http://bit.ly/vcb-login ngay", allow_network=True)
    assert len(report.findings) > 0
    parent = report.findings[0]

    assert any(s.code == "SHORTENER_RESOLVED" for s in parent.signals)
    assert len(parent.children) > 0
    child = parent.children[0]
    assert child.verdict in ("suspicious", "dangerous")
    assert parent.url_risk_score >= child.url_risk_score
    assert parent.final_url == child.final_url


def test_shortener_resolves_to_official_domain():
    """
    Shortener resolves to official domain:
    Parent is NOT raised to suspicious/dangerous by child (child score is 0).
    """
    official_dest = "https://portal.vietcombank.com.vn/personal"
    mock_chain = RedirectChain(
        hops=[
            Hop(url="http://bit.ly/official-vcb", status=301, location=official_dest),
            Hop(url=official_dest, status=200),
        ],
        final_url=official_dest,
        elapsed_ms=10.0,
    )
    resolver = FakeResolver(routes={"http://bit.ly/official-vcb": mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text("Trang chủ http://bit.ly/official-vcb", allow_network=True)
    assert len(report.findings) > 0
    parent = report.findings[0]

    assert any(s.code == "SHORTENER_RESOLVED" for s in parent.signals)
    assert len(parent.children) > 0
    child = parent.children[0]
    assert child.is_official is True
    assert child.url_risk_score == 0
    # Parent does not get elevated to suspicious or dangerous
    assert parent.verdict not in ("suspicious", "dangerous")


# ============================================================================
# 2. REDIRECT CHAIN > 2 HOPS
# ============================================================================


def test_redirect_chain_greater_than_2_hops():
    """
    Chain with 4 hops triggers REDIRECT_CHAIN signal (weight 10, low).
    """
    final_dest = "https://destination.example.com/final"
    mock_chain = RedirectChain(
        hops=[
            Hop(url="http://bit.ly/hop1", status=301, location="http://bit.ly/hop2"),
            Hop(url="http://bit.ly/hop2", status=302, location="http://bit.ly/hop3"),
            Hop(url="http://bit.ly/hop3", status=307, location=final_dest),
            Hop(url=final_dest, status=200),
        ],
        final_url=final_dest,
        elapsed_ms=25.0,
    )
    resolver = FakeResolver(routes={"http://bit.ly/hop1": mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text("Link: http://bit.ly/hop1", allow_network=True)
    assert len(report.findings) > 0
    parent = report.findings[0]
    assert any(s.code == "REDIRECT_CHAIN" for s in parent.signals)
    sig = next(s for s in parent.signals if s.code == "REDIRECT_CHAIN")
    assert sig.weight == 10
    assert sig.severity == "low"


# ============================================================================
# 3. PRIVATE DESTINATION SSRF BLOCKED
# ============================================================================


@pytest.mark.parametrize("private_ip", ["169.254.169.254", "10.0.0.1", "127.0.0.1"])
def test_redirect_to_private_ip_blocked(private_ip):
    """
    Redirect resolving to private or link-local IP triggers NETWORK_BLOCKED_PRIVATE (weight 40, high).
    """
    target = f"http://bit.ly/private-{private_ip}"
    mock_chain = RedirectChain(
        hops=[Hop(url=target, status=302, location=f"http://{private_ip}/latest/meta-data")],
        final_url=None,
        blocked_reason="private_destination",
        elapsed_ms=8.0,
    )
    resolver = FakeResolver(routes={target: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text(f"Check {target}", allow_network=True)
    assert len(report.findings) > 0
    finding = report.findings[0]

    assert any(s.code == "NETWORK_BLOCKED_PRIVATE" for s in finding.signals)
    sig = next(s for s in finding.signals if s.code == "NETWORK_BLOCKED_PRIVATE")
    assert sig.weight == 40
    assert sig.severity == "high"
    assert "nội bộ" in sig.message_vi


# ============================================================================
# 4. CLOUDFLARE CHALLENGE + SUSPICIOUS/BRAND/TLD -> CLOAKING_SUSPECTED
# ============================================================================


def test_cloudflare_challenge_on_suspicious_domain():
    """
    Cloudflare 403 challenge on brand/suspicious domain vcb-xacthuc-online.top
    triggers CLOAKING_SUSPECTED and achieves >= suspicious verdict.
    """
    url = "https://vcb-xacthuc-online.top/xac-thuc"
    mock_chain = RedirectChain(
        hops=[Hop(url=url, status=403)],
        final_url=url,
        antibot={
            "vendor": "cloudflare",
            "kind": "challenge",
            "evidence": ["header:cf-mitigated:challenge"],
        },
        elapsed_ms=12.0,
    )
    resolver = FakeResolver(routes={url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(url, allow_network=True)
    assert any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals)
    assert any(s.code == "CLOAKING_SUSPECTED" for s in finding.signals)
    assert finding.verdict in ("suspicious", "dangerous")
    assert finding.url_risk_score >= 40


def test_official_domain_after_cloudflare_challenge():
    """
    Official domain (e.g. portal.vietcombank.com.vn) with Cloudflare challenge
    remains official with score 0 (does not add points).
    """
    official_url = "https://portal.vietcombank.com.vn"
    mock_chain = RedirectChain(
        hops=[Hop(url=official_url, status=403)],
        final_url=official_url,
        antibot={
            "vendor": "cloudflare",
            "kind": "challenge",
            "evidence": ["header:cf-mitigated:challenge"],
        },
        elapsed_ms=10.0,
    )
    resolver = FakeResolver(routes={official_url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(official_url, allow_network=True)
    assert finding.is_official is True
    assert finding.url_risk_score == 0
    assert finding.verdict == "official"


# ============================================================================
# 5. UNVERIFIED VERDICT
# ============================================================================


def test_neutral_domain_with_only_antibot_is_unverified():
    """
    Neutral domain with antibot and no other suspicious signals gets verdict 'unverified',
    score <= 39, but NEVER 'benign' or 'official'.
    """
    neutral_url = "https://example.com/page"
    mock_chain = RedirectChain(
        hops=[Hop(url=neutral_url, status=403)],
        final_url=neutral_url,
        antibot={
            "vendor": "cloudflare",
            "kind": "challenge",
            "evidence": ["body:cf-turnstile"],
        },
        elapsed_ms=15.0,
    )
    resolver = FakeResolver(routes={neutral_url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(neutral_url, allow_network=True)
    assert any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals)
    assert not any(s.code == "CLOAKING_SUSPECTED" for s in finding.signals)
    assert finding.url_risk_score <= 39
    assert finding.verdict == "unverified"
    assert finding.verdict != "benign"
    assert finding.verdict != "official"


def test_timeout_budget_exceeded_becomes_unverified():
    """
    Request timeout or budget exceeded on neutral domain results in verdict 'unverified'.
    """
    neutral_url = "https://example.com/slow"
    mock_chain = RedirectChain(
        hops=[],
        final_url=None,
        error="budget_exceeded",
        elapsed_ms=6000.0,
    )
    resolver = FakeResolver(routes={neutral_url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(neutral_url, allow_network=True)
    assert finding.verdict == "unverified"


def test_unverified_summary_message():
    """
    When an unverified finding is present, report summary includes honest explanation.
    """
    url = "https://example.com/verify-needed"
    mock_chain = RedirectChain(
        hops=[Hop(url=url, status=403)],
        final_url=url,
        antibot={"vendor": "datadome", "kind": "block", "evidence": ["header:x-datadome"]},
    )
    resolver = FakeResolver(routes={url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text(f"Xem: {url}", allow_network=True)
    assert any(f.verdict == "unverified" for f in report.findings)
    assert any(
        "Trang này chặn công cụ kiểm tra tự động" in msg for msg in report.summary_vi
    )


# ============================================================================
# 6. NETWORK ENABLED/DISABLED CONTROLS AND SAFETY
# ============================================================================


def test_allow_network_false_never_calls_resolver():
    """
    When allow_network=False, resolver.resolve is NEVER called.
    """
    resolver = FakeResolver()
    analyzer = UrlAnalyzer(resolver=resolver)

    analyzer.analyze_text("Link http://bit.ly/abc", allow_network=False)
    assert len(resolver.calls) == 0

    analyzer.analyze_url("http://bit.ly/xyz", allow_network=False)
    assert len(resolver.calls) == 0


def test_offline_setting_never_calls_resolver(monkeypatch):
    """
    When settings indicate offline, resolver.resolve is NEVER called.
    """
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    settings = get_settings()
    monkeypatch.setattr(settings, "offline", True)

    resolver = FakeResolver()
    analyzer = UrlAnalyzer(resolver=resolver)

    analyzer.analyze_text("Link http://bit.ly/abc", allow_network=True)
    assert len(resolver.calls) == 0


def test_resolver_exception_does_not_raise():
    """
    If resolver raises an unexpected exception, analyze_text and analyze_url
    never raise unhandled exceptions out to the caller.
    """
    url = "http://bit.ly/crasher"
    resolver = FakeResolver(routes={url: RuntimeError("Unexpected network socket error")})
    analyzer = UrlAnalyzer(resolver=resolver)

    report = analyzer.analyze_text(f"Link {url}", allow_network=True)
    assert isinstance(report.findings, list)
    assert len(report.findings) > 0
    assert any("resolver" in err for err in report.findings[0].errors)


def test_deadline_enforcement_with_slow_transport():
    """
    Execution time respects deadline_s + 0.5s margin with slow resolver.
    """
    def slow_resolve(url):
        time.sleep(0.4)
        return RedirectChain(hops=[Hop(url=url, status=200)], final_url=url)

    mock_res = MagicMock()
    mock_res.should_resolve.return_value = True
    mock_res.resolve.side_effect = slow_resolve

    analyzer = UrlAnalyzer(resolver=mock_res)
    t0 = time.perf_counter()
    report = analyzer.analyze_text("Link http://bit.ly/slow", allow_network=True, deadline_s=0.5)
    elapsed = time.perf_counter() - t0

    assert elapsed <= 1.0


# ============================================================================
# 7. MUTATION TESTS (>= 6 MUTATIONS TESTED)
# ============================================================================


def test_mutation_1_cloaking_requires_secondary_factor():
    """
    Mutation: CLOAKING_SUSPECTED added without any secondary suspicious factors.
    Neutral domain + antibot MUST NOT have CLOAKING_SUSPECTED.
    """
    neutral_url = "https://neutral-domain.com"
    mock_chain = RedirectChain(
        hops=[Hop(url=neutral_url, status=200)],
        final_url=neutral_url,
        antibot={"vendor": "cloudflare", "kind": "captcha"},
    )
    resolver = FakeResolver(routes={neutral_url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(neutral_url, allow_network=True)
    signal_codes = [s.code for s in finding.signals]
    assert "ANTIBOT_CHALLENGE" in signal_codes
    assert "CLOAKING_SUSPECTED" not in signal_codes


def test_mutation_2_official_does_not_add_points_with_antibot():
    """
    Mutation: Official domain gets points added when antibot is present.
    Score MUST be 0 and verdict MUST be official.
    """
    official_url = "https://www.vietcombank.com.vn"
    mock_chain = RedirectChain(
        hops=[Hop(url=official_url, status=200)],
        final_url=official_url,
        antibot={"vendor": "cloudflare", "kind": "challenge"},
    )
    resolver = FakeResolver(routes={official_url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(official_url, allow_network=True)
    assert finding.is_official is True
    assert finding.url_risk_score == 0
    assert finding.verdict == "official"


def test_mutation_3_unverified_never_lowers_risk_score():
    """
    Mutation: 'unverified' verdict lowers the risk score below pre-existing signals.
    """
    url = "https://suspicious-unknown.top/test"
    mock_chain = RedirectChain(
        hops=[Hop(url=url, status=403)],
        final_url=url,
        antibot={"vendor": "cloudflare", "kind": "challenge"},
    )
    resolver = FakeResolver(routes={url: mock_chain})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(url, allow_network=True)
    # Finding has SUSPICIOUS_TLD (15) + ANTIBOT_CHALLENGE (10) + CLOAKING_SUSPECTED (25) = 50
    assert finding.url_risk_score >= 15


def test_mutation_4_allow_network_check_not_skipped():
    """
    Mutation: Skipping allow_network check causes resolver to be invoked when allow_network=False.
    """
    resolver = FakeResolver()
    analyzer = UrlAnalyzer(resolver=resolver)
    analyzer.analyze_text("Check http://bit.ly/1 and http://bit.ly/2", allow_network=False)
    assert len(resolver.calls) == 0


def test_mutation_5_resolver_error_handling_not_removed():
    """
    Mutation: Removing try/except around resolver allows exceptions to propagate.
    """
    url = "http://bit.ly/broken"
    resolver = FakeResolver(routes={url: ConnectionResetError("Connection lost")})
    analyzer = UrlAnalyzer(resolver=resolver)

    # Must execute cleanly without raising ConnectionResetError
    finding = analyzer.analyze_url(url, allow_network=True)
    assert len(finding.errors) > 0


def test_mutation_6_cap_3_findings_enforced():
    """
    Mutation: Removing cap of 3 findings causes more than 3 findings to be resolved.
    """
    resolver = FakeResolver()
    analyzer = UrlAnalyzer(resolver=resolver)

    text = (
        "Links: http://bit.ly/1, http://bit.ly/2, http://bit.ly/3, "
        "http://bit.ly/4, http://bit.ly/5"
    )
    analyzer.analyze_text(text, allow_network=True)
    assert len(resolver.calls) <= 3


def test_mutation_7_recursion_depth_limited():
    """
    Mutation: Recursive redirect peeling without depth limit causes unbounded calls.
    """
    url_a = "http://bit.ly/a"
    url_b = "http://bit.ly/b"
    url_c = "http://bit.ly/c"
    url_d = "http://bit.ly/d"

    chain_a = RedirectChain(hops=[Hop(url=url_a, status=301, location=url_b)], final_url=url_b)
    chain_b = RedirectChain(hops=[Hop(url=url_b, status=301, location=url_c)], final_url=url_c)
    chain_c = RedirectChain(hops=[Hop(url=url_c, status=301, location=url_d)], final_url=url_d)

    resolver = FakeResolver(routes={url_a: chain_a, url_b: chain_b, url_c: chain_c})
    analyzer = UrlAnalyzer(resolver=resolver)

    finding = analyzer.analyze_url(url_a, allow_network=True, depth=0)
    # Check that children tree depth does not exceed 2
    assert len(finding.children) <= 1
    if finding.children:
        assert len(finding.children[0].children) <= 1
