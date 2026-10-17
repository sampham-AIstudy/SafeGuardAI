import csv
from pathlib import Path
import random
import time
import pytest

from codebase.url_analysis.analyzer import UrlAnalyzer
from codebase.url_analysis.blacklist import PhishBlacklist
from codebase.url_analysis.brands import BrandCatalog


@pytest.fixture(scope="module")
def analyzer():
    # Use standard catalog and a blacklist that includes known test phishing hosts
    cat = BrandCatalog.load()
    bl = PhishBlacklist(
        hosts={"vcb-verify.xyz", "vcb-secure.xyz", "evil-vcb.top", "shopee-hoantien.top"},
        registrables={"auth-token-valid.cc"},
    )
    return UrlAnalyzer(catalog=cat, blacklist=bl)


# ─────────────────────────────────────────────────────────────────────────────
# (c) Minimum 30 samples from UPGRADE_PLAN table (Section 4 / Phase 2)
# ─────────────────────────────────────────────────────────────────────────────
TABLE_CASES = [
    # 1
    ("hxxps://vietcombank-xacthuc[.]com/dang-nhap", "vietcombank-xacthuc.com", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 2
    ("https[:]//acb-online-verify[.]com", "acb-online-verify.com", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 3
    ("vietcombank(.)com(.)vn(.)secure-login(.)top", "vietcombank.com.vn.secure-login.top", {"COMBOSQUAT_BRAND", "SUSPICIOUS_TLD"}, ("suspicious", "dangerous")),
    # 4
    ("https://vietcombank.com.vn@vcb-secure.xyz/login", "vcb-secure.xyz", {"USERINFO_BRAND_DECOY"}, ("dangerous",)),
    # 5: BẮT BUỘC C1
    ("https://vietcombank.com.vn:443@vcb-secure.xyz/login", "vcb-secure.xyz", {"USERINFO_BRAND_DECOY"}, ("dangerous",)),
    # 6
    ("https://vietcombank.com.vn%2Flogin@evil-vcb.top/", "evil-vcb.top", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 7
    ("https://evil-vcb.top\\@vietcombank.com.vn/", "evil-vcb.top", {"BACKSLASH_CONFUSION"}, ("suspicious", "dangerous")),
    # 8
    ("https://v\u0456etcombank.com.vn/login", None, {"HOMOGLYPH_BRAND"}, ("suspicious", "dangerous")),
    # 9
    ("http://xn--80ak6aa92e.com", "xn--80ak6aa92e.com", {"PUNYCODE_HOST"}, ("low", "suspicious", "dangerous")),
    # 10
    ("https://sh\u03bfpee.vn/qua", None, {"HOMOGLYPH_BRAND"}, ("suspicious", "dangerous")),
    # 11
    ("https://zal\u043e.me/verify", None, {"HOMOGLYPH_BRAND"}, ("suspicious", "dangerous")),
    # 12
    ("https://sh0pee.vn/nhan-qua", "sh0pee.vn", {"TYPOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 13
    ("https://vietcornbank.com.vn", "vietcornbank.com.vn", {"TYPOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 14
    ("https://vietconbank.vn", "vietconbank.vn", {"TYPOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 15
    ("https://vietcombank.vn/login", "vietcombank.vn", {"BRAND_TLD_SWAP"}, ("suspicious", "dangerous")),
    # 16
    ("https://momo-hoantien.vip", "momo-hoantien.vip", {"COMBOSQUAT_BRAND", "SUSPICIOUS_TLD"}, ("suspicious", "dangerous")),
    # 21
    ("http://103.2.3.4:8080/vcb/login", "103.2.3.4", {"IP_HOST", "NON_STANDARD_PORT", "BRAND_IN_PATH"}, ("suspicious", "dangerous")),
    # 22
    ("bit.ly/3Vcb-KhoaTK", "bit.ly", {"SHORTENER"}, ("low", "suspicious", "dangerous")),
    # 24
    ("https://s.id/abc", "s.id", {"SHORTENER"}, ("low", "suspicious", "dangerous")),
    # 25: BẮT BUỘC C2
    ("https://www.google.com/url?q=https://vcb-verify.xyz/login", "www.google.com", {"OPEN_REDIRECT_TRUSTED"}, ("dangerous", "suspicious")),
    # 26
    ("https://l.facebook.com/l.php?u=https%3A%2F%2Fshopee-hoantien.top%2F", "l.facebook.com", {"OPEN_REDIRECT_TRUSTED"}, ("dangerous", "suspicious")),
    # 28
    ("https://track.mail-vn.com/c?u=aHR0cHM6Ly92Y2ItdmVyaWZ5Lnh5ei9sb2dpbg", "track.mail-vn.com", {"BASE64_URL"}, ("suspicious", "dangerous")),
    # 29
    ("https://cdn.mail-vn.net/r/68747470733a2f2f7663622d7665726966792e78797a", "cdn.mail-vn.net", {"HEX_URL"}, ("suspicious", "dangerous")),
    # 30
    ("https://%76%69%65%74combank-xacminh.com/", "vietcombank-xacminh.com", {"ENCODED_HOST", "COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 31
    ("https://vietcombank.com.vn\u200b.secure-login.top/", "vietcombank.com.vn.secure-login.top", {"ZERO_WIDTH", "COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 35
    ("http://www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-token-valid.cc/login", "www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-token-valid.cc", {"COMBOSQUAT_BRAND", "DEEP_SUBDOMAIN", "SUSPICIOUS_TLD"}, ("suspicious", "dangerous")),
    # 36
    ("https://login.microsoftonline.com.common.oauth2.secure-login-gateway.info/token", "login.microsoftonline.com.common.oauth2.secure-login-gateway.info", {"DEEP_SUBDOMAIN", "SUSPICIOUS_TLD"}, ("low", "suspicious", "dangerous")),
    # 37
    ("http://dichvucong-gov.vn.app-download.xyz/VNeID.apk", "dichvucong-gov.vn.app-download.xyz", {"APK_DOWNLOAD"}, ("dangerous",)),
    # 38
    ("http://vneid-capnhat.apk", "vneid-capnhat.apk", {"INVALID_TLD", "APK_DOWNLOAD"}, ("dangerous",)),
    # 39
    ("https://vietcombank-hotro.weebly.com", "vietcombank-hotro.weebly.com", {"FREE_HOSTING", "COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 40: BẮT BUỘC Sites Google
    ("https://sites.google.com/view/vcb-xac-thuc", "sites.google.com", {"FREE_HOSTING", "BRAND_IN_PATH"}, ("low", "suspicious")),
    # 43
    ("Truy cập vcb-xacminh.com/login).", "vcb-xacminh.com", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 44
    ("vietcombank-xacminh . com", "vietcombank-xacminh.com", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
    # 45
    ("data:text/html;base64,PHNjcmlwdD4=", "", {"DATA_OR_JS_URI"}, ("suspicious", "dangerous")),
    # 46
    ("HTTPS://VietComBank-XacMinh.COM", "vietcombank-xacminh.com", {"COMBOSQUAT_BRAND"}, ("suspicious", "dangerous")),
]


class TestTableCases:
    @pytest.mark.parametrize(
        "raw_text,expected_host,expected_codes,allowed_verdicts",
        TABLE_CASES,
    )
    def test_plan_table_cases(self, analyzer, raw_text, expected_host, expected_codes, allowed_verdicts):
        report = analyzer.analyze_text(raw_text)
        assert len(report.findings) > 0, f"No finding extracted for: {raw_text}"
        finding = report.findings[0]

        if expected_host is not None and finding.effective_host:
            # Check expected host or punycode equivalent
            assert expected_host.lower() in (finding.effective_host.lower(), finding.effective_host_unicode.lower())

        detected_codes = {s.code for s in finding.signals}
        # Include child codes if finding has children
        for ch in finding.children:
            detected_codes.update(s.code for s in ch.signals)

        missing = expected_codes - detected_codes
        assert not missing, f"Missing codes: {missing} in detected: {detected_codes} for {raw_text}"
        assert finding.verdict in allowed_verdicts, f"Verdict {finding.verdict} not in {allowed_verdicts} for {raw_text}"


class TestMandatoryCases:
    def test_c1_userinfo_brand_decoy_with_port(self, analyzer):
        """Lỗi C1 cũ: userinfo :443@ qua mặt whitelist."""
        url = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
        finding = analyzer.analyze_url(url)
        assert finding.effective_host == "vcb-secure.xyz"
        assert finding.verdict == "dangerous"
        sig_codes = {s.code for s in finding.signals}
        assert "USERINFO_BRAND_DECOY" in sig_codes

    def test_c2_open_redirect_with_dangerous_child(self, analyzer):
        """Lỗi C2 cũ: open redirect mượn uy tín domain lớn."""
        url = "https://www.google.com/url?q=https://vcb-verify.xyz/login"
        finding = analyzer.analyze_url(url)
        assert finding.effective_host == "www.google.com"
        sig_codes = {s.code for s in finding.signals}
        assert "OPEN_REDIRECT_TRUSTED" in sig_codes
        assert len(finding.children) == 1
        child = finding.children[0]
        assert child.effective_host == "vcb-verify.xyz"
        assert child.verdict == "dangerous"
        assert finding.verdict == "dangerous"

    def test_sites_google_not_official(self, analyzer):
        """Platform sharing domains must NEVER be marked official."""
        url = "https://sites.google.com/view/vcb-xac-thuc"
        finding = analyzer.analyze_url(url)
        assert finding.is_official is False
        assert finding.verdict != "official"
        assert any(s.code == "BRAND_IN_PATH" for s in finding.signals)


class TestBenignSamples:
    BENIGN_URLS = [
        ("https://vietcombank.com.vn/vi-VN/Ca-nhan", True, "official"),
        ("https://shopee.vn/m/9-9?utm_source=sms", True, "official"),
        ("https://dichvucong.gov.vn/p/home/dvc-trang-chu.html", True, "official"),
        ("https://www.topcv.vn/viec-lam", False, "benign"),
        ("www.garena.vn", False, "benign"),
        ("https://www.facebook.com/groups/123", False, "benign"),
    ]

    @pytest.mark.parametrize("url,expected_official,expected_verdict", BENIGN_URLS)
    def test_benign_urls_never_suspicious_or_dangerous(self, analyzer, url, expected_official, expected_verdict):
        report = analyzer.analyze_text(url)
        assert len(report.findings) > 0
        finding = report.findings[0]
        assert finding.is_official == expected_official
        assert finding.verdict == expected_verdict
        assert finding.verdict not in ("suspicious", "dangerous")
        assert report.max_url_risk < 40

    def test_benign_email_not_extracted(self, analyzer):
        report = analyzer.analyze_text("Liên hệ qua email: hotro@vietcombank.com.vn nhé")
        assert len(report.findings) == 0
        assert report.max_url_risk == 0

    def test_benign_numbers_and_filenames_not_extracted(self, analyzer):
        text = "Số tiền 500.000đ / phiên bản v2.0 / tệp baocao.docx"
        report = analyzer.analyze_text(text)
        assert len(report.findings) == 0
        assert report.max_url_risk == 0


class TestPerformanceAndReDoS:
    def test_performance_20k_chars_20_urls(self, analyzer):
        urls = [f"https://sub{i}.vietcombank-xacthuc{i}.com/login" for i in range(20)]
        padding = "Nội dung tin nhắn bình thường để kiểm tra hiệu năng hệ thống. " * 300
        text = (padding + " ".join(urls))[:20000]

        start = time.perf_counter()
        report = analyzer.analyze_text(text)
        duration_ms = (time.perf_counter() - start) * 1000

        assert len(report.findings) > 0
        assert duration_ms < 150, f"analyze_text exceeded 150ms limit: {duration_ms:.2f}ms"

    def test_adversarial_redos_strings_linear(self, analyzer):
        pairs = [
            ("a" * 25000, "a" * 50000),
            ("a." * 12500 + "!", "a." * 25000 + "!"),
            ("%" * 10000, "%" * 20000),
            ("http://" + "a@" * 2500 + "example.com", "http://" + "a@" * 5000 + "example.com"),
            ("http://" + "a." * 2500 + "com", "http://" + "a." * 5000 + "com"),
            ("[" * 5000 + "http://example.com" + "]" * 5000, "[" * 10000 + "http://example.com" + "]" * 10000),
            ("http://example.com?" + "q=" * 2500, "http://example.com?" + "q=" * 5000),
            ("\u200b" * 5000 + "http://example.com" + "\u200b" * 5000, "\u200b" * 10000 + "http://example.com" + "\u200b" * 10000),
        ]

        for s1, s2 in pairs:
            t0 = time.perf_counter()
            analyzer.analyze_text(s1)
            d1 = time.perf_counter() - t0

            t0 = time.perf_counter()
            analyzer.analyze_text(s2)
            d2 = time.perf_counter() - t0

            assert d1 < 0.3, f"Adversarial string s1 took {d1:.3f}s >= 0.3s"
            assert d2 < 0.3, f"Adversarial string s2 took {d2:.3f}s >= 0.3s"
            # When duration is measurable, verify linear scaling (<= 3x for 2x input)
            if d1 > 0.005:
                ratio = d2 / d1
                assert ratio <= 3.5, f"Scaling ratio exceeded 3x: {ratio:.2f}x"


class TestGarbageInputsRobustness:
    GARBAGE_INPUTS = [
        None,
        "",
        "   \t\n",
        "\x00\x00\x01\x02",
        "123456789",
        "!@#$%^&*()_+=-~`",
        "https://",
        "http:///",
        "http://:80",
        "http://@",
        "http://256.256.256.256",
        "{'json': 'not an url', 'payload': '<script>'}",
    ]

    @pytest.mark.parametrize("garbage", GARBAGE_INPUTS)
    def test_never_raises_on_garbage(self, analyzer, garbage):
        # Must return valid UrlAnalysisReport without raising
        report = analyzer.analyze_text(garbage)
        assert report is not None
        assert isinstance(report.findings, list)


class TestMutationsKilled:
    def test_mutation_1_is_official_raw_endswith_killed(self, analyzer):
        # Mutation: is_official uses raw endswith without dot
        # 'evilvietcombank.com.vn' must NOT be official
        assert analyzer.catalog.is_official("evilvietcombank.com.vn")[0] is False
        assert analyzer.catalog.is_official("vietcombank.com.vn.evil.xyz")[0] is False

    def test_mutation_2_short_brand_substring_killed(self, analyzer):
        # Mutation: brand short token matching substring
        # 'placebo.com' must NOT match 'acb'
        assert analyzer.catalog.brand_match("placebo.com") is None
        assert analyzer.catalog.brand_match("chambank.net") is None

    def test_mutation_3_typosquat_excludes_other_official_brands(self, analyzer):
        # Mutation: typosquat without excluding official domains of other brands
        # 'shb.com.vn' has distance 1 to 'scb' but MUST NOT be flagged as typosquat of 'scb'
        match = analyzer.catalog.brand_match("shb.com.vn")
        assert match is None

    def test_mutation_4_userinfo_decoy_killed(self, analyzer):
        # Mutation: removing USERINFO_BRAND_DECOY check
        finding = analyzer.analyze_url("https://vietcombank.com.vn:443@vcb-secure.xyz/login")
        assert any(s.code == "USERINFO_BRAND_DECOY" for s in finding.signals)

    def test_mutation_5_platform_domains_never_official(self, analyzer):
        # Mutation: treating platform domains as official
        assert analyzer.catalog.is_official("sites.google.com")[0] is False
        assert analyzer.catalog.is_official("facebook.com")[0] is False

    def test_mutation_6_blacklist_substring_killed(self, analyzer):
        # Mutation: blacklist using substring matching
        bl = PhishBlacklist(hosts={"malicious.xyz"}, use_default_samples=False)
        assert bl.lookup("http://notmalicious.xyz")["hit"] is False

    def test_mutation_7_parent_risk_takes_max_with_child(self, analyzer):
        # Mutation: omitting max with child risk
        finding = analyzer.analyze_url("https://www.google.com/url?q=https://vcb-verify.xyz/login")
        assert finding.url_risk_score == finding.children[0].url_risk_score

    def test_mutation_8_recursion_depth_limited(self, analyzer):
        # Mutation: omitting recursion depth cap
        # Nested redirect chain
        deep_url = "https://www.google.com/url?q=https%3A%2F%2Fl.facebook.com%2Fl.php%3Fu%3Dhttps%253A%252F%252Ftrack.mail-vn.com%252Fc%253Fu%253DaHR0cHM6Ly92Y2ItdmVyaWZ5Lnh5ei9sb2dpbg"
        finding = analyzer.analyze_url(deep_url)
        assert finding is not None
        # Does not exceed depth 2 recursion
        current = finding
        depth = 0
        while current.children:
            current = current.children[0]
            depth += 1
        assert depth <= 2


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
HAS_REAL_DATA = DATA_DIR.exists() and (DATA_DIR / "data-phising-VN-ver2" / "splits" / "url_train.csv").exists()


class TestRealDatasetBlacklist:
    """
    Requirements 3(b):
    Real dataset tests with PhishVN blacklist:
      - 30 benign URLs: no BLACKLIST_HIT, verdict not in ('suspicious', 'dangerous')
      - >= 20 random phish hosts (seed 42) from train split: BLACKLIST_HIT and verdict in ('suspicious', 'dangerous')
    """

    BENIGN_30_URLS = [
        "https://www.facebook.com/groups/123",
        "https://zalo.me/g/abc",
        "https://www.google.com/maps/place/Ha+Noi",
        "https://docs.google.com/document/d/1",
        "https://meet.google.com/abc-defg-hij",
        "https://drive.google.com/drive/u/0/my-drive",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://github.com/torvalds/linux",
        "https://vi.wikipedia.org/wiki/Vi%E1%BB%87t_Nam",
        "https://vnexpress.net/thoi-su",
        "https://tuoitre.vn/kinh-doanh.htm",
        "https://thuvienphapluat.vn/van-ban/Bo-may-hanh-chinh",
        "https://www.topcv.vn/viec-lam",
        "https://vietcombank.com.vn/vi-VN/Ca-nhan",
        "https://mbbank.com.vn/personal",
        "https://shopee.vn/m/ma-giam-gia",
        "https://tiki.vn/khuyen-mai",
        "https://zoom.us/j/1234567890",
        "https://forms.gle/abcdef123",
        "https://t.me/telegram",
        "https://instagram.com/p/abc123",
        "https://twitter.com/x/status/123",
        "https://x.com/explore",
        "https://tiktok.com/@tiktok",
        "https://canva.com/design/123",
        "https://linktr.ee/creator",
        "https://medium.com/@author/story-123",
        "https://notion.site/my-page",
        "https://dichvucong.gov.vn/p/home/dvc-trang-chu.html",
    ]

    @pytest.fixture(scope="class")
    def real_analyzer(self):
        if not HAS_REAL_DATA:
            pytest.skip("data/ directory or PhishVN splits not found")
        # Load real blacklist excluding test split to prevent leakage
        bl = PhishBlacklist.from_dataset(exclude_splits=["test"])
        cat = BrandCatalog.load()
        return UrlAnalyzer(catalog=cat, blacklist=bl)

    @pytest.fixture(scope="class")
    def phish_train_samples_20(self):
        if not HAS_REAL_DATA:
            pytest.skip("data/ directory or PhishVN splits not found")
        train_csv = DATA_DIR / "data-phising-VN-ver2" / "splits" / "url_train.csv"
        from codebase.url_analysis.blacklist import (
            _get_platform_and_free_hosting,
            _get_official_domains,
            _extract_host_and_path,
        )

        platform_domains = _get_platform_and_free_hosting()
        official_domains = _get_official_domains()

        phish_hosts: list[str] = []
        benign_hosts: set[str] = set()

        with open(train_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = (row.get("label") or "").strip().lower()
                val = row.get("domain") or row.get("url") or ""
                h, p, reg = _extract_host_and_path(val)
                if not h:
                    continue
                if label == "benign":
                    benign_hosts.add(h)
                    if reg:
                        benign_hosts.add(reg)
                elif label == "phishing":
                    # Filter out platform, official, and conflicted domains
                    if h in platform_domains or any(h.endswith("." + plat) for plat in platform_domains):
                        continue
                    if reg and reg in platform_domains:
                        continue
                    if h in official_domains or any(h.endswith("." + off) for off in official_domains):
                        continue
                    if reg and reg in official_domains:
                        continue
                    phish_hosts.append(h)

        valid_phish = [h for h in dict.fromkeys(phish_hosts) if h not in benign_hosts]
        random.seed(42)
        assert len(valid_phish) >= 20
        return random.sample(valid_phish, 20)

    @pytest.mark.skipif(not HAS_REAL_DATA, reason="data/ directory not found")
    def test_real_blacklist_30_benign_urls_no_blacklist_hit(self, real_analyzer):
        assert len(self.BENIGN_30_URLS) == 30
        for url in self.BENIGN_30_URLS:
            report = real_analyzer.analyze_text(url)
            assert len(report.findings) > 0, f"No finding extracted for {url}"
            finding = report.findings[0]
            sig_codes = {s.code for s in finding.signals}
            for ch in finding.children:
                sig_codes.update(s.code for s in ch.signals)

            assert "BLACKLIST_HIT" not in sig_codes, f"False positive BLACKLIST_HIT for benign url: {url}"
            assert finding.verdict not in ("suspicious", "dangerous"), (
                f"Benign url {url} got verdict {finding.verdict} with score {finding.url_risk_score}"
            )
            assert report.max_url_risk < 40

    @pytest.mark.skipif(not HAS_REAL_DATA, reason="data/ directory not found")
    def test_real_blacklist_20_random_phish_hosts_hit(self, real_analyzer, phish_train_samples_20):
        assert len(phish_train_samples_20) >= 20
        for host in phish_train_samples_20:
            report = real_analyzer.analyze_text(f"http://{host}/login")
            assert len(report.findings) > 0, f"No finding extracted for phish host: {host}"
            finding = report.findings[0]
            sig_codes = {s.code for s in finding.signals}
            assert "BLACKLIST_HIT" in sig_codes, f"Expected BLACKLIST_HIT for real phishing host {host}, got {sig_codes}"
            assert finding.verdict in ("suspicious", "dangerous")

