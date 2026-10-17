import pytest
from codebase.url_analysis.blacklist import PhishBlacklist
from codebase.url_analysis.parse import parse_url


class TestBlacklistExactMatch:
    def test_exact_host_and_registrable_match(self):
        bl = PhishBlacklist(
            hosts={"malicious.xyz"},
            registrables={"badsite.top"},
            use_default_samples=False,
        )

        # Exact host hit
        res1 = bl.lookup(parse_url("http://malicious.xyz/login"))
        assert res1["hit"] is True
        assert res1["level"] == "host"

        # Registrable domain hit (subdomain of badsite.top)
        res2 = bl.lookup(parse_url("http://sub.badsite.top/account"))
        assert res2["hit"] is True
        assert res2["level"] == "registrable"

        # Non-matching domain
        res3 = bl.lookup(parse_url("https://vietcombank.com.vn/portal"))
        assert res3["hit"] is False
        assert res3["level"] is None

    def test_no_substring_matching_mutation(self):
        """Verify that partial / substring occurrences are NOT treated as hits."""
        bl = PhishBlacklist(
            hosts={"malicious.xyz"},
            registrables={"badsite.top"},
            use_default_samples=False,
        )

        # Host containing malicious.xyz as substring
        assert bl.lookup(parse_url("http://notmalicious.xyz/test"))["hit"] is False
        assert bl.lookup(parse_url("http://malicious.xyz.attacker.com/test"))["hit"] is False
        assert bl.lookup(parse_url("http://mybadsite.top/test"))["hit"] is False


class TestBlacklistPlatformExclusion:
    def test_platform_domains_never_added_to_registrables(self):
        rows = [
            {"domain": "sites.google.com/view/scam-phish", "label": "phishing", "split": "train"},
            {"domain": "facebook.com/fake-fanpage", "label": "phishing", "split": "train"},
            {"domain": "phish-corp.weebly.com", "label": "phishing", "split": "train"},
        ]
        bl = PhishBlacklist.from_dataset(rows)

        # Platform domain must NOT be in registrables
        assert "sites.google.com" not in bl.registrables
        assert "google.com" not in bl.registrables
        assert "facebook.com" not in bl.registrables
        assert "weebly.com" not in bl.registrables

        # Benign pages on platform must NOT be flagged
        res_benign = bl.lookup(parse_url("https://sites.google.com/view/legit-project"))
        assert res_benign["hit"] is False

        # Specific path recorded on platform is flagged
        res_phish = bl.lookup(parse_url("https://sites.google.com/view/scam-phish"))
        assert res_phish["hit"] is True
        assert res_phish["level"] == "path"


class TestBlacklistMissingDataAndSplits:
    def test_missing_data_runs_without_error(self):
        bl = PhishBlacklist.from_dataset(data_source="/invalid/non_existent/data_dir")
        assert isinstance(bl, PhishBlacklist)
        # Does not crash, handles lookup cleanly
        res = bl.lookup(parse_url("https://example.com"))
        assert res["hit"] is False

    def test_exclude_splits_filters_test_data(self):
        rows = [
            {"domain": "train-phish.xyz", "label": "phishing", "split": "train"},
            {"domain": "val-phish.xyz", "label": "phishing", "split": "val"},
            {"domain": "test-leak.xyz", "label": "phishing", "split": "test"},
        ]
        bl = PhishBlacklist.from_dataset(rows, exclude_splits=["test"])

        assert bl.lookup(parse_url("http://train-phish.xyz"))["hit"] is True
        assert bl.lookup(parse_url("http://val-phish.xyz"))["hit"] is True
        # test-leak.xyz MUST be excluded to prevent data leakage
        assert bl.lookup(parse_url("http://test-leak.xyz"))["hit"] is False


class TestBlacklistFalsePositiveFixes:
    """
    Requirements 3(a):
    With fake blacklist:
      - host platform không hit
      - subdomain platform không hit
      - official brand không hit
      - host xung đột nhãn không hit
      - host phishing lạ vẫn hit (exact host và registrable)
      - URL đầy đủ có path trên nền tảng hit khi trùng đúng
    """

    @pytest.fixture
    def fake_blacklist(self):
        rows = [
            # Platform hosts with no path or root path
            {"domain": "facebook.com", "label": "phishing", "split": "train"},
            {"domain": "www.facebook.com", "label": "phishing", "split": "train"},
            {"domain": "google.com", "label": "phishing", "split": "train"},
            {"domain": "docs.google.com", "label": "phishing", "split": "train"},
            {"domain": "meet.google.com", "label": "phishing", "split": "train"},
            {"domain": "zalo.me", "label": "phishing", "split": "train"},
            {"domain": "github.io", "label": "phishing", "split": "train"},
            # Official brand domain
            {"domain": "vietcombank.com.vn", "label": "phishing", "split": "train"},
            {"domain": "ebanking.vietcombank.com.vn", "label": "phishing", "split": "train"},
            # Conflicted host (appeared in phishing AND in benign)
            {"domain": "conflict.com", "label": "phishing", "split": "train"},
            {"domain": "conflict.com", "label": "benign", "split": "train"},
            {"domain": "sub.shared-portal.vn", "label": "phishing", "split": "train"},
            {"domain": "shared-portal.vn", "label": "benign", "split": "train"},
            # Real phishing domains (unrecognized)
            {"domain": "really-evil-phish.xyz", "label": "phishing", "split": "train"},
            {"domain": "sub.stealer-token.top", "label": "phishing", "split": "train"},
            # Platform with exact path recorded
            {"domain": "sites.google.com/view/scam-phish", "label": "phishing", "split": "train"},
            {"domain": "facebook.com/fake-fanpage", "label": "phishing", "split": "train"},
        ]
        return PhishBlacklist.from_dataset(rows, use_cache=False)

    def test_platform_host_no_hit(self, fake_blacklist):
        assert fake_blacklist.lookup(parse_url("https://facebook.com/groups/123"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://google.com/maps/place/Ha+Noi"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://zalo.me/g/abc"))["hit"] is False

    def test_platform_subdomain_no_hit(self, fake_blacklist):
        assert fake_blacklist.lookup(parse_url("https://www.facebook.com/groups/123"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://docs.google.com/document/d/1"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://meet.google.com/abc-defg-hij"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://my-user.github.io/project"))["hit"] is False

    def test_official_brand_and_subdomain_no_hit(self, fake_blacklist):
        assert fake_blacklist.lookup(parse_url("https://vietcombank.com.vn/portal"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://ebanking.vietcombank.com.vn/login"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://shopee.vn/order"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://dichvucong.gov.vn/home"))["hit"] is False

    def test_conflicted_host_no_hit(self, fake_blacklist):
        assert fake_blacklist.lookup(parse_url("http://conflict.com/login"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("http://shared-portal.vn/portal"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("http://sub.shared-portal.vn/portal"))["hit"] is False

    def test_unrecognized_phishing_host_and_registrable_hits(self, fake_blacklist):
        # Exact host hit
        res1 = fake_blacklist.lookup(parse_url("http://really-evil-phish.xyz/login"))
        assert res1["hit"] is True
        assert res1["level"] == "host"

        # Registrable domain hit
        res2 = fake_blacklist.lookup(parse_url("http://sub.stealer-token.top/verify"))
        assert res2["hit"] is True
        assert res2["level"] in ("host", "registrable")

    def test_platform_exact_path_matches(self, fake_blacklist):
        # Exact matching path on platform
        res1 = fake_blacklist.lookup(parse_url("https://sites.google.com/view/scam-phish"))
        assert res1["hit"] is True
        assert res1["level"] == "path"

        res2 = fake_blacklist.lookup(parse_url("https://facebook.com/fake-fanpage"))
        assert res2["hit"] is True
        assert res2["level"] == "path"

        # Subdomain www.facebook.com with exact path also matches
        res3 = fake_blacklist.lookup(parse_url("https://www.facebook.com/fake-fanpage"))
        assert res3["hit"] is True
        assert res3["level"] == "path"

        # Different path on the same platform does NOT match
        assert fake_blacklist.lookup(parse_url("https://sites.google.com/view/legit-project"))["hit"] is False
        assert fake_blacklist.lookup(parse_url("https://facebook.com/legit-fanpage"))["hit"] is False


class TestBlacklistMutations:
    """
    Mutation testing (3 mutations requested):
    1. Bỏ nhóm platform
    2. Bỏ nhóm official
    3. Bỏ conflicted hosts
    """

    def test_mutation_1_omitting_platform_group_fails(self):
        # Mutated: empty platform_domains set (platform filtering disabled)
        bl_mutated = PhishBlacklist(
            hosts={"docs.google.com", "my-site.github.io"},
            platform_domains=set(),
            use_default_samples=False,
        )
        # Without platform protection, benign platform URLs hit the blacklist
        assert bl_mutated.lookup(parse_url("https://docs.google.com/document/d/1"))["hit"] is True
        assert bl_mutated.lookup(parse_url("https://my-site.github.io/project"))["hit"] is True

        # Normal: with platform protection, they never hit
        bl_normal = PhishBlacklist(
            hosts={"docs.google.com", "my-site.github.io"},
            use_default_samples=False,
        )
        assert bl_normal.lookup(parse_url("https://docs.google.com/document/d/1"))["hit"] is False
        assert bl_normal.lookup(parse_url("https://my-site.github.io/project"))["hit"] is False

    def test_mutation_2_omitting_official_group_fails(self):
        # Mutated: empty official_domains set (official brand filtering disabled)
        bl_mutated = PhishBlacklist(
            hosts={"vietcombank.com.vn"},
            official_domains=set(),
            use_default_samples=False,
        )
        # Without official protection, brand domain hits the blacklist
        assert bl_mutated.lookup(parse_url("https://vietcombank.com.vn/portal"))["hit"] is True

        # Normal: with official protection, brand domain never hits
        bl_normal = PhishBlacklist(
            hosts={"vietcombank.com.vn"},
            use_default_samples=False,
        )
        assert bl_normal.lookup(parse_url("https://vietcombank.com.vn/portal"))["hit"] is False

    def test_mutation_3_omitting_conflicted_hosts_fails(self):
        # Mutated: empty conflicted_hosts set (conflicted domain filtering disabled)
        bl_mutated = PhishBlacklist(
            hosts={"conflict.com"},
            conflicted_hosts=set(),
            use_default_samples=False,
        )
        # Without conflicted protection, conflicted domain hits
        assert bl_mutated.lookup(parse_url("http://conflict.com/login"))["hit"] is True

        # Normal: with conflicted protection, conflicted domain is excluded
        bl_normal = PhishBlacklist(
            hosts={"conflict.com"},
            conflicted_hosts={"conflict.com"},
            use_default_samples=False,
        )
        assert bl_normal.lookup(parse_url("http://conflict.com/login"))["hit"] is False

