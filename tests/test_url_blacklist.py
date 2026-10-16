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
