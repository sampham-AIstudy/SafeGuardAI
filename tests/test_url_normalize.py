import pytest
from codebase.url_analysis.models import (
    Candidate,
    ObfuscationStep,
    UrlAnalysisReport,
    UrlFinding,
    UrlSignal,
)
from codebase.url_analysis.normalize import (
    MAX_TEXT_CHARS,
    normalize_for_urls,
)


class TestUrlNormalize:
    """Tests for URL normalization and refanging per UPGRADE_PLAN Phase 2A."""

    @pytest.mark.parametrize(
        "input_text,expected_contains,expected_techniques",
        [
            # 1. Defang hxxps and [.]
            (
                "hxxps://vietcombank-xacthuc[.]com/dang-nhap",
                "https://vietcombank-xacthuc.com/dang-nhap",
                {"defanged"},
            ),
            # 2. Defang [:]//
            (
                "https[:]//acb-online-verify[.]com",
                "https://acb-online-verify.com",
                {"defanged"},
            ),
            # 3. Defang (.)
            (
                "vietcombank(.)com(.)vn",
                "vietcombank.com.vn",
                {"defanged"},
            ),
            # 4. 'hxxp' uppercase
            (
                "HXXPS://VIETCOMBANK-XACTHUC.COM",
                "HTTPS://VIETCOMBANK-XACTHUC.COM",
                {"defanged"},
            ),
            (
                "HXXP://VIETCOMBANK-XACTHUC.COM",
                "HTTP://VIETCOMBANK-XACTHUC.COM",
                {"defanged"},
            ),
            # 5. [dot] and (dot)
            (
                "vietcombank[dot]com",
                "vietcombank.com",
                {"defanged"},
            ),
            (
                "vietcombank(dot)com",
                "vietcombank.com",
                {"defanged"},
            ),
            (
                "vietcombank{dot}com",
                "vietcombank.com",
                {"defanged"},
            ),
            # 6. Fullwidth
            (
                "ｈｔｔｐｓ：／／ｖｃｂ－ｘａｃｍｉｎｈ．ｃｏｍ",
                "https://vcb-xacminh.com",
                {"fullwidth"},
            ),
            # 7. Zero-width in host (using escape sequence, not raw hidden char)
            (
                "https://vietcom\u200bbank.com.vn/login",
                "https://vietcombank.com.vn/login",
                {"zero_width"},
            ),
            # 8. Odd dot '。'
            (
                "vietcombank\u3002com\u3002vn",
                "vietcombank.com.vn",
                {"defanged"},
            ),
            # 9. HTML entities
            (
                "https://vcb&#46;com/test?a=1&amp;b=2",
                "https://vcb.com/test?a=1&b=2",
                {"html_entity"},
            ),
            # 10. Defanged ' dot ' and ' . '
            (
                "vcb dot com",
                "vcb.com",
                {"defanged"},
            ),
            (
                "vcb . com",
                "vcb.com",
                {"defanged"},
            ),
            (
                "vcb . com . vn",
                "vcb.com.vn",
                {"defanged"},
            ),
        ],
    )
    def test_normalize_transformations(self, input_text, expected_contains, expected_techniques):
        clean, steps, stats = normalize_for_urls(input_text)
        assert expected_contains in clean
        assert len(steps) > 0
        recorded_techniques = {s.technique for s in steps}
        assert expected_techniques.issubset(recorded_techniques)
        for s in steps:
            assert len(s.before) <= 200
            assert len(s.after) <= 200
            assert s.detail_vi != ""

    @pytest.mark.parametrize(
        "normal_text",
        [
            "Ok. Com đi chơi",
            "giá 1.5 triệu",
            "Anh A. Nguyễn",
            "Chào bạn. Tôi là người dùng bình thường.",
            "Số dư tài khoản là 500.000 VNĐ.",
            "vcb dot notatld",
            "vcb . notatld",
        ],
    )
    def test_normal_sentences_unchanged(self, normal_text):
        """Ensure standard sentences and abbreviations are not corrupted."""
        clean, steps, stats = normalize_for_urls(normal_text)
        assert clean == normal_text
        assert len(steps) == 0

    def test_idempotence(self):
        """Test that running normalize twice yields the same result with 0 steps on second pass."""
        samples = [
            "hxxps://vietcombank-xacthuc[.]com/dang-nhap",
            "ｈｔｔｐｓ：／／ｖｃｂ－ｘａｃｍｉｎｈ．ｃｏｍ",
            "https://vietcom\u200bbank.com.vn/login",
            "vcb dot com dot vn",
            "Ok. Com đi chơi",
            "https[:]//acb-online-verify[.]com",
        ]
        for s in samples:
            clean1, steps1, stats1 = normalize_for_urls(s)
            clean2, steps2, stats2 = normalize_for_urls(clean1)
            assert clean1 == clean2, f"Failed idempotence for: {s}"
            assert len(steps2) == 0, f"Expected 0 steps on second pass for: {clean1}, got {steps2}"

    def test_zero_width_count_and_stats(self):
        text = "vcb\u200b\u200c\u200d.com\ufeff"
        clean, steps, stats = normalize_for_urls(text)
        assert clean == "vcb.com"
        assert stats.removed_zero_width_chars == 4
        assert stats["removed_zero_width_chars"] == 4
        assert any(s.technique == "zero_width" for s in steps)

    def test_truncation_limit(self):
        huge_text = "a" * (MAX_TEXT_CHARS + 5000)
        clean, steps, stats = normalize_for_urls(huge_text)
        assert len(clean) == MAX_TEXT_CHARS
        assert stats.truncated is True
        assert stats["truncated"] is True

    def test_models_to_dict_recursive(self):
        step = ObfuscationStep(
            technique="defanged",
            detail_vi="Khôi phục scheme",
            before="hxxp://a.com",
            after="http://a.com",
        )
        sig = UrlSignal(
            code="USERINFO_BRAND_DECOY",
            severity="critical",
            weight=60,
            message_vi="Tên đăng nhập giả mạo",
            evidence="userinfo decoy",
        )
        finding = UrlFinding(
            raw="hxxps://vcb[.]com",
            normalized="https://vcb.com",
            final_url="https://vcb.com",
            display_host="vcb.com",
            effective_host="vcb.com",
            effective_host_unicode="vcb.com",
            registrable_domain="vcb.com",
            is_official=False,
            brand_match={"brand_id": "vcb"},
            source="text",
            obfuscation_chain=[step],
            signals=[sig],
        )
        report = UrlAnalysisReport(
            findings=[finding],
            max_url_risk=60,
            has_obfuscation=True,
            critical_codes=["USERINFO_BRAND_DECOY"],
            summary_vi=["Phát hiện URL nguy hiểm"],
        )
        cand = Candidate(raw="https://vcb.com", start=0, end=15, source="text")

        d_report = report.to_dict()
        assert isinstance(d_report, dict)
        assert d_report["max_url_risk"] == 60
        assert len(d_report["findings"]) == 1
        assert d_report["findings"][0]["obfuscation_chain"][0]["technique"] == "defanged"
        assert d_report["findings"][0]["signals"][0]["code"] == "USERINFO_BRAND_DECOY"

        d_cand = cand.to_dict()
        assert isinstance(d_cand, dict)
        assert d_cand["raw"] == "https://vcb.com"
