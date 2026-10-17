import time
import pytest

from codebase.url_analysis.extract import (
    MAX_URLS,
    extract_candidates,
    trim_url,
)
from codebase.url_analysis.models import Candidate
from codebase.url_analysis.normalize import normalize_for_urls


class TestUrlExtract:
    """Tests for URL extraction per UPGRADE_PLAN Phase 2A."""

    # 1. Minimum 25 positive test cases
    @pytest.mark.parametrize(
        "text,expected_url,expected_source,expected_display",
        [
            # 1. userinfo @
            ("Truy cập https://vietcombank.com.vn@vcb-secure.xyz/login ngay", "https://vietcombank.com.vn@vcb-secure.xyz/login", "text", None),
            # 2. backslash
            ("Link: https://evil-vcb.top\\@vietcombank.com.vn/ an toan", "https://evil-vcb.top\\@vietcombank.com.vn/", "text", None),
            # 3. IP decimal
            ("Máy chủ: http://2130706433/ test", "http://2130706433/", "text", None),
            # 4. IP hex
            ("Vào http://0x5DB8D822/ ngay", "http://0x5DB8D822/", "text", None),
            # 5. IP octal
            ("Xem http://0135.0270.0330.042/ tại đây", "http://0135.0270.0330.042/", "text", None),
            # 6. IP shortened with scheme
            ("Link http://93.12113954/ kiểm tra", "http://93.12113954/", "text", None),
            # 7. bit.ly without scheme
            ("Nhấn vào bit.ly/xxx để nhận quà", "bit.ly/xxx", "text", None),
            # 8. Bare domain with trailing punctuation
            ("Xem tại (vcb-xacminh.com/login).", "vcb-xacminh.com/login", "text", None),
            # 9. Markdown mismatch
            ("Xem [https://shopee.vn](https://shopee-hoantien.top) nhé", "https://shopee-hoantien.top", "markdown", "https://shopee.vn"),
            # 10. Anchor mismatch
            ('Nhấn <a href="https://evil.com">https://google.com</a> ngay', "https://evil.com", "anchor", "https://google.com"),
            # 11. Uppercase scheme and host
            ("Vào HTTPS://VietComBank-XacMinh.COM để xác minh", "HTTPS://VietComBank-XacMinh.COM", "text", None),
            # 12. data URI
            ("Xem data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "text", None),
            # 13. javascript URI
            ("Link: javascript:alert(1)", "javascript:alert(1)", "text", None),
            # 14. ftp scheme
            ("Tải ftp://files.example.com/share/app.zip", "ftp://files.example.com/share/app.zip", "text", None),
            # 15. www prefix
            ("Trang chủ www.vietcombank.com.vn chính thức", "www.vietcombank.com.vn", "text", None),
            # 16. www with path
            ("Truy cập www.mbbank.com.vn/ebanking", "www.mbbank.com.vn/ebanking", "text", None),
            # 17. Bare domain with multi-level suffix
            ("Website vietcombank.com.vn an toàn", "vietcombank.com.vn", "text", None),
            # 18. Bare domain with suspicious TLD
            ("Vào vcb-verify.xyz nhận thưởng", "vcb-verify.xyz", "text", None),
            # 19. Bare domain with query string
            ("Link: login-acb.com?ref=123", "login-acb.com?ref=123", "text", None),
            # 20. Bare domain with port
            ("Truy cập vcb-login.com:8080/login", "vcb-login.com:8080/login", "text", None),
            # 21. IPv4 without scheme followed by port
            ("Kết nối 1.2.3.4:8080/path để tiếp tục", "1.2.3.4:8080/path", "text", None),
            # 22. IPv4 without scheme followed by slash
            ("Quản trị tại 127.0.0.1/admin", "127.0.0.1/admin", "text", None),
            # 22b. Bare dotted-quad IPv4 without slash or port
            ("Quản trị tại 192.168.1.1 hệ thống", "192.168.1.1", "text", None),
            # 22c. IPv4 without scheme with path
            ("Đăng nhập 103.2.3.4/login ngay", "103.2.3.4/login", "text", None),
            # 23. Wikipedia URL with balanced parentheses
            ("Tra cứu https://en.wikipedia.org/wiki/Python_(programming_language) chi tiết", "https://en.wikipedia.org/wiki/Python_(programming_language)", "text", None),
            # 24. URL surrounded by quotes
            ('Xem link "https://techcombank.com.vn" nhé', "https://techcombank.com.vn", "text", None),
            # 25. HTTP scheme with subdomains
            ("Đăng nhập http://ebank.bidv.com.vn/wps/portal/", "http://ebank.bidv.com.vn/wps/portal/", "text", None),
        ],
    )
    def test_positive_extraction(self, text, expected_url, expected_source, expected_display):
        cands = extract_candidates(text)
        assert len(cands) >= 1
        urls = [c.raw for c in cands]
        assert expected_url in urls
        target = next(c for c in cands if c.raw == expected_url)
        assert target.source == expected_source
        if expected_display is not None:
            assert target.display_text == expected_display
        if target.start >= 0 and target.end >= 0 and target.source == "text":
            assert text[target.start:target.end] == target.raw

    # 2. Exactly 12 negative test cases that must NOT be extracted
    @pytest.mark.parametrize(
        "negative_text",
        [
            "Liên hệ hotro@vietcombank.com.vn để được hỗ trợ",  # 1. email
            "Số tiền chuyển là 500.000đ bạn nhé",                # 2. amount with currency
            "Nâng cấp lên phiên bản v2.0 hoặc 1.2.3",           # 3. version numbers
            "Vui lòng đọc file baocao.docx đính kèm",           # 4. filename
            "Giá trị pi xấp xỉ 3.14",                           # 5. decimal number
            "Gõ www để tìm kiếm",                               # 6. standalone www
            "Ký hiệu a.b trong toán học",                       # 7. a.b short non-TLD
            "Số hotline: 0912.345.678",                         # 8. phone number
            "Hẹn gặp ngày 12.10.2026",                          # 9. date
            "Du lịch U.S.A mùa hè",                             # 10. abbreviation
            "Xem phim Dr. Strange tối nay",                     # 11. honorific/name
            "Đăng ký tên miền đuôi com.vn giá rẻ",              # 12. standalone suffix com.vn
        ],
    )
    def test_negative_cases_must_not_extract(self, negative_text):
        """Ensure non-URLs are strictly rejected."""
        cands = extract_candidates(negative_text)
        assert len(cands) == 0, f"Expected 0 candidates from '{negative_text}', but got: {[c.raw for c in cands]}"

    def test_multiple_urls_in_one_sentence(self):
        text = "Xem tại https://google.com hoặc vcb-xacminh.com/login và bit.ly/promo"
        cands = extract_candidates(text)
        urls = [c.raw for c in cands]
        assert urls == ["https://google.com", "vcb-xacminh.com/login", "bit.ly/promo"]
        assert len(cands) == 3

    def test_extra_urls_inclusion(self):
        extra = [
            ("https://qr-code.com/scanned", "qr"),
            ("https://ocr-text.com/bill", "ocr", "Hóa đơn tiền điện"),
        ]
        cands = extract_candidates("Không có link trong text", extra_urls=extra)
        assert len(cands) == 2
        assert cands[0].raw == "https://qr-code.com/scanned"
        assert cands[0].source == "qr"
        assert cands[1].raw == "https://ocr-text.com/bill"
        assert cands[1].source == "ocr"
        assert cands[1].display_text == "Hóa đơn tiền điện"

    def test_deduplication_preserves_order(self):
        text = "https://a.com và https://b.com rồi lại https://a.com và https://c.com"
        cands = extract_candidates(text)
        urls = [c.raw for c in cands]
        assert urls == ["https://a.com", "https://b.com", "https://c.com"]
        assert len(cands) == 3

    def test_max_urls_limit(self):
        # 30 unique URLs in text
        links = [f"https://domain{i}.com/path" for i in range(30)]
        text = " ".join(links)
        stats = {}
        cands = extract_candidates(text, stats=stats)
        assert len(cands) == MAX_URLS
        assert cands.truncated is True
        assert stats["truncated"] is True

    def test_long_url_flag(self):
        long_url = "https://example.com/" + "a" * 2100
        cands = extract_candidates(f"Click {long_url}")
        assert len(cands) == 1
        assert cands[0].is_long is True

    # 3. Performance benchmarks (< 0.3s and doubled ratio <= 3x)
    @pytest.mark.parametrize(
        "base_pattern,multiplier",
        [
            ("a", 50000),
            ("a.", 25000),         # + '!'
            ("%", 20000),
            ("http://a@", 5000),
            ("a-", 10000),
            ("(", 10000),
            ("www.", 5000),
            ("x", 20000),          # + '.com'
        ],
    )
    def test_performance_linear_scaling(self, base_pattern, multiplier):
        """
        Verify that normalize + extract completes in < 0.3s for adversarial inputs,
        and execution time ratio when doubling input is <= 3x (strictly linear).
        """
        if base_pattern == "a.":
            s1 = (base_pattern * multiplier) + "!"
            s2 = (base_pattern * (multiplier * 2)) + "!"
        elif base_pattern == "http://a@":
            s1 = "http://" + ("a@" * multiplier)
            s2 = "http://" + ("a@" * (multiplier * 2))
        elif base_pattern == "x":
            s1 = ("x" * multiplier) + ".com"
            s2 = ("x" * (multiplier * 2)) + ".com"
        else:
            s1 = base_pattern * multiplier
            s2 = base_pattern * (multiplier * 2)

        # Warm up
        normalize_for_urls("warmup test https://example.com")

        # Measure s1
        t0 = time.perf_counter()
        clean1, _, _ = normalize_for_urls(s1)
        extract_candidates(clean1)
        t_s1 = time.perf_counter() - t0

        # Measure s2
        t0 = time.perf_counter()
        clean2, _, _ = normalize_for_urls(s2)
        extract_candidates(clean2)
        t_s2 = time.perf_counter() - t0

        assert t_s1 < 0.3, f"Execution took {t_s1:.4f}s for {base_pattern}*N (limit 0.3s)"
        assert t_s2 < 0.3, f"Execution took {t_s2:.4f}s for {base_pattern}*2N (limit 0.3s)"

        # Linear scaling check: if s1 takes measurable time (> 1ms), ratio <= 3.0
        if t_s1 >= 0.002:
            ratio = t_s2 / t_s1
            assert ratio <= 3.0, f"Scaling ratio was {ratio:.2f} > 3.0 for {base_pattern}"

    def test_b1_date_time_fraction_strange_ip_rejection(self):
        """
        B1: Ensure >= 20 non-URL strings (dates with slash, dates with dot, times, fractions,
        ratios, phone numbers, order codes, amounts, versions, and strange IPs without scheme)
        are NEVER extracted as URLs.
        """
        negative_samples = [
            "16/10",
            "20/10",
            "30/10",
            "05/10",
            "20/11",
            "31/10",
            "25/10",
            "22/10",
            "01/01",
            "10/10/2026",
            "1/2",
            "3/4",
            "16.10.2024",
            "05.10.2024",
            "10:15",
            "08:00",
            "16:9",
            "0912.345.678",
            "DH12345/67",
            "500.000đ",
            "v2.0",
            "1.2.3",
            "luc 10:15 16/10. SD: 500.000VND",
            "thanh toán trước ngày 20/10",
            "tỉ lệ 1/2 và phân số 3/4",
            "Server 2130706433 test",
            "Host 0x5DB8D822 kiem tra",
            "Octal 0135.0270.0330.042 here",
            "Shortened 93.12113954 test",
        ]
        assert len(negative_samples) >= 20, "Must test at least 20 negative non-URL samples"
        for sample in negative_samples:
            cands = extract_candidates(sample)
            assert len(cands) == 0, f"Expected 0 candidates for '{sample}', but got {[c.raw for c in cands]}"

    def test_b1_ip_extraction_with_and_without_scheme(self):
        """
        B1: Verify strange IPs are extracted WITH scheme, and only standard dotted-quad
        IPv4 is extracted without scheme.
        """
        # Schemed strange/standard IPs must be extracted
        schemed = [
            ("http://2130706433/", "http://2130706433/"),
            ("http://0x5DB8D822/", "http://0x5DB8D822/"),
            ("http://0135.0270.0330.042/", "http://0135.0270.0330.042/"),
            ("http://93.12113954/", "http://93.12113954/"),
            ("https://103.2.3.4:8080/x", "https://103.2.3.4:8080/x"),
            ("103.2.3.4/login", "103.2.3.4/login"),
            ("192.168.1.1", "192.168.1.1"),
        ]
        assert len(schemed) == 7
        for text, expected in schemed:
            cands = extract_candidates(f"Link {text} here")
            assert len(cands) >= 1, f"Failed to extract '{expected}' from '{text}'"
            assert expected in [c.raw for c in cands]

        # Bare strange IPs (without scheme) MUST NOT be extracted
        bare_strange = [
            "2130706433",
            "0x5DB8D822",
            "0135.0270.0330.042",
            "93.12113954",
            "2130706433/login",
            "0x5DB8D822/login",
        ]
        for text in bare_strange:
            cands = extract_candidates(f"Connect {text} here")
            assert len(cands) == 0, f"Strange bare IP '{text}' should not be extracted, got {[c.raw for c in cands]}"

