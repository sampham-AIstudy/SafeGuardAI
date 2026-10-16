import pytest

from codebase.url_analysis.models import ParsedUrl
from codebase.url_analysis.parse import parse_url


class TestUrlParse:
    """Tests for WHATWG browser-like URL parsing per Phase 2B."""

    # 1. Scheme handling & bare domains
    @pytest.mark.parametrize(
        "raw,expected_scheme,expected_host,expected_port,expected_path",
        [
            ("https://vietcombank.com.vn/login", "https", "vietcombank.com.vn", None, "/login"),
            ("http://vcb.com:8080/portal", "http", "vcb.com", 8080, "/portal"),
            ("HTTP://EXAMPLE.COM/ABC", "http", "example.com", None, "/ABC"),
            ("bit.ly/xyz", "", "bit.ly", None, "/xyz"),
            ("vcb.com/login?ref=1", "", "vcb.com", None, "/login"),
            ("ftp://ftp.example.com/files", "ftp", "ftp.example.com", None, "/files"),
        ],
    )
    def test_scheme_and_basic_parsing(self, raw, expected_scheme, expected_host, expected_port, expected_path):
        parsed = parse_url(raw)
        assert parsed.scheme == expected_scheme
        assert parsed.effective_host == expected_host
        assert parsed.port == expected_port
        assert parsed.path == expected_path

    # 2. Backslash confusion & browser simulation
    def test_backslash_confusion_whatwg(self):
        url = "https://evil-vcb.top\\@vietcombank.com.vn/"
        parsed = parse_url(url)
        assert parsed.effective_host == "evil-vcb.top"
        assert "BACKSLASH_CONFUSION" in parsed.flags
        assert parsed.userinfo == ""

    def test_backslash_without_scheme(self):
        url = "evil-vcb.top\\@vietcombank.com.vn/test"
        parsed = parse_url(url)
        assert parsed.effective_host == "evil-vcb.top"
        assert "BACKSLASH_CONFUSION" in parsed.flags

    def test_backslash_in_path_no_host_confusion(self):
        url = "https://example.com/path\\to\\file"
        parsed = parse_url(url)
        assert parsed.effective_host == "example.com"
        assert "BACKSLASH_CONFUSION" not in parsed.flags

    # 3. Userinfo handling
    def test_userinfo_port_decoy(self):
        url = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
        parsed = parse_url(url)
        assert parsed.userinfo == "vietcombank.com.vn:443"
        assert parsed.display_host == "vietcombank.com.vn"
        assert parsed.effective_host == "vcb-secure.xyz"
        assert "USERINFO_PRESENT" in parsed.flags

    def test_userinfo_encoded_login(self):
        url = "https://%2Flogin@evil-vcb.top"
        parsed = parse_url(url)
        assert parsed.userinfo == "%2Flogin"
        assert parsed.effective_host == "evil-vcb.top"
        assert "USERINFO_PRESENT" in parsed.flags

    def test_userinfo_multiple_at_signs(self):
        # Must split by LAST '@' in authority
        url = "https://user@legit.com@evil-vcb.top/login"
        parsed = parse_url(url)
        assert parsed.userinfo == "user@legit.com"
        assert parsed.effective_host == "evil-vcb.top"
        assert "USERINFO_PRESENT" in parsed.flags

    # 4. Percent-encoded host
    def test_percent_encoded_host(self):
        url = "https://%76%69%65%74combank-xacminh.com/portal"
        parsed = parse_url(url)
        assert parsed.effective_host == "vietcombank-xacminh.com"
        assert "ENCODED_HOST" in parsed.flags

    # 5. IDNA, Homoglyphs, Mixed Script, Punycode
    def test_cyrillic_homoglyph_mixed_script(self):
        # '\u0456' is Cyrillic small letter Byelorussian-Ukrainian i
        url = "https://v\u0456etcombank.com.vn/login"
        parsed = parse_url(url)
        assert parsed.effective_host == "xn--vetcombank-x2i.com.vn"
        assert "PUNYCODE_HOST" in parsed.flags
        assert "MIXED_SCRIPT" in parsed.flags

    def test_greek_homoglyph_mixed_script(self):
        # '\u03bf' is Greek small letter omicron
        url = "https://sh\u03bfpee.vn"
        parsed = parse_url(url)
        assert parsed.effective_host == "xn--shpee-sce.vn"
        assert "PUNYCODE_HOST" in parsed.flags
        assert "MIXED_SCRIPT" in parsed.flags

    def test_pure_punycode_host_not_mixed_script(self):
        url = "http://xn--80ak6aa92e.com"
        parsed = parse_url(url)
        assert parsed.effective_host == "xn--80ak6aa92e.com"
        assert parsed.effective_host_unicode == "\u0430\u0440\u0440\u04cf\u0435.com"
        assert "PUNYCODE_HOST" in parsed.flags
        assert "MIXED_SCRIPT" not in parsed.flags

    # 6. WHATWG IPv4 Parsing and Obfuscation
    @pytest.mark.parametrize(
        "raw_ip,expected_dotted,is_obfuscated",
        [
            ("http://2130706433/", "127.0.0.1", True),
            ("http://0x5DB8D822/", "93.184.216.34", True),
            ("http://0135.0270.0330.042/", "93.184.216.34", True),
            ("http://93.12113954/", "93.184.216.34", True),
            ("http://93.184.216.34/", "93.184.216.34", False),
            ("http://127.0.0.1:8080/", "127.0.0.1", False),
        ],
    )
    def test_whatwg_ipv4_formats(self, raw_ip, expected_dotted, is_obfuscated):
        parsed = parse_url(raw_ip)
        assert parsed.effective_host == expected_dotted
        assert parsed.ip == expected_dotted
        assert "IP_HOST" in parsed.flags
        if is_obfuscated:
            assert "IP_OBFUSCATED" in parsed.flags
        else:
            assert "IP_OBFUSCATED" not in parsed.flags

    def test_ipv6_parsing(self):
        url = "http://[::1]:8080/status"
        parsed = parse_url(url)
        assert parsed.effective_host == "[::1]"
        assert parsed.ip == "::1"
        assert "IP_HOST" in parsed.flags
        assert parsed.port == 8080

    # 7. Ports
    def test_standard_ports_omitted(self):
        p_http = parse_url("http://example.com:80/home")
        assert p_http.port is None
        assert "NON_STANDARD_PORT" not in p_http.flags

        p_https = parse_url("https://example.com:443/home")
        assert p_https.port is None
        assert "NON_STANDARD_PORT" not in p_https.flags

    def test_alternate_ports_flagged(self):
        p8080 = parse_url("http://example.com:8080/test")
        assert p8080.port == 8080
        assert "NON_STANDARD_PORT" in p8080.flags

        p8443 = parse_url("https://example.com:8443/test")
        assert p8443.port == 8443
        assert "NON_STANDARD_PORT" in p8443.flags

        pip_8080 = parse_url("http://103.2.3.4:8080/x")
        assert pip_8080.port == 8080
        assert "NON_STANDARD_PORT" in pip_8080.flags

    def test_non_standard_ports_flagged(self):
        p8888 = parse_url("http://example.com:8888/test")
        assert p8888.port == 8888
        assert "NON_STANDARD_PORT" in p8888.flags

    # 8. Registrable Domain & Free Hosting Platforms
    @pytest.mark.parametrize(
        "raw_url,expected_registrable",
        [
            ("https://evil.weebly.com/login", "evil.weebly.com"),
            ("https://a.b.c.com.vn/portal", "c.com.vn"),
            ("https://sites.google.com/view/test", "sites.google.com"),
            ("https://my-phish.sites.google.com/view/home", "my-phish.sites.google.com"),
            ("https://sub.domain.wixsite.com/site", "domain.wixsite.com"),
            ("https://vietcombank.com.vn", "vietcombank.com.vn"),
            ("https://shopee.vn/item", "shopee.vn"),
        ],
    )
    def test_registrable_domain_rules(self, raw_url, expected_registrable):
        parsed = parse_url(raw_url)
        assert parsed.registrable_domain == expected_registrable

    # 9. Deep Subdomain (>= 4 labels in subdomain)
    def test_deep_subdomain_flag(self):
        url = "https://a.b.c.d.evil.com/login"
        parsed = parse_url(url)
        assert parsed.registrable_domain == "evil.com"
        assert "DEEP_SUBDOMAIN" in parsed.flags

    def test_shallow_subdomain_not_flagged(self):
        url = "https://sub.evil.com/login"
        parsed = parse_url(url)
        assert "DEEP_SUBDOMAIN" not in parsed.flags

    # 10. Data, Javascript, VBScript URIs
    def test_data_and_js_uris(self):
        p_data = parse_url("data:text/html;base64,PHNjcmlwdD4=")
        assert "DATA_OR_JS_URI" in p_data.flags
        assert p_data.effective_host == ""

        p_js = parse_url("javascript:alert(1)")
        assert "DATA_OR_JS_URI" in p_js.flags
        assert p_js.effective_host == ""

        p_vb = parse_url("vbscript:MsgBox(1)")
        assert "DATA_OR_JS_URI" in p_vb.flags
        assert p_vb.effective_host == ""

    # 11. Malformed and Garbage Inputs Never Raise Exceptions
    @pytest.mark.parametrize(
        "garbage",
        [
            "",
            None,
            "[",
            "@@@@",
            "%",
            "http://",
            "http://[::1",
            "\x00" * 50,
            "a" * 10000,
        ],
    )
    def test_garbage_inputs_no_exception(self, garbage):
        parsed = parse_url(garbage)
        assert isinstance(parsed, ParsedUrl)
        assert "INVALID_HOST" in parsed.flags

    def test_long_url_truncation(self):
        long_str = "https://example.com/" + "x" * 3000
        parsed = parse_url(long_str)
        assert "LONG_URL" in parsed.flags
        assert len(parsed.raw) > 2048
        # Cleaned/parsed was truncated to at most 2048
        assert len(parsed.path) <= 2048

    # 12. Mutation-killing tests
    def test_mutation_urlsplit_hostname_divergence(self):
        # Kills Mutation 1: using urlsplit.hostname directly gives 'vietcombank.com.vn'
        # Browser WHATWG parsing MUST give 'evil-vcb.top'
        url = "https://evil-vcb.top\\@vietcombank.com.vn/"
        parsed = parse_url(url)
        assert parsed.effective_host == "evil-vcb.top"
        assert parsed.effective_host != "vietcombank.com.vn"

    def test_mutation_userinfo_split_first_at(self):
        # Kills Mutation 2: splitting userinfo by first '@' gives user='u', host='domain.com@evil.com'
        # WHATWG requires splitting by LAST '@'
        url = "https://u@domain.com@evil.com/login"
        parsed = parse_url(url)
        assert parsed.userinfo == "u@domain.com"
        assert parsed.effective_host == "evil.com"

    def test_mutation_omit_backslash_replace(self):
        # Kills Mutation 3: omitting backslash replacement
        url = "https://target-bank.xyz\\@legit-bank.com.vn/"
        parsed = parse_url(url)
        assert parsed.effective_host == "target-bank.xyz"
        assert "BACKSLASH_CONFUSION" in parsed.flags
