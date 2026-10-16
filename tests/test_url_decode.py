import base64
import time
import pytest

from codebase.url_analysis.decode import peel
from codebase.url_analysis.models import PeelResult


class TestUrlDecode:
    """Tests for URL peeling and deobfuscation per Phase 2B."""

    # 1. Trusted redirectors & OPEN_REDIRECT_TRUSTED
    def test_google_url_redirect(self):
        url = "https://google.com/url?q=https://vcb-verify.xyz/login"
        res = peel(url)
        assert isinstance(res, PeelResult)
        assert "OPEN_REDIRECT_TRUSTED" in res.flags
        assert "EMBEDDED_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == "https://vcb-verify.xyz/login"
        assert res.inner[0].source == "embedded"
        assert res.inner[0].via == "redirect:q"

    def test_facebook_url_redirect(self):
        url = "https://l.facebook.com/l.php?u=https%3A%2F%2Fshopee-hoantien.top%2F"
        res = peel(url)
        assert "OPEN_REDIRECT_TRUSTED" in res.flags
        assert "EMBEDDED_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == "https://shopee-hoantien.top/"

    def test_untrusted_redirector_has_embedded_not_trusted(self):
        url = "https://phishing-redirector.xyz/go?dest=https://bank-login.com"
        res = peel(url)
        assert "EMBEDDED_URL" in res.flags
        assert "OPEN_REDIRECT_TRUSTED" not in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == "https://bank-login.com"

    # 2. Double percent-encoding (%25)
    def test_double_encoding_detection(self):
        url = "https://example.com/login?q=https%253A%252F%252Fvcb-verify.xyz"
        res = peel(url)
        assert "DOUBLE_ENCODING" in res.flags
        assert "EMBEDDED_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == "https://vcb-verify.xyz"
        assert any("mã hóa" in s.detail_vi or "%xx" in s.detail_vi for s in res.steps)

    # 3. Base64 / Base64url token in query
    def test_base64url_decoding(self):
        # Calculate expected base64 dynamically in test
        target = "https://vcb-verify.xyz/login"
        b64url_token = base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")
        assert b64url_token == "aHR0cHM6Ly92Y2ItdmVyaWZ5Lnh5ei9sb2dpbg"

        url = f"https://example.com/verify?token={b64url_token}"
        res = peel(url)
        assert "BASE64_URL" in res.flags
        assert "EMBEDDED_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == target
        assert res.inner[0].via == "base64"

    def test_base64_in_path_segment(self):
        target = "https://vcb-verify.xyz/auth"
        b64_token = base64.b64encode(target.encode("utf-8")).decode("ascii")
        url = f"https://gateway.com/proxy/{b64_token}/run"
        res = peel(url)
        assert "BASE64_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == target

    # 4. Hex token decoding
    def test_hex_url_decoding(self):
        target = "https://vcb-verify.xyz"
        hex_token = target.encode("utf-8").hex()
        assert hex_token == "68747470733a2f2f7663622d7665726966792e78797a"

        url = f"https://example.com/click?link={hex_token}"
        res = peel(url)
        assert "HEX_URL" in res.flags
        assert "EMBEDDED_URL" in res.flags
        assert len(res.inner) > 0
        assert res.inner[0].raw == target
        assert res.inner[0].via == "hex"

    # 5. Multi-level nesting (3 levels)
    def test_three_level_nested_peeling(self):
        # Level 3: https://final-scam.com/login
        # Level 2: https://mid-gateway.com/go?target=https%3A%2F%2Ffinal-scam.com%2Flogin
        # Level 1: https://outer-hub.com/redir?u=https%3A%2F%2Fmid-gateway.com%2Fgo%3Ftarget%3Dhttps%253A%252F%252Ffinal-scam.com%252Flogin
        lvl3 = "https://final-scam.com/login"
        lvl2 = f"https://mid-gateway.com/go?target={lvl3}"
        lvl1 = f"https://outer-hub.com/redir?u={lvl2}"

        res = peel(lvl1, depth=0, max_depth=4)
        raw_inners = [c.raw for c in res.inner]
        assert len(raw_inners) >= 2
        assert any("final-scam.com" in r for r in raw_inners)

    # 6. Loop prevention & depth limits
    def test_loop_prevention(self):
        # A URL that redirects to itself
        loop_url = "https://loop.com/redir?url=https%3A%2F%2Floop.com%2Fredir"
        res = peel(loop_url, max_depth=4)
        # Must not enter infinite recursion and terminate with at most 1 instance
        assert len(res.inner) == 1
        assert res.inner[0].raw == "https://loop.com/redir"

    def test_depth_limit_enforced(self):
        url = "https://site1.com/r?u=https%3A%2F%2Fsite2.com%2Fr%3Fu%3Dhttps%253A%252F%252Fsite3.com"
        # If max_depth is 1, it should peel depth 0 only and not go deeper
        res1 = peel(url, depth=0, max_depth=1)
        assert len(res1.inner) == 1
        assert "site2.com" in res1.inner[0].raw
        assert not any(c.raw == "https://site3.com" for c in res1.inner)

        # If max_depth is 2, it should peel recursively to discover site3.com
        res2 = peel(url, depth=0, max_depth=2)
        assert len(res2.inner) == 2
        assert any(c.raw == "https://site3.com" for c in res2.inner)

    # 7. Non-URL pollution rejection (assert NO inner candidates)
    @pytest.mark.parametrize(
        "url_with_pollution",
        [
            "https://example.com/search?q=hello%20world",
            "https://example.com/search?u=xin%20chao%20cac%20ban",
            "https://example.com/verify?token=eGluIGNoYW8gY2FjIGJhbg==",  # b64 of 'xin chao cac ban'
            "https://example.com/api?id=550e8400-e29b-41d4-a716-446655440000",  # UUID
            "https://example.com/item?hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ],
    )
    def test_pollution_rejection_no_inner(self, url_with_pollution):
        res = peel(url_with_pollution)
        assert len(res.inner) == 0
        assert "EMBEDDED_URL" not in res.flags

    # 8. Mutation-killing tests
    def test_mutation_depth_limit_omission(self):
        # Kills Mutation 4: Removing depth limit
        chain_url = "https://a.com/r?u=https%3A%2F%2Fb.com%2Fr%3Fu%3Dhttps%253A%252F%252Fc.com"
        res1 = peel(chain_url, depth=0, max_depth=1)
        # Depth limit 1 must strictly prevent inner recursion to c.com
        assert len(res1.inner) == 1
        assert not any(c.raw == "https://c.com" for c in res1.inner)

        # Depth limit 2 allows discovering c.com
        res2 = peel(chain_url, depth=0, max_depth=2)
        assert len(res2.inner) == 2
        assert any(c.raw == "https://c.com" for c in res2.inner)

    def test_mutation_loop_prevention_omission(self):
        # Kills Mutation 5: Removing loop prevention
        # Without seen set check, identical URLs would be continuously processed
        loop_url = "https://bounce.com/r?url=https%3A%2F%2Fbounce.com%2Fr"
        res = peel(loop_url, max_depth=4)
        assert len([c for c in res.inner if c.raw == "https://bounce.com/r"]) == 1

    def test_mutation_base64_printable_check_omission(self):
        # Kills Mutation 6: Removing >= 90% printable UTF-8 validation
        # Create non-printable binary bytes that contain ://
        raw_binary = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10" * 3 + b"://"
        b64_garbage = base64.b64encode(raw_binary).decode("ascii")
        url = f"https://example.com/data?token={b64_garbage}"
        res = peel(url)
        assert "BASE64_URL" not in res.flags
        assert len(res.inner) == 0

    # 9. Performance benchmarks on 8 adversarial strings
    @pytest.mark.parametrize(
        "adversarial_str",
        [
            "%" * 20000,
            "http://" + "a@" * 5000,
            "a" * 50000,
            "?u=" * 5000,
            "A" * 4096,
            "%25" * 5000,
            "\\" * 10000,
            "[" * 5000,
        ],
        ids=["percent", "auth", "long_a", "query", "base64", "double_enc", "backslash", "bracket"],
    )
    def test_adversarial_performance_under_300ms(self, adversarial_str):
        t0 = time.perf_counter()
        res = peel(adversarial_str)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        assert elapsed < 0.3, f"Peel took {elapsed:.4f}s on adversarial string (limit 0.3s)"
        assert isinstance(res, PeelResult)

    def test_adversarial_doubling_ratio_under_3x(self):
        generators = [
            lambda n: "%" * n,
            lambda n: "http://" + "a@" * n,
            lambda n: "a" * n,
            lambda n: "?u=" * n,
            lambda n: "A" * n,
            lambda n: "%25" * n,
            lambda n: "\\" * n,
            lambda n: "[" * n,
        ]
        base_lens = [20000, 5000, 50000, 5000, 4096, 5000, 10000, 5000]

        for gen, n in zip(generators, base_lens):
            s1 = gen(n)
            s2 = gen(n * 2)

            # Warmup
            peel(s1)

            t0 = time.perf_counter()
            for _ in range(5):
                peel(s1)
            dur1 = (time.perf_counter() - t0) / 5

            t0 = time.perf_counter()
            for _ in range(5):
                peel(s2)
            dur2 = (time.perf_counter() - t0) / 5

            ratio = dur2 / max(dur1, 1e-6)
            assert ratio <= 3.0, f"Doubling ratio {ratio:.2f}x exceeds 3.0x limit"
