import pytest
from codebase.url_analysis.brands import BrandCatalog, damerau_levenshtein, skeleton


@pytest.fixture
def catalog():
    return BrandCatalog.load()


class TestBrandOfficial:
    @pytest.mark.parametrize(
        "host,expected_official,expected_brand_id",
        [
            ("vietcombank.com.vn", True, "vietcombank"),
            ("www.vietcombank.com.vn", True, "vietcombank"),
            ("ebank.vietcombank.com.vn", True, "vietcombank"),
            ("vietcombank.com.vn.evil.xyz", False, None),
            ("evilvietcombank.com.vn", False, None),
            ("x.gov.vn", True, "gov_generic"),
            ("dichvucong.gov.vn", True, "dichvucong"),
            ("vneid.gov.vn", True, "vneid"),
            ("sites.google.com", False, None),
            ("facebook.com", False, None),
            ("bidv.com.vn", True, "bidv"),
            ("bidv.com.vn.attacker.com", False, None),
            ("agribank.com.vn", True, "agribank"),
            ("fake-agribank.com.vn", False, None),
            ("shopee.vn", True, "shopee"),
            ("shopee.com", False, None),
            ("momo.vn", True, "momo"),
            ("acb.com.vn", True, "acb"),
        ],
    )
    def test_official_and_non_official_pairs(self, catalog, host, expected_official, expected_brand_id):
        is_off, brand = catalog.is_official(host)
        assert is_off == expected_official
        if expected_brand_id is not None:
            assert brand is not None
            assert brand["brand_id"] == expected_brand_id
        else:
            assert brand is None


class TestBrandHomoglyph:
    def test_greek_homoglyph_shopee(self, catalog):
        # sh\u03bfpee.vn: Greek \u03bf
        host = "sh\u03bfpee.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "homoglyph"
        assert match["brand_id"] == "shopee"

    def test_cyrillic_homoglyph_zalo(self, catalog):
        # zal\u043e.me: Cyrillic \u043e
        host = "zal\u043e.me"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "homoglyph"
        assert match["brand_id"] == "zalo"

    def test_cyrillic_homoglyph_vietcombank(self, catalog):
        # v\u0456etcombank.com.vn: Cyrillic \u0456
        host = "v\u0456etcombank.com.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "homoglyph"
        assert match["brand_id"] == "vietcombank"


class TestBrandTyposquat:
    def test_digit_substitution_sh0pee(self, catalog):
        host = "sh0pee.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "typosquat"
        assert match["brand_id"] == "shopee"

    def test_rn_substitution_vietcornbank(self, catalog):
        host = "vietcornbank.com.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "typosquat"
        assert match["brand_id"] == "vietcombank"

    def test_single_letter_typo_vietconbank(self, catalog):
        host = "vietconbank.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "typosquat"
        assert match["brand_id"] == "vietcombank"


class TestBrandTldSwap:
    def test_tld_swap_vietcombank(self, catalog):
        host = "vietcombank.vn"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "tld_swap"
        assert match["brand_id"] == "vietcombank"
        assert match["official_domain"] == "vietcombank.com.vn"


class TestBrandCombosquat:
    def test_combosquat_matches(self, catalog):
        m1 = catalog.brand_match("vcb-xacminh.com")
        assert m1 is not None
        assert m1["technique"] == "combosquat"
        assert m1["brand_id"] == "vietcombank"

        m2 = catalog.brand_match("momo-hoantien.vip")
        assert m2 is not None
        assert m2["technique"] == "combosquat"
        assert m2["brand_id"] == "momo"

        m3 = catalog.brand_match("acb-online-verify.com")
        assert m3 is not None
        assert m3["technique"] == "combosquat"
        assert m3["brand_id"] == "acb"

    def test_short_token_negatives_no_false_positives(self, catalog):
        # 'acb' should NOT match inside 'placebo'
        assert catalog.brand_match("placebo.com") is None
        # 'mb' should NOT match inside 'chambank'
        assert catalog.brand_match("chambank.net") is None
        # 'mb' should NOT match inside 'tambang'
        assert catalog.brand_match("tambang.vn") is None


class TestSubdomainAndPathBrand:
    def test_subdomain_brand_agribank(self, catalog):
        host = "www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-token-valid.cc"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "subdomain_brand"
        assert match["brand_id"] == "agribank"

    def test_subdomain_brand_vietcombank(self, catalog):
        host = "vietcombank.com.vn.evil.xyz"
        match = catalog.brand_match(host)
        assert match is not None
        assert match["technique"] == "subdomain_brand"
        assert match["brand_id"] == "vietcombank"

    def test_path_brand_google_sites(self, catalog):
        match = catalog.brand_match("sites.google.com", path="/view/vcb-xac-thuc")
        assert match is not None
        assert match["technique"] == "path_brand"
        assert match["brand_id"] == "vietcombank"

    def test_path_brand_ip_host(self, catalog):
        match = catalog.brand_match("103.2.3.4", path="/vcb/login")
        assert match is not None
        assert match["technique"] == "path_brand"
        assert match["brand_id"] == "vietcombank"


class TestSkeletonAndLevenshtein:
    def test_skeleton_conversions(self):
        assert skeleton("sh\u03bfpee") == "shopee"
        assert skeleton("zal\u043e") == "zalo"
        assert skeleton("sh0pee") == "shopee"
        assert skeleton("vietcornbank") == "vietcombank"
        assert skeleton("đăng-nhập") == "dangnhap"

    def test_damerau_levenshtein(self):
        assert damerau_levenshtein("vietconbank", "vietcombank") == 1
        assert damerau_levenshtein("veitcombank", "vietcombank") == 1
        assert damerau_levenshtein("vietcornbank", "vietcombank") == 2
        assert damerau_levenshtein("sh0pee", "shopee") == 1
        assert damerau_levenshtein("acb", "acb") == 0
