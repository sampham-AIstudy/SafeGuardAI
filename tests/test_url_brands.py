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


class TestVietnameseIDNHomoglyphs:
    """R1.2: IDN with Vietnamese diacritics must be detected as homoglyphs using real idna.encode."""

    @pytest.mark.parametrize(
        "unicode_host,expected_brand",
        [
            ("viêtcombank.com.vn", "vietcombank"),
            ("shopeé.vn", "shopee"),
            ("mômo.vn", "momo"),
            ("agribànk.vn", "agribank"),
            ("techcômbank.com", "techcombank"),
            ("víettel.vn", "viettel"),
            ("tíkì.vn", "tiki"),
            ("bídv.vn", "bidv"),
            ("zálô.vn", "zalo"),
            ("lazadà.vn", "lazada"),
        ],
    )
    def test_idn_diacritic_punycode_homoglyph_detection(self, catalog, unicode_host, expected_brand):
        import idna
        puny_host = idna.encode(unicode_host).decode("ascii")
        assert "xn--" in puny_host

        match = catalog.brand_match(puny_host)
        assert match is not None, f"Expected homoglyph match for {puny_host} ({unicode_host})"
        assert match["technique"] == "homoglyph"
        assert match["brand_id"] == expected_brand


class TestTyposquatMultiToken:
    """R1.3: Typosquat with and without extra tokens (rn->m, 0->o, 1->l, duplication, deletion, transposition)."""

    VARIANTS = [
        # 1. rn <-> m (no token)
        ("vietcornbank.com.vn", "typosquat", "vietcombank"),
        # 2. rn <-> m (with token)
        ("vietcornbank-login.com", "typosquat", "vietcombank"),
        # 3. o <-> 0 (no token)
        ("sh0pee.vn", "typosquat", "shopee"),
        # 4. o <-> 0 (with token)
        ("sh0pee-vn.com", "typosquat", "shopee"),
        # 5. o <-> 0 (wallet with token)
        ("zal0pay-online.vn", "typosquat", "zalopay"),
        # 6. i <-> 1 (no token)
        ("v1etcombank.vn", "typosquat", "vietcombank"),
        # 7. i <-> 1 (with token)
        ("v1etcombank-ebank.xyz", "typosquat", "vietcombank"),
        # 8. Duplicated letter (no token)
        ("viettcombank.com", "typosquat", "vietcombank"),
        # 9. Duplicated letter (with token)
        ("shoopee-voucher.com", "typosquat", "shopee"),
        # 10. Missing letter (no token)
        ("vietcomban.vn", "typosquat", "vietcombank"),
        # 11. Missing letter (with token)
        ("agriban-online.com", "typosquat", "agribank"),
        # 12. Adjacent transposition (no token)
        ("veitcombank.com", "typosquat", "vietcombank"),
        # 13. Adjacent transposition (with token)
        ("veitcombank-verify.info", "typosquat", "vietcombank"),
        # 14. Adjacent transposition in ecommerce (with token)
        ("sohpee-login.net", "typosquat", "shopee"),
    ]

    @pytest.mark.parametrize("host,expected_technique,expected_brand", VARIANTS)
    def test_typosquat_variants_with_and_without_tokens(self, catalog, host, expected_technique, expected_brand):
        match = catalog.brand_match(host)
        assert match is not None, f"Expected match for {host}"
        assert match["technique"] == expected_technique
        assert match["brand_id"] == expected_brand


class TestRealDomainsNoFalsePositives:
    """R1.4: >= 30 real popular domains in VN and globally must NOT be flagged as brand impersonations."""

    REAL_DOMAINS = [
        "pvcombank.com.vn",
        "shopeefood.vn",
        "shopeepay.vn",
        "acb.vn",
        "mb.com.vn",
        "mbs.com.vn",
        "vietinbank.com.vn",
        "sacombank.com.vn",
        "techcombank.com.vn",
        "vietcombank.com.vn",
        "bidv.com.vn",
        "agribank.com.vn",
        "tpbank.com.vn",
        "vpbank.com.vn",
        "seabank.com.vn",
        "namabank.com.vn",
        "lpbank.com.vn",
        "viettel.vn",
        "vinaphone.com.vn",
        "mobifone.vn",
        "vnpt.com.vn",
        "vnexpress.net",
        "tuoitre.vn",
        "thanhnien.vn",
        "dantri.com.vn",
        "shopee.vn",
        "lazada.vn",
        "tiki.vn",
        "google.com",
        "facebook.com",
        "github.com",
        "wikipedia.org",
        "dichvucong.gov.vn",
        "baohiemxahoi.gov.vn",
        "thuedientu.gdt.gov.vn",
        "congan.gov.vn",
        "vietnamairlines.com",
        "vietjetair.com",
    ]

    @pytest.mark.parametrize("domain", REAL_DOMAINS)
    def test_real_domain_not_flagged(self, catalog, domain):
        match = catalog.brand_match(domain)
        assert match is None, f"Real domain {domain} was falsely flagged: {match}"


class TestNewBrandsRecognition:
    """R1.5: Verification that new brands added to vn_brands.json are properly recognized and protected."""

    def test_new_brands_attacks_detected(self, catalog):
        # VNPT attack
        m_vnpt = catalog.brand_match("vnpt-tracuucuoc.xyz")
        assert m_vnpt is not None
        assert m_vnpt["brand_id"] == "vnpt"

        # Grab attack
        m_grab = catalog.brand_match("grab-khuyenmai.top")
        assert m_grab is not None
        assert m_grab["brand_id"] == "grab"

        # EVN attack
        m_evn = catalog.brand_match("evn-hoadon-dien.net")
        assert m_evn is not None
        assert m_evn["brand_id"] == "evn"

        # Vietnam Airlines attack
        m_vna = catalog.brand_match("vietnamairlines-vemaybay.vip")
        assert m_vna is not None
        assert m_vna["brand_id"] == "vietnamairlines"

        # Vietjet attack
        m_vj = catalog.brand_match("vietjetair-uudai.top")
        assert m_vj is not None
        assert m_vj["brand_id"] == "vietjetair"

        # PVcomBank attack
        m_pvcb = catalog.brand_match("pvcombank-online.xyz")
        assert m_pvcb is not None
        assert m_pvcb["brand_id"] == "pvcombank"
