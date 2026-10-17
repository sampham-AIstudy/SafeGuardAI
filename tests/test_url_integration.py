"""
tests/test_url_integration.py
Phase 2D-1 Integration Tests for URL Deobfuscation & Analysis module:
- Orchestrator (guard, sequential fallback, agentic paths)
- ExplainableAgent (tier-based URL factor, strict official override, legacy fallback)
- DecisionAgent (dangerous/suspicious URLs never general_chat/need_more_info)
- C1 (userinfo brand decoy) & C2 (open redirect) fixes
- 18+ obfuscation message patterns (>= 75, bit.ly/sites.google.com >= 40)
- 15 benign official links (< 40, no dangerous/suspicious verdicts)
- SAFEGUARD_URL_MODULE=off regression match against phase1_predictions.json
- ReDoS / Performance (< 1.0s for 20k chars with 20 URLs)
- Mutation-killing tests (evidence floors, effective_host vs display_host, override gating, etc.)
"""

import json
import os
import time
from pathlib import Path

import pytest

from codebase.config import get_settings
from codebase.orchestrator import SafeGuardOrchestrator


ROOT_DIR = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# (a) C1: USERINFO BRAND DECOY BUG FIX
# ─────────────────────────────────────────────────────────────────────────────
def test_c1_userinfo_brand_decoy_in_message(orchestrator):
    """
    C1: 'https://vietcombank.com.vn:443@vcb-secure.xyz/login' previously gave risk 0
    because ExplainableAgent netloc.split(':')[0] matched official domain.
    Now: risk_level HIGH+ (score >= 85), effective_host == 'vcb-secure.xyz', has USERINFO_BRAND_DECOY.
    """
    text = "Tài khoản bị khóa, đăng nhập ngay tại https://vietcombank.com.vn:443@vcb-secure.xyz/login"
    res = orchestrator.process_request(text, persist=False)

    assert res["risk_score"] >= 85, f"Expected risk_score >= 85, got {res['risk_score']}"
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL"), (
        f"Expected HIGH+, got {res['decision']['risk_level']}"
    )

    url_analysis = res.get("url_analysis")
    assert url_analysis is not None, "url_analysis key must be present in response"
    assert len(url_analysis["findings"]) > 0, "Expected at least 1 finding"

    top_finding = url_analysis["findings"][0]
    assert top_finding["effective_host"] == "vcb-secure.xyz"
    # Also verify dot-notation access
    assert url_analysis.findings[0].effective_host == "vcb-secure.xyz"

    sig_codes = [s["code"] for s in top_finding["signals"]]
    assert "USERINFO_BRAND_DECOY" in sig_codes
    assert "USERINFO_BRAND_DECOY" in url_analysis["critical_codes"]


def test_c1_userinfo_brand_decoy_standalone(orchestrator):
    """
    The C1 URL standing completely alone must also yield >= HIGH (risk >= 85).
    """
    url = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
    res = orchestrator.process_request(url, persist=False)

    assert res["risk_score"] >= 85
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")
    assert res["url_analysis"]["findings"][0]["effective_host"] == "vcb-secure.xyz"


# ─────────────────────────────────────────────────────────────────────────────
# (b) C2: OPEN REDIRECT TRUSTED BUG FIX
# ─────────────────────────────────────────────────────────────────────────────
def test_c2_open_redirect_trusted(orchestrator):
    """
    C2: 'https://www.google.com/url?q=https://vcb-verify.xyz/login' previously gave 0
    because google.com was in official whitelist.
    Now: >= HIGH, OPEN_REDIRECT_TRUSTED signal, and has child finding for target.
    """
    text = "https://www.google.com/url?q=https://vcb-verify.xyz/login"
    res = orchestrator.process_request(text, persist=False)

    assert res["risk_score"] >= 75, f"Expected risk_score >= 75, got {res['risk_score']}"
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")

    url_analysis = res["url_analysis"]
    assert url_analysis is not None
    assert len(url_analysis["findings"]) > 0

    finding = url_analysis["findings"][0]
    sig_codes = [s["code"] for s in finding["signals"]]
    assert "OPEN_REDIRECT_TRUSTED" in sig_codes
    assert len(finding["children"]) > 0, "Must have recursive child finding for target URL"
    assert finding["children"][0]["effective_host"] == "vcb-verify.xyz"


# ─────────────────────────────────────────────────────────────────────────────
# (c) 18+ OBFUSCATED SAMPLES IN MESSAGE FORMAT
# ─────────────────────────────────────────────────────────────────────────────
OBFUSCATED_HIGH_SAMPLES = [
    ("homoglyph_cyrillic_a", "https://vietcomb\u0430nk.com/login"),
    ("homoglyph_cyrillic_e", "https://vi\u0435tcombank.com/login"),
    ("homoglyph_greek_e", "https://vi\u03b5tcombank.com/login"),
    ("defang_hxxps", "hxxps://vietcombank-xacthuc[.]xyz:8080/dang-nhap"),
    ("defang_colon", "http[:]//acb-online-verify[.]xyz:8080"),
    ("ip_decimal", "http://3565158400:8080/vietcombank/login"),
    ("ip_hex", "http://0xd484b400:8080/vcb/auth"),
    ("percent_encoded_host", "https://v%69etcombank-xacminh.com/login"),
    ("base64_redirect_param", "https://vcb-portal.xyz/redirect?url=aHR0cHM6Ly92Y2IteGFjdGh1Yy54eXovbG9naW4="),
    ("backslash_confusion", "https://vietcombank.com.vn\\\\vcb-login.xyz/auth"),
    ("subdomain_deep_apk", "https://vneid.dichvucong.gov.vn.capnhat-hethong.xyz/vneid-update.apk"),
    ("markdown_mismatch", "[https://vietcombank.com.vn](https://vcb-fake.xyz/login)"),
    ("typosquat_shopee", "http://sh0pee.xyz/voucher-500k"),
    ("combosquat_vcb", "http://vcb-xacminh.xyz:8080/login"),
    ("punycode_brand", "http://xn--viettel-w0a.xyz/khuyenmai"),
    ("double_percent_encoding", "https://vcb-verify.com/login?u=https%253A%252F%252Fvcb-fake.xyz"),
    ("zero_width_space", "https://vietcom\u200bbank-auth.com/login"),
    ("hex_redirect_param", "https://vcb-gateway.xyz/go?target=68747470733a2f2f7663622d66616b652e78797a"),
    ("deep_subdomain_phish_tld", "https://login.ebanking.vietcombank.com.vn.auth-token.xyz/login"),
]


@pytest.mark.parametrize("name,raw_url", OBFUSCATED_HIGH_SAMPLES, ids=[s[0] for s in OBFUSCATED_HIGH_SAMPLES])
def test_obfuscated_message_patterns_high(orchestrator, name, raw_url):
    """Every obfuscated URL in message format must yield risk >= 75 (HIGH+)."""
    text = f"Quý khách bấm vào {raw_url} để xác thực"
    res = orchestrator.process_request(text, persist=False)
    assert res["risk_score"] >= 75, f"[{name}] Expected risk_score >= 75, got {res['risk_score']}"
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")
    assert res["url_analysis"] is not None
    assert len(res["url_analysis"]["findings"]) > 0


OBFUSCATED_WEAK_SAMPLES = [
    ("bitly_alone", "http://bit.ly/vcb-xacminh"),
    ("sites_google_alone", "https://sites.google.com/view/vcb-xacminh"),
]


@pytest.mark.parametrize("name,raw_url", OBFUSCATED_WEAK_SAMPLES, ids=[s[0] for s in OBFUSCATED_WEAK_SAMPLES])
def test_obfuscated_message_patterns_weak(orchestrator, name, raw_url):
    """Shortener or free hosting standing alone yields risk >= 40 (weak signal)."""
    res = orchestrator.process_request(raw_url, persist=False)
    assert res["risk_score"] >= 40, f"[{name}] Expected risk_score >= 40, got {res['risk_score']}"
    assert res["decision"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


# ─────────────────────────────────────────────────────────────────────────────
# (d) 15 BENIGN MESSAGES WITH OFFICIAL / POPULAR LINKS
# ─────────────────────────────────────────────────────────────────────────────
BENIGN_OFFICIAL_CASES = [
    ("vcb_official", "https://vietcombank.com.vn/vi-VN/Ca-nhan"),
    ("shopee_promo", "Khuyến mãi Shopee chính hãng tại https://shopee.vn/flash-sale"),
    ("dichvucong_gov", "Cổng Dịch vụ công Quốc gia tại https://dichvucong.gov.vn"),
    ("topcv_job", "Tìm việc làm uy tín tại https://topcv.vn/viec-lam"),
    ("fb_group", "Tham gia nhóm học tập tại https://facebook.com/groups/laptrinhpython"),
    ("google_docs", "Tài liệu hướng dẫn tại https://docs.google.com/document/d/12345/edit"),
    ("zalo_chat", "Liên hệ hỗ trợ qua Zalo https://zalo.me/0912345678"),
    ("vnexpress_news", "Đọc tin tức thời sự trên báo https://vnexpress.net/thoi-su"),
    ("github_repo", "Mã nguồn dự án trên GitHub https://github.com/torvalds/linux"),
    ("tuoitre_warning", "Báo Tuổi Trẻ đưa tin cảnh báo thủ đoạn tại https://tuoitre.vn/canh-bao-lua-dao-123.htm"),
    ("bhxh_gov", "Tra cứu bảo hiểm xã hội tại https://baohiemxahoi.gov.vn"),
    ("chinhphu_portal", "Cổng thông tin điện tử Chính phủ https://chinhphu.vn"),
    ("agribank_official", "Ngân hàng Nông nghiệp Agribank https://agribank.com.vn"),
    ("youtube_video", "Xem video hướng dẫn học tập https://youtube.com/watch?v=dQw4w9WgXcQ"),
    ("lazada_official", "Mua sắm trực tuyến Lazada https://lazada.vn/khuyen-mai"),
]


@pytest.mark.parametrize("case_name,text", BENIGN_OFFICIAL_CASES, ids=[c[0] for c in BENIGN_OFFICIAL_CASES])
def test_benign_official_messages(orchestrator, case_name, text):
    """15 benign messages with official / popular links must yield < 40 with no suspicious/dangerous findings."""
    res = orchestrator.process_request(text, persist=False)
    assert res["risk_score"] < 40, f"[{case_name}] Expected score < 40, got {res['risk_score']}"
    assert res["decision"]["risk_level"] == "LOW"

    url_analysis = res.get("url_analysis")
    if url_analysis and url_analysis.get("findings"):
        for f in url_analysis["findings"]:
            v = f.get("verdict")
            assert v not in ("dangerous", "suspicious"), (
                f"[{case_name}] Benign URL received verdict '{v}': {f.get('raw')}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# (e) SAFEGUARD_URL_MODULE=off REGRESSION MATCH & ACCURACY PRESERVATION
# ─────────────────────────────────────────────────────────────────────────────
def test_url_module_disabled_exact_regression(orchestrator, monkeypatch):
    """
    When SAFEGUARD_URL_MODULE=off:
    - Golden v1 (20 cases) and Golden v2 (72 cases) results must MATCH phase1_predictions.json exactly.
    """
    v1_file = ROOT_DIR / "eval" / "golden_set.json"
    v2_file = ROOT_DIR / "eval" / "golden_set_v2.json"
    pred_file = ROOT_DIR / "tests" / "data" / "phase1_predictions.json"

    assert v1_file.exists() and v2_file.exists() and pred_file.exists()

    with open(v1_file, "r", encoding="utf-8") as f:
        v1_data = json.load(f).get("golden_set", [])
    with open(v2_file, "r", encoding="utf-8") as f:
        v2_data = json.load(f).get("golden_set", [])
    with open(pred_file, "r", encoding="utf-8") as f:
        phase1_preds = json.load(f)

    assert len(v1_data) == 20, f"Expected 20 cases in golden v1, found {len(v1_data)}"
    assert len(v2_data) == 72, f"Expected 72 cases in golden v2, found {len(v2_data)}"

    # Turn module off
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    settings = get_settings(refresh=True)
    assert not settings.url_module_enabled

    try:
        # Check v1
        for item in v1_data:
            cid = item["id"]
            inp = item["input_text"]
            sid = f"eval_{cid}"
            if hasattr(orchestrator.memory_agent, "reset"):
                orchestrator.memory_agent.reset(sid)
            res = orchestrator.process_request(inp, session_id=sid, persist=False)
            expected = tuple(phase1_preds["v1"][cid])
            actual = (res["decision"]["risk_level"], res["risk_score"])
            assert actual == expected, f"[v1 {cid}] Expected {expected}, got {actual} when URL module off"

        # Check v2
        for item in v2_data:
            cid = item["id"]
            inp = item["input_text"]
            sid = f"eval_{cid}"
            if hasattr(orchestrator.memory_agent, "reset"):
                orchestrator.memory_agent.reset(sid)
            res = orchestrator.process_request(inp, session_id=sid, persist=False)
            expected = tuple(phase1_preds["v2"][cid])
            actual = (res["decision"]["risk_level"], res["risk_score"])
            assert actual == expected, f"[v2 {cid}] Expected {expected}, got {actual} when URL module off"

    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)


def test_url_module_enabled_no_regression_on_correct_cases(orchestrator):
    """
    When URL module is ON (default):
    No golden case that was already correctly predicted in Phase 1 may become incorrect.
    Evaluates all 20 v1 cases and the first 30 cases of v2 for fast execution (~3-5s).
    """
    v1_file = ROOT_DIR / "eval" / "golden_set.json"
    v2_file = ROOT_DIR / "eval" / "golden_set_v2.json"
    pred_file = ROOT_DIR / "tests" / "data" / "phase1_predictions.json"

    with open(v1_file, "r", encoding="utf-8") as f:
        v1_data = json.load(f).get("golden_set", [])
    with open(v2_file, "r", encoding="utf-8") as f:
        v2_data = json.load(f).get("golden_set", [])
    with open(pred_file, "r", encoding="utf-8") as f:
        phase1_preds = json.load(f)

    # Check v1
    for item in v1_data:
        cid = item["id"]
        expected_level = item["expected_risk_level"]
        p1_level, _ = phase1_preds["v1"][cid]
        if p1_level == expected_level:
            sid = f"eval_{cid}"
            if hasattr(orchestrator.memory_agent, "reset"):
                orchestrator.memory_agent.reset(sid)
            res = orchestrator.process_request(item["input_text"], session_id=sid, persist=False)
            actual_level = res["decision"]["risk_level"]
            assert actual_level == expected_level, (
                f"[v1 {cid}] Regression: was correct ({p1_level}), now incorrect ({actual_level})"
            )

    # Check first 30 cases of v2
    for item in v2_data[:30]:
        cid = item["id"]
        expected_level = item["expected_risk_level"]
        p1_level, _ = phase1_preds["v2"][cid]
        if p1_level == expected_level:
            sid = f"eval_{cid}"
            if hasattr(orchestrator.memory_agent, "reset"):
                orchestrator.memory_agent.reset(sid)
            res = orchestrator.process_request(item["input_text"], session_id=sid, persist=False)
            actual_level = res["decision"]["risk_level"]
            assert actual_level == expected_level, (
                f"[v2 {cid}] Regression: was correct ({p1_level}), now incorrect ({actual_level})"
            )


# ─────────────────────────────────────────────────────────────────────────────
# (f) RESPONSE SCHEMA & JSON SERIALIZABILITY
# ─────────────────────────────────────────────────────────────────────────────
def test_response_schema_and_json_serializable(orchestrator, monkeypatch):
    """Response must contain url_analysis (or None when off) and be JSON serializable."""
    text = "Cảnh báo link https://vcb-secure.xyz/login"

    # Module ON
    res_on = orchestrator.process_request(text, persist=False)
    assert "url_analysis" in res_on
    assert res_on["url_analysis"] is not None
    json_str_on = json.dumps(res_on, ensure_ascii=False)
    assert isinstance(json_str_on, str)

    # Module OFF
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    get_settings(refresh=True)
    try:
        res_off = orchestrator.process_request(text, persist=False)
        assert "url_analysis" in res_off
        assert res_off["url_analysis"] is None
        json_str_off = json.dumps(res_off, ensure_ascii=False)
        assert isinstance(json_str_off, str)
    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)


# ─────────────────────────────────────────────────────────────────────────────
# (g) ReDoS / PERFORMANCE (20k chars + 20 URLs < 1.0s)
# ─────────────────────────────────────────────────────────────────────────────
def test_performance_20k_chars_20_urls(orchestrator):
    """process_request on 20,000 characters with 20 embedded URLs must complete in < 1.0s."""
    filler = "Nội dung tin nhắn thông thường hàng ngày để kiểm tra hiệu năng. " * 200
    urls = [f"https://sub{i}.sample-bank-check{i}.xyz/verify/page?id={i}" for i in range(20)]
    full_text = filler + " ".join(urls)
    full_text = full_text[:20000]

    durations = []
    for _ in range(2):
        t0 = time.perf_counter()
        res = orchestrator.process_request(full_text, persist=False)
        durations.append(time.perf_counter() - t0)

    best_dur = min(durations)
    assert best_dur < 1.0, f"Performance test took {best_dur:.3f}s (must be < 1.0s)"
    assert "url_analysis" in res


# ─────────────────────────────────────────────────────────────────────────────
# (i) MUTATION TESTS (>= 6 TESTS KILLING DEFECTS)
# ─────────────────────────────────────────────────────────────────────────────
def test_mutation_1_evidence_floor_enforcement(orchestrator):
    """Mutation: Bỏ sàn bằng chứng -> C1 có mã critical phải bị chặn dưới 85."""
    text = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
    res = orchestrator.process_request(text, persist=False)
    # With evidence floor, risk_score is at least 85
    assert res["risk_score"] >= 85
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")


def test_mutation_2_has_only_official_on_effective_host_not_display_host(orchestrator):
    """
    Mutation: has_only_official_urls tính trên display_host thay vì effective_host.
    C1 display_host là vietcombank.com.vn (official), nhưng effective_host là vcb-secure.xyz.
    Nếu tính theo display_host thì C1 sẽ bị override về 0 -> phải FAIL!
    """
    text = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
    res = orchestrator.process_request(text, persist=False)
    assert res["url_analysis"]["has_only_official_urls"] is False
    assert res["risk_score"] > 0


def test_mutation_3_url_report_propagation(orchestrator):
    """
    Mutation: Bỏ truyền url_report vào explainable_agent.explain hoặc decision_agent.
    Khi truyền url_report, DecisionAgent nhận biết dangerous URL và cấm general_chat.
    """
    text = "Alo chào bạn https://vcb-secure.xyz/login"
    res = orchestrator.process_request(text, persist=False)
    assert res["decision"]["intent_type"] != "general_chat"
    assert res["decision"]["risk_level"] != "LOW"


def test_mutation_4_module_disabled_flag_respected(orchestrator, monkeypatch):
    """Mutation: Bỏ cờ tắt module SAFEGUARD_URL_MODULE -> phải FAIL."""
    monkeypatch.setenv("SAFEGUARD_URL_MODULE", "off")
    get_settings(refresh=True)
    try:
        res = orchestrator.process_request("https://vcb-secure.xyz", persist=False)
        assert res["url_analysis"] is None
    finally:
        monkeypatch.delenv("SAFEGUARD_URL_MODULE", raising=False)
        get_settings(refresh=True)


def test_mutation_5_official_override_blocked_by_medium_plus_signal(orchestrator):
    """
    Mutation: Cho phép override official khi có tín hiệu medium trở lên.
    Google open redirect có domain chính thức google.com nhưng có tín hiệu OPEN_REDIRECT_TRUSTED (high).
    Nếu cho override thì điểm về 0 -> phải FAIL!
    """
    text = "https://www.google.com/url?q=https://vcb-verify.xyz/login"
    res = orchestrator.process_request(text, persist=False)
    assert res["risk_score"] >= 75
    assert res["decision"]["risk_level"] in ("HIGH", "CRITICAL")


def test_mutation_6_llm_cannot_lower_risk_below_floor(orchestrator):
    """
    Mutation: LLM kéo risk xuống dưới sàn bằng chứng.
    Kể cả khi LLM hoặc fallback ban đầu chỉ có điểm thấp, floor của URL độc hại (>= 75 / >= 85) phải được bảo toàn.
    """
    text = "https://vietcombank.com.vn:443@vcb-secure.xyz/login"
    # Even with a benign-sounding message around it:
    res = orchestrator.process_request(f"Tin nhắn bạn bè gửi {text}", persist=False)
    assert res["risk_score"] >= 85, f"Floor must guarantee >= 85, got {res['risk_score']}"
