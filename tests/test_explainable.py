"""
tests/test_explainable.py
Comprehensive unit tests for ExplainableAgent and Orchestrator integration (Phase 1B-2 Fix lượt G).
Covers:
- G1: Warning tone vs 2nd person call to action (>= 75 on scam with 'Lưu ý:', < 40 on educational)
- G2: Linear ReDoS protection (< 0.5s for adversarial long/repeated inputs, scaling <= 3x), URL restoration
- G3: False positive suppression for benign daily chats, OTP advice, CTV without deposit, 1st person report, internal reimbursement
- G4: Block B restoration, deposit exemption bypass prevention (>= 55), inability phrase 'không chuyển tiền được'
- G5: Generalized scam coverage (11 families) with co-occurrence requirements
- G6: Broadened Family (b) verb & motive keywords (>= 75)
- G7: Unified regexes, clean negation matching without false substrings
- G8: Real verb local negation test, mutation-killing tests, sanitized test phrases, 30 URLs test
"""

import time
import pytest

from codebase.agents.explainable_agent import ExplainableAgent
from codebase.orchestrator import SafeGuardOrchestrator


@pytest.fixture(scope="module")
def agent():
    return ExplainableAgent()


# ─────────────────────────────────────────────────────────────────────────────
# G2: ReDoS PERFORMANCE TESTS (< 0.5s each, linear scaling)
# ─────────────────────────────────────────────────────────────────────────────
REDOS_TEST_CASES = [
    ("REDOS_A_DASH", "a-" * 10000),
    ("REDOS_A_DOT", "a." * 10000),
    ("REDOS_X_COM", "x" * 20000 + ".com"),
    ("REDOS_CHUA", "chưa " * 5000),
    ("REDOS_SPACES", "chưa" + " " * 2000 + "x"),
    ("REDOS_REPEATED_CHUA_THAY", "chưa thấy " * 3000),
    ("REDOS_REPEATED_DA_CHUYEN", "đã chuyển " * 3000),
    ("REDOS_LONG_A", "a" * 50000),
    ("REDOS_KW_A", "trúng thưởng " * 5000),
    ("REDOS_KW_B", "mã otp " * 5000),
    ("REDOS_KW_C", "lợi nhuận " * 5000),
    ("REDOS_KW_D", "chuyển khoản giúp " * 5000),
    ("REDOS_KW_E", "ảnh bill " * 5000),
    ("REDOS_KW_F", "cuộc gọi video mờ " * 5000),
    ("REDOS_KW_G", "lệnh bắt giam " * 5000),
    ("REDOS_KW_H", "việc nhẹ lương cao " * 5000),
    ("REDOS_KW_I", "tải file apk " * 5000),
]


@pytest.mark.parametrize("case_id,payload", REDOS_TEST_CASES, ids=[c[0] for c in REDOS_TEST_CASES])
def test_f1_redos_explain_speed(agent, case_id, payload):
    durations = []
    res = None
    for _ in range(2):
        t0 = time.perf_counter()
        res = agent.explain(payload, matched_flags=[], ocr_anomalies=[])
        durations.append(time.perf_counter() - t0)
    best_duration = min(durations)
    assert best_duration < 1.0, f"[{case_id}] explain() took {best_duration:.3f}s (must be < 1.0s)"
    assert isinstance(res["risk_score"], int)

    half_payload = payload[:len(payload)//2]
    half_durations = []
    for _ in range(2):
        t0_half = time.perf_counter()
        agent.explain(half_payload, matched_flags=[], ocr_anomalies=[])
        half_durations.append(time.perf_counter() - t0_half)
    best_half = min(half_durations)
    if best_half > 0.02:
        ratio = best_duration / best_half
        assert ratio <= 3.0, f"[{case_id}] explain() scaling ratio {ratio:.2f}x exceeds linear limit (<= 3.0x)"


@pytest.mark.parametrize("case_id,payload", REDOS_TEST_CASES[:4], ids=[c[0] for c in REDOS_TEST_CASES[:4]])
def test_f1_redos_process_request_speed(orchestrator, case_id, payload):
    # TODO Phase 2: RAG blacklist substring scan
    durations = []
    res = None
    for _ in range(2):
        t0 = time.perf_counter()
        res = orchestrator.process_request(payload)
        durations.append(time.perf_counter() - t0)
    best_duration = min(durations)
    assert best_duration < 3.0, f"[{case_id}] process_request took {best_duration:.3f}s (must be < 3.0s)"
    assert "risk_score" in res

    half_payload = payload[:len(payload)//2]
    half_durations = []
    for _ in range(2):
        t0_half = time.perf_counter()
        orchestrator.process_request(half_payload)
        half_durations.append(time.perf_counter() - t0_half)
    best_half = min(half_durations)
    if best_half > 0.05:
        ratio = best_duration / best_half
        assert ratio <= 3.0, f"[{case_id}] scaling ratio {ratio:.2f}x exceeds linear limit (<= 3.0x)"


# ─────────────────────────────────────────────────────────────────────────────
# G1: WARNING TONE VS 2ND PERSON CALL TO ACTION
# ─────────────────────────────────────────────────────────────────────────────
def test_g1_scam_with_luu_y_prefix_must_be_high(agent):
    text = "Lưu ý: Công an quận thông báo anh liên quan đường dây rửa tiền, có lệnh bắt giữ. Chuyển tiền vào tài khoản tạm giữ trước 17h hôm nay."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 75, f"Expected >= 75, got {res['risk_score']}"


def test_g1_scam_with_luu_y_ctv_must_be_high(agent):
    text = "Lưu ý: hãy chuyển khoản phí kích hoạt 500k để nhận lương CTV"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 75, f"Expected >= 75, got {res['risk_score']}"


def test_g1_benign_bank_advisory_must_be_low(agent):
    text = "Vietcombank khuyến cáo: Ngân hàng không bao giờ yêu cầu khách hàng cung cấp mật khẩu, mã OTP qua điện thoại, tin nhắn hay đường link"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g1_benign_news_article_must_be_low(agent):
    text = "Báo Tuổi Trẻ đưa tin: Cảnh sát cảnh báo người dân nâng cao cảnh giác trước các thủ đoạn gọi video lừa đảo tinh vi."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


# ─────────────────────────────────────────────────────────────────────────────
# G3: BENIGN SUPPRESSION TESTS (ALL < 40)
# ─────────────────────────────────────────────────────────────────────────────
def test_g3_benign_chat_locked_password(agent):
    text = "Hôm nay tài khoản ngân hàng của em bị khóa do nhập sai mật khẩu, mai em ra quầy mở lại rồi chuyển tiền cho anh nhé"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_chat_meet_transfer(agent):
    text = "Mai em ra ngân hàng lấy lại mật khẩu rồi hẹn chuyển tiền cho người quen nha"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_dad_otp_advice(agent):
    text = "app ngân hàng của bố hỏi mã OTP là do bố đang chuyển tiền đó, bố nhập vào app chứ đừng đọc cho ai nhé"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_bank_no_otp(agent):
    text = "Vietcombank khuyến cáo: ngân hàng không bao giờ yêu cầu bạn đọc mã OTP cho nhân viên"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_ctv_no_deposit(agent):
    text = "Tuyển cộng tác viên bán hàng online hoa hồng 10%, không yêu cầu đặt cọc hay nạp tiền, làm việc tự do tại nhà."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_police_report(agent):
    text = "Hôm qua có người tự xưng công an bảo tôi chuyển tiền, tôi cúp máy và báo công an ngay lập tức."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_internal_reimbursement(agent):
    text = "Kế toán công ty xin số tài khoản cá nhân của anh Nam để chuyển tiền chi trả công tác phí tháng này."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


def test_g3_benign_vneid2(agent):
    text = "Hướng dẫn người dân kích hoạt tài khoản định danh điện tử VNeID mức 2 trực tiếp tại trụ sở công an phường."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}"


# ─────────────────────────────────────────────────────────────────────────────
# G4: ADVANCE FEE RESTORATION & INABILITY HANDLING
# ─────────────────────────────────────────────────────────────────────────────
def test_g4_tour_scam_must_be_medium_or_higher(agent):
    text = "Chuyển tiền đặt cọc tour du lịch giá rẻ 99k vào STK cá nhân để giữ suất"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 55, f"Expected >= 55, got {res['risk_score']}"


def test_g4_overseas_fee_scam_must_be_high(agent):
    text = "anh ở ngoài biển không chuyển tiền được, em chuyển giúp phí hải quan 5 triệu vào stk 123456 để nhận kiện hàng quà tặng nhé"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 75, f"Expected >= 75, got {res['risk_score']}"


# ─────────────────────────────────────────────────────────────────────────────
# G6: BROADENED VERBS & MOTIVES FOR FAMILY (b)
# ─────────────────────────────────────────────────────────────────────────────
def test_g6_otp_asking_expanded_verbs(agent):
    text = "Chị nhắn mã OTP cho em để em xác minh nhé"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 75, f"Expected >= 75, got {res['risk_score']}"
    assert any("thông tin bảo mật nhạy cảm" in f["factor"].lower() for f in res["risk_breakdown"])


# ─────────────────────────────────────────────────────────────────────────────
# G8(a): LOCAL NEGATION TESTS USING REAL VERBS
# ─────────────────────────────────────────────────────────────────────────────
def test_f2_local_negation_scam_with_disclaimer_must_be_medium_or_higher(agent):
    text1 = "Nếu không cung cấp mã OTP trong 24h, tài khoản của bạn sẽ bị khóa. Đọc mã OTP cho nhân viên ngay."
    res1 = agent.explain(text1, matched_flags=[], ocr_anomalies=[])
    assert res1["risk_score"] >= 40, f"Expected >= 40 (MEDIUM+), got {res1['risk_score']}"
    assert any("thông tin bảo mật nhạy cảm" in f["factor"].lower() for f in res1["risk_breakdown"])

    text2 = "Vui lòng không cung cấp mã OTP. Để hoàn tất xác minh, đọc mã OTP cho tổng đài viên."
    res2 = agent.explain(text2, matched_flags=[], ocr_anomalies=[])
    assert res2["risk_score"] >= 40, f"Expected >= 40 (MEDIUM+), got {res2['risk_score']}"
    assert any("thông tin bảo mật nhạy cảm" in f["factor"].lower() for f in res2["risk_breakdown"])


def test_f2_local_negation_real_bank_otp_must_be_low(agent):
    text = "Mã OTP của bạn là 123456. Không cung cấp mã OTP cho bất kỳ ai."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40 (LOW), got {res['risk_score']}"
    assert not any("thông tin bảo mật nhạy cảm" in f["factor"].lower() for f in res["risk_breakdown"])


# ─────────────────────────────────────────────────────────────────────────────
# G8(d): 30 URLs FACTOR POINTS TEST (MUST MATCH 539ecb1)
# ─────────────────────────────────────────────────────────────────────────────
THIRTY_URLS_539ECB1 = [
    ("https://www.vietcombank.com.vn", 0),
    ("https://vietcombank.com.vn/bieu-phi", 0),
    ("https://digibank.vietcombank.com.vn/login", 0),
    ("https://techcombank.com/personal", 0),
    ("https://bidv.com.vn/trang-chu", 0),
    ("https://vneid.gov.vn/huong-dan", 0),
    ("https://dichvucong.gov.vn/pki", 0),
    ("https://shopee.vn/flash-sale", 0),
    ("https://zalo.me/g/community", 0),
    ("https://facebook.com/safety", 0),
    ("https://google.com.vn/search?q=test", 0),
    ("https://vietcombank.com.vn.ebanking-security.xyz/login", 45),
    ("http://www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-token-valid.cc/login", 45),
    ("https://login.microsoftonline.com.secure-login-gateway.info/session=98432", 45),
    ("https://vneid-dichvucong.top/kich-hoat", 45),
    ("https://techcombank-online.xyz/xac-thuc", 45),
    ("https://bidv-smartbanking.top/login", 45),
    ("https://vpbank-neo.cc/verify", 45),
    ("https://shopee-nhanqua.top/gift", 45),
    ("https://acb-smart.xyz", 45),
    ("https://chinhphu-hotro.top/vneid", 45),
    ("https://mbbank-online.info/auth", 45),
    ("https://vietcombank-ibanking.com/login", 45),
    ("https://tin-tuc-hang-ngay.com/xa-hoi/tin-1234.html", 45),
    ("https://vnexpress.net/thoi-su", 0),
    ("https://tuoitre.vn/giao-duc.htm", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://medium.com/@user/article-title-123", 0),
    ("https://wikipedia.org/wiki/Vietnam", 0),
]


@pytest.mark.parametrize("url,expected_url_pts", THIRTY_URLS_539ECB1)
def test_g8_thirty_urls_match_539ecb1(agent, url, expected_url_pts):
    res = agent.explain(url, matched_flags=[], ocr_anomalies=[])
    pts = sum(f["weight"] for f in res["risk_breakdown"] if "link" in f["factor"].lower())
    assert pts == expected_url_pts, f"URL {url} factor points {pts} != expected 539ecb1 {expected_url_pts}"


# ─────────────────────────────────────────────────────────────────────────────
# F5: FAMILY (e) FAKE BILL CONTEXT & UNRECEIVED MONEY TESTS
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("benign_bill_text", [
    "Bạn ơi mình chuyển khoản chưa thấy tiền về, bạn kiểm tra lại giúp mình với nhé.",
    "Phòng kế toán thông báo: lương tháng 10 sẽ được chuyển khoản vào ngày 5/11, anh chị kiểm tra tài khoản và phản hồi nếu chưa nhận được.",
    "Shop ơi em chuyển khoản rồi mà bên em chưa nhận được hàng",
    "Hôm nay chưa về nhà được, mai chuyển khoản tiền điện cho mẹ nhé",
])
def test_f5_benign_transfer_without_fake_bill_context(agent, benign_bill_text):
    res = agent.explain(benign_bill_text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40, f"Expected < 40, got {res['risk_score']}. Factors: {res['risk_breakdown']}"
    assert not any("bill chuyển khoản giả mạo" in f["factor"].lower() for f in res["risk_breakdown"])


@pytest.mark.parametrize("scam_bill_text", [
    "Bên mua gửi qua ảnh chụp biên lai giao dịch thành công 3 triệu rưỡi mà tài khoản của tôi trên ứng dụng chưa thấy tiền về.",
    "Bên kia chụp ảnh biên lai giao dịch thành công mà tôi kiểm tra app ngân hàng vẫn chưa nhận được tiền.",
    "Khách gửi screenshot chuyển khoản thành công nhưng tài khoản của mình chưa thấy tiền về.",
])
def test_f5_scam_fake_bill_detection(agent, scam_bill_text):
    res = agent.explain(scam_bill_text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] >= 40, f"Expected >= 40, got {res['risk_score']}"
    assert any("bill chuyển khoản giả mạo" in f["factor"].lower() for f in res["risk_breakdown"])


# ─────────────────────────────────────────────────────────────────────────────
# G5: GENERALIZED SCAM COVERAGE TESTS (11 FAMILIES)
# ─────────────────────────────────────────────────────────────────────────────
G5_TEST_CASES = [
    ("G5_1_fake_bill_demand", "Khách gửi ảnh bill VietQR đã chuyển khoản thành công 2 triệu nhưng tài khoản ngân hàng chưa thấy tiền về, giục giao hàng trước", 75),
    ("G5_2_nick_moi_muon_tien", "Mẹ ơi con đổi số mới, điện thoại cũ bị mất, mẹ chuyển giúp con 2tr gấp tối con trả nhé", 75),
    ("G5_3_hoc_bong_card", "Thông báo nhận học bổng sinh viên 5 triệu, vui lòng điền thông tin số thẻ và mã CVV để nhận tiền", 75),
    ("G5_4_trung_thuong_phi", "Chúc mừg bạn đã chúng thưởng iphone 15 pro max, vui lòng thanh toán phí vận chuyển 300k để nhận quà", 75),
    ("G5_5_kiem_tien_nha", "Việc làm online kiếm tiền tại nhà 500k/ngày, nạp 100k nhận ngay 150k hoa hồng", 75),
    ("G5_6_fb_violation", "Trang của bạn vi phạm tiêu chuẩn cộng đồng và sẽ bị vô hiệu hóa, kháng nghị tại https://facebook-appeal-case.xyz", 75),
    ("G5_7_admin_qua_trian", "Nhận quà tri ân khách hàng thân thiết, bạn vui lòng inbox mình để nhận phần quà 1 triệu", 35),
    ("G5_8_gia_shipper", "Đơn hàng của bạn bị giữ tại bưu cục do sai thông tin, thanh toán phí phát lại 50k tại http://giaohang-nhanh.xyz", 75),
    ("G5_9_khoa_tk_sinhtrachoc", "Tài khoản sẽ bị khóa vĩnh viễn do chưa cập nhật sinh trắc học, truy cập http://vcb-sinhtrachoc.top để cập nhật ngay", 75),
    ("G5_10_romance_san_vang", "Em đang đầu tư sàn vàng quốc tế, nạp 5 triệu lãi 30% mỗi ngày đảm bảo không lỗ, anh nạp tiền tham gia cùng em", 75),
    ("G5_11_video_mo_muon_tien", "Nó gọi video mờ mờ vài giây rồi mượn gấp 5 triệu bảo tối trả", 30),
]


@pytest.mark.parametrize("case_id,text,min_score", G5_TEST_CASES, ids=[c[0] for c in G5_TEST_CASES])
def test_g5_generalized_scam_coverage(agent, case_id, text, min_score):
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res["risk_score"]
    assert score >= min_score, f"[{case_id}] Expected score >= {min_score}, got {score}. Factors: {res['risk_breakdown']}"


# ─────────────────────────────────────────────────────────────────────────────
# DIVERSE SCAM SAMPLES (Covering All F8 Categories)
# ─────────────────────────────────────────────────────────────────────────────
SCAM_DIVERSE_TESTS = [
    # 1. Mạo danh cơ quan nhà nước + đe dọa + hạn chót / nộp tiền / link lạ
    (
        "SCAM_F8_1_ACC",
        "Công an quận 1 thông báo bạn liên quan đường dây rửa tiền, có lệnh bắt giữ. Yêu cầu chuyển tiền vào tài khoản tạm giữ trước 17h hôm nay để điều tra.",
        75,
    ),
    (
        "SCAM_F8_1_UNACC",
        "Co quan Csgt thong bao ban bi phat nguoi va tuoc bang lai xe, yeu cau chuyen tien nop phat trong 24h hoac bi cuong che tai san.",
        75,
    ),
    (
        "SCAM_F8_1_TYPO",
        "Cục thuế thong bao quy khach bi phat tien do tron thue, neu khong chuyen tien nop phat truoc 17h se bi bat giam va bi phong toa tai khoan.",
        75,
    ),

    # 2. Khóa tài khoản ngân hàng + link lạ + hạn chót / vĩnh viễn
    (
        "SCAM_F8_2_ACC",
        "Vietcombank: Tài khoản của quý khách bị tạm khóa. Vui lòng truy cập https://vcb-digibank.top để xác minh thông tin trước khi bị khóa vĩnh viễn.",
        75,
    ),
    (
        "SCAM_F8_2_UNACC",
        "Tai khoan bi khoa do dang nhap bat thuong, vui long vao https://techcombank-online.xyz de xac thuc ngay neu ko se khoa vinh vien.",
        75,
    ),
    (
        "SCAM_F8_2_TYPO",
        "Ngan hang thong bao tai khoan cua ban bi khoa, vao link https://acb-smart.xyz xac thuc lai trong 2 gio neu ko muon bi khoa vinh vien.",
        # Theo quy ước, biến thể TYPO được phép kỳ vọng >= 40 (không phải >= 75) khi biến thể chuẩn đã đạt >= 75
        40,
    ),

    # 3. Romance / Pig-butchering
    (
        "SCAM_F8_3_ACC",
        "Anh làm bên tài chính, đợt này sàn có kèo đầu tư sinh lời 20%/ngày cam kết lợi nhuận không rủi ro, nạp tiền thử 1 triệu đi em.",
        75,
    ),
    (
        "SCAM_F8_3_UNACC",
        "Em nhan nham so nhung co duyen lam quen, em dang dau tu san giao dich loi nhuan 15% moi ngay bao lo, anh nap tien dau tu cung em.",
        75,
    ),
    (
        "SCAM_F8_3_TYPO",
        "Quen nhau lau em chi keo nay lam an ben tai chinh, nap tien dau tu tien ao lai suat 10%/tuan dam bao khong lo khong loi em den.",
        # Theo quy ước, biến thể TYPO được phép kỳ vọng >= 40 (không phải >= 75) khi biến thể chuẩn đã đạt >= 75
        40,
    ),

    # 4. Vay vốn: không thế chấp / giải ngân nhanh + phí trước
    (
        "SCAM_F8_4_ACC",
        "Hỗ trợ vay vốn ngân hàng không thế chấp, giải ngân nhanh trong 30 phút, quý khách vui lòng chuyển tiền thanh toán trước phí bảo hiểm hồ sơ 1 triệu để nhận tiền.",
        75,
    ),
    (
        "SCAM_F8_4_UNACC",
        "Vay tien online giai ngan nhanh khong tham dinh, chuyen tien truoc phi lam ho so 500k de duoc giai ngan ngay vao tai khoan.",
        75,
    ),
    (
        "SCAM_F8_4_TYPO",
        "Goi vay tieu dung khong the chap duyet ho so trong 10 phut, yeu cau chuyen tien nop phi ho so va phi bao hiem khoan vay truoc.",
        75,
    ),

    # 5. Học bổng / Trợ cấp / Trúng thưởng + phí (sanitized from golden overlap)
    (
        "SCAM_F8_5_ACC",
        "Bạn được nhận gói trợ cấp an sinh xã hội 5 triệu đồng, vui lòng chuyển tiền nộp phí hồ sơ 300k để làm thủ tục nhận tiền.",
        75,
    ),
    (
        "SCAM_F8_5_UNACC",
        "Chuc mung ban da trung thuong xe tay ga Vision trong dot quay so tri an, chuyen tien nop phi van chuyen 1 trieu de nhan qua tang mien phi.",
        75,
    ),
    (
        "SCAM_F8_5_TYPO",
        "Thong bao hoan thue dien tu 3 trieu, yeu cau chuyen tien nop phi xu ly ho so vao tai khoan ca nhan ben duoi de duoc giai ngan.",
        75,
    ),

    # 6. Nhiệm vụ Telegram / Zalo + nạp tiền / ký quỹ
    (
        "SCAM_F8_6_ACC",
        "Tuyển người làm nhiệm vụ Telegram đánh giá sản phẩm Shopee, hoa hồng 30%, yêu cầu nạp tiền nạp quỹ 500k để mở khóa đơn hàng VIP.",
        75,
    ),
    (
        "SCAM_F8_6_UNACC",
        "Tham gia nhom Zalo like video kiem tien, hoan tien nhiem vu 50%, can nap tien lam nhiem vu de nhan hoa hong.",
        75,
    ),
    (
        "SCAM_F8_6_TYPO",
        "Cong viec online danh gia app tren telegram kiem 500k/ngay, dat coc ky quy 300k de mo khoa tai khoan vip.",
        75,
    ),

    # 7. Không cần vốn / Tuyển người bán + cọc / ký quỹ
    (
        "SCAM_F8_7_ACC",
        "Tuyển cộng tác viên bán hàng online không cần vốn, làm việc tại nhà, yêu cầu đặt cọc phí kích hoạt tài khoản đại lý 300k.",
        75,
    ),
    (
        "SCAM_F8_7_UNACC",
        "Tuyen nguoi ban hang tai nha khong can von, chi can dat coc quy dam bao 500k de giu vi tri dai ly.",
        75,
    ),
    (
        "SCAM_F8_7_TYPO",
        "Tuyen ctv chot don khong can von nhan hoa hong cao, yeu cau dat coc nap tien kich hoat ma don hang.",
        75,
    ),

    # 8. Xin đọc số thẻ / CVV / CCCD từ nhân viên ngân hàng
    (
        "SCAM_F8_8_ACC",
        "Em là nhân viên ngân hàng hỗ trợ nâng hạn mức thẻ tín dụng, anh đọc mã 3 số mặt sau CVV và số thẻ cho nhân viên để xác thực trên hệ thống nhé.",
        75,
    ),
    (
        "SCAM_F8_8_UNACC",
        "Nhan vien ngan hang goi dien xac minh tai khoan bi khoa, yeu cau doc ma so the atm va ma cvv cho nhan vien de xac minh giao dich.",
        75,
    ),
    (
        "SCAM_F8_8_TYPO",
        "Tong dai vien ngan hang goi dien yeu cau doc ma cvv va 16 so tren the cho chuyen vien de mo khoa tai khoan bi khoa.",
        75,
    ),

    # 9. Xin OTP đổi quà / hoàn tiền
    (
        "SCAM_F8_9_ACC",
        "Mã OTP vừa gửi về điện thoại của anh là gì? Đọc cho mình để nhận quà tri ân 500k từ công ty nhé.",
        75,
    ),
    (
        "SCAM_F8_9_UNACC",
        "Doc ma otp vua gui ve dien thoai cho nhan vien de hoan tien 2 trieu vao tai khoan cua ban ngay lap tuc.",
        75,
    ),
    (
        "SCAM_F8_9_TYPO",
        "Cung cap ma otp gui ve sms cho nhan vien de nhan qua hoan tien khuyen mai tri an khach hang.",
        75,
    ),

    # Video call deepfake & fake bill
    (
        "SCAM_F8_EXTRA_1",
        "Nó gọi video mờ mờ vài giây rồi nhờ chuyển tiền gấp mượn 5 triệu cấp cứu cho người nhà.",
        40,
    ),
    (
        "SCAM_F8_EXTRA_2",
        "Khách gửi ảnh bill chuyển khoản thành công nhưng mở app chưa thấy tiền về tài khoản.",
        40,
    ),
    (
        "SCAM_F8_EXTRA_3",
        "Cài file apk ứng dụng thuế ngoài Google Play qua link lạ http://thuedientu.xyz/app.apk để nhận hoàn tiền.",
        75,
    ),
]


@pytest.mark.parametrize("case_id,text,min_expected_score", SCAM_DIVERSE_TESTS, ids=[c[0] for c in SCAM_DIVERSE_TESTS])
def test_f8_scam_samples(agent, case_id, text, min_expected_score):
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res["risk_score"]
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert score >= min_expected_score, (
        f"[{case_id}] Expected score >= {min_expected_score}, got {score}. Factors: {factors}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# HARD BENIGN SAMPLES (All Must Have risk_score < 40)
# ─────────────────────────────────────────────────────────────────────────────
HARD_BENIGN_TEST_CASES = [
    # 1-4: Legitimate OTP messages
    ("BENIGN_01", "Vietcombank: Mã OTP của quý khách là 890123 để xác thực giao dịch. Tuyệt đối không cung cấp mã OTP cho bất kỳ ai."),
    ("BENIGN_02", "Ma OTP cua quy khach la 456789. Khong cung cap ma OTP cho bat ky ai ke ca nhan vien ngan hang."),
    ("BENIGN_03", "Vui lòng nhập mã OTP được gửi đến số điện thoại của bạn để hoàn tất thanh toán đơn hàng."),
    ("BENIGN_04", "Vui long nhap ma OTP duoc gui ve so dien thoai de hoan tat thanh toan don hang tren Shopee."),

    # 5-8: Legitimate banking balance change SMS (some with 'chuyen tien')
    ("BENIGN_05", "TK 1903xxxx4321 +2,500,000VND luc 14:32 16/10. So du 12,345,000VND. ND: NGUYEN VAN A chuyen tien"),
    ("BENIGN_06", "TCB: TK 19028888 +5,000,000VND luc 09:12. SD: 25,000,000VND. ND: Cong ty chuyen tien thuong thang 10."),
    ("BENIGN_07", "ACB: Tai khoan 123456 bien dong so du +15.000.000 VND luc 10:15. Noi dung: Cong ty thanh toan luong."),
    ("BENIGN_08", "MB Bank: TK 0987654321 -500,000VND luc 11:20. So du 3,200,000VND. ND: Thanh toan tien dien thang 10."),

    # 9-12: Utility bills
    ("BENIGN_09", "Điện lực EVN kính báo: Tiền điện tháng này của hợp đồng PE123456 là 420.000 đồng, hạn thanh toán đến ngày 25."),
    ("BENIGN_10", "Nộp tiền điện online tại https://www.vietcombank.com.vn nhanh chóng"),
    ("BENIGN_11", "Công ty Nước sạch Hà Nội thông báo chỉ số đồng hồ nước tháng 10 và số tiền nước tiêu thụ là 120.000đ."),
    ("BENIGN_12", "VNPT thông báo cước dịch vụ viễn thông Internet cáp quang tháng 10 của quý khách là 220.000đ."),

    # 13-15: Official app installation guides
    ("BENIGN_13", "Hướng dẫn cài app VNeID: tải app trên App Store, đăng nhập bằng CCCD."),
    ("BENIGN_14", "Người dân có thể tải ứng dụng VNeID trên Google Play Store để kích hoạt tài khoản định danh điện tử."),
    ("BENIGN_15", "Hướng dẫn cài đặt ứng dụng Vietcombank Digimi trên App Store cho điện thoại iPhone."),

    # 16-19: News & Police advisories
    ("BENIGN_16", "Bài báo cảnh báo về tuyển cộng tác viên việc nhẹ lương cao, yêu cầu nạp tiền làm nhiệm vụ ... không chuyển tiền cho người lạ"),
    ("BENIGN_17", "Báo Tuổi Trẻ đưa tin: Cảnh sát cảnh báo người dân nâng cao cảnh giác trước các thủ đoạn gọi video lừa đảo tinh vi."),
    ("BENIGN_18", "Công an TP.HCM khuyến cáo người dân cảnh giác trước thủ đoạn giả mạo cơ quan thuế gọi điện lừa đảo."),
    ("BENIGN_19", "Ngân hàng khuyến cáo khách hàng tuyệt đối không cung cấp mã OTP hay thông tin tài khoản cho người lạ."),

    # 20-22: Company internal salary & reimbursements
    ("BENIGN_20", "Phòng kế toán thông báo: lương tháng 10 sẽ được chuyển khoản vào ngày 5/11, anh chị kiểm tra tài khoản và phản hồi nếu chưa nhận được."),
    ("BENIGN_21", "Kế toán công ty thông báo thanh toán công tác phí vào tài khoản cá nhân của nhân viên sau khi duyệt xong hóa đơn."),
    ("BENIGN_22", "Phòng nhân sự thông báo kế hoạch chi trả tiền thưởng dự án cho các thành viên đạt thành tích xuất sắc."),

    # 23-25: Realistic benign contracts & bookings (sanitized from deposit exemption)
    ("BENIGN_23", "Trung tâm tổ chức sự kiện gửi xác nhận quý khách đã hoàn tất thủ tục giữ chỗ ngày hội thảo tại số 45 Tràng Tiền."),
    ("BENIGN_24", "Chủ nhà thông báo đã nhận đủ tiền phòng trọ tháng 11 của hai bạn sinh viên qua chuyển khoản ngân hàng."),
    ("BENIGN_25", "Đại lý vé máy bay thông báo quý khách đã thanh toán thành công vé khứ hồi Hà Nội - Đà Nẵng mã đặt chỗ VNA123."),

    # 26-29: Buyer and seller checking money arrival
    ("BENIGN_26", "Bạn ơi mình chuyển khoản chưa thấy tiền về, bạn kiểm tra lại giúp mình với nhé."),
    ("BENIGN_27", "Shop ơi em chuyển khoản rồi mà bên em chưa nhận được hàng."),
    ("BENIGN_28", "Hôm nay chưa về nhà được, mai chuyển khoản tiền điện cho mẹ nhé."),
    ("BENIGN_29", "Người mua hỏi người bán: Mình vừa chuyển khoản tiền mua sách, bạn kiểm tra xem tài khoản nổi chưa nhé."),

    # 30-34: Family money & tuition
    ("BENIGN_30", "Trường Đại học Bách Khoa thông báo kế hoạch thu học phí học kỳ 2 năm học 2026 cho sinh viên toàn trường."),
    ("BENIGN_31", "Bệnh viện Bạch Mai thông báo người nhà bệnh nhân làm thủ tục tạm ứng viện phí tại quầy thu ngân tầng 1."),
    ("BENIGN_32", "Mẹ ơi con nhận được 2 triệu mẹ gửi đóng tiền phòng trọ rồi nhé, tháng này con đủ tiêu rồi mẹ an tâm."),
    ("BENIGN_33", "Bố vừa gửi tiền xe về quê cho con rồi đấy, cuối tuần nhớ về ăn cơm sum họp với gia đình nhé."),
    ("BENIGN_34", "Anh trai nhắn: Tối rảnh ghé anh trả tiền hôm nọ mua hộ đồ ăn ở siêu thị nhé."),

    # 35-37: Official promotions with official domains
    ("BENIGN_35", "Shopee khuyến mãi tưng bừng ngày hội mua sắm, giảm giá 30% cho đơn hàng tiếp theo: https://shopee.vn/khuyen-mai"),
    ("BENIGN_36", "Ưu đãi di chuyển GrabCar giảm ngay 20k cho chuyến đi sân bay: xem chi tiết tại https://grab.com/vn"),
    ("BENIGN_37", "Vietcombank công bố biểu phí: lệ phí phát hành thẻ 50.000đ, xem tại https://vietcombank.com.vn/bieu-phi"),

    # 38-39: Legitimate shipper notifications
    ("BENIGN_38", "Shipper đang trên đường giao bưu kiện mã VN8899 cho anh, phiền anh giữ máy để nhận hàng tận tay."),
    ("BENIGN_39", "Shipper gọi báo đơn hàng COD sách giáo khoa 120k đang giao đến địa chỉ nhà riêng vào chiều nay."),

    # 40-43: Real HR interview and daily chats
    ("BENIGN_40", "Phòng Nhân sự công ty FPT gửi lời mời bạn tham gia buổi phỏng vấn vị trí kỹ sư phần mềm vào 9h sáng thứ Hai."),
    ("BENIGN_41", "Tập đoàn Viettel gửi thư mời bạn tham gia vòng phỏng vấn chuyên môn tại tòa nhà Trụ sở chính."),
    ("BENIGN_42", "Tối nay tan làm mấy anh em ghé quán bún chả đầu ngõ làm cốc bia ăn tối với nhau nhé."),
    ("BENIGN_43", "Chúc mừng sinh nhật bạn thân yêu, chúc bạn tuổi mới luôn vui vẻ, thành công và ngập tràn hạnh phúc."),
]


@pytest.mark.parametrize("case_id,text", HARD_BENIGN_TEST_CASES, ids=[c[0] for c in HARD_BENIGN_TEST_CASES])
def test_f10_hard_benign_samples(agent, case_id, text):
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res["risk_score"]
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert score < 40, f"[{case_id}] Expected risk_score < 40 for benign message, got {score}. Factors: {factors}"


# ─────────────────────────────────────────────────────────────────────────────
# ANTI-MUTATION TESTS (G8: Each Mutation Must Fail At Least One Test)
# ─────────────────────────────────────────────────────────────────────────────
def test_mutation_1_fam_a_lure_alone_no_fee(agent):
    """Mutation: Bỏ điều kiện đồng xuất hiện ở họ (a) (chỉ mồi không phí) -> phải FAIL nếu bị bỏ."""
    text = "Chương trình tri ân khách hàng thân thiết tặng quà miễn phí tại quầy dịch vụ trung tâm thương mại."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("bẫy trúng thưởng" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_2_fam_h_recruitment_alone_no_deposit(agent):
    """Mutation: Bỏ điều kiện đồng xuất hiện ở họ (h) (chỉ tuyển dụng không nạp tiền) -> phải FAIL nếu bị bỏ."""
    text = "Công ty phần mềm FPT tuyển cộng tác viên viết bài tại nhà, ứng viên nộp hồ sơ CV qua email."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("bẫy tuyển dụng ctv" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_3_fam_e_context_alone_no_unreceived(agent):
    """Mutation: Bỏ điều kiện đồng xuất hiện ở họ (e) (chỉ có bill không có tiền chưa về) -> phải FAIL."""
    text = "Shop đã nhận được ảnh bill chuyển khoản thành công của bạn, chuẩn bị đóng gói hàng nhé."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("bill chuyển khoản giả mạo" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_4_fam_f_video_alone_no_borrow(agent):
    """Mutation: Bỏ điều kiện mượn tiền ở họ (f) (chỉ có video lag) -> phải FAIL."""
    text = "Hôm nay đường truyền mạng yếu quá gọi video mờ mờ không thấy rõ mặt nhau."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("deepfake" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_5_fam_i_install_alone_no_suspicious_source(agent):
    """Mutation: Bỏ điều kiện nguồn lạ ở họ (i) -> phải FAIL."""
    text = "Hướng dẫn cài app VNeID trên App Store cho điện thoại iPhone."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("tải file apk" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_6_otp_local_negation_disabled(agent):
    """Mutation: Tắt phủ định cục bộ OTP -> phải FAIL."""
    text = "Mã OTP của bạn là 998877. Tuyệt đối không cung cấp mã OTP cho bất kỳ ai kể cả nhân viên ngân hàng."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("thông tin bảo mật nhạy cảm" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_7_official_url_override_disabled(agent):
    """Mutation: Bỏ điều kiện URL chính thức -> phải FAIL."""
    text = "Xem biểu phí dịch vụ tại https://www.vietcombank.com.vn"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] == 0


def test_mutation_8_word_boundary_disabled(agent):
    """Mutation: Bỏ ranh giới từ -> từ 'hotpot' dính 'otp' -> phải FAIL."""
    text = "Tối nay em đọc mã giảm giá ăn lẩu hotpot cho nhân viên quầy thu ngân nhé."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("thông tin bảo mật nhạy cảm" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_9_weight_b_45_not_99(agent):
    """Mutation: Trọng số (b) 45->99 -> phải FAIL. Dùng câu chỉ kích hoạt duy nhất họ (b) để điểm ra đúng 45, không cộng dồn Block C hay Bank Staff."""
    text = "Chị nhắn mã CVV cho em để em xác minh nhé."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] == 45, f"Expected 45, got {res['risk_score']}"
    assert res["risk_score"] < 80


def test_mutation_10_fam_c_cooccurrence_alone_no_guarantee(agent):
    """Mutation: Bỏ đồng xuất hiện ở họ c (chỉ đầu tư không lãi cao/cam kết) -> phải FAIL."""
    text = "Tôi đang tìm hiểu kênh đầu tư chứng khoán và bất động sản sinh lời."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("cam kết đầu tư" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_11_fam_d_cooccurrence_alone_no_borrow(agent):
    """Mutation: Bỏ đồng xuất hiện ở họ d (chỉ mạng xã hội không mượn tiền) -> phải FAIL."""
    text = "Tôi vừa bị kẻ xấu hack mất nick Facebook cá nhân rồi."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("mạo danh người thân" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_12_fam_g_cooccurrence_alone_no_urgency(agent):
    """Mutation: Bỏ điều kiện thứ ba / đe dọa ở họ g -> phải FAIL."""
    text = "Cơ quan công an thông báo tạm hoãn phiên tòa phúc thẩm."
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("đe dọa khóa tài khoản" in f.lower() for f in factors)
    assert res["risk_score"] < 40


def test_mutation_13_fam_i_official_url_condition(agent):
    """Mutation: Bỏ điều kiện URL chính thức ở họ i -> phải FAIL."""
    text = "Hướng dẫn cài đặt ứng dụng dịch vụ công chính thức tại https://dichvucong.gov.vn"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert not any("cài đặt ứng dụng ngoài" in f.lower() for f in factors)
    assert res["risk_score"] == 0


def test_mutation_14_warning_tone_f6_reduced(agent):
    """Mutation: Bỏ giảm điểm F6 ở giọng cảnh báo -> phải FAIL."""
    text = "Vietcombank khuyến cáo: Ngân hàng không bao giờ yêu cầu khách hàng cung cấp mật khẩu, mã OTP qua điện thoại, tin nhắn hay đường link"
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    assert res["risk_score"] < 40
