"""
tests/test_emergency.py
Unit tests and mutation-resistance verification for EmergencyAgent.
"""

import pytest
from codebase.agents.emergency_agent import EmergencyAgent


@pytest.fixture(scope="module")
def emergency_agent():
    return EmergencyAgent()


# Full parameterized test suite for EmergencyAgent cases in E1
EMERGENCY_TEST_CASES = [
    # ── AFFIRMATIVE EMERGENCY CASES (MUST BE TRUE) ──
    (
        "Tôi lỡ chuyển 20 triệu rồi, làm sao để không mất thêm?",
        True,
        "Victim already transferred, prevention question in second clause",
    ),
    (
        "Tôi đã chuyển 20 triệu cho kẻ lừa đảo, làm sao biết nó là ai?",
        True,
        "Victim transferred to scammer, inquiry in second clause",
    ),
    (
        "Em bị lừa nạp tổng cộng 45 triệu làm nhiệm vụ Shopee trên Telegram rồi anh ơi... em hết sạch tiền rồi!",
        True,
        "CASE_70: Scammed deposit + total amount + lost all money",
    ),
    (
        "Tôi lỡ chuyển 20 triệu cho kẻ giả danh công an rồi",
        True,
        "Accented transfer to impersonator",
    ),
    (
        "toi lo chuyen 20 trieu cho ke gia danh cong an roi",
        True,
        "Folded unaccented transfer to impersonator",
    ),
    (
        "Tôi vừa bị lừa chuyển 50 triệu qua mạng xã hội rồi",
        True,
        "Recent scammed transfer of 50M",
    ),
    (
        "Cứu em với, em vừa lỡ chuyển 20 triệu vào số tài khoản của bên giả danh công an rồi, giờ em phải làm sao để khóa giao dịch?",
        True,
        "Call for help after transfer to impersonator",
    ),
    (
        "Tôi vừa bấm vào link https://vietcombank.com.vn@vcb-xacthuc-online.top/login và đã trót nhập mã OTP ngân hàng gửi về rồi, tài khoản vừa bị trừ tiền!",
        True,
        "Shared OTP + account balance deducted",
    ),
    (
        "Em lỡ tải và cài file dichvucong.apk từ đường link lạ theo lời bên xưng cán bộ thuế rồi, màn hình điện thoại bị đen và máy tự thao tác chuyển tiền!",
        True,
        "Installed malware APK + phone hijacked money transfer",
    ),
    (
        "Tôi vừa nhập mật khẩu và mã OTP vào trang https[:]//bidv-smartbanking[.]xyz theo tin nhắn thông báo, vừa xong tài khoản bị chuyển mất 15 triệu!",
        True,
        "Shared credentials + 15M deducted",
    ),
    (
        "Em đã chuyển 5 triệu tiền phí bảo hiểm khoản vay theo hướng dẫn qua Zalo, nhưng giờ họ đe dọa tung ảnh danh bạ nếu không chuyển thêm 10 triệu nữa!",
        True,
        "Transferred fee + extortion demand",
    ),
    (
        "Em vừa bị lừa chuyển 5 triệu cho bên tuyển dụng rồi anh ơi, phải làm sao bây giờ?",
        True,
        "Scammed transfer to fake recruiter",
    ),
    (
        "AI lấy lại 10 triệu em vừa bị lừa chuyển khoản giúp em được không?",
        True,
        "Seeking recovery after transfer",
    ),
    (
        "Tôi bị lừa 50 triệu rồi",
        True,
        "Direct victim: bị lừa 50 triệu rồi",
    ),
    (
        "Bị lừa sạch tiền tiết kiệm rồi",
        True,
        "Direct victim: Bị lừa sạch tiền",
    ),
    (
        "bị hack mất tiền trong tài khoản",
        True,
        "Direct victim: bị hack mất tiền",
    ),
    (
        "Tôi sợ quá, tôi đã chuyển 20 triệu rồi",
        True,
        "Fear clue + transfer 20M across clause boundary",
    ),
    (
        "Tôi không biết làm sao, em lỡ chuyển 50 triệu cho nó rồi",
        True,
        "Inherent emergency transfer: lỡ chuyển 50 triệu cho nó",
    ),
    (
        "Ông ngoại vừa bị người ta lừa chuyển 300 triệu",
        True,
        "Family relative scammed transfer of 300M",
    ),
    (
        "mẹ tôi vừa chuyển 200 triệu cho người lạ",
        True,
        "Family relative transfer with stranger clue",
    ),
    (
        "toang rồi mất sạch tiền",
        True,
        "Direct victim: toang rồi mất sạch tiền",
    ),
    (
        "Chưa ai trong nhà tôi biết. Tôi đã chuyển 20 triệu cho kẻ lừa đảo rồi",
        True,
        "Negation in previous sentence does not negate emergency in next sentence",
    ),
    (
        "Không ngờ tôi bị lừa mất 20 triệu",
        True,
        "D2-a: Non-negating idiom 'không ngờ' before victim transfer",
    ),
    (
        "Tôi không hiểu sao mình bị lừa mất 20 triệu",
        True,
        "D2-a: Non-negating idiom 'không hiểu sao' before victim transfer",
    ),
    (
        "Chuyển nhầm cho kẻ lừa đảo 15 triệu rồi",
        True,
        "D2-c: Accidental transfer to scammer destination",
    ),
    (
        "Chị ơi em chưa kịp nghĩ đã chuyển 20 triệu cho kẻ lừa đảo rồi",
        True,
        "D2-c: Preceding temporal clause 'chưa kịp nghĩ' does not negate transfer",
    ),

    # ── NEGATION & NEAR-MISS CASES (MUST BE FALSE) ──
    (
        "Tôi suýt chuyển khoản rồi thì phát hiện",
        False,
        "Near-miss: suýt chuyển khoản",
    ),
    (
        "May mà chưa bị lừa mất tiền",
        False,
        "Negation: may mà chưa bị lừa mất tiền",
    ),
    (
        "Tôi suýt bị lừa mất 10 triệu",
        False,
        "Near-miss: suýt bị lừa mất tiền",
    ),
    (
        "Suýt bị lừa rồi, may quá",
        False,
        "Near-miss: suýt bị lừa rồi",
    ),
    (
        "chưa chuyển",
        False,
        "Negation: chưa chuyển",
    ),
    (
        "không chuyển",
        False,
        "Negation: không chuyển",
    ),
    (
        "suýt chuyển tiền",
        False,
        "Near-miss: suýt chuyển tiền",
    ),
    (
        "may mà chưa chuyển",
        False,
        "Negation: may mà chưa chuyển",
    ),
    (
        "Tôi sợ mất tiền lắm",
        False,
        "Subjective fear / hesitation: sợ mất tiền",
    ),
    (
        "Cách tránh mất tiền khi mua online",
        False,
        "Educational / prevention: tránh mất tiền",
    ),

    # ── SINGLE-SYLLABLE & BENIGN WORDS (MUST BE FALSE) ──
    (
        "Dạ tại sao vậy anh",
        False,
        "Benign: 'da tai' single-syllable false positive",
    ),
    (
        "Em lo cái điện thoại hỏng",
        False,
        "Benign: 'lo cai' single-syllable false positive",
    ),
    (
        "Sức khỏe mẹ đã cải thiện",
        False,
        "Benign: 'da cai' single-syllable false positive",
    ),
    (
        "Con đã nhập học rồi",
        False,
        "Benign: 'da nhap' single-syllable false positive",
    ),
    (
        "Tôi đã gửi hồ sơ xin việc",
        False,
        "Benign: 'da gui' single-syllable false positive",
    ),
    (
        "Nhà mình đã chuyển nhà",
        False,
        "Benign: 'da chuyen' without money/scam context",
    ),
    (
        "Tôi đã tải ảnh lên",
        False,
        "Benign: 'da tai' without apk/malware context",
    ),
    (
        "tôi lỡ tay bấm nhầm",
        False,
        "Benign accidental click without money loss / credentials",
    ),
    (
        "Làm sao để không bị lừa khi mua hàng online?",
        False,
        "Educational prevention inquiry",
    ),
    (
        "Mẹ ơi con cần chuyển 5 triệu đóng học phí",
        False,
        "Family legitimate transfer request (cần chuyển)",
    ),

    # ── BANK NOTIFICATION SMS (MUST BE FALSE) ──
    (
        "Đã chuyển khoản thành công 500.000đ",
        False,
        "Bank transaction notification: thành công",
    ),
    (
        "Quý khách đã nạp tiền thành công",
        False,
        "Bank deposit notification: thành công",
    ),

    # ── THIRD-PERSON NARRATIVE (MUST BE FALSE) ──
    (
        "Bài báo kể một nạn nhân đã bị lừa 500 triệu",
        False,
        "Third-person news reporting",
    ),
    (
        "Theo tin tức nạn nhân đã chuyển 200 triệu cho kẻ lừa đảo",
        False,
        "Third-person reporting without first-person perspective",
    ),
    (
        "Theo báo, nạn nhân chỉ trong một ngày đã bị lừa 500 triệu",
        False,
        "Media reporting with 'Theo báo' and 'trong một ngày'",
    ),
    (
        "Em đã chuyển khoản 500k tiền hàng rồi nhé chị",
        False,
        "Neutral commercial transfer without scam clues",
    ),
    (
        "Tôi vừa nạp tiền điện thoại 100k",
        False,
        "Neutral phone top-up without scam clues",
    ),
    (
        "Tôi đã chuyển tiền học phí cho con rồi",
        False,
        "Neutral tuition transfer without scam clues",
    ),
    (
        "Đừng để bị lừa mất tiền nhé mẹ",
        False,
        "D2-b: Warning/advice with 'Đừng để'",
    ),
    (
        "Người phụ nữ bị lừa mất 2 tỷ, công an cảnh báo",
        False,
        "D2-b: Third-person report with 'Người phụ nữ', 'công an cảnh báo'",
    ),
    (
        "Cảnh báo: nhiều người bị lừa mất tiền vì link này",
        False,
        "D2-b: Warning alert with 'Cảnh báo: nhiều người'",
    ),
    (
        "Bạn nào bị lừa mất tiền thì gọi 113",
        False,
        "D2-b: Conditional / inquiry with 'Bạn nào'",
    ),
    (
        "Tôi muốn học cách phòng tránh bị lừa mất tiền",
        False,
        "D2-b: Educational request with 'học cách phòng tránh'",
    ),
]


@pytest.mark.parametrize("text,expected_emergency,reason", EMERGENCY_TEST_CASES)
def test_emergency_agent_all_cases(emergency_agent, text, expected_emergency, reason):
    res = emergency_agent.check_trigger(text)
    assert res is not None, f"check_trigger returned None for: {text}"
    actual = res.get("is_emergency", False)
    assert actual == expected_emergency, (
        f"Failed for case [{reason}]: expected is_emergency={expected_emergency}, got {actual}. "
        f"Text: '{text}'"
    )
    if expected_emergency:
        assert res.get("risk_level") == "CRITICAL"
        assert res.get("risk_score") == 99
        assert len(res.get("protocol_steps", [])) == 5


# ── SPECIFIC MUTATION-RESISTANCE TESTS ──

def test_negation_mutation_resistance(emergency_agent):
    """Fails if negation check is omitted."""
    near_misses = [
        "Tôi suýt chuyển khoản rồi thì phát hiện",
        "May mà chưa bị lừa mất tiền",
        "Tôi suýt bị lừa mất 10 triệu",
        "Suýt bị lừa rồi, may quá",
        "chưa chuyển",
        "không chuyển",
        "suýt chuyển tiền",
        "may mà chưa chuyển",
        "Tôi sợ mất tiền lắm",
    ]
    for text in near_misses:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is False, f"Negation check failed on: '{text}'"


def test_order_prevention_evidence_mutation_resistance(emergency_agent):
    """Fails if prevention check runs BEFORE emergency evidence check."""
    complex_cases = [
        "Tôi lỡ chuyển 20 triệu rồi, làm sao để không mất thêm?",
        "Tôi đã chuyển 20 triệu cho kẻ lừa đảo, làm sao biết nó là ai?",
    ]
    for text in complex_cases:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is True, (
            f"Ordering mutation detected: genuine emergency misclassified due to early prevention check on: '{text}'"
        )


def test_word_boundary_and_single_syllable_mutation_resistance(emergency_agent):
    """Fails if word boundaries are removed or unaccented single syllables are matched."""
    false_positives = [
        "Dạ tại sao vậy anh",
        "Em lo cái điện thoại hỏng",
        "Sức khỏe mẹ đã cải thiện",
        "Con đã nhập học rồi",
        "Tôi đã gửi hồ sơ xin việc",
        "Nhà mình đã chuyển nhà",
        "Tôi đã tải ảnh lên",
    ]
    for text in false_positives:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is False, (
            f"Word boundary / single-syllable mutation detected on: '{text}'"
        )


def test_emergency_mutation_1_distant_negation_resistance(emergency_agent):
    """
    (Mutation 1 Test) Negation far away (>2 words) must NOT turn off emergency.
    If the negation window is widened beyond 2 words or ignores clause boundaries,
    this genuine emergency report will falsely evaluate to False.
    """
    cases = [
        "Chưa ai biết nên tôi sợ lắm, tôi đã chuyển 20 triệu cho kẻ lừa đảo",
        "Chưa ai biết tôi đã chuyển 20 triệu cho kẻ lừa đảo",
    ]
    for text in cases:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is True, f"Mutation 1: Distant negation incorrectly shut off emergency: '{text}'"
        assert res["risk_level"] == "CRITICAL"



def test_emergency_mutation_2_word_boundary_resistance(emergency_agent):
    r"""
    (Mutation 2 Test) Missing word boundaries (?<!\w) in emergency patterns:
    Glued words like 'khongchuyen' or 'abclodachuyen' or substrings inside other words
    must NOT match emergency transfer patterns.
    """
    glued_inputs = [
        "khongchuyen",
        "abclodachuyen",
        "Toi abclodachuyen 20 trieu cho ke lua dao",
        "hom nay tochuyen khoan thanh cong",
    ]
    for text in glued_inputs:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is False, f"Mutation 2: Glued word matched emergency without word boundary: '{text}'"


def test_emergency_mutation_4_bank_sms_exclusion_resistance(emergency_agent):
    """
    (Mutation 4 Test) Bank notification SMS exclusion:
    Legitimate transaction SMS notifications (balance change, deposit/transfer success)
    must NOT trigger emergency, even when containing fee/loan terms without victim loss.
    """
    bank_sms_cases = [
        "Quý khách đã chuyển khoản 5 triệu phí bảo hiểm thành công. SD: 2.000.000đ",
        "GD: -5.000.000đ lúc 10:21 ND: tien khoan vay",
    ]
    for text in bank_sms_cases:
        res = emergency_agent.check_trigger(text)
        assert res["is_emergency"] is False, f"Mutation 4: Bank notification SMS wrongly triggered emergency: '{text}'"

