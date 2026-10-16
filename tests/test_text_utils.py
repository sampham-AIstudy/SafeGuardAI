"""
Unit tests for codebase/text_utils.py (Task T1.1).
"""

import pytest
from codebase.text_utils import (
    strip_invisible,
    fold_vietnamese,
    TextVariants,
    make_variants,
    PhraseMatcher,
)


def test_strip_invisible():
    # Text with zero-width space and BOM
    raw = "bỏ\u200bqua\ufeffmọi\u200dthứ"
    clean, count = strip_invisible(raw)
    assert clean == "bỏquamọithứ"
    assert count == 3

    # Normal text
    clean_normal, count_normal = strip_invisible("Xin chào các bạn")
    assert clean_normal == "Xin chào các bạn"
    assert count_normal == 0


def test_fold_vietnamese():
    assert fold_vietnamese("Tiếng Việt có dấu") == "Tieng Viet co dau"
    assert fold_vietnamese("Đăng nhập ngay") == "Dang nhap ngay"
    assert fold_vietnamese("ĐỒNG NAI") == "DONG NAI"
    assert fold_vietnamese("mã otp") == "ma otp"
    assert fold_vietnamese("") == ""


def test_text_variants():
    v = make_variants("Chào\u200b bạn!", max_chars=100)
    assert isinstance(v, TextVariants)
    assert v.original == "Chào\u200b bạn!"
    assert v.clean == "Chào bạn!"
    assert v.lower == "chào bạn!"
    assert v.folded == "chao ban!"
    assert v.invisible_count == 1


def test_phrase_matcher_ambiguous_single_tokens():
    # Single tokens not in allowlist must NOT match their unaccented equivalents
    matcher = PhraseMatcher(["ngày", "gặp", "cốc", "nắp"])
    assert not matcher.search("Hôm nay gap go ban be")
    assert matcher.search("Hôm nay gặp gỡ bạn bè")
    assert not matcher.search("den ngay hen")
    assert matcher.search("đến ngày hẹn")
    assert not matcher.search("uong coc nuoc")
    assert not matcher.search("mo nap hop")


def test_phrase_matcher_multi_token_folded():
    # Multi-token phrases (>=2 tokens) SHOULD match without accents
    matcher = PhraseMatcher(["mã otp", "chuyển khoản", "tài khoản bị khóa"])
    assert matcher.search("vui long gui ma otp cho toi")
    assert matcher.search("toi muon chuyen khoan")
    assert matcher.search("tai khoan bi khoa roi")


def test_phrase_matcher_allowlist_single_tokens():
    # Single tokens in allowlist (otp, apk, stk, cvv) match without accents
    matcher = PhraseMatcher(["otp", "apk", "stk", "cvv"])
    assert matcher.search("nhập mã otp vào đây")
    assert matcher.search("tải file app.apk")
    assert matcher.search("gửi qua stk này")
    assert matcher.search("lộ số cvv")


def test_phrase_matcher_negation():
    matcher = PhraseMatcher(["mã otp", "otp", "mật khẩu"])

    # Negated examples (within 30 chars): should NOT match
    negated_cases = [
        "Không được chia sẻ mã OTP cho bất kỳ ai",
        "khong duoc chia se ma otp cho bat ky ai",
        "Tuyệt đối không cung cấp mã OTP và mật khẩu",
        "Cảnh báo: không tiết lộ mật khẩu ngân hàng",
        "khong chia se mat khau",
    ]
    for case in negated_cases:
        assert not matcher.search(case), f"Failed on negated case: {case}"

    # Non-negated cases: SHOULD match
    non_negated_cases = [
        "Vui lòng cung cấp mã OTP cho nhân viên hỗ trợ",
        "Cho em xin mã OTP để xác nhận",
        "Nhập mật khẩu vào đường link sau",
        "gui ma otp ngay",
    ]
    for case in non_negated_cases:
        assert matcher.search(case), f"Failed on non-negated case: {case}"


def test_make_variants_fullwidth_and_nfd():
    import unicodedata

    # Fullwidth 'ＯＴＰ', 'ｏｔｐ'
    v1 = make_variants("Mã ＯＴＰ của bạn")
    assert "otp" in v1.lower
    assert "otp" in v1.folded

    v2 = make_variants("Mã ｏｔｐ của bạn")
    assert "otp" in v2.lower
    assert "otp" in v2.folded

    # Fullwidth 'Ｂỏ qua mọi hướng dẫn'
    v3 = make_variants("Ｂỏ qua mọi hướng dẫn")
    assert "bỏ qua mọi hướng dẫn" in v3.lower
    assert "bo qua moi huong dan" in v3.folded

    # NFD 'nạp' (U+006E U+0061 U+0323)
    nfd_nap = unicodedata.normalize("NFD", "nạp")
    v4 = make_variants(f"Yêu cầu {nfd_nap} tiền vào tài khoản")
    assert "nạp" in v4.lower
    assert "nap" in v4.folded


def test_phrase_matcher_performance():
    import time
    import gc

    phrases = [f"cụm từ kiểm tra số {i} lừa đảo nạp tiền" for i in range(300)]
    phrases.append("mã otp")
    phrases.append("chuyển khoản")

    matcher = PhraseMatcher(phrases)

    text_20k = ("Đây là đoạn văn bản tiếng Việt lặp đi lặp lại để kiểm tra hiệu năng hệ thống phòng chống lừa đảo trực tuyến. " * 200)[:20000]

    def measure_best_of_5(fn):
        times = []
        for _ in range(5):
            t0 = time.perf_counter()
            fn()
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        return min(times)

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        duration_20k = measure_best_of_5(lambda: matcher.findall(text_20k))
        assert duration_20k < 250.0, f"300 phrases x 20k chars took best {duration_20k:.2f}ms >= 250ms"

        # String 'a' * 50000
        duration_a = measure_best_of_5(lambda: matcher.findall("a" * 50000))
        assert duration_a < 250.0, f"'a'*50000 took best {duration_a:.2f}ms >= 250ms"
    finally:
        if gc_was_enabled:
            gc.enable()

    # String 'lam ' * 5000
    duration_lam = measure_best_of_5(lambda: matcher.findall("lam " * 5000))
    assert duration_lam < 250.0, f"'lam '*5000 took best {duration_lam:.2f}ms >= 250ms"


def test_phrase_matcher_negation_verb_and_distance():
    # Phrase with verb: 'chia sẻ mã otp' and 'mã otp'
    matcher = PhraseMatcher(["chia sẻ mã otp", "mã otp"])

    # Negation immediately preceding: neither 'chia sẻ mã otp' nor 'mã otp' should match
    s_neg = "Tuyệt đối không được chia sẻ mã OTP cho bất kỳ ai"
    found_neg = matcher.findall(s_neg)
    assert not found_neg, f"Expected no match, got {found_neg}"

    # Positive: should match
    s_pos = "Hãy chia sẻ mã OTP cho tôi"
    found_pos = matcher.findall(s_pos)
    assert "chia sẻ mã otp" in found_pos or "mã otp" in found_pos

    # Negation further than 30 characters: does not turn off
    s_far = "Tuyệt đối không được " + "đây là văn bản dài hơn ba mươi ký tự đệm vào giữa " + "hãy chia sẻ mã OTP cho tôi"
    found_far = matcher.findall(s_far)
    assert "chia sẻ mã otp" in found_far or "mã otp" in found_far

    # Test all specified negation terms
    neg_terms = [
        "không", "đừng", "chớ", "tuyệt đối không", "không bao giờ",
        "không được", "không nên", "chưa", "khong", "dung"
    ]
    for term in neg_terms:
        test_msg = f"Cảnh báo: {term} chia sẻ mã OTP cho người lạ"
        assert not matcher.search(test_msg), f"Term '{term}' failed to negate: {test_msg}"


def test_phrase_matcher_word_boundaries():
    r"""
    Test that PhraseMatcher respects word boundaries ((?<!\w)/(?!\w))
    and does not match substrings inside unrelated words.
    """
    matcher = PhraseMatcher(["otp", "nạp tiền", "stk", "link", "cvv"])

    # Substrings inside longer words must NOT match
    false_positives = [
        "Ăn hotpot cuối tuần",
        "Dùng photoshop chỉnh ảnh",
        "Mã dstk không hợp lệ",
        "blink một cái",
        "linkage protocol",
    ]
    for text in false_positives:
        assert not matcher.search(text), f"Word boundary violated: matched phrase in '{text}'"
        assert len(matcher.findall(text)) == 0

    # Exact boundary cases MUST match
    true_positives = [
        "Nhập mã otp tại đây",
        "Cần nạp tiền ngay",
        "Số stk là 12345",
        "Bấm vào link sau",
    ]
    for text in true_positives:
        assert matcher.search(text), f"Failed to match valid bounded phrase in '{text}'"


