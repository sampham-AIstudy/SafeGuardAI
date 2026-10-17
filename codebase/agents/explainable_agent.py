import re
from urllib.parse import urlparse
from typing import Any

from codebase.config import get_settings
from codebase.text_utils import PhraseMatcher, make_variants


class AnalysisDict(dict):
    """
    A dict subclass supporting attribute access (e.g. report.findings, finding.effective_host)
    and transparent JSON serialization with standard json.dumps.
    """
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def to_dict(self) -> dict[str, Any]:
        return dict(self)


def _wrap_report_dict(val: Any) -> Any:
    """Recursively wrap dictionaries/lists into AnalysisDict for attribute access."""
    if val is None:
        return None
    if hasattr(val, "to_dict") and not isinstance(val, dict):
        val = val.to_dict()
    if isinstance(val, dict):
        return AnalysisDict({k: _wrap_report_dict(v) for k, v in val.items()})
    if isinstance(val, list):
        return [_wrap_report_dict(item) for item in val]
    return val

OFFICIAL_WHITELIST_DOMAINS = {
    # Official Vietnam Banks
    "agribank.com.vn", "vietcombank.com.vn", "techcombank.com", "techcombank.com.vn",
    "bidv.com.vn", "vpbank.com.vn", "mbbank.com.vn", "acb.com.vn", "tpbank.com.vn",
    "sacombank.com.vn", "vietinbank.vn", "vib.com.vn", "shb.com.vn", "hdbank.com.vn",
    "scb.com.vn", "msb.com.vn", "ocb.com.vn", "momo.vn", "vnpay.vn", "zalopay.vn",

    # Official Vietnam Government & Public Agencies
    "vneid.gov.vn", "chinhphu.vn", "dichvucong.gov.vn", "gdt.gov.vn", "bocongan.gov.vn",
    "mofa.gov.vn", "tinnhiemmang.vn", "chongluadao.vn",

    # Major Legitimate Platforms
    "microsoft.com", "microsoftonline.com", "office.com", "live.com", "google.com",
    "google.com.vn", "youtube.com", "facebook.com", "zalo.me", "shopee.vn", "lazada.vn",
    "tiki.vn", "tiktok.com", "apple.com"
}


def is_local_negated(
    text: str,
    start_idx: int,
    end_idx: int | None = None,
    max_words: int = 6,
    is_deposit: bool = False
) -> bool:
    """
    Check if a matched phrase at start_idx is locally negated.
    Lookback window: <= max_words words immediately before start_idx.
    Must NOT cross punctuation: , . ! ? ; : \\n
    Uses word-boundary token matching to avoid substring pitfalls ('cho', 'dung' -> 'sử dụng').
    """
    lookback = text[max(0, start_idx - 100):start_idx]
    last_punct_idx = -1
    for i, ch in enumerate(lookback):
        if ch in ",.!?;:\n":
            last_punct_idx = i

    if last_punct_idx != -1:
        lookback = lookback[last_punct_idx + 1:]

    words = lookback.strip().split()
    if not words:
        return False

    window_words = words[-max_words:]
    window_text = " ".join(window_words).lower()

    if is_deposit:
        deposit_neg_pattern = re.compile(
            r"\b(?:không\s+yêu\s+cầu|khong\s+yeu\s+cau|"
            r"không\s+cần|khong\s+can|"
            r"miễn|mien|"
            r"không\s+thu|khong\s+thu|"
            r"không\s+bắt\s+buộc|khong\s+bat\s+buoc|"
            r"không\s+phải|khong\s+phai)\b",
            re.IGNORECASE
        )
        return bool(deposit_neg_pattern.search(window_text))

    # Condition check: e.g. "Nếu không cung cấp..." -> condition, NOT negation of scam request
    if re.search(r"\b(?:nếu|neu)\b[^.\n]{0,20}\b(?:không|khong|ko|chưa|chua)\b", window_text):
        return False

    # Inability check: e.g. "không chuyển tiền được" -> "được" immediately after is NOT a negation of scam action
    if end_idx is not None and end_idx < len(text):
        after_text = text[end_idx:end_idx + 25].strip().lower()
        if re.match(r"^(?:được|duoc)\b", after_text):
            return False

    neg_pattern = re.compile(
        r"\b(?:tuyệt\s+đối\s+không|tuyet\s+doi\s+khong|"
        r"không\s+bao\s+giờ|khong\s+bao\s+gio|"
        r"chưa\s+bao\s+giờ|chua\s+bao\s+gio|"
        r"không\s+được|khong\s+duoc|"
        r"không\s+nên|khong\s+nen|"
        r"không\s+hề|khong\s+he|"
        r"chứ\s+đừng|chu\s+dung|"
        r"đừng|dung|không|khong|chớ)\b",
        re.IGNORECASE
    )
    return bool(neg_pattern.search(window_text))


class ExplainableAgent:
    """
    Explainable AI Agent:
    Provides explicit breakdown of Risk Score % based on weighted evidence factors.
    Accurately distinguishes between Official Whitelisted Domains (0% risk)
    and Subdomain Impersonation / Phishing Links (80-99% risk).
    """
    def __init__(self):
        # Scam action keywords (restored to 539ecb1)
        self._scam_action_keywords = [
            "nạp tiền", "nạp quỹ", "cọc", "quỹ đảm bảo", "đặt cọc", "phí kích hoạt",
            "mã otp", "mã xác thực", "tải file apk", ".apk", "chuyển khoản cho",
            "vừa bị lừa", "chuyển tiền gấp"
        ]

        # BLOCK A: Fake Recruitment / CTV (539ecb1)
        self._block_a_matcher = PhraseMatcher([
            "tuyển dụng", "ctv", "việc làm", "chốt đơn", "xem tiktok", "làm việc tại nhà",
            "tuyển người bán", "tuyển người bán hàng", "không cần vốn"
        ], allow_folded=True, folded_allowlist=("ctv",))

        # BLOCK B: Advance Payment / Money Deposit Request
        # check_negation=False so PhraseMatcher doesn't prematurely drop phrases with internal negation
        self._block_b_accented = PhraseMatcher([
            "chuyển tiền", "nạp tiền", "nạp quỹ", "cọc", "quỹ đảm bảo", "đặt cọc",
            "phí xác nhận", "phí kích hoạt", "thanh toán trước"
        ], allow_folded=False, check_negation=False)
        self._block_b_unaccented_multi = PhraseMatcher([
            "nap quy", "quy dam bao", "phi xac nhan", "phi kich hoat", "thanh toan truoc", "ky quy"
        ], allow_folded=False, check_negation=False)
        self._block_b_unaccented_single = PhraseMatcher([
            "nap tien", "dat coc"
        ], allow_folded=False, check_negation=False)

        # BLOCK C: Fake Banking / OTP Phishing (539ecb1 triggers)
        self._block_c_matcher = PhraseMatcher([
            "tài khoản bị khóa", "tài khoản của quý khách", "xác minh thông tin",
            "đăng nhập ngay", "cập nhật thông tin", "tài khoản bị tạm khóa",
            "internet banking", "mã otp", "mã xác thực", "cảnh báo bảo mật", "nạp tiền ví"
        ], allow_folded=True, folded_allowlist=())

        # BLOCK F: Government / Authority Impersonation (539ecb1)
        self._block_f_matcher = PhraseMatcher([
            "cục thuế", "công an", "tòa án", "viện kiểm sát", "vneid", "bộ công an",
            "cán bộ", "cơ quan điều tra", "phòng cảnh sát"
        ], allow_folded=True)

        # BLOCK G: Personal Bank Account (539ecb1)
        self._block_g_matcher = PhraseMatcher([
            "tài khoản cá nhân", "stk", "số tài khoản", "chuyển khoản cho"
        ], allow_folded=True, folded_allowlist=("stk",))

        # BLOCK H: Urgency / Time Pressure (539ecb1)
        self._block_h_matcher = PhraseMatcher([
            "gấp", "ngay", "nhanh", "30 phút", "hạn chót", "khẩn cấp", "sẽ bị khóa"
        ], allow_folded=True, folded_allowlist=())

        # BLOCK I: Emergency / Already Scammed (539ecb1)
        self._block_i_matcher = PhraseMatcher([
            "vừa bị lừa", "chuyển rồi", "chuyển nhầm", "mất tiền", "lừa đảo rồi", "bị hack"
        ], allow_folded=True)

        # ─────────────────────────────────────────
        # THE 9 SIGNAL FAMILIES (a to i)
        # ─────────────────────────────────────────
        # Family (a): Mồi trúng thưởng/hoàn tiền + nộp phí/thẻ cào: 35
        self._fam_a_lure = PhraseMatcher([
            "trúng thưởng", "trúng giải", "nhận quà", "quà tri ân",
            "nhận quà miễn phí", "tặng quà miễn phí", "quà tặng miễn phí",
            "nhận thưởng", "hoàn tiền may mắn", "quay số trúng", "quay số",
            "học bổng", "tiền hỗ trợ", "hoàn thuế", "hoàn thuế thu nhập", "hoàn thuế điện tử",
            "vay không thế chấp", "vay vốn nhanh", "giải ngân nhanh",
            "không cần thẩm định", "không thẩm định", "không thế chấp",
            "vay tiêu dùng", "gói vay tiêu dùng", "gói vay", "khoản vay",
            "vay vốn", "vay tiền online", "vay tiền", "duyệt hồ sơ",
            "quà tặng", "kiện hàng quà tặng", "quà từ nước ngoài"
        ], allow_folded=True)
        self._fam_a_fee = PhraseMatcher([
            "nộp phí", "đóng phí", "phí làm hồ sơ", "phí vận chuyển", "phí nhận giải",
            "phí hồ sơ", "phí bảo hiểm", "tiền cọc nhận quà", "mua thẻ cào",
            "mã thẻ cào", "nạp thẻ cào", "đóng thuế nhận thưởng",
            "phí xác nhận giải", "phí giải ngân", "phí xử lý", "chuyển trước phí",
            "nộp phí giải ngân", "chuyển trước", "chuyen truoc",
            "chuyển tiền trước", "chuyen tien truoc", "chuyển tiền nộp phí", "chuyen tien nop phi",
            "yêu cầu chuyển tiền", "yeu cau chuyen tien", "phí xử lý hồ sơ", "phi xu ly",
            "phí bảo hiểm khoản vay", "phi bao hiem", "tiền cọc", "tien coc",
            "phí hải quan", "phi hai quan", "thuế hải quan", "thue hai quan", "phí vận chuyển quốc tế"
        ], allow_folded=True)

        # Family (b): Thu thập thẻ/OTP/CVV/CCCD (45) - co-occurrence check
        # 1. Verbs: đọc, gửi, cung cấp, chụp, báo, nhập, đưa, nhắn, xin, cho mình, gửi giúp, nhắn giúp (G6)
        self._fam_b_verb_regex = re.compile(
            r"\b(?:đọc|gửi|cung\s+cấp|chụp|báo|nhập|đưa|nhắn|xin|cho\s+mình|gửi\s+giúp|nhắn\s+giúp|"
            r"doc|gui|cung\s+cap|chup|bao|nhap|dua|nhan|xin|cho\s+minh|gui\s+giup|nhan\s+giup)(?!\w)",
            re.IGNORECASE
        )
        # 2. Sensitive: otp, mã xác thực, cvv, số thẻ, 16 số, 3 số mặt sau, mật khẩu, cccd
        self._fam_b_target_regex = re.compile(
            r"\b(?:mã\s+otp|ma\s+otp|otp|mã\s+xác\s+thực|ma\s+xac\s+thuc|cvv|cvc|số\s+thẻ|so\s+the|"
            r"16\s+số(?:\s+trên\s+thẻ)?|16\s+so(?:\s+tren\s+the)?|3\s+số\s+mặt\s+sau|3\s+so\s+mat\s+sau|"
            r"mã\s+3\s+số(?:\s+mặt\s+sau)?|ma\s+3\s+so(?:\s+mat\s+sau)?|mật\s+khẩu|mat\s+khau|cccd|cmnd)(?!\w)",
            re.IGNORECASE
        )
        # 3. Recipient / Motive (G6 added: giúp em, để em xác minh, để hoàn tất, để nhận)
        self._fam_b_motive_regex = re.compile(
            r"(?:cho\s+nhân\s+viên|cho\s+nhan\s+vien|cho\s+chuyên\s+viên|cho\s+chuyen\s+vien|"
            r"cho\s+cán\s+bộ|cho\s+can\s+bo|cho\s+tổng\s+đài|cho\s+tong\s+dai|"
            r"qua\s+điện\s+thoại|qua\s+dien\s+thoai|qua\s+link|để\s+nhận\s+quà|de\s+nhan\s+qua|"
            r"để\s+(?:em\s+|anh\s+)?xác\s+(?:minh|thực)|de\s+(?:em\s+|anh\s+)?xac\s+(?:minh|thuc)|"
            r"xác\s+thực\s+trên\s+hệ\s+thống|xac\s+thuc\s+tren\s+he\s+thong|"
            r"để\s+kích\s+hoạt|de\s+kich\s+hoat|"
            r"để\s+gia\s+hạn|de\s+gia\s+han|để\s+tránh\s+khóa|de\s+tranh\s+khoa|"
            r"để\s+hoàn\s+tiền|de\s+hoan\s+tien|hoàn\s+tiền|hoan\s+tien|"
            r"đọc\s+cho\s+mình|doc\s+cho\s+minh|cho\s+mình|cho\s+minh|gửi\s+mình|gui\s+minh|cho\s+em|cho\s+toi|"
            r"giúp\s+em|giup\s+em|để\s+em\s+xác\s+minh|de\s+em\s+xac\s+minh|"
            r"để\s+hoàn\s+tất\s+(?:xác\s+minh|thủ\s+tục|hồ\s+sơ|nhận|kích\s+hoạt)|de\s+hoan\s+tat\s+(?:xac\s+minh|thu\s+tuc|ho\s+so|nhan|kich\s+hoat)|"
            r"để\s+nhận|de\s+nhan)(?!\w)",
            re.IGNORECASE
        )

        # Family (c): Đầu tư cam kết lãi cao (35)
        self._fam_c_invest = PhraseMatcher([
            "đầu tư", "chứng khoán", "tiền ảo", "giao dịch tài chính", "lợi nhuận",
            "sinh lời", "hoa hồng", "lãi suất", "sàn giao dịch", "đầu tư sinh lời",
            "làm trong ngành tài chính", "nhắn nhầm số", "quen qua mạng", "bên tài chính",
            "sàn quốc tế", "tiền kỹ thuật số"
        ], allow_folded=True)
        self._fam_c_guarantee = PhraseMatcher([
            "lợi nhuận đảm bảo", "không rủi ro", "cam kết sinh lời", "cam kết lợi nhuận",
            "bao lỗ", "vốn ít lời nhiều", "cam kết lãi", "lãi khủng", "lãi suất khủng",
            "lợi nhuận khủng", "đảm bảo không lỗ", "không lời em đền", "chắc chắn có lãi"
        ], allow_folded=True)
        self._fam_c_regex_day = re.compile(
            r"(?:\b|\D)\d{1,3}\s*%\s*\/\s*(?:ngày|ngay|tuần|tuan|tháng|thang|hôm|hom)(?:\b|\D)",
            re.IGNORECASE
        )
        self._fam_c_regex_each = re.compile(
            r"(?:\b|\D)\d{1,3}\s*%\s*(?:mỗi|moi|từng|tung)\s*(?:ngày|ngay|tuần|tuan)(?:\b|\D)",
            re.IGNORECASE
        )

        # Family (d) & (f): Mượn tiền amount regex (G7 unified)
        self._borrow_amount_regex = re.compile(
            r"\b(?:cho\s+)?(?:mượn|muon|vay|ck|chuyển|chuyen)\s+\d[\d.,]*\s*(?:k|nghìn|nghin|triệu|trieu|tr|củ|cu)\b",
            re.IGNORECASE
        )

        # Family (d): Mượn tiền qua mạng xã hội / người thân giả (30)
        self._fam_d_social = PhraseMatcher([
            "nick facebook", "tài khoản facebook", "nick zalo", "tài khoản zalo",
            "nhắn qua messenger", "bị hack nick", "mất nick", "tài khoản bị hack",
            "mượn tài khoản", "nhờ chuyển tiền hộ", "nhờ chuyển khoản hộ"
        ], allow_folded=True)
        self._fam_d_borrow = PhraseMatcher([
            "cho mượn", "cho vay", "chuyển khoản giúp", "chuyển khoản hộ",
            "nhờ chuyển tiền", "mượn tạm", "bắn tiền cho", "chuyển tiền gấp", "nhờ chuyển gấp"
        ], allow_folded=True)

        # Family (e): Bill báo thành công nhưng tiền chưa về (40)
        self._fam_e_context = PhraseMatcher([
            "bill", "ảnh bill", "biên lai", "ảnh chụp bill", "sao kê", "screenshot",
            "ảnh chụp màn hình", "chuyển khoản thành công", "giao dịch thành công", "vietqr"
        ], allow_folded=True)

        # Family (f): Video call mờ / deepfake + mượn tiền (30)
        self._fam_f_video_phrases = PhraseMatcher([
            "video call mờ", "gọi video mờ", "cuộc gọi video mờ", "video nhòe",
            "video chập chờn", "deepfake", "video call lag", "video giật lag"
        ], allow_folded=True)
        self._fam_f_video_regex = re.compile(
            r"(?:video\s*call|gọi\s*video|cuộc\s*gọi\s*video|goi\s*video|cuoc\s*goi\s*video)\s*(?:mờ|mo|lag|chập\s*chờn|chap\s*chon|nhòe|nhoe|giật|giat|chất\s*lượng\s*thấp|chat\s*luong\s*thap|không\s*rõ|khong\s*ro|vài\s*giây|vai\s*giay|\d+\s*giây|\d+\s*giay)(?!\w)",
            re.IGNORECASE
        )
        self._fam_f_borrow_phrases = PhraseMatcher([
            "mượn tiền", "mượn gấp", "cho mượn", "vay tiền", "chuyển tiền cấp cứu",
            "chuyển khoản gấp", "nhờ chuyển tiền"
        ], allow_folded=True)

        # Family (g): Mạo danh cơ quan nhà nước + đe dọa khóa/phạt/bắt giữ + hạn chót (35)
        # G3(a)(i): 'ngân hàng' trần KHÔNG phải mạo danh cơ quan
        self._fam_g_agency = PhraseMatcher([
            "công an", "cơ quan điều tra", "viện kiểm sát", "tòa án", "cục thuế",
            "bộ công an", "phòng cảnh sát", "csgt", "cảnh sát giao thông", "bhxh",
            "bảo hiểm xã hội", "chi cục thuế", "tổng cục thuế"
        ], allow_folded=True, folded_allowlist=("csgt", "bhxh"))
        self._fam_g_threat = PhraseMatcher([
            "lệnh bắt giữ", "lệnh bắt giam", "bắt tạm giam", "bắt giữ", "bị bắt giữ",
            "bị bắt", "khởi tố", "bị khởi tố", "xử phạt", "phạt tiền", "bị phạt", "phạt nguội",
            "bị cắt điện", "cắt điện", "cưỡng chế", "tước bằng", "tước bằng lái",
            "bị phong tỏa", "phong tỏa", "phong tỏa tài khoản", "bị tạm dừng",
            "khóa vĩnh viễn", "khóa vỉnh viễn", "truy tố", "lệnh bắt",
            "đóng băng", "rửa tiền", "trốn thuế", "bị bắt giam"
        ], allow_folded=True)
        # G3(a)(ii): Urgency must be a time deadline or fine demand, NOT bare "chuyển tiền/chuyển khoản"
        self._fam_g_urgency = PhraseMatcher([
            "trước 17h", "trong 24h", "trong vòng 24 giờ", "2 giờ tới", "hôm nay", "hôm nai", "trong ngày",
            "truoc 17h", "2 gio toi", "hom nay", "hom nai", "trong ngay", "hạn chót", "han chot",
            "nộp phạt", "đóng phạt", "tài khoản tạm giữ", "nop phat", "dong phat", "tai khoan tam giu",
            "nếu không", "nếu ko", "trong 2 giờ", "trong 2 gio", "2 giờ", "2 gio"
        ], allow_folded=True, folded_allowlist=("ko",))
        self._fam_g_phone_regex = re.compile(r"(?:\b|[^0-9])(?:0\d{9,10}|02\d{8,9})\b")

        # Family (h): Tuyển CTV / việc nhẹ lương cao / không cần vốn + nạp tiền / cọc / nhiệm vụ (40)
        self._fam_h_recruitment = PhraseMatcher([
            "việc nhẹ lương cao", "tuyển ctv", "tuyển cộng tác viên", "chốt đơn",
            "làm việc tại nhà", "không cần vốn", "khong can von", "tuyển người bán", "tuyen nguoi ban",
            "tuyển người bán hàng", "tuyen nguoi ban hang", "nhiệm vụ telegram",
            "nhiệm vụ zalo", "đánh giá sản phẩm", "like video", "đánh giá app",
            "lương ctv", "nhận lương ctv", "ctv"
        ], allow_folded=True, folded_allowlist=("ctv",))
        self._fam_h_salary_regex = re.compile(
            r"\b(?:lương|luong|kiếm|kiem)\s+\d[\d.,]*\s*(?:k|nghìn|nghin|triệu|trieu|tr)\s*\/\s*(?:ngày|ngay|giờ|gio|tuần|tuan)\b",
            re.IGNORECASE
        )
        self._fam_h_deposit = PhraseMatcher([
            "nạp tiền", "nạp quỹ", "đặt cọc", "dat coc", "quỹ đảm bảo", "quy dam bao", "làm nhiệm vụ",
            "nhiệm vụ nạp tiền", "phí kích hoạt", "phi kich hoat", "chuyển khoản trước", "nộp tiền cọc",
            "nạp tiền nhận hoa hồng", "nộp tiền", "nộp quỹ", "ký quỹ", "ky quy", "mở khóa vip", "hoàn tiền nhiệm vụ"
        ], allow_folded=True)

        # Family (i): Link / APK lạ yêu cầu cài đặt (35)
        self._fam_i_install = PhraseMatcher([
            "cài app", "tải app", "cài ứng dụng", "tải ứng dụng", "cài phần mềm",
            "tải phần mềm", "cài đặt ứng dụng", "cài đặt vneid", "tải vneid",
            "tải dịch vụ công", "cài đặt dịch vụ công", "cài file", "cài file apk", "tải file apk"
        ], allow_folded=True, folded_allowlist=("apk",))
        self._fam_i_suspicious_source = PhraseMatcher([
            "ngoài ch play", "ngoài app store", "ngoài google play", "nguồn không rõ",
            "nguồn không xác định", "cài file", "cài file apk", "tải file apk",
            "qua link", "đường link lạ", "bật cài đặt"
        ], allow_folded=True)

        # Educational tone detection (G1):
        # Only educational / warning news markers; NO bare "Lưu ý" or "Cảnh báo"
        self._educational_tone_matcher = PhraseMatcher([
            "không bao giờ yêu cầu", "khong bao gio yeu cau",
            "khuyến cáo người dân", "khuyen cao nguoi dan",
            "khuyến cáo khách hàng", "khuyen cao khach hang",
            "ngân hàng khuyến cáo", "ngan hang khuyen cao",
            "công an khuyến cáo", "cong an khuyen cao",
            "cảnh sát cảnh báo", "canh sat canh bao",
            "các hình thức lừa đảo", "cac hinh thuc lua dao",
            "thủ đoạn lừa đảo", "thu doan lua dao",
            "thủ đoạn tinh vi", "nhận biết lừa đảo",
            "công an đã bắt", "cong an da bat",
            "theo báo", "bài báo cảnh báo", "báo tuổi trẻ",
            "báo thanh niên", "báo vnexpress", "nạn nhân bị lừa",
            "một số đối tượng", "đối tượng lừa đảo",
            "nâng cao cảnh giác", "cảnh giác trước"
        ], allow_folded=True)

        # Call to action regex in 2nd person (G1)
        self._call_to_action_regex = re.compile(
            r"\b(?:hãy|vui\s+lòng|yêu\s+cầu|"
            r"(?:anh|chị|bạn|quý\s+khách|anh\s*[\/.]\s*chị)\s+(?:phải|cần|vui\s+lòng|hãy)|"
            r"hay|vui\s+long|yeu\s+cau|"
            r"(?:anh|chi|ban|quy\s+khach)\s+(?:phai|can|vui\s+long|hay))"
            r"[^.\n]{0,40}"
            r"\b(?:chuyển|nộp|đóng|đọc|gửi|bấm|nhấp|tải|cài|đăng\s+nhập|xác\s+minh|liên\s+hệ|"
            r"chuyen|nop|dong|doc|gui|bam|nhap|tai|cai|dang\s+nhap|xac\s+minh|lien\s+he)\b",
            re.IGNORECASE
        )

        # Linear local domain regex for family-specific bare domains (G2):
        self._linear_domain_regex = re.compile(
            r"(?<![A-Za-z0-9-])[A-Za-z0-9-]{1,63}\.(?:com|net|org|top|xyz|vip|online|info|site|club|help|icu|cc|me|vn|link|shop|app)(?![A-Za-z0-9-])",
            re.IGNORECASE
        )

    def _extract_urls(self, text):
        return re.findall(r'https?://[^\s]+|www\.[^\s]+', text)

    def _parse_hostname(self, url_str):
        if not url_str.startswith(("http://", "https://")):
            url_str = "https://" + url_str
        try:
            parsed = urlparse(url_str)
            return parsed.netloc.split(":")[0].lower()
        except Exception:
            return ""

    def is_official_domain(self, url_or_host):
        hostname = self._parse_hostname(url_or_host) if "/" in url_or_host or "." in url_or_host else url_or_host.lower()
        if not hostname:
            return False
        for official in OFFICIAL_WHITELIST_DOMAINS:
            if hostname == official or hostname.endswith("." + official):
                return True
        try:
            from codebase.url_analysis.brands import BrandCatalog
            cat = BrandCatalog.load()
            is_off, _ = cat.is_official(hostname)
            if is_off:
                return True
            is_rel, _ = cat.is_related(hostname)
            if is_rel:
                return True
        except Exception:
            pass
        return False

    @property
    def url_analyzer(self):
        try:
            from codebase.url_analysis import get_shared_url_analyzer
            return get_shared_url_analyzer()
        except Exception:
            if not hasattr(self, "_lazy_url_analyzer") or self._lazy_url_analyzer is None:
                from codebase.url_analysis.analyzer import UrlAnalyzer
                from codebase.url_analysis.blacklist import PhishBlacklist
                self._lazy_url_analyzer = UrlAnalyzer(blacklist=PhishBlacklist())
            return self._lazy_url_analyzer

    def _legacy_url_factor(self, text, text_lower, clean_norm, factors, has_only_official_urls):
        urls = self._extract_urls(text)
        url_hostnames = [self._parse_hostname(u) for u in urls if u]

        suspicious_tld = [".xyz", ".cc", ".apk", ".tk", ".ml", ".ga", ".cf", ".info", ".top", ".pw"]
        brand_keywords = [
            "vietcombank", "techcombank", "agribank", "vpbank", "bidv", "vneid",
            "microsoft", "microsoftonline", "shopee", "chinhphu"
        ]

        impersonated_detected = False
        for url, host in zip(urls, url_hostnames):
            if not host:
                continue

            if self.is_official_domain(host):
                continue

            is_brand_impersonation = False
            for brand in brand_keywords:
                if brand in host:
                    is_brand_impersonation = True
                    break

            is_suspicious_tld = any(host.endswith(tld) or tld in host for tld in suspicious_tld)

            if is_brand_impersonation or is_suspicious_tld or "-" in host:
                impersonated_detected = True

        added_weight = 0
        if impersonated_detected:
            weight = 45
            factors.append({"factor": "Đường link giả mạo / Domain impersonation ngân hàng hoặc cơ quan nhà nước", "weight": weight})
            added_weight += weight
        elif any(w in text_lower for w in ["link lạ", "nhấp vào đây", "click here"]) and not has_only_official_urls:
            weight = 30
            factors.append({"factor": "Chứa đường link dẫn đến địa chỉ nghi vấn", "weight": weight})
            added_weight += weight
        return added_weight

    def explain(self, text, matched_flags=None, ocr_anomalies=None, escalation_info=None, url_report=None):
        settings = get_settings()
        module_enabled = bool(settings.url_module_enabled)
        matched_flags = matched_flags or []
        ocr_anomalies = ocr_anomalies or []

        if url_report is None and module_enabled:
            try:
                clean_for_url = re.sub(r'(?<![0-9a-zA-Z/])(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?![0-9a-zA-Z/]|(?:\.[a-zA-Z]))', ' ', text)
                url_report = self.url_analyzer.analyze_text(clean_for_url)
            except Exception:
                url_report = None

        variants = make_variants(text)
        text_lower = variants.lower
        factors = []
        total_risk_score = 0

        # Linear ReDoS protection: collapse multiple whitespace before regex matching
        clean_norm = re.sub(r'\s+', ' ', variants.clean)
        folded_norm = re.sub(r'\s+', ' ', variants.folded)

        bare_domains = self._linear_domain_regex.findall(clean_norm)
        has_suspicious_bare_domain = any(not self.is_official_domain(d) for d in bare_domains)

        all_signals = []
        if module_enabled and url_report is not None:
            findings = getattr(url_report, "findings", None)
            if findings is None and isinstance(url_report, dict):
                findings = url_report.get("findings", [])

            raw_off = getattr(url_report, "has_only_official_urls", None)
            if raw_off is None and isinstance(url_report, dict):
                raw_off = url_report.get("has_only_official_urls", False)
            has_only_official_urls = bool(raw_off)

            has_suspicious_urls = any(
                not (getattr(f, "is_official", False) if not isinstance(f, dict) else f.get("is_official", False))
                for f in (findings or [])
            )
        else:
            urls = self._extract_urls(text)
            url_hostnames = [self._parse_hostname(u) for u in urls if u]
            has_urls = len(urls) > 0
            official_urls_count = sum(1 for h in url_hostnames if self.is_official_domain(h))
            has_only_official_urls = has_urls and (official_urls_count == len(urls))
            has_suspicious_urls = any(not self.is_official_domain(h) for h in url_hostnames)

        # Check for explicit scam action indicators (exact 539ecb1 logic)
        has_scam_actions = any(kw in text_lower for kw in self._scam_action_keywords)

        # G1: Educational tone vs 2nd person call to action
        has_educational_tone = bool(self._educational_tone_matcher.search(variants))
        has_call_to_action = bool(
            self._call_to_action_regex.search(clean_norm)
            or self._call_to_action_regex.search(folded_norm)
            or re.search(r"\b(?:chuyển\s+tiền|chuyển\s+khoản|chuyen\s+tien|chuyen\s+khoan)\s+(?:vào|vao)\s+(?:tài\s+khoản|tai\s+khoan)\s+(?:tạm\s+giữ|tam\s+giu)", clean_norm, re.I)
        )
        is_educational_advisory = has_educational_tone and not has_call_to_action

        # G3(d): First person reporting / refusal check ('tôi cúp máy', 'tôi đã báo công an')
        has_first_person_refusal = bool(
            re.search(
                r"\b(?:tôi|toi|mình|minh|em)\s+(?:cúp\s+máy|cup\s+may|báo\s+công\s+an|bao\s+cong\s+an|"
                r"đã\s+báo|da\s+bao|từ\s+chối|tu\s+choi|không\s+chuyển|khong\s+chuyen|"
                r"nhận\s+ra\s+lừa\s+đảo|nhan\s+ra\s+lua\s+dao)\b",
                clean_norm,
                re.I
            )
        )

        # G3(d): Internal accounting reimbursement check
        is_internal_reimbursement = bool(
            re.search(
                r"\b(?:kế\s+toán|ke\s+toan)\b[^.\n]{0,30}\b(?:xin|gửi|cung\s+cấp)\b[^.\n]{0,30}\b(?:số\s+tài\s+khoản|stk|so\s+tai\s+khoan)\b|"
                r"\b(?:thanh\s+toán|chi\s+trả|tra|hoàn)\b[^.\n]{0,30}\b(?:công\s+tác\s+phí|cong\s+tac\s+phi|tiền\s+lương|lương)\b",
                clean_norm,
                re.I
            )
        )

        # ─────────────────────────────────────────
        # BLOCK A: Fake Recruitment / CTV / Shopee / TikTok (539ecb1)
        # ─────────────────────────────────────────
        if self._block_a_matcher.search(variants) and not is_educational_advisory:
            weight = 20
            factors.append({"factor": "Dấu hiệu tuyển dụng CTV lương cao bất thường (Fake Recruitment)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK B: Advance Payment / Money Deposit Request
        # ─────────────────────────────────────────
        is_personal_outgoing_transfer = bool(
            re.search(
                r"\b(?:hẹn|mai\s+(?:em|anh|chị|mình)|em|tôi|mình)\s+[^.\n]{0,25}(?:chuyển\s+tiền|chuyển\s+khoản|chuyen\s+tien|chuyen\s+khoan)\s+(?:cho\s+(?:người\s+quen|bạn|anh|chị|em|mẹ|bố|nhau))|"
                r"\b(?:do|vì|vi)?\s*(?:bố|mẹ|anh|chị|em|mình|tôi|con)\s+đang\s+(?:chuyển\s+tiền|chuyển\s+khoản)",
                clean_norm,
                re.I
            )
        )
        is_deposit_negated = bool(
            re.search(
                r"\b(?:không\s+yêu\s+cầu|khong\s+yeu\s+cau|không\s+cần|khong\s+can|miễn|mien|không\s+thu|khong\s+thu)\s+[^,.!?;:\n]{0,25}(?:đặt\s+cọc|dat\s+coc|nạp\s+tiền|nap\s+tien|ký\s+quỹ|ky\s+quy|cọc)\b",
                clean_norm,
                re.I
            )
            and not re.search(r"\b(?:không\s+cần|khong\s+can)\s+vốn\b", clean_norm, re.I)
        )

        has_block_b = False
        if not is_educational_advisory and not has_first_person_refusal and not is_personal_outgoing_transfer and not is_deposit_negated and not is_internal_reimbursement:
            if self._block_b_accented.search(variants):
                has_block_b = True
            elif self._block_b_unaccented_multi.search(variants):
                has_block_b = True
            elif self._block_b_unaccented_single.search(variants):
                has_secondary = (
                    self._block_a_matcher.search(variants)
                    or self._block_h_matcher.search(variants)
                    or self._block_g_matcher.search(variants)
                    or has_suspicious_urls
                    or bool(self._fam_h_recruitment.search(variants))
                    or bool(self._fam_a_lure.search(variants))
                    or bool(self._fam_c_invest.search(variants))
                )
                if has_secondary:
                    has_block_b = True

        if has_block_b:
            weight = 40
            factors.append({"factor": "Yêu cầu chuyển tiền / đặt cọc / nạp quỹ trước (Advance Payment)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK C: Fake Banking / OTP Phishing
        # ─────────────────────────────────────────
        is_first_person_locked = bool(
            re.search(
                r"\b(?:tôi|em|con|mình)\s+bị\s+(?:tạm\s+)?khóa\b|"
                r"\btài\s+khoản\s+(?:ngân\s+hàng\s+)?của\s+(?:tôi|em|con|mình)\s+bị\s+(?:tạm\s+)?khóa\b|"
                r"\btài\s+khoản\s+bị\s+khóa\s+do\s+(?:tôi|em|con|mình)\s+nhập\s+sai\b",
                clean_norm,
                re.I
            )
        )
        is_otp_negated = bool(
            re.search(
                r"\b(?:không\s+bao\s+giờ\s+yêu\s+cầu|khong\s+bao\s+gio\s+yeu\s+cau|chưa\s+bao\s+giờ|chua\s+bao\s+gio|không\s+hề|khong\s+he|không\s+được|khong\s+duoc|tuyệt\s+đối\s+không|tuyet\s+doi\s+khong|chứ\s+đừng|chu\s+dung|đừng|dung)\s+[^.\n]{0,35}\b(?:mã\s+otp|otp|mật\s+khẩu|mat\s+khau)\b|"
                r"\b(?:chứ\s+đừng|chu\s+dung|đừng|dung|không|khong|tuyệt\s+đối\s+không|tuyet\s+doi\s+khong)\s+(?:đọc|doc|cung\s+cấp|cung\s+cap|chia\s+sẻ|chia\s+se|gửi|gui|nhắn|nhan)\b[^.\n]{0,25}\b(?:cho\s+ai|cho\s+bất\s+kỳ\s+ai|cho\s+bat\s+ky\s+ai|cho\s+người\s+lạ|cho\s+nguoi\s+la)\b",
                clean_norm,
                re.I
            )
        )
        is_legitimate_payment_otp = bool(
            re.search(
                r"\b(?:hoàn\s+tất\s+thanh\s+toán|hoan\s+tat\s+thanh\s+toan|thanh\s+toán\s+đơn\s+hàng|thanh\s+toan\s+don\s+hang|xác\s+thực\s+giao\s+dịch|xac\s+thuc\s+giao\s+dich)\b",
                clean_norm,
                re.I
            )
            and not bool(
                re.search(
                    r"\b(?:tài\s+khoản\s+bị\s+khóa|tai\s+khoan\s+bi\s+khoa|bị\s+khóa|bi\s+khoa|tạm\s+khóa|tam\s+khoa|khóa\s+vĩnh\s+viễn|khoa\s+vinh\s+vien|cho\s+nhân\s+viên|cho\s+nhan\s+vien|cho\s+tổng\s+đài|cho\s+tong\s+dai|cho\s+chuyên\s+viên|cho\s+chuyen\s+vien|cho\s+cán\s+bộ|cho\s+can\s+bo|cho\s+mình|cho\s+minh|cho\s+em|cho\s+toi)\b",
                    clean_norm,
                    re.I
                )
            )
            and not has_suspicious_urls
            and not has_suspicious_bare_domain
        )

        has_block_c = False
        if not has_only_official_urls and not is_educational_advisory and not has_first_person_refusal:
            matched_c_phrases = self._block_c_matcher.search(variants)
            if matched_c_phrases:
                is_only_first_person_locked = is_first_person_locked and not bool(
                    re.search(r"\b(?:quý\s+khách|quy\s+khach|của\s+bạn|của\s+anh|của\s+chị)\b[^.\n]{0,30}\b(?:khóa|tạm\s+khóa)\b", clean_norm, re.I)
                    or re.search(r"\b(?:vui\s+lòng|hãy|để\s+tránh|cần)\s+[^.\n]{0,30}(?:xác\s+minh|đăng\s+nhập|cập\s+nhật|mở\s+khóa)\b", clean_norm, re.I)
                    or "đăng nhập ngay" in text_lower
                    or "mã otp" in text_lower
                    or "mã xác thực" in text_lower
                    or "internet banking" in text_lower
                )
                is_only_negated_otp = (is_otp_negated or is_legitimate_payment_otp) and not bool(
                    "tài khoản bị khóa" in text_lower
                    or "tài khoản bị tạm khóa" in text_lower
                    or "đăng nhập ngay" in text_lower
                    or "cập nhật thông tin" in text_lower
                )
                if not is_only_first_person_locked and not is_only_negated_otp:
                    has_block_c = True

        if has_block_c:
            weight = 35
            factors.append({"factor": "Giả mạo thông báo ngân hàng / cảnh báo tài khoản (Banking Phishing)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK D: URL / Fake Link Factor
        # ─────────────────────────────────────────
        if module_enabled and url_report is not None:
            max_url_risk = getattr(url_report, "max_url_risk", None)
            if max_url_risk is None and isinstance(url_report, dict):
                max_url_risk = url_report.get("max_url_risk", 0)
            max_url_risk = max_url_risk or 0

            if max_url_risk >= 70:
                url_weight = 50
            elif max_url_risk >= 40:
                url_weight = 35
            elif max_url_risk >= 20:
                url_weight = 20
            elif max_url_risk >= 1:
                url_weight = 15
            else:
                url_weight = 0

            def _collect_signals(f_item):
                sigs = getattr(f_item, "signals", None)
                if sigs is None and isinstance(f_item, dict):
                    sigs = f_item.get("signals", [])
                for s in sigs or []:
                    all_signals.append(s)
                ch_list = getattr(f_item, "children", None)
                if ch_list is None and isinstance(f_item, dict):
                    ch_list = f_item.get("children", [])
                for ch in ch_list or []:
                    _collect_signals(ch)

            for f in (findings or []):
                _collect_signals(f)

            severity_prio = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            def _sig_rank(s):
                sev = getattr(s, "severity", None) if not isinstance(s, dict) else s.get("severity")
                w = getattr(s, "weight", None) if not isinstance(s, dict) else s.get("weight")
                return (severity_prio.get(sev, 0), w or 0)

            non_info = [s for s in all_signals if (getattr(s, "severity", None) if not isinstance(s, dict) else s.get("severity")) != "info"]
            sig_pool = non_info if non_info else all_signals
            top_signal = max(sig_pool, key=_sig_rank, default=None) if sig_pool else None
            top_msg = ""
            if top_signal:
                top_msg = getattr(top_signal, "message_vi", None) if not isinstance(top_signal, dict) else top_signal.get("message_vi", "")

            if url_weight > 0:
                factor_text = f"Đường link giả mạo / che giấu: {top_msg}" if top_msg else "Đường link giả mạo / che giấu nguy hiểm"
                factors.append({"factor": factor_text, "weight": url_weight})
                total_risk_score += url_weight
            elif any(w in text_lower for w in ["link lạ", "nhấp vào đây", "click here"]) and not has_only_official_urls and not (findings or []):
                factors.append({"factor": "Chứa đường link dẫn đến địa chỉ nghi vấn", "weight": 30})
                total_risk_score += 30
        else:
            total_risk_score += self._legacy_url_factor(text, text_lower, clean_norm, factors, has_only_official_urls)

        # ─────────────────────────────────────────
        # BLOCK E: APK Malware / Fake App Installation (539ecb1)
        # ─────────────────────────────────────────
        has_block_e = False
        if ".apk" in text_lower or any("cài" in a.lower() or ".apk" in a.lower() for a in ocr_anomalies):
            has_block_e = True
            weight = 50
            factors.append({"factor": "File mã độc Android (.apk) yêu cầu cài ngoài Google Play Store", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK F: Government / Authority Impersonation (539ecb1)
        # ─────────────────────────────────────────
        if self._block_f_matcher.search(variants) and not has_only_official_urls and not is_educational_advisory and not has_first_person_refusal:
            weight = 30
            factors.append({"factor": "Mạo danh cơ quan nhà nước / Cán bộ công quyền (Authority Impersonation)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK G: Personal Bank Account (539ecb1)
        # ─────────────────────────────────────────
        if self._block_g_matcher.search(variants) and not is_internal_reimbursement and not has_first_person_refusal:
            weight = 15
            factors.append({"factor": "Sử dụng tài khoản ngân hàng cá nhân thay vì tài khoản doanh nghiệp", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK H: Urgency / Time Pressure (539ecb1)
        # ─────────────────────────────────────────
        if self._block_h_matcher.search(variants) and not is_educational_advisory:
            weight = 15
            factors.append({"factor": "Tạo áp lực thời gian / Hối thúc hành động ngay (Urgency Pressure)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK I: Emergency / Already Scammed (539ecb1)
        # ─────────────────────────────────────────
        if self._block_i_matcher.search(variants):
            weight = 25
            factors.append({"factor": "Đã bị lừa đảo / Chuyển tiền rồi — Kích hoạt Emergency Protocol", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # THE 9 SIGNAL FAMILIES (a to i) + GENERAL COVERAGE (G5)
        # ─────────────────────────────────────────


        # (a) Mồi trúng thưởng/hoàn tiền + nộp phí/thẻ cào: 35
        has_fam_a_lure = bool(
            self._fam_a_lure.search(variants)
            or re.search(r"\b(?:trúng\s+thưởng|trung\s+thuong|chúng\s+thưởng|chung\s+thuong|trúng\s+giải|quà\s+tặng|qua\s+tang|iphone|xe\s+máy|xe\s+may|chúc\s+mừng|chuc\s+mung|chúc\s+mừg|chuc\s+mug|học\s+bổng|hoc\s+bong|trợ\s+cấp|tro\s+cap|tiền\s+hỗ\s+trợ|tien\s+ho\s+tro)\b", clean_norm, re.I)
        )
        has_fam_a_fee = bool(
            self._fam_a_fee.search(variants)
            or re.search(r"\b(?:phí\s+vận\s+chuyển|phi\s+van\s+chuyen|fí|thanh\s+toán\s+phí|thanh\s+toan\s+phi|nộp\s+phí|nop\s+phi|đóng\s+phí|dong\s+phi|nộp\s+lệ\s+phí|nop\s+le\s+phi|phí\s+hồ\s+sơ|phi\s+ho\s+so|phí\s+hải\s+quan|phi\s+hai\s+quan|thuế\s+hải\s+quan|điền\s+thông\s+tin\s+thẻ|số\s+thẻ|cvv)\b", clean_norm, re.I)
        )
        if not is_educational_advisory and not has_first_person_refusal and has_fam_a_lure and has_fam_a_fee:
            weight = 35
            factors.append({"factor": "Dấu hiệu bẫy trúng thưởng / tri ân yêu cầu nộp phí hoặc nạp thẻ cào", "weight": weight})
            total_risk_score += weight
            has_advance_fee = any(w in text_lower for w in [
                "chuyển trước", "chuyen truoc", "chuyển tiền trước", "chuyen tien truoc",
                "chuyển tiền nộp phí", "chuyen tien nop phi", "yêu cầu chuyển tiền", "yeu cau chuyen tien",
                "phí làm hồ sơ", "phi lam ho so", "phí hồ sơ", "phi ho so", "phí xử lý", "phi xu ly",
                "phí bảo hiểm", "phi bao hiem", "phí giải ngân", "phi giai ngan", "phí vận chuyển", "phi van chuyen",
                "phí hải quan", "phi hai quan", "thuế hải quan", "thue hai quan", "chuyển giúp"
            ])
            if has_advance_fee and not any("Advance Payment" in f["factor"] for f in factors):
                adv_weight = 40
                factors.append({"factor": "Yêu cầu nộp phí / chuyển tiền trước để nhận tiền hoặc giải ngân (Advance Fee)", "weight": adv_weight})
                total_risk_score += adv_weight

        # (b) Thu thập thẻ/OTP/CVV/CCCD (45)
        has_unnegated_verb = False
        for m in self._fam_b_verb_regex.finditer(variants.clean):
            if not is_local_negated(variants.clean, m.start(), m.end()):
                has_unnegated_verb = True
                break
        if not has_unnegated_verb:
            for m in self._fam_b_verb_regex.finditer(variants.folded):
                if not is_local_negated(variants.folded, m.start(), m.end()):
                    has_unnegated_verb = True
                    break

        has_target = bool(
            self._fam_b_target_regex.search(clean_norm)
            or self._fam_b_target_regex.search(folded_norm)
        )
        has_motive = bool(
            self._fam_b_motive_regex.search(clean_norm)
            or self._fam_b_motive_regex.search(folded_norm)
        )

        if not is_educational_advisory and not is_otp_negated and not is_legitimate_payment_otp and has_unnegated_verb and has_target and has_motive:
            weight = 45
            factors.append({"factor": "Yêu cầu cung cấp thông tin bảo mật nhạy cảm (OTP / Mật khẩu / CVV / CCCD)", "weight": weight})
            total_risk_score += weight
            has_bank_staff = any(kw in clean_norm or kw in folded_norm for kw in [
                "nhân viên ngân hàng", "nhan vien ngan hang", "tổng đài viên", "tong dai vien",
                "chuyên viên ngân hàng", "chuyen vien ngan hang", "chuyên viên", "chuyen vien"
            ])
            if has_bank_staff:
                staff_weight = 35
                factors.append({"factor": "Mạo danh nhân viên ngân hàng yêu cầu cung cấp thông tin thẻ / CVV / OTP", "weight": staff_weight})
                total_risk_score += staff_weight

        # (c) Đầu tư cam kết lãi cao: 35
        has_high_rate = bool(
            self._fam_c_regex_day.search(clean_norm)
            or self._fam_c_regex_day.search(folded_norm)
            or self._fam_c_regex_each.search(clean_norm)
            or self._fam_c_regex_each.search(folded_norm)
        )
        has_crypto_romance = bool(
            re.search(r"\b(?:sàn\s+vàng|sàn\s+coin|sàn\s+forex|sàn\s+quốc\s+tế|nền\s+tảng\s+đầu\s+tư|san\s+vang|san\s+coin|san\s+forex|san\s+quoc\s+te)\b", clean_norm, re.I)
            and re.search(r"\b(?:gấp\s+đôi|gap\s+doi|lãi\s+\d+\s*%|lai\s+\d+\s*%|đảm\s+bảo|dam\s+bao|không\s+lỗ|khong\s+lo|bao\s+lỗ|bao\s+lo|chắc\s+chắn|chac\s+chan)\b", clean_norm, re.I)
        )
        if not is_educational_advisory and (self._fam_c_invest.search(variants) or has_crypto_romance) and (self._fam_c_guarantee.search(variants) or has_high_rate or has_crypto_romance):
            weight = 35
            factors.append({"factor": "Cam kết đầu tư tài chính sinh lời cao bất thường / lợi nhuận đảm bảo", "weight": weight})
            total_risk_score += weight

        # (d) Mượn tiền qua mạng xã hội / người thân giả: 30
        has_borrow_request = (
            self._fam_d_borrow.search(variants)
            or bool(self._borrow_amount_regex.search(clean_norm))
            or bool(self._borrow_amount_regex.search(folded_norm))
        )
        has_social_or_nick = (
            self._fam_d_social.search(variants)
            or bool(re.search(r"\b(?:nick\s+mới|số\s+mới|mất\s+điện\s+thoại|mất\s+máy|đổi\s+số|đổi\s+số\s+zalo|nick\s+zalo|so\s+moi|mat\s+dien\s+thoai|mat\s+may|doi\s+so)\b", clean_norm, re.I))
        )
        has_nick_detail = bool(re.search(r"\b(?:nick\s+mới|số\s+mới|mất\s+điện\s+thoại|mất\s+máy|đổi\s+số|đổi\s+số\s+zalo|nick\s+zalo|so\s+moi|mat\s+dien\s+thoai|mat\s+may|doi\s+so)\b", clean_norm, re.I))
        has_borrow_action = bool(re.search(r"\b(?:nhờ|cho\s+mượn|chuyển\s+giúp|ck\s+giúp|chuyển\s+hộ|bắn\s+giúp|vay|nho|cho\s+muon|chuyen\s+giup|ck\s+giup|chuyen\s+ho)\b", clean_norm, re.I))
        has_raw_amount = bool(re.search(r"\b\d+[\d.,]*\s*(?:k|nghìn|nghin|triệu|trieu|tr|củ|cu)\b", clean_norm, re.I))
        has_promise_urgency = bool(re.search(r"\b(?:gấp|gap|mai\s+trả|tối\s+trả|hôm\s+nay\s+trả|chút\s+nữa\s+trả|mai\s+tra|toi\s+tra|hom\s+nay\s+tra|hứa\s+trả)\b", clean_norm, re.I))

        is_fam_d_match = (has_social_or_nick and has_borrow_request) or (has_nick_detail and has_borrow_action and has_raw_amount)
        if not is_educational_advisory and is_fam_d_match:
            weight = 30
            factors.append({"factor": "Nghi vấn mạo danh người thân / nick mạng xã hội mượn tiền gấp", "weight": weight})
            total_risk_score += weight
            if has_nick_detail and has_borrow_action and has_raw_amount and has_promise_urgency:
                if not any("Advance Payment" in f["factor"] for f in factors):
                    factors.append({"factor": "Yêu cầu chuyển tiền / đặt cọc / nạp quỹ trước (Advance Payment)", "weight": 40})
                    total_risk_score += 40
                if not any("Urgency Pressure" in f["factor"] for f in factors):
                    factors.append({"factor": "Tạo áp lực thời gian / Hối thúc hành động ngay (Urgency Pressure)", "weight": 15})
                    total_risk_score += 15

        # (e) Bill báo thành công nhưng tiền chưa về: 40
        has_unreceived = bool(
            re.search(r"\b(?:chưa|chua)\s+[^.\n]{0,30}(?:tiền|tien|số\s+dư|so\s+du|ting\s+ting|vào\s+tài\s+khoản|vao\s+tai\s+khoan)\b", clean_norm, re.I)
            or re.search(r"\b(?:tiền|tien|số\s+dư|so\s+du|ting\s+ting)\s+[^.\n]{0,30}(?:chưa|chua)\s+(?:về|ve|vào|vao|tăng|tang|nổi|noi|thấy|thay|nhận|nhan)\b", clean_norm, re.I)
        )
        has_e_demand = bool(
            re.search(r"\b(?:giao\s+hàng\s+trước|gửi\s+hàng\s+trước|giao\s+hàng\s+đi|gửi\s+hàng\s+đi|tiền\s+sẽ\s+về|ngân\s+hàng\s+lỗi|giao\s+hang\s+truoc|gui\s+hang\s+truoc|tien\s+se\s+ve)\b", clean_norm, re.I)
        )
        if not is_educational_advisory and self._fam_e_context.search(variants) and has_unreceived:
            weight = 40
            factors.append({"factor": "Dấu hiệu bill chuyển khoản giả mạo / tiền chưa vào tài khoản thực tế", "weight": weight})
            total_risk_score += weight
            if has_e_demand:
                if not any("Urgency Pressure" in f["factor"] for f in factors):
                    factors.append({"factor": "Tạo áp lực thời gian / Hối thúc hành động ngay (Urgency Pressure)", "weight": 15})
                    total_risk_score += 15
                if not any("Advance Payment" in f["factor"] for f in factors):
                    factors.append({"factor": "Yêu cầu chuyển tiền / đặt cọc / nạp quỹ trước (Advance Payment)", "weight": 40})
                    total_risk_score += 40

        # (f) Video call mờ / deepfake + mượn tiền: 30
        has_video_issue = (
            self._fam_f_video_phrases.search(variants)
            or bool(self._fam_f_video_regex.search(clean_norm))
            or bool(self._fam_f_video_regex.search(folded_norm))
        )
        has_f_borrow = (
            self._fam_f_borrow_phrases.search(variants)
            or bool(self._borrow_amount_regex.search(clean_norm))
            or bool(self._borrow_amount_regex.search(folded_norm))
        )
        if not is_educational_advisory and has_video_issue and has_f_borrow:
            weight = 30
            factors.append({"factor": "Cuộc gọi video mờ / nghi vấn Deepfake kết hợp mượn tiền", "weight": weight})
            total_risk_score += weight

        # (g) Mạo danh cơ quan / ngân hàng + đe dọa khóa/phạt/bắt giữ + hạn chót (35)
        has_bank_impersonation = bool(
            re.search(
                r"\b(?:ngân\s+hàng(?:\s+[a-z0-9]+)?\s*(?:thông\s+báo|thong\s+bao|:|kính\s+báo|kinh\s+bao)|"
                r"ngan\s+hang(?:\s+[a-z0-9]+)?\s*(?:thông\s+báo|thong\s+bao|:|kính\s+báo|kinh\s+bao)|"
                r"(?:vietcombank|bidv|techcombank|agribank|mbbank|acb|vpbank)\s*(?:thông\s+báo|:|kính\s+báo)|"
                r"em\s+là\s+nhân\s+viên\s+ngân\s+hàng|chúng\s+tôi\s+từ\s+ngân\s+hàng)\b",
                clean_norm,
                re.I
            )
        )
        has_agency = self._fam_g_agency.search(variants) or has_bank_impersonation
        has_threat = self._fam_g_threat.search(variants) or (
            bool(re.search(r"\b(?:khóa\s+tài\s+khoản|bị\s+khóa|tạm\s+khóa)\b", clean_norm, re.I))
            and not is_first_person_locked
        )
        has_g_third_cond = (
            self._fam_g_urgency.search(variants)
            or bool(self._fam_g_phone_regex.search(clean_norm))
            or has_suspicious_urls
            or has_suspicious_bare_domain
        )

        if not is_educational_advisory and not has_first_person_refusal and has_agency and has_threat and has_g_third_cond:
            weight = 35
            factors.append({"factor": "Đe dọa khóa tài khoản / xử lý vi phạm pháp luật thúc ép hành động", "weight": weight})
            total_risk_score += weight
            if not any("Authority Impersonation" in f["factor"] for f in factors):
                auth_weight = 30
                factors.append({"factor": "Mạo danh cơ quan nhà nước / Cán bộ công quyền (Authority Impersonation)", "weight": auth_weight})
                total_risk_score += auth_weight
            has_fine_demand = any(w in text_lower for w in [
                "nộp phạt", "nop phat", "tài khoản tạm giữ", "tai khoan tam giu", "trong 24h", "trước 17h", "truoc 17h"
            ])
            if has_fine_demand and not any("Urgency Pressure" in f["factor"] for f in factors):
                urg_weight = 15
                factors.append({"factor": "Tạo áp lực thời gian / Hối thúc hành động ngay (Urgency Pressure)", "weight": urg_weight})
                total_risk_score += urg_weight

        # (h) Tuyển CTV / việc nhẹ lương cao + nạp tiền / cọc / nhiệm vụ: 40
        has_recruitment = (
            self._fam_h_recruitment.search(variants)
            or bool(self._fam_h_salary_regex.search(clean_norm))
            or bool(self._fam_h_salary_regex.search(folded_norm))
            or bool(re.search(r"\b(?:kiếm\s+tiền\s+tại\s+nhà|kiem\s+tien\s+tai\s+nha)\b", clean_norm, re.I))
        )
        has_deposit_demand = (
            self._fam_h_deposit.search(variants)
            or bool(re.search(r"\bnạp\s+\d+[\d.,]*\s*k\s+nhận\s+(?:lại\s+|ngay\s+)?\d+[\d.,]*\s*k\b", clean_norm, re.I))
            or bool(re.search(r"\bnap\s+\d+[\d.,]*\s*k\s+nhan\s+(?:lai\s+|ngay\s+)?\d+[\d.,]*\s*k\b", folded_norm, re.I))
        )
        if not is_educational_advisory and not is_deposit_negated and has_recruitment and has_deposit_demand:
            weight = 40
            factors.append({"factor": "Bẫy tuyển dụng CTV / việc nhẹ lương cao yêu cầu nạp tiền, đặt cọc", "weight": weight})
            total_risk_score += weight

        # (i) Link / APK lạ yêu cầu cài đặt: 35
        has_suspicious_source = (
            has_suspicious_urls
            or has_suspicious_bare_domain
            or self._fam_i_suspicious_source.search(variants)
            or (".apk" in text_lower and not has_block_e)
        )
        if not is_educational_advisory and self._fam_i_install.search(variants) and has_suspicious_source and not has_only_official_urls:
            weight = 35
            factors.append({"factor": "Yêu cầu cài đặt ứng dụng ngoài hoặc tải file APK nghi vấn", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # GENERALIZED CO-OCCURRENCE COVERAGE (G5: 6, 7, 8, 9)
        # ─────────────────────────────────────────
        # G5(6): Platform violation impersonation + suspicious link
        has_community_violation = bool(
            re.search(
                r"\b(?:vi\s+phạm\s+tiêu\s+chuẩn\s+cộng\s+đồng|vi\s+pham\s+tieu\s+chuan\s+cong\s+dong|"
                r"sẽ\s+bị\s+vô\s+hiệu\s+hóa|se\s+bi\s+vo\s+hieu\s+hoa|"
                r"kháng\s+nghị\s+tại|khang\s+nghi\s+tai)\b",
                clean_norm,
                re.I
            )
        )
        if not is_educational_advisory and has_community_violation and (has_suspicious_urls or has_suspicious_bare_domain):
            if not any("Đe dọa khóa tài khoản" in f["factor"] for f in factors):
                factors.append({"factor": "Đe dọa khóa tài khoản / xử lý vi phạm pháp luật thúc ép hành động", "weight": 35})
                total_risk_score += 35
            if not any("Authority Impersonation" in f["factor"] for f in factors):
                factors.append({"factor": "Mạo danh cơ quan nhà nước / Cán bộ công quyền (Authority Impersonation)", "weight": 30})
                total_risk_score += 30

        # G5(7): Group admin / gift lure to private channel
        has_gift_lure = bool(re.search(r"\b(?:nhận\s+quà\s+tri\s+ân|nhan\s+qua\s+tri\s+an|quà\s+tri\s+ân|qua\s+tri\s+an)\b", clean_norm, re.I))
        has_private_channel = bool(re.search(r"\b(?:inbox\s+mình|ib\s+mình|nhắn\s+tin\s+riêng|inbox\s+minh|ib\s+minh|vào\s+nhóm\s+telegram|vao\s+nhom\s+telegram)\b", clean_norm, re.I))
        if not is_educational_advisory and has_gift_lure and has_private_channel:
            if not any("bẫy trúng thưởng" in f["factor"].lower() for f in factors):
                factors.append({"factor": "Dấu hiệu bẫy trúng thưởng / tri ân yêu cầu nộp phí hoặc nạp thẻ cào", "weight": 35})
                total_risk_score += 35

        # G5(8): Fake delivery / package held fee
        has_delivery_held = bool(re.search(r"\b(?:đơn\s+hàng|bưu\s+kiện|kiện\s+hàng|don\s+hang|buu\s+kien)\b[^.\n]{0,25}\b(?:bị\s+giữ|bi\s+giu|chưa\s+giao|tạm\s+giữ)\b", clean_norm, re.I))
        has_delivery_fee = bool(re.search(r"\b(?:thanh\s+toán\s+phí|thanh\s+toan\s+phi|nộp\s+phí|nop\s+phi|phí\s+phát\s+lại)\b[^.\n]{0,20}\b\d+[\d.,]*\s*k\b", clean_norm, re.I))
        if not is_educational_advisory and has_delivery_held and (has_delivery_fee or has_suspicious_urls or has_suspicious_bare_domain):
            if not any("Advance Payment" in f["factor"] for f in factors):
                factors.append({"factor": "Yêu cầu nộp phí / chuyển tiền trước để nhận tiền hoặc giải ngân (Advance Fee)", "weight": 40})
                total_risk_score += 40

        # G5(9): Account locked due to biometric / verification + short link / strange domain + urgency
        has_biometric_reason = bool(re.search(r"\b(?:chưa\s+cập\s+nhật\s+sinh\s+trắc\s+học|chua\s+cap\s+nhat\s+sinh\s+trac\s+hoc|chưa\s+xác\s+thực|chua\s+xac\s+thuc|chưa\s+cập\s+nhật\s+cccd|chua\s+cap\s+nhat\s+cccd)\b", clean_norm, re.I))
        has_short_link = bool(re.search(r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|goo\.gl)\b", text_lower))
        has_bio_urgency = bool(re.search(r"\b(?:ngay|vĩnh\s+viễn|vinh\s+vien|trong\s+24h|hạn\s+chót)\b", clean_norm, re.I))
        if not is_educational_advisory and has_biometric_reason and (has_suspicious_urls or has_suspicious_bare_domain or has_short_link) and has_bio_urgency:
            if not any("Banking Phishing" in f["factor"] for f in factors):
                factors.append({"factor": "Giả mạo thông báo ngân hàng / cảnh báo tài khoản (Banking Phishing)", "weight": 35})
                total_risk_score += 35
            if not any("Đe dọa khóa tài khoản" in f["factor"] for f in factors):
                factors.append({"factor": "Đe dọa khóa tài khoản / xử lý vi phạm pháp luật thúc ép hành động", "weight": 35})
                total_risk_score += 35

        # ─────────────────────────────────────────
        # BLOCK J: Historical / Escalation Memory Pattern
        # ─────────────────────────────────────────
        if escalation_info and escalation_info.get("escalation_detected"):
            weight = 15
            factors.append({"factor": "Khớp chuỗi lịch sử lừa đảo leo thang (Memory Pattern Escalation)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK K: RAG matched_flags bonus
        # ─────────────────────────────────────────
        if matched_flags and total_risk_score < 25 and not has_only_official_urls:
            weight = 20
            factors.append({"factor": f"Xuất hiện {len(matched_flags)} từ khoá nghi vấn trong CSDL PhishVN", "weight": weight})
            total_risk_score += weight

        # Special Override: If input contains ONLY official whitelisted domains and no scam actions, set risk to 0%
        if module_enabled and url_report is not None:
            has_medium_plus = any(
                (getattr(s, "severity", None) if not isinstance(s, dict) else s.get("severity")) in ("medium", "high", "critical")
                for s in all_signals
            )
            if has_only_official_urls and not has_medium_plus and not has_scam_actions:
                final_risk_score = 0
                factors = []
            else:
                final_risk_score = min(total_risk_score, 99)
        else:
            if has_only_official_urls and not has_scam_actions:
                final_risk_score = 0
                factors = []
            else:
                final_risk_score = min(total_risk_score, 99)

        return {
            "risk_score": final_risk_score,
            "risk_breakdown": factors,
            "reasons": [f"{item['factor']}: +{item['weight']}%" for item in factors],
            "url_analysis": _wrap_report_dict(url_report) if (module_enabled and url_report is not None) else None
        }


if __name__ == "__main__":
    exp = ExplainableAgent()

    test_urls = [
        "https://login.microsoftonline.com.common.oauth2.authorize.client-id-84729472.secure-login-gateway.info/session=98432048230948",
        "http://www.agribank.com.vn.ebanking.chuyen-tien-nhanh.auth-token-valid.cc/login?user=admin&token=abcdef123456",
        "https://www.agribank.com.vn/vn/ve-agribank/tin-tuc/dtl?current=true&urile=wcm:path:/agbank/ve-agribank/tai-san-ban-dau-gia/tinh-can-tho/agribank-amc-ltd-dgts-3831"
    ]

    for u in test_urls:
        res = exp.explain(u, [], [])
        print(f"\nURL: {u[:60]}...")
        print(f"Risk Score: {res['risk_score']}%")
        for r in res["reasons"]:
            print("  -", r)
