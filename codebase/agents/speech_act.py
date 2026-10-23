"""
codebase/agents/speech_act.py

Speech-Act / Intent Gate — phân loại ngữ cảnh tin nhắn để giảm báo động giả.
Module thuần (không I/O, không mạng). Không dùng `.*` hay lượng từ lồng nhau.
Input được giới hạn độ dài trước khi xử lý.

Nhãn:
  'solicitation'   — kẻ lừa đảo/đối tượng ĐANG yêu cầu người nhận hành động rủi ro
  'news_report'    — tường thuật ngôi thứ ba
  'public_warning' — cảnh báo/khuyến cáo cộng đồng có nguồn cơ quan
  'victim_advice'  — ngôi thứ nhất kể chuyện đã bị lừa, hỏi cách xử lý
  'everyday'       — chat đời thường nhắc tiền (học phí, tiền nhà, chia tiền, đồ cũ)
  'unknown'        — không đủ tín hiệu

Ưu tiên: nếu có đặc trưng 'solicitation' mạnh (yêu cầu hành động rủi ro hướng tới
người nhận) THÌ nhãn là 'solicitation' dù văn bản có giọng cảnh báo/tường thuật.
Cần >=2 tín hiệu độc lập (hoặc 1 rất mạnh) để cho nhãn lành tính; không chắc => 'unknown'.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from codebase.text_utils import fold_vietnamese

# ─────────────────────────────────────────────────────────────────────────────
# Hằng số giới hạn độ dài đầu vào (tránh ReDoS với đầu vào siêu dài)
# ─────────────────────────────────────────────────────────────────────────────
_MAX_INPUT_CHARS = 8000


@dataclass
class SpeechAct:
    label: str                        # 'solicitation' | 'news_report' | 'public_warning' | 'victim_advice' | 'everyday' | 'unknown'
    confidence: float                 # 0.0 .. 1.0
    evidence: List[str] = field(default_factory=list)  # tín hiệu hỗ trợ (ngắn gọn)


# ─────────────────────────────────────────────────────────────────────────────
# Regex tuyến tính — không dùng `.*` / `.*?` / lượng từ lồng nhau
# Cửa sổ giới hạn: [^.\n]{0,40} hoặc \S{0,30}
# ─────────────────────────────────────────────────────────────────────────────

# ----- SOLICITATION signals (yêu cầu hành động rủi ro hướng tới người nhận) -----

# S1: Động từ hành động rủi ro + ngôi thứ hai / mệnh lệnh thức
_RE_SOL_ACTION = re.compile(
    r"\b(?:"
    # chuyển tiền / chuyển khoản
    r"(?:hãy\s+|vui\s+lòng\s+|vui\s+long\s+|yêu\s+cầu\s+|yeu\s+cau\s+|cần\s+|phai\s+|phải\s+)?(?:chuyển\s+tiền|chuyen\s+tien|chuyển\s+khoản|chuyen\s+khoan|nộp\s+tiền|nop\s+tien|nạp\s+tiền|nap\s+tien|đóng\s+tiền|dong\s+tien|đặt\s+cọc|dat\s+coc|nộp\s+phí|nop\s+phi|đóng\s+phí|dong\s+phi)"
    r"|(?:hãy|vui\s+lòng|vui\s+long|yêu\s+cầu|yeu\s+cau)\s+[^.\n]{0,35}\b(?:chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong|bấm|bam|nhấp|nhap|tải\s+về|tai\s+ve|cài\s+đặt|cai\s+dat|cung\s+cấp|cung\s+cap|đọc|doc|gửi|gui)\b"
    r"|(?:bấm|nhấp|click|tap)\s+(?:vào\s+)?(?:link|đường\s+link|liên\s+kết|lien\s+ket|đây|day)"
    r"|(?:tải|cài)\s+(?:app|ứng\s+dụng|phần\s+mềm|file|apk)"
    r"|(?:quét|scan)\s+qr"
    r"|(?:cung\s+cấp|cung\s+cap|đọc|doc|gửi|gui|nhắn|nhan|nhập|nhap|cho\s+(?:mình|minh|em|tôi|toi|anh|chị|chi))\s+[^.\n]{0,25}\b(?:otp|mã\s+otp|ma\s+otp|mã\s+xác\s+thực|ma\s+xac\s+thuc|mật\s+khẩu|mat\s+khau|cvv|cccd|cmnd|số\s+thẻ|so\s+the)"
    r")\b",
    re.IGNORECASE,
)

# S2: Đe dọa khóa tài khoản / pháp lý kèm yêu cầu hành động
_RE_SOL_THREAT_ACTION = re.compile(
    r"(?:khóa\s+(?:tài\s+khoản|tk)|tạm\s+khóa|dong\s+bang\s+tai\s+khoan|đóng\s+băng\s+tài\s+khoản|bị\s+phong\s+tỏa|bi\s+phong\s+toa|bị\s+khởi\s+tố|bi\s+khoi\s+to|lệnh\s+bắt|lenh\s+bat)"
    r"[^.\n]{0,40}"
    r"(?:vui\s+lòng|hãy|vui\s+long|hay|ngay|gấp|gap|trước\s+khi|truoc\s+khi|để\s+tránh|de\s+tranh)",
    re.IGNORECASE,
)

# S3: Hứa lợi ích đổi hành động (trúng thưởng/quà + yêu cầu nộp phí/cung cấp)
_RE_SOL_LURE_FEE = re.compile(
    r"(?:trúng\s+thưởng|trung\s+thuong|nhận\s+thưởng|nhan\s+thuong|nhận\s+quà|nhan\s+qua|hoàn\s+tiền|hoan\s+tien|giải\s+ngân|giai\s+ngan)"
    r"[^.\n]{0,40}"
    r"(?:nộp\s+phí|nop\s+phi|đóng\s+phí|dong\s+phi|chuyển\s+khoản|chuyen\s+khoan|đặt\s+cọc|dat\s+coc|mua\s+thẻ\s+cào|mua\s+the\s+cao|nạp\s+thẻ\s+cào|nap\s+the\s+cao)",
    re.IGNORECASE,
)

# S4: Ngôi thứ hai trực tiếp + OTP/mật khẩu yêu cầu
_RE_SOL_SECOND_PERSON_OTP = re.compile(
    r"\b(?:anh|chị|bạn|quý\s+khách|bác|em|quy\s+khach|ban|chi)\b"
    r"[^.\n]{0,30}"
    r"\b(?:otp|mã\s+xác\s+thực|ma\s+xac\s+thuc|mật\s+khẩu|mat\s+khau|số\s+thẻ|so\s+the|cvv|cccd)\b",
    re.IGNORECASE,
)

# S5: Mạo danh ngân hàng/công an ĐANG yêu cầu (không phải tường thuật)
_RE_SOL_IMPERSONATION = re.compile(
    r"\b(?:em\s+là\s+(?:nhân\s+viên|can\s+bo|cán\s+bộ)|chúng\s+tôi\s+(?:từ|là)|chung\s+toi\s+(?:tu|la))\b"
    r"[^.\n]{0,30}"
    r"\b(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|viện\s+kiểm\s+sát|tòa\s+án|bộ\s+công\s+an)\b",
    re.IGNORECASE,
)

# ----- NEWS REPORT signals (tường thuật ngôi thứ ba) -----

# N1: Từ ngữ tường thuật điển hình
_RE_NEWS_NARRATIVE = re.compile(
    r"\b(?:"
    r"đối\s+tượng|doi\s+tuong"
    r"|bị\s+can|bi\s+can"
    r"|nạn\s+nhân|nan\s+nhan"
    r"|bị\s+hại|bi\s+hai"
    r"|cơ\s+quan\s+(?:điều\s+tra|cong\s+an|công\s+an|chức\s+năng)|co\s+quan\s+(?:dieu\s+tra|cong\s+an|chuc\s+nang)"
    r"|(?:công\s+an|cong\s+an)\s+(?:đã\s+(?:bắt|khởi\s+tố|triệu\s+tập)|da\s+(?:bat|khoi\s+to|trieu\s+tap))"
    r"|(?:khởi\s+tố|truy\s+tố|xét\s+xử|bat\s+giu|bắt\s+giữ)[^.\n]{0,30}(?:bị\s+can|bị\s+cáo|đối\s+tượng)"
    r"|theo\s+thông\s+tin|theo\s+bao\s+cao|theo\s+báo\s+cáo|theo\s+nguồn\s+tin"
    r")\b",
    re.IGNORECASE,
)

# N2: Dẫn nguồn báo chí / ngày tháng tường thuật
_RE_NEWS_SOURCE = re.compile(
    r"\b(?:"
    r"báo\s+(?:tuổi\s+trẻ|thanh\s+niên|vnexpress|dân\s+trí|zing|vietnamnet|tiền\s+phong|pháp\s+luật|an\s+ninh|lao\s+động|tienphong)"
    r"|bao\s+(?:tuoi\s+tre|thanh\s+nien|dan\s+tri|tien\s+phong|phap\s+luat|an\s+ninh|lao\s+dong)"
    r"|(?:theo|nguồn|nguon)\s+(?:báo|bao|vnexpress|zing|vtv|vov|tienphong)"
    r"|(?:ngày|ngay)\s+\d{1,2}[/\-]\d{1,2}(?:[/\-]\d{2,4})?\s+(?:vừa\s+qua|qua|phóng\s+viên|báo\s+đưa|bao\s+dua)"
    r")\b",
    re.IGNORECASE,
)

# N3: Quá khứ / thời gian tường thuật
_RE_NEWS_PAST = re.compile(
    r"\b(?:"
    r"(?:hồi|vào\s+(?:tháng|ngày|năm))\s+\d"
    r"|(?:mới\s+đây|gần\s+đây|vừa\s+qua|trước\s+đó)\s+(?:cơ\s+quan|công\s+an|cong\s+an|tòa\s+án|nạn\s+nhân)"
    r"|đã\s+(?:bắt\s+giữ|khởi\s+tố|xét\s+xử|tuyên\s+phạt|tuyên\s+án)\b"
    r")\b",
    re.IGNORECASE,
)

# ----- PUBLIC WARNING signals (cảnh báo/khuyến cáo cộng đồng) -----

# W1: Từ ngữ khuyến cáo cộng đồng điển hình
_RE_WARN_COMMUNITY = re.compile(
    r"\b(?:"
    r"(?:khuyến\s+cáo|khuyen\s+cao)\s+(?:người\s+dân|khách\s+hàng|cộng\s+đồng|nguoi\s+dan|khach\s+hang|cong\s+dong)"
    r"|(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bộ\s+công\s+an|bo\s+cong\s+an)\s+(?:khuyến\s+cáo|khuyen\s+cao|cảnh\s+báo|canh\s+bao)"
    r"|tuyệt\s+đối\s+không\s+(?:cung\s+cấp|cung\s+cap|chia\s+sẻ|chia\s+se|gửi|gui)\s+[^.\n]{0,30}\b(?:otp|mật\s+khẩu|mat\s+khau|thông\s+tin)"
    r"|nâng\s+cao\s+(?:cảnh\s+giác|canh\s+giac)"
    r"|cảnh\s+giác\s+(?:trước|voi|với|khi)\s+[^.\n]{0,30}\b(?:thủ\s+đoạn|thu\s+doan|chiêu\s+trò|chieu\s+tro|lừa\s+đảo|lua\s+dao)"
    r"|(?:không\s+bao\s+giờ|khong\s+bao\s+gio)\s+(?:yêu\s+cầu|yeu\s+cau)"
    r")\b",
    re.IGNORECASE,
)

# W2: Nguồn cơ quan / tổ chức trong cảnh báo
_RE_WARN_SOURCE = re.compile(
    r"\b(?:"
    r"(?:phía|từ|theo)\s+(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bộ\s+công\s+an|bca|nhà\s+nước|nha\s+nuoc)"
    r"|(?:theo\s+)?(?:thông\s+báo|thong\s+bao|khuyến\s+cáo|khuyen\s+cao|cảnh\s+báo\s+chính\s+thức|canh\s+bao\s+chinh\s+thuc)"
    r"\s+(?:của\s+)?(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bca|nhà\s+nước|nha\s+nuoc|bộ)"
    r")\b",
    re.IGNORECASE,
)

# ----- VICTIM ADVICE signals (ngôi thứ nhất kể chuyện đã bị lừa, hỏi xử lý) -----

# V1: Ngôi thứ nhất + đã bị lừa / mất tiền
_RE_VIC_FIRST_PERSON_SCAMMED = re.compile(
    r"\b(?:tôi|em|mình|toi|minh)\b"
    r"[^.\n]{0,30}"
    r"\b(?:"
    r"(?:vừa|vua|đã|da|mới|moi)\s+(?:bị\s+lừa|bi\s+lua|bị\s+mất\s+tiền|bi\s+mat\s+tien|chuyển\s+nhầm|chuyen\s+nham|bị\s+hack|bi\s+hack|bị\s+lấy\s+mất|bi\s+lay\s+mat)"
    r"|mất\s+(?:tiền|tien|\d+\s*(?:triệu|trieu|tr|k|nghìn))"
    r"|(?:bị\s+lừa|bi\s+lua)\s+(?:mất|mat)\s+\d"
    r")\b",
    re.IGNORECASE,
)

# V2: Câu hỏi cách xử lý sau khi bị lừa
_RE_VIC_HOW_TO_HANDLE = re.compile(
    r"\b(?:"
    r"giờ\s+(?:phải\s+)?(?:làm\s+sao|lam\s+sao|làm\s+gì|lam\s+gi)"
    r"|có\s+(?:lấy\s+lại|lay\s+lai|đòi\s+lại|doi\s+lai|thu\s+hồi|thu\s+hoi)\s+(?:được|duoc)\s+không"
    r"|(?:em|tôi|toi|mình|minh)\s+(?:nên|nen|cần|can|phải|phai)\s+(?:báo|bao|làm|lam|liên\s+hệ|lien\s+he)"
    r"|báo\s+ở\s+đâu|bao\s+o\s+dau|báo\s+(?:cho|cai)\s+ai|bao\s+cho\s+ai"
    r"|(?:xử\s+lý|xu\s+ly|giải\s+quyết|giai\s+quyet)\s+(?:thế\s+nào|the\s+nao|như\s+thế\s+nào|nhu\s+the\s+nao)"
    r"|cần\s+(?:làm|lam)\s+gì\s+(?:tiếp|tiep|bây\s+giờ|bay\s+gio|ngay\s+bây\s+giờ)"
    r")\b",
    re.IGNORECASE,
)

# ----- EVERYDAY signals (chat đời thường nhắc tiền lành tính) -----

# E1: Tiền học phí / tiền nhà / tiền điện / tiền ăn / tiền xăng bình thường
_RE_EVERYDAY_EXPENSE = re.compile(
    r"\b(?:"
    r"học\s+phí|hoc\s+phi"
    r"|tiền\s+nhà|tien\s+nha"
    r"|tiền\s+điện|tien\s+dien"
    r"|tiền\s+nước|tien\s+nuoc"
    r"|tiền\s+ăn|tien\s+an"
    r"|tiền\s+xăng|tien\s+xang"
    r"|tiền\s+taxi|tien\s+taxi"
    r"|tiền\s+đặt\s+cọc\s+(?:phòng|nhà|trọ)|tien\s+dat\s+coc\s+(?:phong|nha|tro)"
    r"|tiền\s+phòng|tien\s+phong"
    r"|tiền\s+tour|tien\s+tour"
    r"|đặt\s+cọc\s+(?:tour|tiệc|bàn|phòng|nhà\s+hàng)|dat\s+coc\s+(?:tour|tiec|ban|phong|nha\s+hang)"
    r"|tiền\s+cọc\s+(?:tour|tiệc|bàn|phòng)|tien\s+coc\s+(?:tour|tiec|ban|phong)"
    r"|chia\s+tiền|chia\s+bill|chia\s+tien"
    r"|chuyển\s+(?:khoản\s+)?tiền\s+(?:học\s+phí|nhà\s+trọ|sinh\s+hoạt|an\s+uong|ăn\s+uống)"
    r"|(?:mua\s+bán|ban\s+chuyen\s+nhuong)\s+(?:xe|máy|điện\s+thoại|laptop|iphone|samsung)\s+(?:đã\s+|cu\s+|cũ\s+)?(?:nhận\s+hàng|nhan\s+hang|xong\s+rồi|xong\s+roi)"
    r"|nhận\s+hàng\s+rồi|nhan\s+hang\s+roi"
    r")\b",
    re.IGNORECASE,
)

# E2: Biến động số dư thật (thông báo từ ngân hàng hệ thống, không phải yêu cầu)
_RE_EVERYDAY_BANK_NOTIFY = re.compile(
    r"\b(?:"
    r"(?:số\s+dư|so\s+du)\s+(?:tài\s+khoản|tai\s+khoan)\s+(?:của\s+(?:bạn|ban|quý\s+khách|quy\s+khach))?"
    r"\s*(?:còn|con|hiện\s+tại|hien\s+tai)?\s*(?:là|la)?\s*\d"
    r"|(?:giao\s+dịch|giao\s+dich)\s+(?:thành\s+công|thanh\s+cong|đã\s+hoàn\s+thành|da\s+hoan\s+thanh)"
    r"\s+[^.\n]{0,30}\s*(?:lúc|vào\s+lúc|vao\s+luc)\s+\d"
    r"|otp\s+(?:của\s+(?:bạn|ban|quý\s+khách|quy\s+khach))?\s+(?:là|la)\s+\d{4,8}"
    r"|mã\s+xác\s+(?:thực|nhận)\s+(?:của\s+(?:bạn|ban))?\s*(?:là|la)\s+\d{4,8}"
    r"|(?:tiền\s+đã\s+về|tien\s+da\s+ve|đã\s+nhận\s+được\s+tiền|da\s+nhan\s+duoc\s+tien)"
    r")\b",
    re.IGNORECASE,
)

# E3: Cuộc trò chuyện chia sẻ tiền trong nhóm bạn / gia đình (ngôi thứ nhất + số tiền + lý do thông thường)
_RE_EVERYDAY_SPLIT = re.compile(
    r"\b(?:"
    r"(?:tôi|em|mình|bạn|bao|bác|anh|chị|toi|minh)\s+"
    r"(?:đã\s+chuyển|da\s+chuyen|vừa\s+chuyển|vua\s+chuyen|chuyển\s+rồi|chuyen\s+roi)\s+"
    r"\d[^.\n]{0,20}\b(?:học\s+phí|tiền\s+nhà|tiền\s+tour|tiền\s+tiệc|hoc\s+phi|tien\s+nha|tien\s+tour|tien\s+tiec)\b"
    r"|(?:mọi\s+người|moi\s+nguoi|tụi\s+mình|tui\s+minh|nhóm\s+mình|nhom\s+minh)\s+(?:chia\s+nhau|chia\s+tiền|chia\s+bill|chuyen\s+tien)"
    r")\b",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Hàm phân loại chính
# ─────────────────────────────────────────────────────────────────────────────

def classify_speech_act(text: str) -> SpeechAct:
    """
    Phân loại ngữ cảnh (speech act) của một đoạn văn bản.

    Trả về SpeechAct(label, confidence, evidence).
    Hàm thuần — không gọi mạng, không I/O.
    Encoding đầu vào: str (Python str đã giải mã UTF-8).
    Input bị cắt ở _MAX_INPUT_CHARS để bảo vệ ReDoS.
    """
    if not isinstance(text, str):
        text = str(text)

    # Giới hạn độ dài đầu vào
    text = text[:_MAX_INPUT_CHARS]

    # Chuẩn bị biến thể bỏ dấu
    folded = fold_vietnamese(text)
    # Hợp nhất để tăng tốc matching
    combined = text + "\n" + folded

    evidence: list[str] = []
    sol_score = 0
    news_score = 0
    warn_score = 0
    vic_score = 0
    every_score = 0

    # ── SOLICITATION ──────────────────────────────────────────────────────────
    if _RE_SOL_ACTION.search(combined):
        sol_score += 2  # tín hiệu rất mạnh
        evidence.append("solicitation:action")
    if _RE_SOL_THREAT_ACTION.search(combined):
        sol_score += 2
        evidence.append("solicitation:threat_action")
    if _RE_SOL_LURE_FEE.search(combined):
        sol_score += 2
        evidence.append("solicitation:lure_fee")
    if _RE_SOL_SECOND_PERSON_OTP.search(combined):
        sol_score += 1
        evidence.append("solicitation:2nd_person_otp")
    if _RE_SOL_IMPERSONATION.search(combined):
        sol_score += 1
        evidence.append("solicitation:impersonation")

    # ── NEWS REPORT ───────────────────────────────────────────────────────────
    if _RE_NEWS_NARRATIVE.search(combined):
        news_score += 2
        evidence.append("news:narrative")
    if _RE_NEWS_SOURCE.search(combined):
        news_score += 2
        evidence.append("news:source")
    if _RE_NEWS_PAST.search(combined):
        news_score += 1
        evidence.append("news:past_tense")

    # ── PUBLIC WARNING ────────────────────────────────────────────────────────
    if _RE_WARN_COMMUNITY.search(combined):
        warn_score += 2
        evidence.append("warning:community")
    if _RE_WARN_SOURCE.search(combined):
        warn_score += 1
        evidence.append("warning:source")

    # ── VICTIM ADVICE ─────────────────────────────────────────────────────────
    if _RE_VIC_FIRST_PERSON_SCAMMED.search(combined):
        vic_score += 2
        evidence.append("victim:first_person_scammed")
    if _RE_VIC_HOW_TO_HANDLE.search(combined):
        vic_score += 2
        evidence.append("victim:how_to_handle")

    # ── EVERYDAY ─────────────────────────────────────────────────────────────
    if _RE_EVERYDAY_EXPENSE.search(combined):
        every_score += 2
        evidence.append("everyday:expense")
    if _RE_EVERYDAY_BANK_NOTIFY.search(combined):
        every_score += 2
        evidence.append("everyday:bank_notify")
    if _RE_EVERYDAY_SPLIT.search(combined):
        every_score += 1
        evidence.append("everyday:split")

    # ── QUY TẮC ƯU TIÊN ─────────────────────────────────────────────────────
    # Nếu có đặc trưng solicitation mạnh (>=2), đó là nhãn cuối cùng — dù văn bản
    # có giọng cảnh báo/tường thuật (kẻ gian mạo danh công an / ngân hàng).
    if sol_score >= 2:
        conf = min(0.55 + 0.15 * (sol_score - 2), 0.95)
        return SpeechAct(
            label="solicitation",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("solicitation")],
        )

    # Nếu chỉ có 1 tín hiệu solicitation yếu nhưng không có tín hiệu lành tính mạnh → unknown
    if sol_score == 1 and (news_score + warn_score + vic_score + every_score) < 2:
        return SpeechAct(label="unknown", confidence=0.4, evidence=evidence)

    # ── PHÂN LOẠI LÀNH TÍNH (cần >=2 điểm) ──────────────────────────────────
    # Victim advice: cần >=2 điểm (có kể + có hỏi = 4 điểm; hoặc một tín hiệu rất mạnh)
    if vic_score >= 2:
        conf = min(0.55 + 0.1 * (vic_score - 2), 0.90)
        return SpeechAct(
            label="victim_advice",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("victim")],
        )

    # News report: cần >=2 điểm
    if news_score >= 2:
        conf = min(0.55 + 0.1 * (news_score - 2), 0.90)
        return SpeechAct(
            label="news_report",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("news")],
        )

    # Public warning: cần >=2 điểm (warn_score>=2)
    if warn_score >= 2:
        conf = min(0.55 + 0.1 * (warn_score - 2), 0.90)
        return SpeechAct(
            label="public_warning",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("warning")],
        )

    # Everyday: cần >=2 điểm
    if every_score >= 2:
        conf = min(0.55 + 0.1 * (every_score - 2), 0.90)
        return SpeechAct(
            label="everyday",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("everyday")],
        )

    # Không đủ tín hiệu
    return SpeechAct(label="unknown", confidence=0.3, evidence=evidence)
