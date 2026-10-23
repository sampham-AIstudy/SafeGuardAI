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
from typing import Any, List

from codebase.text_utils import fold_vietnamese

# ─────────────────────────────────────────────────────────────────────────────
# Hằng số giới hạn độ dài đầu vào (tránh ReDoS với đầu vào siêu dài)
# ─────────────────────────────────────────────────────────────────────────────
_MAX_INPUT_CHARS = 8000

# Ngưỡng tin cậy tối thiểu cho Speech Act Gate
SPEECH_ACT_CONFIDENCE_THRESHOLD = 0.55

# Trần điểm rủi ro LLM khi ngữ cảnh là lành tính và không có bằng chứng cứng
SPEECH_ACT_LLM_CAP = 35


@dataclass
class SpeechAct:
    label: str                        # 'solicitation' | 'news_report' | 'public_warning' | 'victim_advice' | 'everyday' | 'unknown'
    confidence: float                 # 0.0 .. 1.0
    evidence: List[str] = field(default_factory=list)  # tín hiệu hỗ trợ (ngắn gọn)


# ─────────────────────────────────────────────────────────────────────────────
# Regex tuyến tính — không dùng `.*` / `.*?` / lượng từ lồng nhau
# Cửa sổ giới hạn: [^.\n]{0,35} hoặc [^.\n]{0,45}
# ─────────────────────────────────────────────────────────────────────────────

# Phủ định hành động trong cảnh báo cộng đồng
_RE_NEGATED_ACTION = re.compile(
    r"\b(?:"
    r"tuyệt\s+đối\s+không|tuyet\s+doi\s+khong|"
    r"không\s+bao\s+giờ|khong\s+bao\s+gio|"
    r"không\s+được|khong\s+duoc|"
    r"không\s+nên|khong\s+nen|"
    r"chúng\s+tôi\s+không|chung\s+toi\s+khong|"
    r"không\s+yêu\s+cầu|khong\s+yeu\s+cau|"
    r"không\s+có\s+cán\s+bộ|khong\s+co\s+can\s+bo|"
    r"khuyến\s+cáo\s+không|khuyen\s+cao\s+khong|"
    r"cảnh\s+báo\s+không|canh\s+bao\s+khong|"
    r"đừng|dung|chớ"
    r")\b[^.\n]{0,35}\b(?:"
    r"cung\s+cấp|cung\s+cap|chia\s+sẻ|chia\s+se|gửi|gui|đọc|doc|nhập|nhap|"
    r"bấm|bam|nhấp|nhap|click|cài|cai|tải|tai|quét|scan|"
    r"chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong"
    r")\b"
    r"|\b(?:không|khong)\s+(?:click|nhấp|nhap|bấm|bam|vào\s+link|cài|cai|tải|tai|cung\s+cấp|cung\s+cap|chia\s+sẻ|chia\s+se)\b",
    re.IGNORECASE,
)

# Chi phí đời thường (everyday expenses)
_RE_EVERYDAY_EXPENSE = re.compile(
    r"\b(?:"
    r"học\s+phí|hoc\s+phi"
    r"|tiền\s+nhà|tien\s+nha"
    r"|tiền\s+điện|tien\s+dien"
    r"|tiền\s+nước|tien\s+nuoc"
    r"|tiền\s+ăn|tien\s+an"
    r"|tiền\s+xăng|tien\s+xang"
    r"|tiền\s+taxi|tien\s+taxi"
    r"|tiền\s+(?:đặt\s+)?cọc\s+(?:phòng|nhà|trọ|tour|tiệc|bàn)|tien\s+(?:dat\s+)?coc\s+(?:phong|nha|tro|tour|tiec|ban)"
    r"|tiền\s+phòng|tien\s+phong"
    r"|tiền\s+tour|tien\s+tour"
    r"|đặt\s+cọc\s+(?:tour|tiệc|bàn|phòng|nhà\s+hàng)|dat\s+coc\s+(?:tour|tiec|ban|phong|nha\s+hang)"
    r"|chia\s+tiền|chia\s+bill|chia\s+tien"
    r"|góp\s+tiền|gop\s+tien"
    r"|tiền\s+mua\s+(?:xe|điện\s+thoại|laptop|máy|đồ|iphone|samsung)|tien\s+mua\s+(?:xe|dien\s+thoai|laptop|may|do|iphone|samsung)"
    r"|mua\s+(?:xe|điện\s+thoại|laptop|máy)\s+(?:cũ|cu)"
    r"|nhận\s+hàng\s+rồi|nhan\s+hang\s+roi|đã\s+nhận\s+hàng|da\s+nhan\s+hang"
    r")\b",
    re.IGNORECASE,
)

# Quá khứ / khẳng định trả tiền đời thường
_RE_ASSERTIVE_PAST_PAYMENT = re.compile(
    r"\b(?:"
    r"(?:tôi|em|mình|anh|chị|toi|minh)\s+(?:đã|da|vừa|vua)\s+(?:chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong|trả|tra|gửi|gui)"
    r"|(?:tôi|em|mình|anh|chị|toi|minh)\s+(?:cần\s+(?:chuyển|nộp|nạp|đóng)|can\s+(?:chuyen|nop|nap|dong)|chuyển|chuyen|trả|tra|nộp|nop)\s+[^.\n]{0,30}\b(?:ngay\s+đây|ngay\s+day|xong\s+rồi|xong\s+roi|rồi\s+nhé|roi\s+nhe|cho\s+(?:anh|chị|bạn|em)|nhé|nhe|cho\s+bạn|trước|truoc)\b"
    r"|(?:đã|da)\s+trả\s+tiền|da\s+tra\s+tien|trả\s+tiền\s+nhà|tra\s+tien\s+nha"
    r")\b",
    re.IGNORECASE,
)

# Câu hỏi thăm dò tiền bạc đời thường (không phải mệnh lệnh thúc ép)
_RE_QUESTION_PAYMENT = re.compile(
    r"(?:chuyển\s+tiền|chuyen\s+tien|chuyển\s+khoản|chuyen\s+khoan)[^.\n]{0,35}\b(?:chưa\s*\?|chua\s*\?|không\s*\?|khong\s*\?|được\s+chưa|duoc\s+chua)\b",
    re.IGNORECASE,
)

# ----- SOLICITATION signals (yêu cầu hành động rủi ro hướng tới người nhận) -----

# S1: Động từ hành động rủi ro mang tính mệnh lệnh / yêu cầu
_RE_SOL_DIRECTIVE = re.compile(
    r"\b(?:"
    r"(?:hãy\s+|vui\s+lòng\s+|vui\s+long\s+|yêu\s+cầu\s+|yeu\s+cau\s+|bắt\s+buộc\s+|bat\s+buoc\s+|cần\s+|phải\s+|phai\s+)"
    r"(?:chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong)\s+(?:tiền|tien|khoản|khoan|phí|phi|vào|cọc|coc)?"
    r"|(?:chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong)\s+(?:tiền|khoản|phí|tiền\s+vào|ngay|gấp|gap)\s+[^.\n]{0,35}\b(?:ngay|gấp|gap|vào\s+tài\s+khoản|vào\s+số|tai\s+khoan\s+tam\s+giu|tài\s+khoản\s+tạm\s+giữ|để\s+kích\s+hoạt|để\s+giải\s+ngân|để\s+xác\s+minh|trước\s+\d|trong\s+\d)"
    r"|(?:chuyển\s+khoản|chuyen\s+khoan)\s+(?:ngay|gấp|gap)\b"
    r"|(?:bấm|nhấp|click|tap)\s+(?:vào\s+)?(?:link|đường\s+link|liên\s+kết|lien\s+ket|đây|day)"
    r"|(?:tải|cài)\s+(?:file\s+)?(?:app|ứng\s+dụng|phần\s+mềm|file|apk)\b"
    r"|(?:quét|scan)\s+(?:mã\s+|ma\s+)?qr\b"
    r"|(?:cung\s+cấp|cung\s+cap|đọc|doc|gửi|gui|nhắn|nhan|nhập|nhap|cho\s+(?:mình|minh|em|tôi|toi|anh|chị|chi))\s+[^.\n]{0,25}\b(?:otp|mã\s+otp|ma\s+otp|mã\s+xác\s+thực|ma\s+xac\s+thuc|mật\s+khẩu|mat\s+khau|cvv|cccd|cmnd|số\s+thẻ|so\s+the|16\s+số)"
    r"|(?:nhiệm\s+vụ|nhiem\s+vu)[^.\n]{0,30}(?:nạp|nap|chuyển|chuyen)[^.\n]{0,45}\b(?:hoa\s+hồng|hoa\s+hong|tiền\s+về)"
    r"|(?:chuyển|chuyen|nộp|nop)[^.\n]{0,25}\b(?:tài\s+khoản\s+tạm\s+giữ|tai\s+khoan\s+tam\s+giu)"
    # Lệnh chuyển/nộp tiền vào STK/tài khoản kèm dấu hiệu mồi (tài khoản cá nhân, giữ suất/giữ chỗ, giá rẻ, nhận quà/hàng)
    r"|(?:chuyển|chuyen|nộp|nop|nạp|nap|đóng|dong|gửi|gui)\s+[^.\n]{0,45}\b(?:vào|vao|qua|sang)\s+(?:stk|số\s+tk|so\s+tk|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|tai\s+khoan)\b[^.\n]{0,40}\b(?:cá\s+nhân|ca\s+nhan|giữ\s+suất|giu\s+suat|giữ\s+chỗ|giu\s+cho|giá\s+rẻ|gia\s+re|nhận\s+(?:quà|qua|hàng|hang|kiện|kien))"
    r")\b",
    re.IGNORECASE,
)

# S2: Đe dọa khóa tài khoản / pháp lý kèm yêu cầu hành động
_RE_SOL_THREAT_ACTION = re.compile(
    r"(?:khóa\s+(?:tài\s+khoản|tk)|tạm\s+khóa|dong\s+bang\s+tai\s+khoan|đóng\s+băng\s+tài\s+khoản|bị\s+phong\s+tỏa|bi\s+phong\s+toa|bị\s+khởi\s+tố|bi\s+khoi\s+to|lệnh\s+bắt|lenh\s+bat|nợ\s+thuế|no\s+thue|rửa\s+tiền|rua\s+tien|xâm\s+nhập|bị\s+tấn\s+công)"
    r"[^.\n]{0,40}"
    r"(?:vui\s+lòng|hãy|vui\s+long|hay|ngay|gấp|gap|trước\s+khi|truoc\s+khi|để\s+tránh|de\s+tranh|cần|yêu\s+cầu)",
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
    r"\b(?:em\s+là\s+(?:nhân\s+viên|can\s+bo|cán\s+bộ)|tôi\s+là\s+(?:cán\s+bộ|nhân\s+viên|điều\s+tra\s+viên|công\s+an)|chúng\s+tôi\s+(?:từ|là)|chung\s+toi\s+(?:tu|la))\b"
    r"[^.\n]{0,30}"
    r"\b(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|viện\s+kiểm\s+sát|tòa\s+án|bộ\s+công\s+an|cục\s+thuế)\b",
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
    r"|triệt\s+phá|triet\s+pha"
    r")\b",
    re.IGNORECASE,
)

# N2: Dẫn nguồn báo chí / ngày tháng tường thuật
_RE_NEWS_SOURCE = re.compile(
    r"\b(?:"
    r"báo\s+(?:tuổi\s+trẻ|thanh\s+niên|vnexpress|dân\s+trí|zing|vietnamnet|tiền\s+phong|pháp\s+luật|an\s+ninh|lao\s+động|tienphong)"
    r"|bao\s+(?:tuoi\s+tre|thanh\s+nien|dan\s+tri|tien\s+phong|phap\s+luat|an\s+ninh|lao\s+dong)"
    r"|(?:theo|nguồn|nguon)\s+(?:báo|bao|vnexpress|zing|vtv|vov|tienphong)"
    r"|(?:ngày|ngay)\s+\d{1,2}[/\-]\d{1,2}(?:[/\-]\d{2,4})?\s+(?:vừa\s+qua|qua|phóng\s+viên|báo\s+đưa|bao\s+dua|tòa\s+án|cảnh\s+sát)"
    r")\b",
    re.IGNORECASE,
)

# N3: Quá khứ / thời gian tường thuật
_RE_NEWS_PAST = re.compile(
    r"\b(?:"
    r"(?:hồi|vào\s+(?:tháng|ngày|năm))\s+\d"
    r"|(?:mới\s+đây|gần\s+đây|vừa\s+qua|trước\s+đó)\s+(?:cơ\s+quan|công\s+an|cong\s+an|tòa\s+án|nạn\s+nhân|cảnh\s+sát)"
    r"|đã\s+(?:bắt\s+giữ|khởi\s+tố|xét\s+xử|tuyên\s+phạt|tuyên\s+án)\b"
    r")\b",
    re.IGNORECASE,
)

# ----- PUBLIC WARNING signals (cảnh báo/khuyến cáo cộng đồng) -----

# W1: Từ ngữ khuyến cáo cộng đồng điển hình
_RE_WARN_COMMUNITY = re.compile(
    r"\b(?:"
    r"(?:khuyến\s+cáo|khuyen\s+cao)\s+[^.\n]{0,35}\b(?:người\s+dân|nguoi\s+dan|khách\s+hàng|khach\s+hang|cộng\s+đồng|cong\s+dong)"
    r"|(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bộ\s+công\s+an|bo\s+cong\s+an|cảnh\s+sát|canh\s+sat|cục\s+an\s+toàn\s+thông\s+tin|cuc\s+an\s+toan\s+thong\s+tin)\s+[^.\n]{0,30}\b(?:khuyến\s+cáo|khuyen\s+cao|cảnh\s+báo|canh\s+bao|nhắc\s+lại|nhac\s+lai)"
    r"|(?:tuyệt\s+đối\s+không|tuyet\s+doi\s+khong|không\s+bao\s+giờ|khong\s+bao\s+gio|không\s+được|khong\s+duoc|không\s+chia\s+sẻ|khong\s+chia\s+se|không\s+cài|khong\s+cai|không\s+click|không\s+bao\s+gio)\s+[^.\n]{0,35}\b(?:cung\s+cấp|cung\s+cap|chia\s+sẻ|chia\s+se|gửi|gui|nhấp|nhap|bấm|bam|click|cài|cai|tải|tai|chuyển|chuyen)\b"
    r"|(?:không\s+chia\s+sẻ|khong\s+chia\s+se)\s+[^.\n]{0,30}\b(?:thông\s+tin|otp|mật\s+khẩu|mat\s+khau)"
    r"|nâng\s+cao\s+(?:cảnh\s+giác|canh\s+giac)"
    r"|cảnh\s+giác\s+(?:trước|với|khi|voi)\s+[^.\n]{0,35}\b(?:thủ\s+đoạn|thu\s+doan|chiêu\s+trò|chieu\s+tro|lừa\s+đảo|lua\s+dao|hình\s+thức|hinh\s+thuc)"
    r"|(?:không\s+có\s+cán\s+bộ|khong\s+co\s+can\s+bo)\s+[^.\n]{0,30}\b(?:yêu\s+cầu|yeu\s+cau|nộp|nop)"
    r"|(?:chúng\s+tôi|chung\s+toi)\s+(?:không\s+bao\s+giờ|khong\s+bao\s+gio|không\s+yêu\s+cầu|khong\s+yeu\s+cau)\b"
    r"|(?:khuyến\s+cáo|khuyen\s+cao|cảnh\s+báo|canh\s+bao)[^.\n]{0,25}\b(?:người\s+dân|nguoi\s+dan)\b"
    r"|(?:gia\s+tăng|gia\s+tang)[^.\n]{0,25}\b(?:lừa\s+đảo|lua\s+dao)\b"
    r")\b",
    re.IGNORECASE,
)

# W2: Nguồn cơ quan / tổ chức trong cảnh báo
_RE_WARN_SOURCE = re.compile(
    r"\b(?:"
    r"(?:phía|từ|theo)\s+(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bộ\s+công\s+an|bca|nhà\s+nước|nha\s+nuoc|cảnh\s+sát|cục\s+an\s+toàn\s+thông\s+tin)"
    r"|(?:theo\s+)?(?:thông\s+báo|thong\s+bao|khuyến\s+cáo|khuyen\s+cao|cảnh\s+báo\s+chính\s+thức|canh\s+bao\s+chinh\s+thuc)"
    r"\s+(?:của\s+)?(?:ngân\s+hàng|ngan\s+hang|công\s+an|cong\s+an|bca|nhà\s+nước|nha\s+nuoc|bộ|cảnh\s+sát|cục)"
    r"|(?:cục\s+an\s+toàn\s+thông\s+tin|cuc\s+an\s+toan\s+thong\s+tin)\b"
    r")\b",
    re.IGNORECASE,
)

# ----- VICTIM ADVICE signals (ngôi thứ nhất kể chuyện đã bị lừa, hỏi xử lý) -----

# V1: Ngôi thứ nhất + đã bị lừa / mất tiền
_RE_VIC_FIRST_PERSON_SCAMMED = re.compile(
    r"\b(?:tôi|em|mình|toi|minh)\b"
    r"[^.\n]{0,35}"
    r"\b(?:"
    r"(?:vừa|vua|đã|da|mới|moi)\s+(?:bị\s+lừa|bi\s+lua|bị\s+mất\s+tiền|bi\s+mat\s+tien|chuyển\s+nhầm|chuyen\s+nham|bị\s+hack|bi\s+hack|bị\s+lấy\s+mất|bi\s+lay\s+mat|bị\s+chiếm\s+đoạt|chuyển\s+tiền\s+theo\s+yêu\s+cầu)"
    r"|mất\s+(?:tiền|tien|\d+\s*(?:triệu|trieu|tr|k|nghìn))"
    r"|(?:bị\s+lừa|bi\s+lua)\s+(?:mất|mat|đảo|dao|\b)"
    r"|bị\s+hack\s+(?:tài\s+khoản|nick)"
    r"|mất\s+liên\s+lạc"
    r")\b",
    re.IGNORECASE,
)

# V2: Câu hỏi cách xử lý sau khi bị lừa
_RE_VIC_HOW_TO_HANDLE = re.compile(
    r"\b(?:"
    r"giờ\s+(?:phải\s+)?(?:làm\s+sao|lam\s+sao|làm\s+gì|lam\s+gi)"
    r"|có\s+(?:lấy\s+lại|lay\s+lai|đòi\s+lại|doi\s+lai|thu\s+hồi|thu\s+hoi|cách\s+nào\s+lấy\s+lại)\s+(?:được|duoc)?\s*(?:không|khong|\?)"
    r"|(?:em|tôi|toi|mình|minh)\s+(?:nên|nen|cần|can|phải|phai)\s+(?:báo|bao|làm|lam|liên\s+hệ|lien\s+he)"
    r"|báo\s+ở\s+đâu|bao\s+o\s+dau|báo\s+(?:cho|cai)\s+ai|bao\s+cho\s+ai"
    r"|(?:xử\s+lý|xu\s+ly|giải\s+quyết|giai\s+quyet)\s+(?:thế\s+nào|the\s+nao|như\s+thế\s+nào|nhu\s+the\s+nao)"
    r"|cần\s+(?:làm|lam)\s+gì\s+(?:tiếp|tiep|bây\s+giờ|bay\s+gio|ngay\s+bây\s+giờ)"
    r"|làm\s+sao\s+(?:thu\s+hồi|đòi\s+lại|lấy\s+lại)"
    r"|cần\s+liên\s+hệ\s+ai"
    r"|tố\s+cáo"
    r"|có\s+nên\s+báo\s+công\s+an"
    r")\b",
    re.IGNORECASE,
)

# ----- EVERYDAY signals (chat đời thường nhắc tiền lành tính) -----

# E1: Biến động số dư thật
_RE_EVERYDAY_BANK_NOTIFY = re.compile(
    r"\b(?:"
    r"(?:số\s+dư|so\s+du)\s+(?:tài\s+khoản|tai\s+khoan)\s+(?:của\s+(?:bạn|ban|quý\s+khách|quy\s+khach))?"
    r"\s*(?:còn|con|hiện\s+tại|hien\s+tai)?\s*(?:là|la)?\s*\d"
    r"|(?:giao\s+dịch|giao\s+dich)\s+(?:thành\s+công|thanh\s+cong|đã\s+hoàn\s+thành|da\s+hoan\s+thanh)"
    r"\s+[^.\n]{0,30}\s*(?:lúc|vào\s+lúc|vao\s+luc)\s+\d"
    r"|otp\s+(?:của\s+(?:bạn|ban|quý\s+khách|quy\s+khach))?\s+(?:là|la)\s+\d{4,8}"
    r"|mã\s+này\s+dùng\s+để\s+xác\s+thực|ma\s+nay\s+dung\s+de\s+xac\s+thuc"
    r"|mã\s+xác\s+(?:thực|nhận)\s+(?:của\s+(?:bạn|ban))?\s*(?:là|la)\s+\d{4,8}"
    r"|(?:tiền\s+đã\s+về|tien\s+da\s+ve|đã\s+nhận\s+được\s+tiền|da\s+nhan\s+duoc\s+tien)"
    r")\b",
    re.IGNORECASE,
)

# E2: Cuộc trò chuyện chia sẻ tiền trong nhóm bạn / gia đình
_RE_EVERYDAY_SPLIT = re.compile(
    r"\b(?:"
    r"(?:tôi|em|mình|bạn|bao|bác|anh|chị|toi|minh)\s+"
    r"(?:đã\s+chuyển|da\s+chuyen|vừa\s+chuyển|vua\s+chuyen|chuyển\s+rồi|chuyen\s+roi)\s+"
    r"\d[^.\n]{0,20}\b(?:học\s+phí|tiền\s+nhà|tiền\s+tour|tiền\s+tiệc|hoc\s+phi|tien\s+nha|tien\s+tour|tien\s+tiec)\b"
    r"|(?:mọi\s+người|moi\s+nguoi|tụi\s+mình|tui\s+minh|nhóm\s+mình|nhom\s+minh|ai\s+chưa\s+chuyển)\s+(?:chia\s+nhau|chia\s+tiền|chia\s+bill|chuyen\s+tien|đặt\s+cọc|góp\s+tiền|chuyển\s+sớm)"
    r"|góp\s+tiền\s+mua\s+quà"
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
    combined = text + "\n" + folded

    # Hỗ trợ nhận diện tiếng Việt không dấu (unaccented Vietnamese)
    allow_unaccented = True
    if not allow_unaccented and (text.strip() == folded.strip() and any(c.isalpha() for c in text)):
        return SpeechAct(label="unknown", confidence=0.0, evidence=[])

    evidence: list[str] = []
    sol_score = 0
    news_score = 0
    warn_score = 0
    vic_score = 0
    every_score = 0

    # Kiểm tra ngữ cảnh phủ định và ngữ cảnh đời thường
    is_negated_action = bool(_RE_NEGATED_ACTION.search(combined))
    is_assertive_past = bool(_RE_ASSERTIVE_PAST_PAYMENT.search(combined))
    is_question_payment = bool(_RE_QUESTION_PAYMENT.search(combined))
    has_everyday_expense = bool(_RE_EVERYDAY_EXPENSE.search(combined))

    # ── SOLICITATION ──────────────────────────────────────────────────────────
    if _RE_SOL_DIRECTIVE.search(combined):
        if not is_negated_action and not is_assertive_past and not is_question_payment:
            sol_score += 2
            evidence.append("solicitation:action")
    if _RE_SOL_THREAT_ACTION.search(combined):
        sol_score += 2
        evidence.append("solicitation:threat_action")
    if _RE_SOL_LURE_FEE.search(combined):
        if not is_assertive_past:
            sol_score += 2
            evidence.append("solicitation:lure_fee")
    if _RE_SOL_SECOND_PERSON_OTP.search(combined):
        if not is_negated_action:
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
    if is_negated_action:
        warn_score += 1
        evidence.append("warning:negated_action")

    # ── VICTIM ADVICE ─────────────────────────────────────────────────────────
    if _RE_VIC_FIRST_PERSON_SCAMMED.search(combined):
        vic_score += 2
        evidence.append("victim:first_person_scammed")
    if _RE_VIC_HOW_TO_HANDLE.search(combined):
        vic_score += 2
        evidence.append("victim:how_to_handle")

    # ── EVERYDAY ─────────────────────────────────────────────────────────────
    if has_everyday_expense:
        every_score += 2
        evidence.append("everyday:expense")
    if _RE_EVERYDAY_BANK_NOTIFY.search(combined):
        every_score += 2
        evidence.append("everyday:bank_notify")
    if _RE_EVERYDAY_SPLIT.search(combined) or is_assertive_past or is_question_payment:
        every_score += 1
        evidence.append("everyday:split_or_past")

    # ── QUY TẮC ƯU TIÊN ─────────────────────────────────────────────────────
    # Nạn nhân kể chuyện và hỏi cách xử lý (vic_score >= 3): ưu tiên victim_advice
    if vic_score >= 3:
        conf = min(0.65 + 0.1 * (vic_score - 2), 0.95)
        return SpeechAct(
            label="victim_advice",
            confidence=round(conf, 2),
            evidence=[e for e in evidence if e.startswith("victim")],
        )

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
    # Victim advice: cần >=2 điểm
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


# ─────────────────────────────────────────────────────────────────────────────
# S2: Hàm thuần cap_llm_risk (Tầng Tổng hợp)
# ─────────────────────────────────────────────────────────────────────────────

def cap_llm_risk(
    llm_risk: int,
    speech_act: SpeechAct | dict[str, Any] | None,
    hard_evidence: bool,
    threshold: float = SPEECH_ACT_CONFIDENCE_THRESHOLD,
    cap: int = SPEECH_ACT_LLM_CAP,
) -> int:
    """
    Giới hạn điểm số rủi ro do mô hình LLM dự đoán (Stage B) khi ngữ cảnh văn bản
    được phân loại là lành tính (news_report, public_warning, victim_advice, everyday)
    với confidence >= threshold và KHÔNG có bằng chứng kỹ thuật cứng nào.

    Bằng chứng cứng gồm:
      - emergency (tình huống khẩn cấp, vừa chuyển tiền cần hỗ trợ)
      - url max_url_risk >= 40 hoặc có tín hiệu URL >= medium
      - critical_evidence / extra_critical_codes (blacklist, APK độc hại, ...)
      - threat-intel độc hại
      - has_risky_qr
      - nhãn speech_act là 'solicitation'

    Sau cap vẫn thực hiện max(det_risk, llm_risk) nên không bao giờ hạ dưới điểm Tầng A.
    Hàm thuần: không I/O, không gọi mạng.
    """
    if llm_risk <= cap or hard_evidence or speech_act is None:
        return llm_risk

    if isinstance(speech_act, dict):
        label = speech_act.get("label", "unknown")
        confidence = float(speech_act.get("confidence", 0.0))
    else:
        label = getattr(speech_act, "label", "unknown")
        confidence = float(getattr(speech_act, "confidence", 0.0))

    benign_labels = {"news_report", "public_warning", "victim_advice", "everyday"}
    if label in benign_labels and confidence >= threshold:
        return min(llm_risk, cap)

    return llm_risk
