import re
from codebase.agents.llm_output import clean_llm_string


class DecisionAgent:
    """
    Decision Support Agent:
    Synthesizes risk scores from sub-agents and produces human-centered recommendations.
    Differentiates between General Chat Greetings (e.g. "chào bạn", "hello", "đây là gì?")
    and Scam Analysis Evidence to avoid robotic copy-paste responses.
    """
    def __init__(self):
        self._greetings = {
            "chào", "chào bạn", "hello", "hi", "xin chào",
            "đây là gì", "bạn là ai", "hướng dẫn",
            "help", "alo", "alo bạn", "alo bạn ơi"
        }
        self._greeting_suffixes = {"nhé", "ạ", "nha", "ơi", "ban", "bạn"}
        self._url_pattern = re.compile(
            r"(?:https?://|www\.|\b[a-zA-Z0-9-]{1,63}\.(?:com|vn|xyz|top|net|org|edu|gov|cc|site|online|me|info|biz|co|vip|club|link|icu|cfd|sbs|win|bet)\b)",
            re.IGNORECASE
        )
        self._money_action_keywords = {
            "tiền", "tien", "nạp", "nap", "chuyển", "chuyen", "stk", "tài khoản", "tai khoan",
            "tk", "phí", "phi", "cọc", "coc", "đặt cọc", "dat coc", "vay", "lãi", "lai",
            "triệu", "trieu", "nghìn", "nghin", "dong", "đồng", "vnd", "bill", "hóa đơn", "hoa don",
            "hoàn tiền", "hoan tien", "trúng thưởng", "trung thuong", "nhận quà", "nhan qua",
            "bấm", "bam", "click", "tải", "tai", "cài", "cai", "đăng nhập", "dang nhap",
            "xác minh", "xac minh", "xác nhận", "xac nhan", "cung cấp", "cung cap",
            "nhập", "nhap", "gửi", "gui", "kiểm tra", "kiem tra", "check", "quét", "quet",
            "otp", "mật khẩu", "mat khau", "pass", "password", "link", "apk", "mã độc", "ma doc",
            "lừa", "lua", "hack", "mất", "mat", "bị", "bi", "lộ", "lo", "chiếm", "chiem",
            "cứu", "cuu", "toang", "hoảng", "hoang", "giúp", "giup"
        }
        parts = [re.escape(k) for k in sorted(self._money_action_keywords, key=len, reverse=True)]
        self._money_action_regex = re.compile(rf"(?<!\w)(?:{'|'.join(parts)})(?!\w)", re.IGNORECASE)

    def _has_url(self, text: str, url_report=None) -> bool:
        if url_report is not None:
            findings = getattr(url_report, "findings", None)
            if findings is not None and len(findings) > 0:
                return True
            if isinstance(url_report, dict) and url_report.get("findings"):
                return True
        if not text:
            return False
        return bool(self._url_pattern.search(text))

    def evaluate_decision(
        self,
        risk_score,
        confidence_info,
        explainable_info,
        emergency_info,
        user_text="",
        real_llm_result=None,
        critical_evidence: bool = False,
        url_report=None,
        has_image: bool = False,
        full_text: str = None,
    ):
        txt_raw = (user_text or "").strip()
        txt_clean = txt_raw.lower()
        cleaned_punct = re.sub(r"^[^\w]+|[^\w]+$", "", txt_clean).strip()

        # Check factors from explainable_info
        factors = []
        if isinstance(explainable_info, dict):
            factors = explainable_info.get("risk_breakdown") or explainable_info.get("factors") or []
        has_factors = len(factors) > 0

        has_url = self._has_url(txt_raw, url_report)
        is_emergency = bool(emergency_info and emergency_info.get("is_emergency"))

        # Exact greeting match: matches full greeting or greeting + courtesy suffix
        is_exact_greeting = cleaned_punct in self._greetings
        if not is_exact_greeting:
            tokens = cleaned_punct.split()
            if len(tokens) >= 2 and tokens[-1] in self._greeting_suffixes:
                base = " ".join(tokens[:-1])
                if base in self._greetings:
                    is_exact_greeting = True

        words = txt_clean.split()
        word_count = len(words)
        has_money_action = bool(self._money_action_regex.search(txt_clean))
        if full_text and isinstance(full_text, str) and self._money_action_regex.search(full_text.lower()):
            has_money_action = True

        has_dangerous_or_suspicious_url = False
        if url_report is not None:
            findings = getattr(url_report, "findings", None)
            if findings is None and isinstance(url_report, dict):
                findings = url_report.get("findings", [])
            for f in findings or []:
                v = getattr(f, "verdict", None) if not isinstance(f, dict) else f.get("verdict")
                r = getattr(f, "url_risk_score", 0) if not isinstance(f, dict) else f.get("url_risk_score", 0)
                if v in ("dangerous", "suspicious") or (r and r >= 40):
                    has_dangerous_or_suspicious_url = True
                    break

        # General Chat condition:
        # No URL, no factors, risk_score < 25, not emergency, no image, no dangerous/suspicious URL,
        # AND (matches exact greeting OR 1 <= words <= 8 without money/action keywords)
        can_be_general = (
            (not has_url)
            and (not has_factors)
            and (risk_score < 25)
            and (not is_emergency)
            and (not has_image)
            and (not has_dangerous_or_suspicious_url)
        )
        is_general_chat = can_be_general and (is_exact_greeting or (1 <= word_count <= 8 and not has_money_action))

        # Extract sanitized LLM conversational reply if available and valid
        llm_reply = None
        if real_llm_result and isinstance(real_llm_result, dict):
            status = real_llm_result.get("status") or real_llm_result.get("llm_status")
            if status not in ("llm_invalid", "llm_error", "llm_timeout"):
                raw_reply = real_llm_result.get("conversational_reply")
                if raw_reply and isinstance(raw_reply, str):
                    cleaned_reply = clean_llm_string(raw_reply, max_len=600)
                    if cleaned_reply:
                        llm_reply = cleaned_reply

        if is_general_chat:
            reply = llm_reply
            if not reply:
                if "đây là gì" in txt_clean or "bạn là ai" in txt_clean:
                    reply = "Tôi là SafeGuard AI — Trợ lý Vệ sĩ Số phòng chống lừa đảo trực tuyến tại Việt Nam. Bạn có thể gửi tin nhắn, đường link nghi vấn hoặc ảnh chụp bill VietQR/SMS để tôi hỗ trợ phân tích độ an toàn!"
                else:
                    reply = "Xin chào bạn! Tôi là SafeGuard AI, trợ lý vệ sĩ số của bạn. Hãy gửi cho tôi bất kỳ tin nhắn, đường link hoặc ảnh chụp nghi vấn lừa đảo nào để tôi giúp bạn kiểm tra nhé."

            return {
                "intent_type": "general_chat",
                "risk_level": "LOW",
                "headline": reply,
                "llm_commentary": None,
                "recommendations": [],
                "hitl_disclaimer": "SafeGuard AI — Trợ lý Vệ sĩ Số phòng chống lừa đảo trực tuyến."
            }

        # Need More Info condition:
        # Query has no URL, no factors, risk < 25, not emergency, but is too short or ambiguous without content
        if can_be_general and (word_count <= 15):
            reply = llm_reply
            if not reply:
                reply = "SafeGuard AI cần thêm thông tin để đánh giá. Vui lòng gửi cho tôi đầy đủ nội dung tin nhắn, số tài khoản, số điện thoại hoặc dán đường link nghi vấn cần kiểm tra nhé!"

            return {
                "intent_type": "need_more_info",
                "risk_level": "LOW",
                "headline": reply,
                "llm_commentary": None,
                "recommendations": [
                    "Dán toàn bộ nội dung tin nhắn đáng ngờ bạn nhận được.",
                    "Gửi đường link trang web hoặc file cài đặt nghi vấn.",
                    "Tải lên ảnh chụp màn hình hóa đơn hoặc đoạn chat."
                ],
                "hitl_disclaimer": "SafeGuard AI — Trợ lý Vệ sĩ Số phòng chống lừa đảo trực tuyến."
            }

        # Scam Analysis Intent
        is_critical = is_emergency or (risk_score >= 90 and critical_evidence)
        if is_critical:
            risk_level = "CRITICAL"
            if is_emergency:
                headline = "🚨 PHÁT HIỆN TÌNH HUỐNG KHẨN CẤP: KÍCH HOẠT QUY TRÌNH ỨNG PHÓ KHẨN CẤP (EMERGENCY PROTOCOL)"
                recommends = [
                    "1. Gọi ngay hotline Ngân hàng để yêu cầu Khóa thẻ/Khóa tài khoản khẩn cấp.",
                    "2. Đổi mật khẩu dịch vụ Internet Banking & ứng dụng OTT.",
                    "3. Trình báo cơ quan Công an gần nhất và gửi phản ánh tới NCSC (canhsat.gov.vn)."
                ]
            else:
                headline = "🚨 NGUY HIỂM ĐẶC BIỆT NGHIÊM TRỌNG: Phát hiện bằng chứng lừa đảo hoặc liên kết độc hại có tính sát thương cao."
                recommends = [
                    "❌ Tuyệt đối KHÔNG nạp tiền, chuyển khoản hay nhập thông tin cá nhân/mã OTP.",
                    "🔒 Khóa ngay tài khoản thẻ ngân hàng nếu đã lỡ điền thông tin.",
                    "⚠️ Báo cáo đường link/nội dung lừa đảo tới cơ quan chức năng hoặc NCSC."
                ]
        elif risk_score >= 75:
            risk_level = "HIGH"
            headline = "🔴 CẢNH BÁO RỦI RO CAO: Có nhiều dấu hiệu trùng khớp kịch bản lừa đảo đã ghi nhận."
            recommends = [
                "❌ Tuyệt đối KHÔNG nạp tiền, chuyển khoản hay đặt cọc quỹ dưới bất kỳ lý do gì.",
                "❌ Không bấm vào các đường link lạ hoặc tải file ứng dụng đuôi .apk.",
                "❌ Không cung cấp OTP, mật khẩu hay ảnh chụp CCCD/CMND.",
                "🔍 Kiểm tra đối soát trực tiếp qua số tổng đài chính thức của đơn vị."
            ]
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            headline = "🟡 CẢNH BÁO RỦI RO TRUNG BÌNH: Thông tin chứa các dấu hiệu nghi vấn, cần thận trọng."
            recommends = [
                "👤 Xác minh thủ công: Gọi điện thoại xác nhận với người thân hoặc đơn vị liên quan.",
                "❌ Không vội vàng giao dịch chuyển tiền khi chưa kiểm tra chính xác.",
                "🔍 Tra cứu thêm thông tin tài khoản/số điện thoại trên cổng NCSC."
            ]
        else:
            risk_level = "LOW"
            headline = "🟢 RỦI RO THẤP: Chưa phát hiện dấu hiệu lừa đảo rõ ràng trong nội dung kiểm tra."
            recommends = [
                "✔️ Hiện tại thông tin chưa có dấu hiệu lừa đảo phổ biến.",
                "💡 Vẫn duy trì cảnh giác khi thực hiện giao dịch online với người lạ."
            ]

        return {
            "intent_type": "scam_analysis",
            "risk_level": risk_level,
            "headline": headline,
            "llm_commentary": llm_reply,
            "recommendations": recommends,
            "hitl_disclaimer": "SafeGuard AI là Hệ thống Hỗ trợ Quyết định (Decision Support System). Quyết định giao dịch hoàn toàn thuộc về bạn."
        }


if __name__ == "__main__":
    agent = DecisionAgent()
    res = agent.evaluate_decision(85, {}, {}, {}, user_text="Tuyển CTV Shopee nạp 500k")
    print("[DecisionAgent] Result:", res)

