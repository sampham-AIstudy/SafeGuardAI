import re

class PromptGuard:
    """
    Prompt Injection, Jailbreak & Ethical Safety Guardrail:
    - Detects prompt injection attempts (e.g. 'ignore previous instructions', 'override rules', 'DAN mode')
    - Detects illegal / malicious / harmful content requests (malware generation, scam script creation, illegal acts)
    - Enforces System Prompt supremacy and input delimiting
    """
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|above)\s+instructions",
        r"forget\s+(all\s+)?(previous|above)\s+rules",
        r"override\s+(system|safety|security)\s+prompt",
        r"disregard\s+(all\s+)?prior\s+guidelines",
        r"you\s+are\s+now\s+(in\s+)?DAN\s+mode",
        r"act\s+as\s+an\s+unfiltered",
        r"bỏ\s+qua\s+(mọi\s+)?hướng\s+dẫn",
        r"quên\s+(hết\s+)?quy\s+tắc",
        r"tiết\s+lộ\s+(hệ\s+thống|system\s+prompt|api\s+key|mật\s+mã)",
        r"bắt\s+buộc\s+đánh\s+giá\s+0%",
        r"bắt\s+buộc\s+trả\s+lời\s+an\s+toàn"
    ]

    MALICIOUS_INTENT_PATTERNS = [
        r"viết\s+mã\s+độc",
        r"tạo\s+kịch\s+bản\s+lừa\s+đảo",
        r"hướng\s+dẫn\s+hack",
        r"chiếm\s+đoạt\s+tài\s+khoản",
        r"hướng\s+dẫn\s+lừa\s+tiền",
        r"phát\s+tán\s+mã\s+độc",
        r"tạo\s+trang\s+web\s+giả\s+mạo"
    ]

    def evaluate_input(self, user_text: str) -> dict:
        text_lower = user_text.lower()
        
        # Check Injection Patterns
        for pat in self.INJECTION_PATTERNS:
            if re.search(pat, text_lower, re.IGNORECASE):
                return {
                    "is_safe": False,
                    "reason": "prompt_injection_detected",
                    "refusal_message": (
                        "🛡️ **THÔNG BÁO BẢO MẬT SAFEGUARD AI**\n\n"
                        "Hệ thống phát hiện câu lệnh chứa hành vi thao túng/can thiệp quy tắc an toàn (Prompt Injection).\n"
                        "SafeGuard AI từ chối thực thi và giữ nguyên nguyên tắc phân tích an ninh mạng trung thực, đúng đắn.\n\n"
                        "Vui lòng cung cấp tin nhắn, đường link hoặc tình huống nghi vấn lừa đảo để được hỗ trợ phân tích."
                    )
                }

        # Check Malicious Intent Patterns
        for pat in self.MALICIOUS_INTENT_PATTERNS:
            if re.search(pat, text_lower, re.IGNORECASE):
                return {
                    "is_safe": False,
                    "reason": "malicious_intent_detected",
                    "refusal_message": (
                        "🛡️ **TỪ CHỐI AN TOÀN SAFEGUARD AI**\n\n"
                        "SafeGuard AI từ chối xử lý các yêu cầu tạo kịch bản lừa đảo, phát tán mã độc hoặc vi phạm an ninh mạng và pháp luật.\n"
                        "Hệ thống hoạt động duy nhất với mục đích vệ sĩ số phòng chống lừa đảo và bảo vệ người dùng."
                    )
                }

        return {
            "is_safe": True,
            "reason": "safe",
            "refusal_message": ""
        }

    @staticmethod
    def wrap_untrusted_input(text: str) -> str:
        """Wrap user text inside XML delimiters to prevent prompt injection."""
        clean_text = text.replace("<user_input_untrusted>", "").replace("</user_input_untrusted>", "")
        return f"<user_input_untrusted>\n{clean_text}\n</user_input_untrusted>"
