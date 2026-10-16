import re
from codebase.text_utils import make_variants


class PromptGuard:
    """
    Prompt Injection, Jailbreak & Ethical Safety Guardrail:
    - Detects prompt injection attempts (e.g. 'ignore previous instructions', 'override rules', 'DAN mode')
    - Detects illegal / malicious / harmful content requests (scam script creation, malware generation)
    - Enforces System Prompt supremacy and input delimiting
    """

    INJECTION_PATTERNS = [
        r"ignore\s+(?:all\s+|the\s+)?(?:previous|above)\s+instructions",
        r"forget\s+(?:all\s+|the\s+)?(?:previous|above)\s+rules",
        r"override\s+(?:system|safety|security)\s+prompt",
        r"disregard\s+(?:all\s+|the\s+)?(?:prior|previous)\s+(?:guidelines|instructions)",
        r"you\s+are\s+now\s+(?:in\s+)?dan\s+mode",
        r"act\s+as\s+an?\s+unfiltered",
        r"phớt[\s_]*lờ\s*(?:các\s*|mọi\s*|tất\s*cả\s*)?(?:chỉ\s*dẫn|hướng\s*dẫn)(?:\s+trước\s+đó)?",
        r"phot[\s_]*lo\s*(?:cac\s*|moi\s*|tat\s*ca\s*)?(?:chi\s*dan|huong\s*dan)(?:\s+truoc\s+do)?",
        r"bỏ[\s_]*qua\s*(?:các\s*|mọi\s*|tất\s*cả\s*(?:các\s*)?)?(?:hướng\s*dẫn|chỉ\s*dẫn)(?:\s+trước\s+đó)?",
        r"bo[\s_]*qua\s*(?:cac\s*|moi\s*|tat\s*ca\s*(?:cac\s*)?)?(?:huong\s*dan|chi\s*dan)(?:\s+truoc\s+do)?",
        r"bỏ[\s_]*qua\s*hệ\s*thống(?:\s+và\s+trả\s+lời\s+an\s+toàn)?",
        r"bo[\s_]*qua\s*he\s*thong(?:\s+va\s+tra\s+loi\s+an\s+toan)?",
        r"quên\s*(?:hết\s*)?(?:quy\s*tắc|hướng\s*dẫn)",
        r"quen\s*(?:het\s*)?(?:quy\s*tac|huong\s*dan)",
        r"tiết\s*lộ\s*(?:hệ\s*thống|system\s*prompt|api\s*key|mật\s*mã)",
        r"tiet\s*lo\s*(?:he\s*thong|system\s*prompt|api\s*key|mat\s*ma)",
        r"bắt\s*buộc\s*đánh\s*giá\s*0%",
        r"bat\s*buoc\s*danh\s*gia\s*0%",
        r"bắt\s*buộc\s*trả\s*lời\s*an\s*toàn",
        r"bat\s*buoc\s*tra\s*loi\s*an\s*toan",
    ]

    CMD_VERB = (
        r"(?:"
        r"(?:hãy|giúp|cho|nhờ)\s+(?:(?:tôi|mình|em|anh|chị)\s+)?(?:viết|tạo|soạn|làm|dựng|code|lập\s+trình|lập)(?!\s+(?:theo|sao|có\s+phải|không|được|xem))|"
        r"(?<!cách\s)(?:viết|tạo|soạn|làm|dựng|code|lập\s+trình|lập)(?!\s+(?:theo|sao|có\s+phải|không|được|xem))\s+(?:(?:giúp|cho|hộ|nhờ)\s+)?(?:tôi|mình|em|anh|chị)|"
        r"(?:hãy\s+)?(?:lập\s+trình|code|soạn|viết)(?!\s+(?:theo|sao|có\s+phải|không|được|xem))\s+(?:giúp|cho|hộ|nhờ)?|"
        r"(?:làm|tạo)(?!\s+(?:theo|sao|có\s+phải|không|được|xem))\s+(?:giúp|cho|hộ|nhờ|hãy|tôi|mình|em|anh|chị)|"
        r"soạn\s+(?:cho\s+)?(?:tôi|mình|em|anh|chị)?"
        r")"
    )

    TARGET_OBJ = r"(?:kịch\s+bản|tin\s+nhắn|email|trang\s+đăng\s+nhập|trang\s+web|website|trang|link|ứng\s+dụng|app|mã\s+độc|script)"
    BAD_INTENT = r"(?:lừa\s+đảo|giả\s+danh|giả\s+mạo|phishing|lừa|chiếm\s+đoạt|giả\s+làm|giống\s+hệt|đánh\s+cắp|(?<!bị\s)hack)"

    PAT_ACTION_REQUEST = re.compile(
        rf"\b{CMD_VERB}\b[^.\n]{{0,40}}?\b{TARGET_OBJ}\b[^.\n]{{0,40}}?\b{BAD_INTENT}\b",
        re.IGNORECASE
    )

    PAT_GUIDE_REQUEST = re.compile(
        r"\b(?:hướng\s+dẫn|chỉ|dạy)\s+(?:(?:cho\s+)?(?:tôi|mình|em|anh|chị)\s+)?(?:cách\s+)?(?:hack|chiếm\s+đoạt|lừa|đánh\s+cắp)\b",
        re.IGNORECASE
    )

    PAT_MALWARE_REQUEST = re.compile(
        r"\b(?:hãy|giúp|cho|nhờ)?\s*(?:viết|tạo|phát\s+tán|code|lập\s+trình)\s+(?:cho\s+(?:tôi|mình|em|anh|chị)\s+)?\b(?:mã\s+độc|malware|virus|trojan|ransomware)\b",
        re.IGNORECASE
    )

    # Unaccented folded patterns for Task C3(a) & D1
    CMD_VERB_FOLDED = (
        r"(?:"
        r"(?:hay|giup|cho|nho)\s+(?:(?:toi|minh|em|anh|chi)\s+)?(?:viet|tao|soan|lam|dung|code|lap\s+trinh|lap)(?!\s+(?:theo|sao|co\s+phai|khong|duoc|xem))|"
        r"(?<!cach\s)(?:viet|tao|soan|lam|dung|code|lap\s+trinh|lap)(?!\s+(?:theo|sao|co\s+phai|khong|duoc|xem))\s+(?:(?:giup|cho|ho|nho)\s+)?(?:toi|minh|em|anh|chi)|"
        r"(?:hay\s+)?(?:lap\s+trinh|code|soan|viet)(?!\s+(?:theo|sao|co\s+phai|khong|duoc|xem))\s+(?:giup|cho|ho|nho)?|"
        r"(?:lam|tao)(?!\s+(?:theo|sao|co\s+phai|khong|duoc|xem))\s+(?:giup|cho|ho|nho|hay|toi|minh|em|anh|chi)|"
        r"soan\s+(?:cho\s+)?(?:toi|minh|em|anh|chi)?"
        r")"
    )

    TARGET_OBJ_FOLDED = r"(?:kich\s+ban|tin\s+nhan|email|trang\s+dang\s+nhap|trang\s+web|website|trang|link|ung\s+dung|app|ma\s+doc|script)"
    BAD_INTENT_FOLDED = r"(?:lua\s+dao|gia\s+danh|gia\s+mao|phishing|lua(?!\s+chon)|chiem\s+doat|gia\s+lam|giong\s+het|danh\s+cap|(?<!bi\s)hack)"

    PAT_ACTION_REQUEST_FOLDED = re.compile(
        rf"\b{CMD_VERB_FOLDED}\b[^.\n]{{0,40}}?\b{TARGET_OBJ_FOLDED}\b[^.\n]{{0,40}}?\b{BAD_INTENT_FOLDED}\b",
        re.IGNORECASE
    )

    PAT_GUIDE_REQUEST_FOLDED = re.compile(
        r"\b(?:huong\s+dan|chi|day)\s+(?:(?:cho\s+)?(?:toi|minh|em|anh|chi)\s+)?(?:cach\s+)?(?:hack|chiem\s+doat|lua(?!\s+chon)|danh\s+cap)\b",
        re.IGNORECASE
    )

    PAT_MALWARE_REQUEST_FOLDED = re.compile(
        r"\b(?:hay|giup|cho|nho)?\s*(?:viet|tao|phat\s+tan|code|lap\s+trinh)\s+(?:cho\s+(?:toi|minh|em|anh|chi)\s+)?\b(?:ma\s+doc|malware|virus|trojan|ransomware)\b",
        re.IGNORECASE
    )

    # English malicious action pattern and exclusion for Task D1
    PAT_ENGLISH_ACTION = re.compile(
        r"\b(?:write|create|make|build|generate)\b[^.\n]{0,40}?\b(?:phishing|scam|fake)\b[^.\n]{0,40}?\b(?:email|message|page|site|login)\b",
        re.IGNORECASE
    )
    PAT_ENGLISH_PREVENTION = re.compile(
        r"\bhow\s+to\s+(?:spot|detect|avoid|report)\b",
        re.IGNORECASE
    )

    # Prevention / education exclusion terms for Task C1 & D1
    # Chấp nhận rủi ro: yêu cầu độc hại có thể lách bằng từ phòng chống trong ±40 ký tự.
    PREVENTION_TERMS = re.compile(
        r"\b(?:cảnh\s+báo|phòng\s+tránh|phòng\s+chống|tránh|nhận\s+biết|dấu\s+hiệu|tuyên\s+truyền|trả\s+lời|tố\s+cáo|báo\s+cáo|trình\s+báo|không\s+bị|chống|bài\s+học|slide|lớp\s+học|đào\s+tạo|đừng|báo|phát\s+hiện|hỏi|có\s+phải|nhắc|kiểm\s+tra|nhận\s+diện)\b",
        re.IGNORECASE
    )

    PREVENTION_TERMS_FOLDED = re.compile(
        r"\b(?:canh\s+bao|phong\s+tranh|phong\s+chong|tranh|nhan\s+biet|dau\s+hieu|tuyen\s+truyen|tra\s+loi|to\s+cao|bao\s+cao|trinh\s+bao|khong\s+bi|chong|bai\s+hoc|slide|lop\s+hoc|dao\s+tao|dung|bao|phat\s+hien|hoi|co\s+phai|nhac|kiem\s+tra|nhan\s+dien)\b",
        re.IGNORECASE
    )

    # Coercion / roleplay detection to prevent malicious requests from evading refusal
    ROLEPLAY_COERCION = re.compile(
        r"\b(?:đóng\s+vai|dong\s+vai|bị\s+(?:[^.\n]{0,20}\s+)?ép|bi\s+(?:[^.\n]{0,20}\s+)?ep|ép\s+buộc|ep\s+buoc|giả\s+vờ|gia\s+vo|giả\s+sử|gia\s+su)\b",
        re.IGNORECASE
    )

    URL_INDICATORS = ("://", "www.", "[.]", "hxxp")
    URL_REGEX = re.compile(
        r"(?:https?://|hxxps?://|www\.|\b[a-zA-Z0-9-]{1,50}\[\.\][a-zA-Z0-9-]{1,10}\b|\b[a-zA-Z0-9-]{1,50}\.(?:com|vn|xyz|top|net|org|edu|gov|cc|site|online|me|info|biz|co|vip|club|link|icu|cfd|sbs|win|bet)\b)",
        re.IGNORECASE
    )

    def evaluate_input(self, user_text: str) -> dict:
        variants = make_variants(user_text)

        # 1. Check Injection Patterns (both lower and folded)
        injection_detected = False
        for pat in self.INJECTION_PATTERNS:
            if re.search(pat, variants.lower, re.IGNORECASE) or re.search(pat, variants.folded, re.IGNORECASE):
                injection_detected = True
                break

        # 2. Check URL presence:
        # Rủi ro đã chấp nhận: Yêu cầu độc hại kèm domain thật vẫn đi tiếp vào pipeline
        # (không refusal sớm) để hệ thống quét URL, phân tích mối đe dọa và cảnh báo kịp thời.
        has_url = any(marker in user_text for marker in self.URL_INDICATORS) or (
            "." in user_text and bool(self.URL_REGEX.search(user_text))
        )

        # 3. Check Malicious Intent Patterns
        malicious_request_detected = False
        if not has_url:
            accented_patterns = [self.PAT_ACTION_REQUEST, self.PAT_GUIDE_REQUEST, self.PAT_MALWARE_REQUEST]
            for pat in accented_patterns:
                for m in pat.finditer(variants.clean):
                    match_start = m.start()
                    match_end = m.end()
                    pre_window = variants.clean[max(0, match_start - 40):match_start]
                    post_window = variants.clean[match_end:min(len(variants.clean), match_end + 40)]
                    match_str = m.group(0)

                    has_roleplay = bool(self.ROLEPLAY_COERCION.search(variants.clean[:match_start]))

                    has_prevention = bool(
                        self.PREVENTION_TERMS.search(pre_window)
                        or self.PREVENTION_TERMS.search(match_str)
                        or self.PREVENTION_TERMS.search(post_window)
                    )

                    if has_prevention and not has_roleplay:
                        continue

                    malicious_request_detected = True
                    break
                if malicious_request_detected:
                    break

            if not malicious_request_detected:
                folded_patterns = [self.PAT_ACTION_REQUEST_FOLDED, self.PAT_GUIDE_REQUEST_FOLDED, self.PAT_MALWARE_REQUEST_FOLDED]
                for pat in folded_patterns:
                    for m in pat.finditer(variants.folded):
                        match_start = m.start()
                        match_end = m.end()
                        pre_window = variants.folded[max(0, match_start - 40):match_start]
                        post_window = variants.folded[match_end:min(len(variants.folded), match_end + 40)]
                        match_str = m.group(0)

                        has_roleplay = bool(self.ROLEPLAY_COERCION.search(variants.folded[:match_start]))

                        has_prevention = bool(
                            self.PREVENTION_TERMS_FOLDED.search(pre_window)
                            or self.PREVENTION_TERMS_FOLDED.search(match_str)
                            or self.PREVENTION_TERMS_FOLDED.search(post_window)
                        )

                        if has_prevention and not has_roleplay:
                            continue

                        malicious_request_detected = True
                        break
                    if malicious_request_detected:
                        break

            if not malicious_request_detected:
                for m in self.PAT_ENGLISH_ACTION.finditer(variants.clean):
                    match_start = m.start()
                    match_end = m.end()
                    pre_window = variants.clean[max(0, match_start - 40):match_start]
                    post_window = variants.clean[match_end:min(len(variants.clean), match_end + 40)]
                    match_str = m.group(0)

                    has_english_prevention = bool(
                        self.PAT_ENGLISH_PREVENTION.search(pre_window)
                        or self.PAT_ENGLISH_PREVENTION.search(match_str)
                        or self.PAT_ENGLISH_PREVENTION.search(post_window)
                    )
                    if has_english_prevention:
                        continue
                    malicious_request_detected = True
                    break

        if malicious_request_detected:
            return {
                "is_safe": False,
                "reason": "malicious_intent_detected",
                "intent_type": "refusal",
                "injection_detected": injection_detected,
                "malicious_request_detected": True,
                "refusal_message": (
                    "🛡️ TỪ CHỐI AN TOÀN SAFEGUARD AI\n\n"
                    "SafeGuard AI từ chối xử lý các yêu cầu tạo kịch bản lừa đảo, phát tán mã độc hoặc vi phạm an ninh mạng và pháp luật.\n"
                    "Hệ thống hoạt động duy nhất với mục đích vệ sĩ số phòng chống lừa đảo và bảo vệ người dùng."
                ),
            }

        if injection_detected:
            return {
                "is_safe": True,
                "reason": "prompt_injection_detected",
                "intent_type": "scam_analysis",
                "injection_detected": True,
                "malicious_request_detected": False,
                "refusal_message": "",
            }

        return {
            "is_safe": True,
            "reason": "safe",
            "intent_type": "scam_analysis",
            "injection_detected": False,
            "malicious_request_detected": False,
            "refusal_message": "",
        }

    @staticmethod
    def wrap_untrusted_input(text: str) -> str:
        """Wrap user text inside XML delimiters to prevent prompt injection."""
        clean_text = re.sub(r"(?i)</?\s*user_input_untrusted\s*>", "", text or "")
        return f"<user_input_untrusted>\n{clean_text}\n</user_input_untrusted>"
