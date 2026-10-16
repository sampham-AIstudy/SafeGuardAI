import re
from codebase.text_utils import make_variants


class EmergencyAgent:
    """
    Emergency Agent:
    Triggers Immediate Emergency Protocol (1' - 3' - 5' - 10' - 30') when user reports
    having already transferred money or shared OTP / malware credentials.
    """

    # Bank transaction notifications (e.g. SMS) that are not scam reports
    BANK_NOTIFICATION_PATTERN = re.compile(
        r"(?<!\w)(?:thành\s+công|thanh\s+cong|quý\s+khách\s+đã|quy\s+khach\s+da|số\s+dư|so\s+du|gd:|sd:|sodu|bdsd|biến\s+động\s+số\s+dư)(?!\w)",
        re.IGNORECASE
    )

    # Indicator of victim / scam presence to override bank notification exclusion
    SCAM_EVIDENCE_PATTERN = re.compile(
        r"(?<!\w)(?:lừa|lua|scam|kẻ|ke|giả\s+danh|gia\s+danh|chiếm\s+đoạt|chiem\s+doat|cứu|cuu|giúp|giup|hết\s+sạch|het\s+sach|mất\s+sạch|mat\s+sach|đe\s+dọa|de\s+doa|tống\s+tiền|tong\s+tien|bên\s+lừa|ben\s+lua|tài\s+khoản\s+của\s+bên)(?!\w)",
        re.IGNORECASE
    )

    # News report pattern: media / third-person reporting that must not trigger emergency
    NEWS_REPORT_PATTERN = re.compile(
        r"(?<!\w)(?:bài\s+báo|đọc\s+báo|doc\s+bao|báo\s+chí|bao\s+chi|theo\s+báo|theo\s+bao|báo\s+đưa\s+tin|bao\s+dua\s+tin|theo\s+tin\s+tức|theo\s+tin\s+tuc|vụ\s+án|vu\s+an|nạn\s+nhân\s+[^.\n]{0,30}?\btrong\s+(?:một|1)\s+ngày)(?!\w)",
        re.IGNORECASE
    )

    # First-person and family perspective: no unaccented single-syllables (chi, con, me, bo)
    FIRST_PERSON_AND_FAMILY_PATTERN = re.compile(
        r"(?<!\w)(?:tôi|toi|em|mình|minh|bố\s+tôi|mẹ\s+tôi|anh\s+tôi|chị\s+tôi|em\s+tôi|con\s+tôi|cháu\s+tôi|ông\s+ngoại|bà\s+ngoại|ông\s+nội|bà\s+nội|bố|mẹ|anh|chị|con|cháu|ông|bà|người\s+nhà|nguoi\s+nha)(?!\w)",
        re.IGNORECASE
    )

    # Negation strictly adjacent to verb: (chưa|không|suýt|may mà|nếu|đừng|chớ)
    # Excludes: sợ, so, cho, dung, tranh
    NEGATION_PATTERN = re.compile(
        r"(?<!\w)(?:chưa|không|suýt|may\s+mà|may\s+quá|nếu|đừng|chớ)(?!\w)",
        re.IGNORECASE
    )
    NEGATION_PATTERN_FOLDED = re.compile(
        r"(?<!\w)(?:chua|khong|suyt|may\s+ma|may\s+qua|neu)(?!\w)",
        re.IGNORECASE
    )

    # Clues indicating victim or scam presence needed for neutral transfer patterns
    VICTIM_OR_SCAM_CLUES = re.compile(
        r"(?<!\w)(?:lỡ|lo|trót|trot|nhầm|nham|kẻ\s+gian|ke\s+gian|lừa\s+đảo|lua\s+dao|lừa|lua|giả\s+danh|gia\s+danh|người\s+lạ|nguoi\s+la|công\s+an|cong\s+an|cán\s+bộ|can\s+bo|nhân\s+viên\s+ngân\s+hàng|nhan\s+vien\s+ngan\s+hang|cứu|cuu|giúp|giup|làm\s+sao|lam\s+sao|sợ\s+quá|so\s+qua|hoảng|hoang|toang|cho\s+nó|cho\s+no|bên\s+lừa|ben\s+lua|đối\s+tượng|doi\s+tuong|scam|gian\s+lận|đe\s+dọa|de\s+doa|tống\s+tiền|tong\s+tien|tung\s+ảnh|tung\s+anh|danh\s+bạ|danh\s+ba|khoản\s+vay|khoan\s+vay|bảo\s+hiểm|bao\s+hiem|tuyển\s+dụng|tuyen\s+dung)(?!\w)",
        re.IGNORECASE
    )

    # Direct victim patterns (inherently embody loss or victimization)
    DIRECT_VICTIM_PATTERNS = [
        # bị lừa + (sạch|hết|mất)? + số tiền/'tiền'
        re.compile(r"(?<!\w)bị(?:\s+người\s+ta)?\s+lừa\s+(?:(?:sạch|hết|mất|toàn\s+bộ|hơn|gần|khoảng|tầm)\s+)?(?:tiền|\d+\s*(?:triệu|tr|k|nghìn|đ|đồng|vnd))(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)bi(?:\s+nguoi\s+ta)?\s+lua\s+(?:(?:sach|het|mat|toan\s+bo|hon|gan|khoang|tam)\s+)?(?:tien|\d+\s*(?:trieu|tr|k|nghin|d|dong|vnd))(?!\w)", re.IGNORECASE),

        # bị lừa nạp / bị lừa chuyển / bị lừa gửi / bị lừa đưa (including CASE_70 and CASE_10)
        re.compile(r"(?<!\w)bị(?:\s+người\s+ta)?\s+lừa\s+(?:nạp|chuyển(?:\s+khoản|\s+tiền)?|mất|gửi\s+tiền|đưa\s+tiền)(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)bi(?:\s+nguoi\s+ta)?\s+lua\s+(?:nap|chuyen(?:\s+khoan|\s+tien)?|mat|gui\s+tien|dua\s+tien)(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)bị(?:\s+người\s+ta)?\s+lừa\s+(?:nạp|chuyển|mất|gửi|đưa)\s+[^.\n]{0,35}?(?:\d+|triệu|tr|k|tiền|hết)(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)bi(?:\s+nguoi\s+ta)?\s+lua\s+(?:nap|chuyen|mat|gui|dua)\s+[^.\n]{0,35}?(?:\d+|trieu|tr|k|tien|het)(?!\w)", re.IGNORECASE),

        # bị lừa rồi
        re.compile(r"(?<!\w)bị\s+lừa\s+rồi(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)bi\s+lua\s+roi(?!\w)", re.IGNORECASE),

        # bị hack / bị chiếm + mất tiền
        re.compile(r"(?<!\w)(?:bị\s+hack|bị\s+chiếm)(?:\s+[^.\n]{0,25}?)?mất\s+tiền(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:bi\s+hack|bi\s+chiem)(?:\s+[^.\n]{0,25}?)?mat\s+tien(?!\w)", re.IGNORECASE),

        # mất (sạch|hết) tiền / hết sạch tiền
        re.compile(r"(?<!\w)(?:mất|hết)\s+(?:sạch|hết)\s+tiền(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:mat|het)\s+(?:sach|het)\s+tien(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)mất\s+(?:hết\s+|sạch\s+)?tiền\s+rồi(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)mat\s+(?:het\s+|sach\s+)?tien\s+roi(?!\w)", re.IGNORECASE),

        # toang rồi mất sạch tiền
        re.compile(r"(?<!\w)toang(?:\s+rồi)?(?:\s+[^.\n]{0,25}?)?mất\s+(?:sạch|hết)?\s*tiền(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)toang(?:\s+roi)?(?:\s+[^.\n]{0,25}?)?mat\s+(?:sach|het)?\s*tien(?!\w)", re.IGNORECASE),

        # tài khoản bị trừ sạch tiền / chuyển mất tiền
        re.compile(r"(?<!\w)(?:tài\s+khoản\s+)?(?:vừa\s+)?bị\s+(?:trừ|chuyển\s+mất)\s+(?:hết\s+|sạch\s+)?(?:tiền|\d+)(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:tai\s+khoan\s+)?(?:vua\s+)?bi\s+(?:tru|chuyen\s+mat)\s+(?:het\s+|sach\s+)?(?:tien|\d+)(?!\w)", re.IGNORECASE),

        # credentials / malware: lộ OTP, nhập OTP, cài file APK
        re.compile(r"(?<!\w)lộ\s+(?:mã\s+)?otp(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)lo\s+(?:ma\s+)?otp(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)lộ\s+mật\s+khẩu(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)lo\s+mat\s+khau(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:đã|lỡ|trót|vừa)\s+(?:nhập|đọc|cung\s+cấp|gửi)\s+[^.\n]{0,20}?(?:mã\s+)?otp(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:da|lo|trot|vua)\s+(?:nhap|doc|cung\s+cap|gui)\s+[^.\n]{0,20}?(?:ma\s+)?otp(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:đã|lỡ|trót|vừa)\s+nhập\s+mật\s+khẩu(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:da|lo|trot|vua)\s+nhap\s+mat\s+khau(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:đã|lỡ|trót|vừa)\s+(?:cài|tải)\s+[^.\n]{0,30}?(?:\.apk|apk|app\s+lạ|mã\s+độc)(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:da|lo|trot|vua)\s+(?:cai|tai)\s+[^.\n]{0,30}?(?:\.apk|apk|app\s+la|ma\s+doc)(?!\w)", re.IGNORECASE),
    ]

    # Inherent emergency transfers (explicit regret or scammer destination)
    INHERENT_EMERGENCY_TRANSFER_PATTERNS = [
        re.compile(
            r"(?<!\w)(?:lỡ|trót)\s+(?:chuyển(?:\s+khoản|\s+tiền)?|nạp(?:\s+tiền)?|gửi\s+tiền|đưa\s+tiền)\s+[^.\n]{0,35}?(?:\d+|triệu|tr|k|tiền|cho\s+(?:kẻ|bên|đối\s+tượng|scam|nó|người\s+lạ))(?!\w)",
            re.IGNORECASE
        ),
        re.compile(
            r"(?<!\w)(?:lo|trot)\s+(?:chuyen(?:\s+khoan|\s+tien)?|nap(?:\s+tien)?|gui\s+tien|dua\s+tien)\s+[^.\n]{0,35}?(?:\d+|trieu|tr|k|tien|cho\s+(?:ke|ben|doi\s+tuong|scam|no|nguoi\s+la))(?!\w)",
            re.IGNORECASE
        ),
        re.compile(r"(?<!\w)(?:lỡ|trót)\s*chuyển\s+(?:khoản|tiền)\s+rồi(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:lo|trot)\s*chuyen\s+(?:khoan|tien)\s+roi(?!\w)", re.IGNORECASE),
    ]

    # Neutral past transfers: only trigger emergency when victim/scam clue is present
    NEUTRAL_TRANSFER_PATTERNS = [
        re.compile(
            r"(?<!\w)(?:đã|vừa)\s+(?:chuyển(?:\s+khoản|\s+tiền)?|nạp(?:\s+tiền)?|gửi\s+tiền|đưa\s+tiền)\s+[^.\n]{0,35}?(?:\d+|triệu|tr|k|tiền|học\s+phí|phí|cho\s+(?:kẻ|bên|đối\s+tượng|scam|nó|người\s+lạ))(?!\w)",
            re.IGNORECASE
        ),
        re.compile(
            r"(?<!\w)(?:da|vua)\s+(?:chuyen(?:\s+khoan|\s+tien)?|nap(?:\s+tien)?|gui\s+tien|dua\s+tien)\s+[^.\n]{0,35}?(?:\d+|trieu|tr|k|tien|hoc\s+phi|phi|cho\s+(?:ke|ben|doi\s+tuong|scam|no|nguoi\s+la))(?!\w)",
            re.IGNORECASE
        ),
        re.compile(r"(?<!\w)(?:đã|vừa)\s*chuyển\s+(?:khoản|tiền)\s+rồi(?!\w)", re.IGNORECASE),
        re.compile(r"(?<!\w)(?:da|vua)\s*chuyen\s+(?:khoan|tien)\s+roi(?!\w)", re.IGNORECASE),
    ]

    def __init__(self):
        pass

    @staticmethod
    def _extract_clause_window(text: str, match_start: int, max_window: int = 25) -> str:
        """
        Extract preceding window up to max_window characters,
        strictly cut at the nearest clause punctuation boundary [,.!?;:\n].
        """
        raw_start = max(0, match_start - max_window)
        preceding = text[raw_start:match_start]
        punct_indices = [preceding.rfind(c) for c in ",.!?;:\n"]
        last_punct = max(punct_indices)
        if last_punct != -1:
            preceding = preceding[last_punct + 1:]
        return preceding

    def check_trigger(self, text: str) -> dict:
        if not text:
            return {"is_emergency": False}

        variants = make_variants(text)

        # 1. Bank notification check (e.g. SMS 'Đã chuyển khoản thành công 500.000đ')
        # Only exclude if there is no indicator of scam/victim evidence
        is_bank_notification = bool(
            self.BANK_NOTIFICATION_PATTERN.search(variants.lower)
            or self.BANK_NOTIFICATION_PATTERN.search(variants.folded)
        )
        has_scam_evidence = bool(
            self.SCAM_EVIDENCE_PATTERN.search(variants.lower)
            or self.SCAM_EVIDENCE_PATTERN.search(variants.folded)
        )
        if is_bank_notification and not has_scam_evidence:
            return {"is_emergency": False}

        # 2. News report check: media coverage of third-person victims
        is_news_report = bool(
            self.NEWS_REPORT_PATTERN.search(variants.lower)
            or self.NEWS_REPORT_PATTERN.search(variants.folded)
        )
        if is_news_report:
            return {"is_emergency": False}

        # 3. Check emergency patterns with preceding negation window cut at clause boundaries
        is_emergency = False
        target_texts = [(variants.lower, self.NEGATION_PATTERN), (variants.folded, self.NEGATION_PATTERN_FOLDED)]

        # A. Check Direct Victim Patterns
        for text_variant, neg_pat in target_texts:
            for pat in self.DIRECT_VICTIM_PATTERNS:
                for match in pat.finditer(text_variant):
                    preceding = self._extract_clause_window(text_variant, match.start(), 25)
                    if neg_pat.search(preceding):
                        continue
                    is_emergency = True
                    break
                if is_emergency:
                    break
            if is_emergency:
                break

        # B. Check Inherent Emergency Transfer Patterns
        if not is_emergency:
            for text_variant, neg_pat in target_texts:
                for pat in self.INHERENT_EMERGENCY_TRANSFER_PATTERNS:
                    for match in pat.finditer(text_variant):
                        preceding = self._extract_clause_window(text_variant, match.start(), 25)
                        if neg_pat.search(preceding):
                            continue
                        is_emergency = True
                        break
                    if is_emergency:
                        break
                if is_emergency:
                    break

        # C. Check Neutral Transfer Patterns (only if victim/scam clue is present)
        if not is_emergency:
            has_scam_clue = bool(
                self.VICTIM_OR_SCAM_CLUES.search(variants.lower)
                or self.VICTIM_OR_SCAM_CLUES.search(variants.folded)
            )
            if has_scam_clue:
                for text_variant, neg_pat in target_texts:
                    for pat in self.NEUTRAL_TRANSFER_PATTERNS:
                        for match in pat.finditer(text_variant):
                            preceding = self._extract_clause_window(text_variant, match.start(), 25)
                            if neg_pat.search(preceding):
                                continue
                            is_emergency = True
                            break
                        if is_emergency:
                            break
                    if is_emergency:
                        break

        if is_emergency:
            return {
                "is_emergency": True,
                "risk_level": "CRITICAL",
                "risk_score": 99,
                "protocol_steps": [
                    {
                        "time_window": "⏱️ 1 PHÚT ĐẦU",
                        "action": "Khóa ứng dụng Internet Banking & Thẻ ngân hàng khẩn cấp (qua app hoặc cú pháp SMS khóa thẻ).",
                        "priority": "CRITICAL"
                    },
                    {
                        "time_window": "⏱️ 3 PHÚT",
                        "action": "Gọi Hotline chính thức của Ngân hàng yêu cầu tra soát giao dịch khẩn cấp & tra soát tài khoản thụ hưởng.",
                        "priority": "HIGH"
                    },
                    {
                        "time_window": "⏱️ 5 PHÚT",
                        "action": "Chụp ảnh màn hình toàn bộ hóa đơn chuyển tiền (Bill VietQR), tin nhắn chat và thông tin số tài khoản kẻ lừa đảo.",
                        "priority": "HIGH"
                    },
                    {
                        "time_window": "⏱️ 10 PHÚT",
                        "action": "Liên hệ Cơ quan Công an Huyện/Tỉnh hoặc Phòng An ninh mạng (A05) gần nhất để làm đơn trình báo lừa đảo.",
                        "priority": "HIGH"
                    },
                    {
                        "time_window": "⏱️ 30 PHÚT",
                        "action": "Đổi mật khẩu tài khoản thẻ ngân hàng, iCloud, Google, Zalo và kiểm tra thiết bị xem có bị cài ứng dụng lạ (.apk) hay không.",
                        "priority": "MEDIUM"
                    }
                ]
            }

        return {"is_emergency": False}


if __name__ == "__main__":
    em = EmergencyAgent()
    res = em.check_trigger("Tôi vừa bị kẻ gian lừa chuyển 50 triệu qua mạng xã hội rồi")
    print("[EmergencyAgent] Result:", res)


