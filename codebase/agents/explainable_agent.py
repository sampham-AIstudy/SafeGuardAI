import re
from urllib.parse import urlparse

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


class ExplainableAgent:
    """
    Explainable AI Agent:
    Provides explicit breakdown of Risk Score % based on weighted evidence factors.
    Accurately distinguishes between Official Whitelisted Domains (0% risk)
    and Subdomain Impersonation / Phishing Links (80-99% risk).
    """
    def __init__(self):
        pass

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
        return False

    def explain(self, text, matched_flags, ocr_anomalies, escalation_info=None):
        text_lower = text.lower()
        factors = []
        total_risk_score = 0

        urls = self._extract_urls(text)
        url_hostnames = [self._parse_hostname(u) for u in urls if u]

        has_urls = len(urls) > 0
        official_urls_count = sum(1 for h in url_hostnames if self.is_official_domain(h))
        has_only_official_urls = has_urls and (official_urls_count == len(urls))

        # Check for explicit scam action indicators
        scam_action_keywords = [
            "nạp tiền", "nạp quỹ", "cọc", "quỹ đảm bảo", "đặt cọc", "phí kích hoạt",
            "mã otp", "mã xác thực", "tải file apk", ".apk", "chuyển khoản cho",
            "vừa bị lừa", "chuyển tiền gấp"
        ]
        has_scam_actions = any(kw in text_lower for kw in scam_action_keywords)

        # ─────────────────────────────────────────
        # BLOCK A: Fake Recruitment / CTV / Shopee / TikTok
        # ─────────────────────────────────────────
        if any(w in text_lower for w in ["tuyển dụng", "ctv", "việc làm", "chốt đơn", "xem tiktok", "làm việc tại nhà"]):
            weight = 20
            factors.append({"factor": "Dấu hiệu tuyển dụng CTV lương cao bất thường (Fake Recruitment)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK B: Advance Payment / Money Deposit Request
        # ─────────────────────────────────────────
        if any(w in text_lower for w in ["chuyển tiền", "nạp tiền", "nạp quỹ", "cọc", "quỹ đảm bảo", "đặt cọc", "phí xác nhận", "phí kích hoạt", "thanh toán trước"]):
            weight = 40
            factors.append({"factor": "Yêu cầu chuyển tiền / đặt cọc / nạp quỹ trước (Advance Payment)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK C: Fake Banking / OTP Phishing
        # ─────────────────────────────────────────
        banking_phishing_triggers = [
            "tài khoản bị khóa", "tài khoản của quý khách", "xác minh thông tin",
            "đăng nhập ngay", "cập nhật thông tin", "tài khoản bị tạm khóa",
            "internet banking", "mã otp", "mã xác thực", "cảnh báo bảo mật", "nạp tiền ví"
        ]
        # Only trigger banking phishing if explicit phishing keywords exist OR if domain is not official
        if any(w in text_lower for w in banking_phishing_triggers) and not has_only_official_urls:
            weight = 35
            factors.append({"factor": "Giả mạo thông báo ngân hàng / cảnh báo tài khoản (Banking Phishing)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK D: Domain Impersonation & Fake Links
        # ─────────────────────────────────────────
        suspicious_tld = [".xyz", ".cc", ".apk", ".tk", ".ml", ".ga", ".cf", ".info", ".top", ".pw"]
        brand_keywords = [
            "vietcombank", "techcombank", "agribank", "vpbank", "bidv", "vneid",
            "microsoft", "microsoftonline", "shopee", "chinhphu"
        ]

        impersonated_detected = False
        for url, host in zip(urls, url_hostnames):
            if not host:
                continue

            # If host is official, it's NOT an impersonation
            if self.is_official_domain(host):
                continue

            # If host is NOT official but contains official brand in subdomains or hyphenated patterns
            is_brand_impersonation = False
            for brand in brand_keywords:
                if brand in host:
                    is_brand_impersonation = True
                    break

            is_suspicious_tld = any(host.endswith(tld) or tld in host for tld in suspicious_tld)

            if is_brand_impersonation or is_suspicious_tld or "-" in host:
                impersonated_detected = True

        if impersonated_detected:
            weight = 45
            factors.append({"factor": "Đường link giả mạo / Domain impersonation ngân hàng hoặc cơ quan nhà nước", "weight": weight})
            total_risk_score += weight
        elif any(w in text_lower for w in ["link lạ", "nhấp vào đây", "click here"]) and not has_only_official_urls:
            weight = 30
            factors.append({"factor": "Chứa đường link dẫn đến địa chỉ nghi vấn", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK E: APK Malware / Fake App Installation
        # ─────────────────────────────────────────
        if ".apk" in text_lower or any("cài" in a.lower() or ".apk" in a.lower() for a in ocr_anomalies):
            weight = 50
            factors.append({"factor": "File mã độc Android (.apk) yêu cầu cài ngoài Google Play Store", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK F: Government / Authority Impersonation
        # ─────────────────────────────────────────
        authority_keywords = [
            "cục thuế", "công an", "tòa án", "viện kiểm sát", "vneid", "bộ công an",
            "cán bộ", "cơ quan điều tra", "phòng cảnh sát"
        ]
        if any(w in text_lower for w in authority_keywords) and not has_only_official_urls:
            weight = 30
            factors.append({"factor": "Mạo danh cơ quan nhà nước / Cán bộ công quyền (Authority Impersonation)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK G: Personal Bank Account
        # ─────────────────────────────────────────
        if any(w in text_lower for w in ["tài khoản cá nhân", "stk", "số tài khoản", "chuyển khoản cho"]):
            weight = 15
            factors.append({"factor": "Sử dụng tài khoản ngân hàng cá nhân thay vì tài khoản doanh nghiệp", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK H: Urgency / Time Pressure
        # ─────────────────────────────────────────
        if any(w in text_lower for w in ["gấp", "ngay", "nhanh", "30 phút", "hạn chót", "khẩn cấp", "sẽ bị khóa"]):
            weight = 15
            factors.append({"factor": "Tạo áp lực thời gian / Hối thúc hành động ngay (Urgency Pressure)", "weight": weight})
            total_risk_score += weight

        # ─────────────────────────────────────────
        # BLOCK I: Emergency / Already Scammed
        # ─────────────────────────────────────────
        if any(w in text_lower for w in ["vừa bị lừa", "chuyển rồi", "chuyển nhầm", "mất tiền", "lừa đảo rồi", "bị hack"]):
            weight = 25
            factors.append({"factor": "Đã bị lừa đảo / Chuyển tiền rồi — Kích hoạt Emergency Protocol", "weight": weight})
            total_risk_score += weight

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
        if has_only_official_urls and not has_scam_actions:
            final_risk_score = 0
            factors = []
        else:
            final_risk_score = min(total_risk_score, 99)

        return {
            "risk_score": final_risk_score,
            "risk_breakdown": factors,
            "reasons": [f"{item['factor']}: +{item['weight']}%" for item in factors]
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
