class EmergencyAgent:
    """
    Emergency Agent:
    Triggers Immediate Emergency Protocol (1' - 3' - 5' - 10' - 30') when user reports
    having already transferred money or shared OTP / malware credentials.
    """
    def __init__(self):
        pass

    def check_trigger(self, text):
        text_lower = text.lower()
        trigger_keywords = [
            "đã chuyển tiền", "vừa chuyển", "mất tiền", "bị lừa",
            "chuyển khoản rồi", "chuyển 5 triệu", "trót nạp"
        ]

        is_emergency = any(kw in text_lower for kw in trigger_keywords)

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
                        "action": "Đổi mật khẩu tài khoản ngân hàng, iCloud, Google, Zalo và kiểm tra thiết bị xem có bị cài ứng dụng lạ (.apk) hay không.",
                        "priority": "MEDIUM"
                    }
                ]
            }

        return {"is_emergency": False}

if __name__ == "__main__":
    em = EmergencyAgent()
    res = em.check_trigger("Em vừa bị lừa chuyển 5 triệu rồi anh ơi")
    print("[EmergencyAgent] Result:", res)
