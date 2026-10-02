class DecisionAgent:
    """
    Decision Support Agent:
    Synthesizes risk scores from sub-agents and produces human-centered recommendations.
    Differentiates between General Chat Greetings (e.g. "chào bạn", "hello", "đây là gì?")
    and Scam Analysis Evidence to avoid robotic copy-paste responses.
    """
    def __init__(self):
        pass

    def evaluate_decision(self, risk_score, confidence_info, explainable_info, emergency_info, user_text="", real_llm_result=None):
        txt_clean = (user_text or "").strip().lower()

        # Detect General Greetings / Informal Questions
        greetings = ["chào", "chào bạn", "hello", "hi", "xin chào", "đây là gì", "bạn là ai", "hướng dẫn", "giúp tôi", "help", "alo", "alo bạn", "alo bạn ơi"]
        is_general_chat = any(txt_clean == g or txt_clean.startswith(f"{g} ") or txt_clean.startswith(f"{g},") or txt_clean == f"{g} nhé" or txt_clean == f"{g} ạ" for g in greetings)

        # Informal friendly check-ins with no scam indicators
        if any(w in txt_clean for w in ["dạo này còn làm chỗ cũ không", "check giúp em với"]) and not any(w in txt_clean for w in ["chuyển tiền", "nạp", "stk", "link", ".apk"]):
            is_general_chat = True

        if is_general_chat:
            reply = real_llm_result.get("conversational_reply") if real_llm_result else None
            if not reply:
                if "đây là gì" in txt_clean or "bạn là ai" in txt_clean:
                    reply = "Tôi là SafeGuard AI — Trợ lý Vệ sĩ Số phòng chống lừa đảo trực tuyến tại Việt Nam. Bạn có thể gửi tin nhắn, đường link nghi vấn hoặc ảnh chụp bill VietQR/SMS để tôi hỗ trợ phân tích độ an toàn!"
                else:
                    reply = "Xin chào bạn! Tôi là SafeGuard AI, trợ lý vệ sĩ số của bạn. Hãy gửi cho tôi bất kỳ tin nhắn, đường link hoặc ảnh chụp nghi vấn lừa đảo nào để tôi giúp bạn kiểm tra nhé."

            return {
                "intent_type": "general_chat",
                "risk_level": "LOW",
                "headline": reply,
                "recommendations": [],
                "hitl_disclaimer": "SafeGuard AI — Trợ lý Vệ sĩ Số phòng chống lừa đảo trực tuyến."
            }

        # Scam Analysis Intent
        if emergency_info.get("is_emergency"):
            risk_level = "CRITICAL"
            headline = "🚨 PHÁT HIỆN TÌNH HUỐNG KHẨN CẤP: KÍCH HOẠT QUY TRÌNH ỨNG PHÓ KHẨN CẤP (EMERGENCY PROTOCOL)"
            recommends = [
                "1. Gọi ngay hotline Ngân hàng để yêu cầu Khóa thẻ/Khóa tài khoản khẩn cấp.",
                "2. Đổi mật khẩu dịch vụ Internet Banking & ứng dụng OTT.",
                "3. Trình báo cơ quan Công an gần nhất và gửi phản ánh tới NCSC (canhsat.gov.vn)."
            ]
        elif risk_score >= 75:
            risk_level = "HIGH"
            headline = "🔴 CẢNH BÁO RỦI RO CAO: Có nhiều dấu hiệu trùng khớp kịch bản lừa đảo đã ghi nhận."
            recommends = [
                "❌ Tuyệt đối KHÔNG nạp tiền, chuyển khoản hay đặt cọc quỹ dưới bất kỳ lý do gì.",
                "❌ Không bấm vào các đường link lạ hoặc tải file ứng dụng đuôi .apk.",
                "❌ Không cung cấp mã OTP, mật khẩu hay ảnh chụp CCCD/CMND.",
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
                "💡 Vẫn duy trì cảnh giác khi thực hiện các giao dịch trực tuyến với người lạ."
            ]

        if real_llm_result and real_llm_result.get("conversational_reply"):
            headline = real_llm_result["conversational_reply"]

        return {
            "intent_type": "scam_analysis",
            "risk_level": risk_level,
            "headline": headline,
            "recommendations": recommends,
            "hitl_disclaimer": "SafeGuard AI là Hệ thống Hỗ trợ Quyết định (Decision Support System). Quyết định giao dịch hoàn toàn thuộc về bạn."
        }

if __name__ == "__main__":
    agent = DecisionAgent()
    res = agent.evaluate_decision(85, {}, {}, {}, user_text="Tuyển CTV Shopee nạp 500k")
    print("[DecisionAgent] Result:", res)
