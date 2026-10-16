"""
Test suite for Task E4: RAG trigger_phrases precision.
Verifies that >= 30 benign messages match zero trigger patterns,
>= 10 scam messages match trigger patterns,
and 'Tháng này mình cần mượn tiền gấp của chị gái để đóng viện phí cho mẹ'
evaluates to LOW risk via orchestrator.process_request.
"""

import pytest
from codebase.agents.rag_agent import RAGAgent
from codebase.orchestrator import SafeGuardOrchestrator


BENIGN_MESSAGES = [
    "Vietcombank: TK 0123456789 GD: -500,000VND chuyen khoan thanh cong toi NGUYEN VAN A.",
    "BIDV thông báo: Quý khách đã xác nhận chuyển khoản số tiền 200.000 VND thành công.",
    "Techcombank: Giao dịch chuyển khoản thành công lúc 14:30 ngày 15/10/2026.",
    "MB Bank: Bạn vừa chuyển khoản thành công 150.000 VND tới tài khoản 987654321.",
    "ACB: Xác nhận chuyển khoản tiền thuê nhà tháng 10 cho chủ trọ.",
    "Anh ơi em là shipper giao hàng Shopee, em để kiện hàng ở bàn lễ tân nhé.",
    "Shipper giao hàng tiết kiệm đang tới ngõ nhà mình, bạn chuẩn bị nhận hàng nhé.",
    "Đơn hàng sách Tiki của bạn shipper giao hàng đã tới nơi rồi ạ.",
    "Hôm nay em thanh toán cod tiền mua quần áo cho bạn shipper rồi chị nhé.",
    "Mẹ ơi con đã thanh toán cod 120k cho anh giao hàng lúc sáng rồi.",
    "Bưu điện thông báo: Mời bạn ra bưu cục nhận bưu phẩm gửi từ quê lên.",
    "Anh ra nhận hàng bưu cục quận 1 giúp em với nhé, bưu tá vừa gọi.",
    "Công an phường thông báo bà con đến trụ sở để cài đặt vneid mức 2.",
    "Hướng dẫn cài đặt VNeID từ kho ứng dụng chính thức Google Play Store cho người dân.",
    "Người dân cần mang theo CCCD gắn chip để làm định danh điện tử mức 2 tại công an quận.",
    "Hôm nay phường tổ chức cấp tài khoản định danh điện tử mức 2 cho các cụ cao tuổi.",
    "Lập trình viên tải ứng dụng apk mẫu từ repository nội bộ công ty để thử nghiệm.",
    "Nhân dịp ngày lễ 8/3, shop xin gửi tặng bó hoa hồng ngày lễ rực rỡ đến các cô giáo.",
    "Vườn hoa Đà Lạt cung cấp hoa hồng ngày lễ tình nhân giá sỉ tốt nhất.",
    "Chúc mừng sinh nhật em gái, chúc em nhận được nhiều hoa hồng ngày hôm nay.",
    "Mạng chập chờn quá, nãy gọi video bị mờ không nhìn rõ mặt ông bà ở quê.",
    "Mạng yếu nên cuộc gọi video bị mờ và giật hình liên tục.",
    "Bố ơi tài khoản người quen của con hôm qua chuyển cho con tiền sách rồi nhé.",
    "Tài khoản người quen gửi quà mừng cưới cho hai vợ chồng.",
    "Tháng này mình cần mượn tiền gấp của chị gái để đóng viện phí cho mẹ.",
    "Em mượn tạm ít tiền của anh trai để đóng tiền điện thoại cuối tháng.",
    "Chiều nay cả nhóm hẹn nhau đi cà phê và làm bài tập lớn môn cơ sở dữ liệu.",
    "Công ty thông báo lịch nghỉ mát hè năm nay tại Đà Nẵng cho toàn thể nhân viên.",
    "Ngày mai thời tiết Hà Nội chuyển rét đậm, các bạn nhớ mặc áo ấm khi đi học.",
    "Biên lai thanh toán tiền điện tháng này của gia đình là 650.000 đồng.",
    "Bác sĩ gửi ảnh chụp biên lai viện phí cho người nhà bệnh nhân lưu giữ.",
    "Anh shipper để gói hàng ở chỗ bác bảo vệ chung cư giúp em nhé."
]

SCAM_MESSAGES = [
    "Tuyển cộng tác viên chốt đơn Shopee nạp quỹ đảm bảo nhận hoa hồng 20%/ngày.",
    "Làm nhiệm vụ nạp tiền nhận hoa hồng khủng, chuyển tiền làm nhiệm vụ ngay.",
    "Đóng phí để nhận thưởng trúng thưởng xe máy SH từ chương trình tri ân.",
    "Bộ Công an yêu cầu cài vneid qua link độc hại để cập nhật hồ sơ định danh.",
    "Cục Thuế thông báo tải phần mềm cục thuế qua link apk sau để hoàn thuế thu nhập.",
    "Hướng dẫn cài đặt dịch vụ công qua link để không bị khóa tài khoản ngân hàng.",
    "Bạn có khoản tiền chuyển nhầm, hãy quét mã qr để nhận hoàn tiền ngay.",
    "Bấm vào link sau để hoàn trả tiền chuyển nhầm qua link và xác thực số dư ngân hàng.",
    "Shipper thông báo: Đơn hàng gửi bảo vệ yêu cầu chuyển khoản nhận hộ tiền hàng ngay.",
    "Tài khoản người thân bị hack: nhờ chuyển tiền vào tài khoản lạ để cấp cứu gấp.",
    "Gọi video giật lag mượn tiền chuyển vào số tài khoản này gấp nhé bạn."
]


def test_benign_messages_zero_trigger_matches():
    """All >= 30 benign messages must match zero trigger patterns (Task E4)."""
    assert len(BENIGN_MESSAGES) >= 30, f"Must have >= 30 benign messages, got {len(BENIGN_MESSAGES)}"
    agent = RAGAgent()
    for idx, msg in enumerate(BENIGN_MESSAGES):
        res = agent.search(msg)
        assert res["total_patterns_matched"] == 0, (
            f"Benign message #{idx} falsely matched triggers: '{msg}' -> {res['matched_flags']}"
        )
        assert len(res["matched_flags"]) == 0
        assert len(res["matched_tactics"]) == 0


def test_scam_messages_match_triggers():
    """All >= 10 scam messages must match at least one trigger pattern (Task E4)."""
    assert len(SCAM_MESSAGES) >= 10, f"Must have >= 10 scam messages, got {len(SCAM_MESSAGES)}"
    agent = RAGAgent()
    for idx, msg in enumerate(SCAM_MESSAGES):
        res = agent.search(msg)
        assert res["total_patterns_matched"] > 0, (
            f"Scam message #{idx} failed to match any triggers: '{msg}'"
        )
        assert len(res["matched_flags"]) > 0


def test_borrow_money_sister_hospital_evaluates_to_low():
    """Specific case: 'Tháng này mình cần mượn tiền gấp của chị gái để đóng viện phí cho mẹ' must evaluate to LOW."""
    text = "Tháng này mình cần mượn tiền gấp của chị gái để đóng viện phí cho mẹ."
    orch = SafeGuardOrchestrator()
    res = orch.process_request(user_text=text, session_id="test_benign_borrow_money")
    risk_level = res.get("decision", {}).get("risk_level")
    risk_score = res.get("risk_score", 0)
    assert risk_level == "LOW", f"Expected LOW risk for benign borrow money, got {risk_level} (score: {risk_score})"
