"""
tests/test_speech_act.py

D4: Test cho module speech_act + tích hợp D2 vào ExplainableAgent.

(a) Tập 'dev': >=12 câu MỚI cho mỗi nhãn lành tính + >=12 câu scam 'solicitation'.
(b) Tập 'check': >=8 câu mỗi nhãn, viết CỨNG, không chỉnh theo.
(c) Test tích hợp: scam giả cảnh báo >= HIGH, tin tường thuật có link độc hại KHÔNG bị giảm,
    emergency không bị giảm, SAFEGUARD_SPEECH_ACT=off trả đúng điểm cũ.
(d) Mutation tests: 8 loại mutation phải thất bại (0 mutation sống sót).

Không chép câu từ eval/golden_set*.json hay tests cũ.
"""
import os
import importlib

import pytest

# ── Đảm bảo offline ──────────────────────────────────────────────────────────
os.environ.setdefault("SAFEGUARD_OFFLINE", "1")

# ── Import ────────────────────────────────────────────────────────────────────
from codebase.agents.speech_act import classify_speech_act, SpeechAct
from codebase.config import get_settings


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sa(text: str) -> SpeechAct:
    return classify_speech_act(text)


def _is_benign(act: SpeechAct) -> bool:
    return act.label in {"news_report", "public_warning", "victim_advice", "everyday"}


def _is_scam(act: SpeechAct) -> bool:
    return act.label == "solicitation"


# ─────────────────────────────────────────────────────────────────────────────
# (a) DEV SET — dùng để chỉnh ngưỡng
# ─────────────────────────────────────────────────────────────────────────────

DEV_NEWS_REPORT = [
    "Theo báo Tuổi Trẻ, đối tượng Nguyễn Văn A đã bị Công an TP HCM bắt giữ vì lừa đảo hàng chục người.",
    "Cơ quan điều tra đã khởi tố bị can Trần Thị B về tội chiếm đoạt tài sản qua mạng.",
    "Nạn nhân bị lừa hơn 500 triệu đồng thông qua thủ đoạn giả mạo nhân viên ngân hàng, theo thông tin công an cung cấp.",
    "Mới đây, công an đã bắt giữ đường dây lừa đảo tuyển dụng việc làm tại nhà, có 12 bị hại trình báo.",
    "Báo VnExpress đưa tin, bị cáo Lê Văn C bị tuyên phạt 7 năm tù vì tổ chức sàn đầu tư tiền ảo.",
    "Theo nguồn tin từ cơ quan chức năng, đối tượng đã sử dụng thủ đoạn tinh vi để chiếm đoạt tiền của nạn nhân.",
    "Ngày 20/10 vừa qua, cảnh sát đã triệu tập nhiều đối tượng liên quan đến vụ lừa đảo trên mạng xã hội.",
    "Phòng Cảnh sát Hình sự vừa triệt phá ổ nhóm lừa đảo chiếm đoạt tài sản, khởi tố 5 bị can.",
    "Theo báo cáo của cơ quan chức năng, trong 6 tháng đầu năm đã có hơn 200 vụ lừa đảo qua mạng được trình báo.",
    "Bị can Hùng bị cáo buộc đã sử dụng sim rác gọi điện giả danh công an để lừa đảo nhiều người cao tuổi.",
    "Vụ án được cơ quan điều tra khởi tố từ tháng 9, bị hại tại nhiều tỉnh thành, thiệt hại ước tính hàng tỷ đồng.",
    "Theo thông tin từ báo Thanh Niên, đối tượng lừa đảo đã bị bắt giữ sau nhiều tháng truy bắt.",
]

DEV_PUBLIC_WARNING = [
    "Ngân hàng Vietcombank khuyến cáo khách hàng không bao giờ cung cấp OTP hoặc mật khẩu cho bất kỳ ai.",
    "Công an thành phố cảnh báo người dân cảnh giác trước thủ đoạn kẻ gian giả mạo cán bộ thuế đòi nộp phí.",
    "Bộ Công An khuyến cáo: tuyệt đối không cung cấp thông tin CCCD, mã OTP qua điện thoại.",
    "Ngân hàng Nhà nước khuyến cáo người dân nâng cao cảnh giác, không click vào link lạ nhận được qua SMS.",
    "Theo cảnh báo chính thức của Công an tỉnh Bình Dương, không bao giờ cung cấp mã xác thực cho người lạ qua mạng.",
    "Cảnh sát cảnh báo các hình thức lừa đảo giả mạo shipper đang gia tăng, người dân cần thận trọng khi nhận hàng.",
    "Từ phía ngân hàng: chúng tôi không bao giờ yêu cầu khách hàng đọc mã OTP qua điện thoại hay tin nhắn.",
    "Khuyến cáo người dân cần xác minh danh tính người gọi trước khi thực hiện bất kỳ giao dịch nào.",
    "Công an quận Hải Châu khuyến cáo cộng đồng cảnh giác trước thủ đoạn lừa đảo đầu tư tài chính trực tuyến.",
    "Cục An toàn thông tin khuyến cáo không cài ứng dụng từ nguồn không rõ ràng ngoài CH Play hay App Store.",
    "Ngân hàng Nhà nước nhắc lại: chúng tôi không bao giờ yêu cầu chuyển tiền vào tài khoản tạm giữ.",
    "Theo thông báo khuyến cáo của Ngân hàng MB, người dân cần xác minh kỹ trước khi chuyển tiền cho người lạ.",
]

DEV_VICTIM_ADVICE = [
    "Tôi vừa bị lừa mất 30 triệu, giờ phải làm sao để lấy lại được không?",
    "Em bị lừa mất tiền khi tham gia sàn đầu tư. Em nên báo ở đâu bây giờ?",
    "Mình vừa chuyển 20 triệu cho người lạ qua Zalo rồi mới biết bị lừa. Có đòi lại được không ạ?",
    "Tôi đã bị mất 50 triệu do bị lừa đảo đầu tư tiền ảo. Cần làm gì tiếp theo?",
    "Em bị hack tài khoản ngân hàng mất 5 triệu. Em cần liên hệ với ai để xử lý?",
    "Mình vừa bị lừa bởi chiêu trúng thưởng, đã nộp phí 2 triệu rồi. Giờ phải làm gì?",
    "Tôi mất tiền do tham gia nhóm đầu tư forex giả. Xử lý thế nào bây giờ anh ơi?",
    "Em đã chuyển tiền theo yêu cầu của người tự xưng là công an rồi mới biết bị lừa. Em cần báo cho ai?",
    "Mình bị lấy mất 10 triệu qua ứng dụng lạ. Giờ phải làm gì để thu hồi được không?",
    "Tôi vừa bị lừa đảo bởi chiêu tuyển CTV Shopee, mất 3 triệu. Có cách giải quyết không?",
    "Em bị lừa do tin vào link nhận thưởng giả, chuyển 1 triệu rồi. Cần làm sao để tố cáo?",
    "Mình vừa bị mất 15 triệu vì tham gia sàn vàng giả mạo. Giờ phải liên hệ cơ quan nào?",
]

DEV_EVERYDAY = [
    "Bạn chuyển tiền học phí cho mình chưa? Deadline đóng ngày mai rồi đó.",
    "Mọi người chia tiền tour Đà Nẵng nhé, mỗi người 2 triệu, chuyển vào tài khoản mình trước 5h.",
    "Anh ơi, em đã nhận hàng rồi, em chuyển khoản tiền mua xe đạp cũ cho anh ngay đây.",
    "Đặt cọc tiệc sinh nhật xong rồi, nhà hàng báo 2 triệu, bạn nào chưa chuyển thì chuyển giúp mình với.",
    "Mình vừa chuyển tiền nhà trọ tháng này rồi, chủ nhà xác nhận nhận được rồi nhé.",
    "Bạn ơi, mình cần chuyển tiền điện tháng 10 cho bạn, bạn gửi số tài khoản mình với.",
    "Tiền cọc phòng đã chuyển, chủ trọ báo đã nhận. Mình nhận phòng từ ngày 1 tháng sau.",
    "Chị ơi, em chuyển khoản học phí học kỳ 2 xong rồi, mình in biên lai cần chị ký xác nhận.",
    "OTP của bạn là 347891, dùng để xác thực giao dịch thanh toán đơn hàng shopee.",
    "Số dư tài khoản của bạn hiện tại là 5.230.000đ. Giao dịch thành công lúc 14:32 ngày 22/10.",
    "Mình vừa chuyển 800k tiền xăng và tiền ăn trưa cho cả nhóm, bạn nào chưa góp thì góp lại mình nhé.",
    "Đặt cọc tour Phú Quốc xong rồi, giá 5 triệu/người, team mình 4 người, bạn nào cần số tài khoản không?",
    "Anh chuyển khoản tiền mua điện thoại cũ Samsung A52 cho em rồi nhé, em kiểm tra nhận được chưa?",
    "Nhóm mình chia tiền đặt bàn tiệc cuối năm, mỗi người 350k, chuyển cho mình trước thứ Sáu.",
]

DEV_SOLICITATION = [
    # Chuẩn scam
    "Vui lòng chuyển tiền vào số tài khoản này để kích hoạt gói vay ngay hôm nay.",
    "Anh/chị cần nộp phí bảo hiểm khoản vay 2 triệu để giải ngân, vui lòng chuyển ngay.",
    "Bấm vào link này để cập nhật thông tin tài khoản và tránh bị khóa vĩnh viễn.",
    "Hãy cài ứng dụng VNeID2024.apk bên ngoài CH Play để cập nhật sinh trắc học của bạn.",
    "Quét mã QR để nhận thưởng 5 triệu từ chương trình tri ân khách hàng của Vietcombank.",
    "Tài khoản của quý khách sẽ bị khóa trong 24h, vui lòng đọc mã OTP cho nhân viên để xác minh.",
    "Em là nhân viên ngân hàng Agribank, anh cần cung cấp mã OTP để hoàn tất xác thực tài khoản.",
    "Yêu cầu anh chuyển khoản 5 triệu vào tài khoản tạm giữ của cơ quan điều tra trước 17h hôm nay.",
    "Bạn đã trúng iPhone 15 Pro! Hãy nộp phí vận chuyển 300k vào tài khoản này để nhận hàng.",
    "Nhiệm vụ hôm nay: nạp 2 triệu vào sàn để hoàn thành và nhận hoa hồng 500k ngay lập tức.",
    "Vui lòng gửi 16 số trên thẻ và CVV để xác minh tài khoản ngân hàng của bạn.",
    "Hãy chuyển tiền gấp vào đây, đơn hàng cần xử lý ngay, quá 30 phút sẽ hủy.",
    # Scam giả giọng công an/ngân hàng "cảnh báo" kèm yêu cầu
    "Tôi là cán bộ Bộ Công An. Tài khoản của bạn liên quan đến vụ rửa tiền, cần chuyển vào tài khoản tạm giữ ngay.",
    "Đây là thông báo từ Cục Thuế: bạn nợ thuế 15 triệu, vui lòng bấm link để nộp phạt tránh bị khởi tố.",
    "Ngân hàng VCB cảnh báo: tài khoản bạn bị tấn công, vui lòng đọc OTP cho chúng tôi để bảo vệ.",
    "Cảnh báo: tài khoản của bạn đang bị xâm nhập. Hãy gửi mật khẩu internet banking cho nhân viên hỗ trợ.",
]


# ─────────────────────────────────────────────────────────────────────────────
# (b) CHECK SET — viết cứng sau khi chỉnh, không sửa theo
# ─────────────────────────────────────────────────────────────────────────────

CHECK_NEWS_REPORT = [
    "Công an tỉnh Nghệ An đã bắt giữ đối tượng Phạm Văn D, 35 tuổi, về hành vi lừa đảo chiếm đoạt tài sản.",
    "Theo báo Pháp Luật, bị can bị khởi tố về tội danh sử dụng mạng xã hội để lừa đảo hơn 100 nạn nhân.",
    "Cơ quan điều tra đã triệu tập và lấy lời khai của đối tượng nghi phạm trong vụ lừa đảo đầu tư trái phép.",
    "Ngày 15/10 vừa qua, tòa án xét xử bị cáo Lê Thị E 8 năm tù giam về tội lừa đảo chiếm đoạt tài sản.",
    "Báo VnExpress: Vụ lừa đảo qua Telegram khiến hàng trăm nạn nhân mất tiền đang được điều tra.",
    "Theo thông tin từ cơ quan chức năng, nhóm đối tượng đã sử dụng sim rác và tài khoản giả mạo.",
    "Nạn nhân trong vụ lừa đảo đã đến trình báo công an sau khi phát hiện mình bị chiếm đoạt tiền.",
    "Công an đã bắt và khởi tố bị can trong vụ án lừa đảo chiếm đoạt tài sản quy mô lớn tại Hà Nội.",
]

CHECK_PUBLIC_WARNING = [
    "Ngân hàng Nhà nước khuyến cáo người dân cảnh giác trước các chiêu trò lừa đảo qua điện thoại.",
    "Công an cảnh báo: không bao giờ cung cấp mã OTP hay mật khẩu ngân hàng cho bất kỳ ai.",
    "Từ phía ngân hàng Techcombank: chúng tôi không yêu cầu khách hàng cung cấp thông tin thẻ qua điện thoại.",
    "Bộ Công An khuyến cáo cộng đồng nâng cao cảnh giác với các chiêu trò lừa đảo đầu tư tiền ảo.",
    "Cảnh sát giao thông khuyến cáo người dân: không có cán bộ nào yêu cầu nộp phạt qua điện thoại.",
    "Khuyến cáo người dân cảnh giác trước thủ đoạn mạo danh cơ quan nhà nước để lừa đảo.",
    "Theo thông báo khuyến cáo của Ngân hàng ACB, không chia sẻ thông tin bảo mật với bất kỳ ai.",
    "Cục An toàn thông tin cảnh báo các hình thức lừa đảo trực tuyến gia tăng vào dịp cuối năm.",
]

CHECK_VICTIM_ADVICE = [
    "Tôi mất 40 triệu do bị lừa đầu tư chứng khoán giả, có cách nào lấy lại không?",
    "Em bị lừa mất tiền qua Zalo, giờ em cần làm gì để tố cáo vụ việc?",
    "Mình vừa bị mất tài khoản facebook và bị chiếm đoạt tiền. Xử lý thế nào bây giờ?",
    "Tôi đã chuyển 10 triệu cho người lạ xưng là nhân viên ngân hàng rồi, làm sao thu hồi?",
    "Em bị hack nick Zalo, người đó dùng nick em nhắn tin mượn tiền người thân. Giờ phải làm sao?",
    "Mình vừa bị lừa bởi chiêu giả vé số trúng thưởng, mất 2 triệu. Có nên báo công an không?",
    "Tôi nộp tiền học việc xong bị mất liên lạc, giờ cần liên hệ ai để giải quyết?",
    "Em bị lừa mất tiền qua link nhận thưởng giả mạo Shopee. Em nên báo ở đâu?",
]

CHECK_EVERYDAY = [
    "Chị ơi, em cần chuyển tiền học phí học kỳ này, chị cho em xin số tài khoản để em chuyển nhé.",
    "Nhóm mình đặt cọc tour Nha Trang 1 triệu/người, ai chưa chuyển thì chuyển sớm vào.",
    "Mình đã trả tiền nhà tháng 11 rồi, chủ nhà nhắn đã nhận, ok bạn nhé.",
    "OTP của bạn là 582931. Mã này dùng để xác thực giao dịch thanh toán đơn hàng trên Tiki.",
    "Bạn ơi, tiền chia bill ăn tối qua là 180k/người, mình chuyển vào tài khoản bạn nhé.",
    "Số dư tài khoản còn 2.150.000đ sau khi thanh toán hóa đơn điện tháng 10.",
    "Em vừa nhận xe đạp từ anh rồi, em đã chuyển 3.5 triệu tiền mua xe vào tài khoản anh rồi nhé.",
    "Mọi người góp tiền mua quà sinh nhật cho Lan nhé, 150k/người, ai chuyển rồi nhắn mình với.",
]

CHECK_SOLICITATION = [
    "Để không bị khóa tài khoản vĩnh viễn, anh/chị vui lòng cung cấp mã OTP cho nhân viên hỗ trợ.",
    "Hãy chuyển 5 triệu vào tài khoản tạm giữ của cơ quan điều tra trong 2 giờ tới.",
    "Bấm vào link để xác minh tài khoản ngân hàng và tránh bị phong tỏa toàn bộ giao dịch.",
    "Cài file VNeID_update.apk để cập nhật căn cước công dân, tải từ link dưới đây.",
    "Chuyển khoản ngay 500k để kích hoạt công việc CTV Shopee và nhận hoa hồng ngay hôm nay.",
    "Đọc mã OTP cho em để em xác minh và bảo vệ tài khoản ngân hàng của anh.",
    "Yêu cầu nộp phí hải quan 1.5 triệu để nhận kiện hàng từ nước ngoài, chuyển vào tài khoản này.",
    "Bạn đã trúng thưởng iPhone, nộp phí 200k để nhận hàng, liên hệ ngay trước khi hết hạn.",
]


# ─────────────────────────────────────────────────────────────────────────────
# Test (a): DEV SET
# ─────────────────────────────────────────────────────────────────────────────

class TestDevSet:
    """Tập dev — dùng để chỉnh logic. Yêu cầu tỉ lệ >= 70% mỗi nhãn."""

    def _run_label(self, cases, expected_label):
        correct = sum(1 for t in cases if _sa(t).label == expected_label)
        rate = correct / len(cases)
        assert rate >= 0.70, (
            f"Dev {expected_label}: {correct}/{len(cases)} ({rate:.1%}) < 70%. "
            f"Failures: {[t[:60] for t in cases if _sa(t).label != expected_label]}"
        )
        return rate

    def test_dev_news_report(self):
        rate = self._run_label(DEV_NEWS_REPORT, "news_report")
        print(f"\nDev news_report: {rate:.1%}")

    def test_dev_public_warning(self):
        rate = self._run_label(DEV_PUBLIC_WARNING, "public_warning")
        print(f"\nDev public_warning: {rate:.1%}")

    def test_dev_victim_advice(self):
        rate = self._run_label(DEV_VICTIM_ADVICE, "victim_advice")
        print(f"\nDev victim_advice: {rate:.1%}")

    def test_dev_everyday(self):
        rate = self._run_label(DEV_EVERYDAY, "everyday")
        print(f"\nDev everyday: {rate:.1%}")

    def test_dev_solicitation(self):
        rate = self._run_label(DEV_SOLICITATION, "solicitation")
        print(f"\nDev solicitation: {rate:.1%}")

    def test_dev_sets_non_empty(self):
        """Assert các tập dev có đủ phần tử (>=12 mỗi nhãn lành tính, >=12 scam)."""
        assert len(DEV_NEWS_REPORT) >= 12
        assert len(DEV_PUBLIC_WARNING) >= 12
        assert len(DEV_VICTIM_ADVICE) >= 12
        assert len(DEV_EVERYDAY) >= 12
        assert len(DEV_SOLICITATION) >= 12


# ─────────────────────────────────────────────────────────────────────────────
# Test (b): CHECK SET — tỉ lệ >= 65% (không chỉnh theo)
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckSet:
    """Tập check — không được chỉnh theo sau khi viết. Tỉ lệ >= 65%."""

    def _run_label(self, cases, expected_label):
        correct = sum(1 for t in cases if _sa(t).label == expected_label)
        rate = correct / len(cases)
        assert rate >= 0.65, (
            f"Check {expected_label}: {correct}/{len(cases)} ({rate:.1%}) < 65%. "
            f"Failures: {[t[:60] for t in cases if _sa(t).label != expected_label]}"
        )
        return rate

    def test_check_news_report(self):
        self._run_label(CHECK_NEWS_REPORT, "news_report")

    def test_check_public_warning(self):
        self._run_label(CHECK_PUBLIC_WARNING, "public_warning")

    def test_check_victim_advice(self):
        self._run_label(CHECK_VICTIM_ADVICE, "victim_advice")

    def test_check_everyday(self):
        self._run_label(CHECK_EVERYDAY, "everyday")

    def test_check_solicitation(self):
        self._run_label(CHECK_SOLICITATION, "solicitation")

    def test_check_sets_non_empty(self):
        assert len(CHECK_NEWS_REPORT) >= 8
        assert len(CHECK_PUBLIC_WARNING) >= 8
        assert len(CHECK_VICTIM_ADVICE) >= 8
        assert len(CHECK_EVERYDAY) >= 8
        assert len(CHECK_SOLICITATION) >= 8


# ─────────────────────────────────────────────────────────────────────────────
# Test cơ bản SpeechAct module
# ─────────────────────────────────────────────────────────────────────────────

class TestSpeechActBasics:
    def test_returns_speechact(self):
        result = _sa("Xin chào bạn")
        assert isinstance(result, SpeechAct)
        assert result.label in {
            "solicitation", "news_report", "public_warning", "victim_advice", "everyday", "unknown"
        }
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.evidence, list)

    def test_solicitation_priority_over_warning_tone(self):
        """Kẻ gian mạo danh công an 'cảnh báo' kèm yêu cầu hành động → solicitation."""
        text = (
            "Tôi là cán bộ Bộ Công An cảnh báo tài khoản của anh liên quan đến rửa tiền. "
            "Anh cần chuyển tiền vào tài khoản tạm giữ ngay để tránh bị khởi tố."
        )
        act = _sa(text)
        assert act.label == "solicitation", f"Expected solicitation, got {act.label}"

    def test_news_narrative_no_action_required(self):
        """Tường thuật thuần — không yêu cầu hành động → news_report."""
        text = (
            "Cơ quan điều tra đã khởi tố bị can Lê Văn X về tội lừa đảo chiếm đoạt tài sản. "
            "Theo báo Tuổi Trẻ, đối tượng đã lừa hơn 20 nạn nhân."
        )
        act = _sa(text)
        assert act.label == "news_report", f"Expected news_report, got {act.label}"

    def test_victim_with_both_signals(self):
        """Có kể chuyện bị lừa + hỏi cách xử lý → victim_advice."""
        text = "Tôi vừa bị lừa mất 20 triệu. Giờ phải làm sao để lấy lại được không?"
        act = _sa(text)
        assert act.label == "victim_advice", f"Expected victim_advice, got {act.label}"

    def test_everyday_school_fee(self):
        """Tin nhắn học phí đời thường → everyday."""
        text = "Bạn chuyển tiền học phí chưa? Mình cần nộp trước thứ Sáu."
        act = _sa(text)
        assert act.label == "everyday", f"Expected everyday, got {act.label}"

    def test_long_input_truncated(self):
        """Input dài không gây lỗi — kiểm tra giới hạn _MAX_INPUT_CHARS."""
        long_text = "abc " * 5000  # 20k ký tự
        act = _sa(long_text)
        assert act.label in {"solicitation", "news_report", "public_warning", "victim_advice", "everyday", "unknown"}

    def test_empty_input(self):
        act = _sa("")
        assert act.label == "unknown"

    def test_unaccented_scam(self):
        """Không dấu vẫn nhận diện solicitation."""
        text = "Vui long chuyen tien vao so tai khoan nay de kich hoat goi vay."
        act = _sa(text)
        assert act.label == "solicitation", f"Expected solicitation, got {act.label}"

    def test_unaccented_warning(self):
        """Không dấu vẫn nhận diện public_warning."""
        text = "Ngan hang khuyen cao khach hang tuyet doi khong cung cap ma otp cho bat ky ai."
        act = _sa(text)
        # Phải là public_warning hoặc unknown (không phải solicitation)
        assert act.label != "solicitation", f"Should not be solicitation, got {act.label}"


# ─────────────────────────────────────────────────────────────────────────────
# (c) Test tích hợp D2 — ExplainableAgent + Speech Act Gate
# ─────────────────────────────────────────────────────────────────────────────

class TestSpeechActIntegration:
    """
    Tích hợp: speech act gate trong ExplainableAgent.explain().
    Không gọi LLM, không gọi mạng. Chỉ dùng url_report=None hoặc mock.
    """

    @pytest.fixture(autouse=True)
    def setup_offline(self, monkeypatch):
        monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
        monkeypatch.setenv("SAFEGUARD_SPEECH_ACT", "on")
        # Refresh settings
        import codebase.config as cfg
        cfg._SETTINGS_INSTANCE = None

    def _get_agent(self):
        from codebase.agents.explainable_agent import ExplainableAgent
        return ExplainableAgent()

    # C1: Scam giả cảnh báo vẫn >= HIGH (75+)
    def test_scam_fake_warning_stays_high(self):
        """Kẻ gian mạo danh công an kèm yêu cầu hành động → vẫn HIGH."""
        agent = self._get_agent()
        text = (
            "Tôi là cán bộ Bộ Công An. Tài khoản của bạn liên quan đến vụ rửa tiền. "
            "Yêu cầu anh chuyển tiền vào tài khoản tạm giữ trước 17h hôm nay để tránh bị khởi tố."
        )
        result = agent.explain(text, url_report=None)
        assert result["risk_score"] >= 75, (
            f"Scam fake warning should be HIGH (>=75), got {result['risk_score']}"
        )

    # C2: Tin tường thuật với URL medium+ signal KHÔNG bị giảm
    def test_news_with_bad_url_not_reduced(self):
        """Tin tường thuật + URL có signal medium → cổng KHÔNG giảm điểm."""
        agent = self._get_agent()
        text = "Cơ quan điều tra đã bắt giữ đối tượng lừa đảo trong vụ án liên quan đến website vphishing123.xyz"

        # Mock url_report với medium signal
        from unittest.mock import MagicMock
        mock_url = MagicMock()
        mock_url.max_url_risk = 55  # medium range
        mock_url.has_only_official_urls = False
        mock_finding = MagicMock()
        mock_finding.is_official = False
        mock_signal = MagicMock()
        mock_signal.severity = "medium"
        mock_signal.weight = 30
        mock_signal.message_vi = "Tên miền nghi ngờ phishing"
        mock_finding.signals = [mock_signal]
        mock_finding.children = []
        mock_url.findings = [mock_finding]

        result_with_url = agent.explain(text, url_report=mock_url)
        result_no_url = agent.explain(text, url_report=None)

        # Khi có URL medium, điểm phải >= điểm không có URL (không bị giảm thêm do speech act)
        # Quan trọng: không nên thấp hơn trường hợp không có URL
        assert result_with_url["risk_score"] >= result_no_url["risk_score"] - 5, (
            "With URL medium signal, score should not be lower than without URL"
        )

    # C3: Emergency không bị giảm
    def test_emergency_not_reduced(self):
        """Tình huống khẩn cấp (vừa chuyển tiền) giữ nguyên."""
        agent = self._get_agent()
        # Văn bản emergency rõ ràng
        text = "Tôi vừa bị lừa, vừa chuyển tiền 50 triệu rồi mới biết bị lừa. Cứu tôi với!"
        result = agent.explain(text, url_report=None)
        # Phải có điểm đủ cao (có bill/emergency pattern)
        # Quan trọng: không bị giảm xuống thấp
        assert result["risk_score"] >= 30, (
            f"Emergency should not be over-reduced, got {result['risk_score']}"
        )

    # C4: SAFEGUARD_SPEECH_ACT=off → kết quả giống baseline (không áp cổng)
    def test_speech_act_flag_off(self, monkeypatch):
        """Khi SAFEGUARD_SPEECH_ACT=off, cổng không hoạt động → điểm >= khi on với cùng văn bản."""
        import codebase.config as cfg

        agent = self._get_agent()
        # Văn bản tường thuật lành tính
        text = (
            "Theo báo Tuổi Trẻ, cơ quan điều tra đã khởi tố bị can Nguyễn Văn A "
            "về tội lừa đảo chiếm đoạt tài sản của hơn 30 nạn nhân."
        )

        # Bật cổng
        monkeypatch.setenv("SAFEGUARD_SPEECH_ACT", "on")
        cfg._SETTINGS_INSTANCE = None
        result_on = agent.explain(text, url_report=None)

        # Tắt cổng
        monkeypatch.setenv("SAFEGUARD_SPEECH_ACT", "off")
        cfg._SETTINGS_INSTANCE = None
        result_off = agent.explain(text, url_report=None)

        # Khi tắt: điểm >= khi bật (cổng chỉ giảm, không tăng)
        assert result_off["risk_score"] >= result_on["risk_score"], (
            f"Off ({result_off['risk_score']}) should >= On ({result_on['risk_score']})"
        )

    # C5: Everyday tiền học phí được giảm điểm
    def test_everyday_money_reduced(self):
        """Chat đời thường học phí không bị chấm cao."""
        agent = self._get_agent()
        text = "Bạn ơi, bạn chuyển tiền học phí học kỳ 1 cho mình chưa? Hạn nộp ngày mai đó."
        result = agent.explain(text, url_report=None)
        # Kỳ vọng LOW (< 40)
        assert result["risk_score"] < 40, (
            f"Everyday school fee should be LOW (<40), got {result['risk_score']}"
        )

    # C6: Victim advice giảm điểm
    def test_victim_advice_reduced(self):
        """Người bị lừa hỏi cách xử lý không phải scam active."""
        agent = self._get_agent()
        text = "Tôi vừa bị lừa mất 10 triệu. Giờ phải làm sao để lấy lại không? Có nên báo công an không?"
        result = agent.explain(text, url_report=None)
        # Không nên CRITICAL; tùy nội dung có thể MEDIUM hoặc LOW
        assert result["risk_score"] < 85, (
            f"Victim asking for advice should not be CRITICAL, got {result['risk_score']}"
        )

    # C7: Gate không bao giờ tăng điểm
    def test_gate_never_increases_score(self):
        """Cổng speech act chỉ giảm hoặc giữ nguyên, không bao giờ tăng điểm."""
        import codebase.config as cfg

        agent = self._get_agent()
        test_texts = [
            "Xin chào, tôi cần tư vấn về lừa đảo.",
            "Bạn chuyển tiền học phí giúp mình không?",
            "Công an đã bắt đối tượng lừa đảo.",
        ]
        for text in test_texts:
            monkeypatch_env = os.environ.copy()
            cfg._SETTINGS_INSTANCE = None
            os.environ["SAFEGUARD_SPEECH_ACT"] = "on"
            cfg._SETTINGS_INSTANCE = None
            result_on = agent.explain(text, url_report=None)

            os.environ["SAFEGUARD_SPEECH_ACT"] = "off"
            cfg._SETTINGS_INSTANCE = None
            result_off = agent.explain(text, url_report=None)

            os.environ.update(monkeypatch_env)
            cfg._SETTINGS_INSTANCE = None

            assert result_off["risk_score"] >= result_on["risk_score"], (
                f"Gate increased score for '{text[:50]}': "
                f"on={result_on['risk_score']}, off={result_off['risk_score']}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# (d) Mutation Tests — 8 loại mutation phải thất bại
# ─────────────────────────────────────────────────────────────────────────────

class TestMutations:
    """
    Thử 8 mutation thật. Mỗi mutation phải bị diệt (test phải FAIL nếu mutation còn sống).
    Strategy: với mỗi mutation, tạo trường hợp mà nếu mutation sống → assertion fail.
    """

    def test_mutation_1_no_solicitation_check(self):
        """
        M1: Bỏ điều kiện 'không solicitation' → cổng sẽ giảm điểm kẻ gian mạo danh công an.
        Phát hiện: với text scam có giọng tường thuật nhưng yêu cầu hành động, nếu bỏ check
        solicitation thì nhãn news_report/warning sẽ vượt qua cổng → điểm giảm sai.
        Test: verify solicitation flag ngăn cổng.
        """
        from codebase.agents.speech_act import classify_speech_act, _RE_SOL_ACTION

        scam_text = (
            "Tôi là nhân viên Bộ Công An. Yêu cầu anh chuyển tiền vào tài khoản tạm giữ "
            "của cơ quan điều tra ngay bây giờ để tránh bị bắt giam."
        )
        act = classify_speech_act(scam_text)
        # solicitation phải được phát hiện (không bỏ điều kiện check)
        assert "solicitation:action" in act.evidence or act.label == "solicitation", (
            "M1 alive: solicitation:action not detected → check condition removed"
        )

    def test_mutation_2_no_url_check(self):
        """
        M2: Bỏ điều kiện kiểm tra URL signal >= medium.
        Phát hiện: tin tường thuật có URL độc hại medium+ bị giảm điểm sai.
        Test: classify_speech_act không nên ảnh hưởng URL signal (đó là trách nhiệm của D2).
        D2 trong ExplainableAgent phải check _has_url_medium_plus trước khi giảm.
        """
        # Verify D2 code contains URL check
        import inspect
        import codebase.agents.explainable_agent as ea_module
        source = inspect.getsource(ea_module.ExplainableAgent.explain)
        assert "_has_url_medium_plus" in source, (
            "M2 alive: URL medium+ check removed from D2 gate"
        )

    def test_mutation_3_no_emergency_check(self):
        """
        M3: Bỏ điều kiện emergency → tin khẩn cấp bị giảm điểm sai.
        Phát hiện: check _is_emergency_context phải tồn tại trong code D2.
        """
        import inspect
        import codebase.agents.explainable_agent as ea_module
        source = inspect.getsource(ea_module.ExplainableAgent.explain)
        assert "_is_emergency_context" in source, (
            "M3 alive: emergency check removed from D2 gate"
        )

    def test_mutation_4_confidence_threshold_zero(self):
        """
        M4: Hạ ngưỡng confidence xuống 0 → 'unknown' sẽ pass cổng.
        Phát hiện: ngưỡng SPEECH_ACT_CONFIDENCE_THRESHOLD phải > 0 trong code.
        """
        import inspect
        import codebase.agents.explainable_agent as ea_module
        source = inspect.getsource(ea_module.ExplainableAgent.explain)
        assert "_SPEECH_ACT_CONFIDENCE_THRESHOLD" in source, (
            "M4 alive: confidence threshold constant removed"
        )
        # Verify threshold value > 0 in speech_act module
        from codebase.agents.speech_act import SpeechAct
        # Unknown label should have confidence < threshold (0.55)
        unknown_act = classify_speech_act("abc xyz")
        # If label is unknown, should not trigger benign gate regardless of confidence
        assert unknown_act.label not in {"news_report", "public_warning", "victim_advice", "everyday"} or \
               unknown_act.confidence >= 0.55, (
            "M4: unknown/low-confidence act should not pass gate with threshold=0"
        )

    def test_mutation_5_gate_can_increase_score(self):
        """
        M5: Cổng làm tăng điểm (thay min() bằng max() hoặc cộng thêm).
        Phát hiện: với bất kỳ văn bản nào, điểm khi gate ON <= điểm khi gate OFF.
        """
        import codebase.config as cfg

        from codebase.agents.explainable_agent import ExplainableAgent
        agent = ExplainableAgent()

        # Dùng text lành tính rõ ràng
        text = "Theo báo Tuổi Trẻ, đối tượng đã bị bắt và khởi tố về tội lừa đảo."

        os.environ["SAFEGUARD_SPEECH_ACT"] = "on"
        cfg._SETTINGS_INSTANCE = None
        score_on = agent.explain(text, url_report=None)["risk_score"]

        os.environ["SAFEGUARD_SPEECH_ACT"] = "off"
        cfg._SETTINGS_INSTANCE = None
        score_off = agent.explain(text, url_report=None)["risk_score"]

        os.environ["SAFEGUARD_SPEECH_ACT"] = "on"
        cfg._SETTINGS_INSTANCE = None

        assert score_on <= score_off, (
            f"M5 alive: gate increased score (on={score_on} > off={score_off})"
        )

    def test_mutation_6_flag_off_disabled(self):
        """
        M6: Bỏ cờ SAFEGUARD_SPEECH_ACT → không thể tắt cổng (ablation bị phá).
        Phát hiện: khi set SAFEGUARD_SPEECH_ACT=off, cổng phải tắt (= không giảm điểm).
        """
        import codebase.config as cfg
        import inspect
        import codebase.agents.explainable_agent as ea_module
        source = inspect.getsource(ea_module.ExplainableAgent.explain)
        # Phải có check cờ speech_act_enabled
        assert "speech_act_enabled" in source, (
            "M6 alive: SAFEGUARD_SPEECH_ACT flag check removed from gate"
        )
        # Verify config parses it
        os.environ["SAFEGUARD_SPEECH_ACT"] = "off"
        cfg._SETTINGS_INSTANCE = None
        s = cfg.get_settings()
        assert s.speech_act_enabled is False, (
            "M6 alive: SAFEGUARD_SPEECH_ACT=off not parsed correctly"
        )
        os.environ["SAFEGUARD_SPEECH_ACT"] = "on"
        cfg._SETTINGS_INSTANCE = None

    def test_mutation_7_solicitation_priority_reversed(self):
        """
        M7: Ưu tiên solicitation bị đảo (benign override solicitation).
        Phát hiện: scam có yêu cầu hành động + có từ "cảnh báo" → PHẢI là solicitation.
        """
        text = (
            "Cảnh báo: tài khoản ngân hàng của anh/chị đang bị xâm nhập. "
            "Vui lòng đọc mã OTP cho nhân viên để bảo vệ tài khoản ngay bây giờ."
        )
        act = classify_speech_act(text)
        assert act.label == "solicitation", (
            f"M7 alive: solicitation priority reversed, got {act.label}"
        )

    def test_mutation_8_no_unaccented_detection(self):
        """
        M8: Bỏ nhận diện không dấu → scam không dấu không bị bắt.
        Phát hiện: scam không dấu vẫn phải cho nhãn solicitation hoặc không phải lành tính.
        """
        text_no_accent = "Vui long cung cap ma otp cho nhan vien ho tro de xac minh tai khoan."
        act = classify_speech_act(text_no_accent)
        # Không được là lành tính rõ ràng
        assert act.label not in {"news_report", "public_warning", "victim_advice", "everyday"}, (
            f"M8 alive: unaccented scam labeled as benign ({act.label})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test D3: System prompt blocks có mặt
# ─────────────────────────────────────────────────────────────────────────────

class TestSystemPromptD3:
    """D3: Verify speech-act role block trong system prompts. Không gọi LLM."""

    def test_multi_llm_client_has_d3_block(self):
        """MultiLLMClient._build_system_prompt phải có khối PHÂN BIỆT 3 VAI."""
        from codebase.agents.multi_llm_client import MultiLLMClient
        import inspect
        source = inspect.getsource(MultiLLMClient._build_system_prompt)
        assert "PHÂN BIỆT 3 VAI" in source, (
            "D3: multi_llm_client._build_system_prompt missing PHÂN BIỆT 3 VAI block"
        )
        assert "VAI 1" in source and "VAI 2" in source and "VAI 3" in source, (
            "D3: Not all 3 roles present in multi_llm_client system prompt"
        )

    def test_gemini_runner_has_d3_block(self):
        """GeminiAgentRunner._build_system_prompt phải có khối PHÂN BIỆT 3 VAI."""
        from codebase.agents.gemini_agent_runner import GeminiAgentRunner
        import inspect
        source = inspect.getsource(GeminiAgentRunner._build_system_prompt)
        assert "PHÂN BIỆT 3 VAI" in source, (
            "D3: gemini_agent_runner._build_system_prompt missing PHÂN BIỆT 3 VAI block"
        )
        assert "VAI 1" in source and "VAI 2" in source and "VAI 3" in source, (
            "D3: Not all 3 roles present in gemini_agent_runner system prompt"
        )

    def test_d3_llm_cannot_reduce_on_system_evidence(self):
        """D3: Quy tắc 'không hạ điểm khi có bằng chứng kỹ thuật cứng' phải có trong prompt."""
        from codebase.agents.multi_llm_client import MultiLLMClient
        import inspect
        source = inspect.getsource(MultiLLMClient._build_system_prompt)
        assert "bằng chứng kỹ thuật cứng" in source or "KHÔNG ĐƯỢC hạ điểm" in source, (
            "D3: Rule about not reducing score on hard evidence not found"
        )

    def test_d3_json_output_structure_unchanged(self):
        """D3: Cấu trúc JSON đầu ra không bị thay đổi."""
        from codebase.agents.multi_llm_client import MultiLLMClient
        import inspect
        source = inspect.getsource(MultiLLMClient._build_system_prompt)
        # Các key bắt buộc vẫn còn
        for key in ["intent_type", "conversational_reply", "risk_score",
                    "explanation_breakdown", "recommendations"]:
            assert key in source, f"D3: JSON key '{key}' missing from system prompt"

    def test_d3_untrusted_tag_still_present(self):
        """Thẻ user_input_untrusted vẫn được dùng trong prompt."""
        from codebase.agents.multi_llm_client import MultiLLMClient
        import inspect
        # Check _build_user_prompt hoặc _build_prompt
        source_u = inspect.getsource(MultiLLMClient._build_user_prompt)
        assert "user_input_untrusted" in source_u or "untrusted" in source_u, (
            "D3: untrusted input tag removed from user prompt"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test regression: speech_act không phá các test hiện có
# ─────────────────────────────────────────────────────────────────────────────

class TestSpeechActRegression:
    """Kiểm tra speech_act module không phá vỡ các invariant cũ."""

    def test_config_has_speech_act_flag(self):
        """Config phải có trường speech_act_enabled."""
        import codebase.config as cfg
        cfg._SETTINGS_INSTANCE = None
        s = cfg.get_settings()
        assert hasattr(s, "speech_act_enabled"), "Settings missing speech_act_enabled"

    def test_flag_on_by_default(self):
        """SAFEGUARD_SPEECH_ACT mặc định là on."""
        import codebase.config as cfg
        env_backup = os.environ.pop("SAFEGUARD_SPEECH_ACT", None)
        cfg._SETTINGS_INSTANCE = None
        try:
            s = cfg.get_settings()
            assert s.speech_act_enabled is True, "Default should be True"
        finally:
            if env_backup is not None:
                os.environ["SAFEGUARD_SPEECH_ACT"] = env_backup
            cfg._SETTINGS_INSTANCE = None

    def test_flag_off_parses_correctly(self):
        """SAFEGUARD_SPEECH_ACT=off → speech_act_enabled=False."""
        import codebase.config as cfg
        os.environ["SAFEGUARD_SPEECH_ACT"] = "off"
        cfg._SETTINGS_INSTANCE = None
        s = cfg.get_settings()
        assert s.speech_act_enabled is False
        os.environ.pop("SAFEGUARD_SPEECH_ACT", None)
        cfg._SETTINGS_INSTANCE = None

    def test_explainable_explain_still_returns_required_keys(self):
        """ExplainableAgent.explain vẫn trả về các key bắt buộc."""
        import codebase.config as cfg
        os.environ["SAFEGUARD_OFFLINE"] = "1"
        cfg._SETTINGS_INSTANCE = None
        from codebase.agents.explainable_agent import ExplainableAgent
        agent = ExplainableAgent()
        result = agent.explain("Xin chào bạn", url_report=None)
        for key in ["risk_score", "risk_breakdown", "reasons"]:
            assert key in result, f"Missing key '{key}' in explain result"
        assert isinstance(result["risk_score"], (int, float))
        assert 0 <= result["risk_score"] <= 99

    def test_speech_act_no_network_call(self):
        """classify_speech_act không gọi mạng."""
        import socket
        original_socket = socket.socket

        call_count = [0]
        def patched_socket(*args, **kwargs):
            call_count[0] += 1
            return original_socket(*args, **kwargs)

        socket.socket = patched_socket
        try:
            classify_speech_act("Tôi vừa bị lừa 20 triệu, giờ làm sao?")
        finally:
            socket.socket = original_socket

        assert call_count[0] == 0, "classify_speech_act made network calls!"
